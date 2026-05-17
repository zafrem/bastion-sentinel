package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/zafrem/bastion-sentinel/cache"
	"github.com/zafrem/bastion-sentinel/config"
	"github.com/zafrem/bastion-sentinel/engine"
	"github.com/zafrem/bastion-sentinel/types"
)

const maxBodyBytes = 1 << 20 // 1 MB

// REST is the HTTP server for Bastion-Sentinel.
type REST struct {
	mu       sync.RWMutex
	val      cache.Validator
	cacheRef cache.Cache
	cfg      *config.Config
	cfgPath  string
	started  time.Time
	srv      *http.Server
	log      *slog.Logger
	notifier *Notifier
}

func NewREST(cfg *config.Config, val cache.Validator, c cache.Cache, cfgPath string, log *slog.Logger, notifier *Notifier) *REST {
	s := &REST{
		cfg:      cfg,
		val:      val,
		cacheRef: c,
		cfgPath:  cfgPath,
		started:  time.Now(),
		log:      log,
		notifier: notifier,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/validate", s.handleValidate)
	mux.HandleFunc("/v1/validate/batch", s.handleBatch)
	mux.HandleFunc("/v1/health", s.handleHealth)
	mux.HandleFunc("/v1/config", s.handleGetConfig)
	mux.HandleFunc("/v1/config/reload", s.handleConfigReload)
	mux.Handle("/v1/metrics", metricsHandler())
	mux.HandleFunc("/health/live", handleLive)
	mux.HandleFunc("/health/ready", s.handleReady)

	s.srv = &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.RESTPort),
		Handler:      withMiddleware(mux),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	return s
}

// Reload swaps the engine and config atomically (mirrors gRPC Reload and POST /v1/config/reload).
func (s *REST) Reload(cfg *config.Config, newEng cache.Validator) {
	s.mu.Lock()
	s.cfg = cfg
	if cv, ok := s.val.(*cache.CachedValidator); ok {
		cv.SwapEngine(newEng)
	} else {
		s.val = newEng
		_ = s.cacheRef.Flush()
	}
	s.mu.Unlock()
}

func (s *REST) Addr() string { return s.srv.Addr }

func (s *REST) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.srv.Handler.ServeHTTP(w, r)
}

func (s *REST) ListenAndServe() error {
	return s.srv.ListenAndServe()
}

func (s *REST) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

// ─── middleware ───────────────────────────────────────────────────────────────

func withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("X-Request-ID")
		if reqID == "" {
			reqID = uuid.New().String()
		}
		w.Header().Set("X-Request-ID", reqID)
		w.Header().Set("Content-Type", "application/json")
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		next.ServeHTTP(w, r)
	})
}

// ─── POST /v1/validate ────────────────────────────────────────────────────────

type validateReq struct {
	RequestID string            `json:"request_id"`
	Query     string            `json:"query"`
	Metadata  map[string]string `json:"metadata"`
	Options   *reqOptions       `json:"options,omitempty"`
}

type reqOptions struct {
	StrictMode     bool   `json:"strict_mode"`
	TimeoutMs      int    `json:"timeout_ms"`
	IncludeDetails bool   `json:"include_details"`
	OutputFormat   string `json:"output_format"`
}

func (s *REST) handleValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "use POST")
		return
	}
	if !isJSONContent(r) {
		writeError(w, http.StatusUnsupportedMediaType, "INVALID_CONTENT_TYPE", "Content-Type must be application/json")
		return
	}

	var req validateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if req.RequestID == "" {
		req.RequestID = r.Header.Get("X-Request-ID")
	}
	if req.Metadata == nil {
		req.Metadata = map[string]string{}
	}

	var opts types.ValidateOptions
	if req.Options != nil {
		opts.StrictMode = req.Options.StrictMode
		opts.TimeoutMs = req.Options.TimeoutMs
		opts.IncludeDetails = req.Options.IncludeDetails
		opts.OutputFormat = req.Options.OutputFormat
	}

	s.mu.RLock()
	val := s.val
	s.mu.RUnlock()

	resp := val.Validate(types.ValidateRequest{
		RequestID: req.RequestID,
		Query:     req.Query,
		Metadata:  req.Metadata,
		Options:   opts,
	})

	requestsTotal.WithLabelValues(string(resp.Status)).Inc()
	requestDurationMs.Observe(resp.ProcessingTimeMs)
	injectionScore.Observe(resp.PromptCheck.RiskScore)
	s.log.Info("validate",
		"request_id", resp.RequestID,
		"status", resp.Status,
		"processing_time_ms", resp.ProcessingTimeMs,
		"prompt_injection_score", resp.PromptCheck.RiskScore,
		"metadata_valid", resp.MetadataCheck.Status == types.StatusPassed,
		"method", resp.PromptCheck.Method,
		"tenant_id", req.Metadata["tenant_id"],
		"user_id", req.Metadata["user_id"],
	)
	s.notifier.Notify(resp)

	httpStatus := http.StatusOK
	if resp.Status == types.StatusBlocked {
		httpStatus = http.StatusForbidden
	}
	writeJSON(w, httpStatus, toAPIResponse(resp))
}

// ─── POST /v1/validate/batch ──────────────────────────────────────────────────

type batchResp struct {
	Total   int           `json:"total"`
	Passed  int           `json:"passed"`
	Blocked int           `json:"blocked"`
	Results []apiResponse `json:"results"`
}

func (s *REST) handleBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "use POST")
		return
	}
	if !isJSONContent(r) {
		writeError(w, http.StatusUnsupportedMediaType, "INVALID_CONTENT_TYPE", "Content-Type must be application/json")
		return
	}

	var reqs []validateReq
	if err := json.NewDecoder(r.Body).Decode(&reqs); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}

	s.mu.RLock()
	batchVal := s.val
	s.mu.RUnlock()

	results := make([]apiResponse, len(reqs))
	sem := make(chan struct{}, 8) // max 8 concurrent workers
	var wg sync.WaitGroup
	var mu sync.Mutex

	for i, req := range reqs {
		wg.Add(1)
		go func(idx int, req validateReq) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if req.RequestID == "" {
				req.RequestID = fmt.Sprintf("batch-%d", idx+1)
			}
			if req.Metadata == nil {
				req.Metadata = map[string]string{}
			}
			resp := batchVal.Validate(types.ValidateRequest{
				RequestID: req.RequestID,
				Query:     req.Query,
				Metadata:  req.Metadata,
			})
			mu.Lock()
			results[idx] = toAPIResponse(resp)
			mu.Unlock()
		}(i, req)
	}
	wg.Wait()

	passed, blocked := 0, 0
	for _, res := range results {
		requestsTotal.WithLabelValues(res.Status).Inc()
		if res.Status == string(types.StatusPassed) {
			passed++
		} else {
			blocked++
		}
	}
	s.log.Info("validate_batch",
		"total", len(results),
		"passed", passed,
		"blocked", blocked,
	)
	writeJSON(w, http.StatusOK, batchResp{
		Total:   len(results),
		Passed:  passed,
		Blocked: blocked,
		Results: results,
	})
}

// ─── GET /v1/health ───────────────────────────────────────────────────────────

type healthResp struct {
	Status        string  `json:"status"`
	Version       string  `json:"version"`
	UptimeSeconds float64 `json:"uptime_seconds"`
	Engine        string  `json:"engine"`
}

func (s *REST) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "use GET")
		return
	}
	s.mu.RLock()
	version := s.cfg.Version
	s.mu.RUnlock()
	writeJSON(w, http.StatusOK, healthResp{
		Status:        "ok",
		Version:       version,
		UptimeSeconds: time.Since(s.started).Seconds(),
		Engine:        "ready",
	})
}

// ─── GET /health/live ────────────────────────────────────────────────────────
// Kubernetes liveness probe — always 200 while the process is alive.

func handleLive(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "alive"})
}

// ─── GET /health/ready ───────────────────────────────────────────────────────
// Kubernetes readiness probe — 200 when the engine is initialised, 503 during reload.

func (s *REST) handleReady(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	ready := s.val != nil
	s.mu.RUnlock()
	if ready {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	} else {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready"})
	}
}

// ─── GET /v1/config ───────────────────────────────────────────────────────────

func (s *REST) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "use GET")
		return
	}
	s.mu.RLock()
	cfg := s.cfg
	s.mu.RUnlock()
	writeJSON(w, http.StatusOK, cfg)
}

// ─── POST /v1/config/reload ───────────────────────────────────────────────────

func (s *REST) handleConfigReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "use POST")
		return
	}
	if s.cfgPath == "" {
		writeJSON(w, http.StatusOK, map[string]string{
			"status":  "no-op",
			"message": "running with built-in defaults; provide --config <file> to enable hot-reload",
		})
		return
	}
	newCfg, err := config.Load(s.cfgPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "CONFIG_ERROR", err.Error())
		return
	}
	newEng, err := engine.New(newCfg)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ENGINE_ERROR", err.Error())
		return
	}
	s.mu.Lock()
	s.cfg = newCfg
	if cv, ok := s.val.(*cache.CachedValidator); ok {
		cv.SwapEngine(newEng) // swaps engine + flushes cache
	} else {
		s.val = newEng
		_ = s.cacheRef.Flush()
	}
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"message": "config reloaded",
		"source":  s.cfgPath,
	})
}

// ─── response types ───────────────────────────────────────────────────────────

type apiResponse struct {
	RequestID        string       `json:"request_id"`
	Status           string       `json:"status"`
	Timestamp        string       `json:"timestamp"`
	ProcessingTimeMs float64      `json:"processing_time_ms"`
	Checks           checksJSON   `json:"checks"`
	ExtractedData    extractedJSON `json:"extracted_data"`
}

type checksJSON struct {
	PromptInjection    promptCheckJSON `json:"prompt_injection"`
	MetadataValidation metaCheckJSON   `json:"metadata_validation"`
}

type promptCheckJSON struct {
	Status          string   `json:"status"`
	RiskScore       float64  `json:"risk_score"`
	Method          string   `json:"method"`
	MatchedPatterns []string `json:"matched_patterns"`
}

type metaCheckJSON struct {
	Status                string   `json:"status"`
	RequiredFieldsPresent bool     `json:"required_fields_present"`
	FormatErrors          []string `json:"format_errors"`
}

type extractedJSON struct {
	TenantID     string `json:"tenant_id"`
	UserID       string `json:"user_id"`
	CleanedQuery string `json:"cleaned_query"`
}

func toAPIResponse(resp types.ValidateResponse) apiResponse {
	return apiResponse{
		RequestID:        resp.RequestID,
		Status:           string(resp.Status),
		Timestamp:        resp.Timestamp.UTC().Format(time.RFC3339Nano),
		ProcessingTimeMs: resp.ProcessingTimeMs,
		Checks: checksJSON{
			PromptInjection: promptCheckJSON{
				Status:          string(resp.PromptCheck.Status),
				RiskScore:       resp.PromptCheck.RiskScore,
				Method:          resp.PromptCheck.Method,
				MatchedPatterns: nilSafe(resp.PromptCheck.MatchedPatterns),
			},
			MetadataValidation: metaCheckJSON{
				Status:                string(resp.MetadataCheck.Status),
				RequiredFieldsPresent: len(resp.MetadataCheck.MissingFields) == 0,
				FormatErrors:          nilSafe(resp.MetadataCheck.FormatErrors),
			},
		},
		ExtractedData: extractedJSON{
			TenantID:     resp.ExtractedData.TenantID,
			UserID:       resp.ExtractedData.UserID,
			CleanedQuery: resp.ExtractedData.CleanedQuery,
		},
	}
}

// ─── helpers ──────────────────────────────────────────────────────────────────

type errResp struct {
	Error   string `json:"error"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errResp{
		Error:   http.StatusText(status),
		Code:    code,
		Message: message,
	})
}

func isJSONContent(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Content-Type"), "application/json")
}

func nilSafe(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
