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
	"github.com/zafrem/bastion-sentinel/hooks"
	"github.com/zafrem/bastion-sentinel/types"
)

const maxBodyBytes = 1 << 20 // 1 MB

// REST is the HTTP server for Bastion-Sentinel.
type REST struct {
	mu        sync.RWMutex
	val       cache.Validator
	cacheRef  cache.Cache
	cfg       *config.Config
	cfgPath   string
	started   time.Time
	srv       *http.Server
	log       *slog.Logger
	notifier  *Notifier
	outputEng *engine.OutputEngine
	pub       *EventPublisher
	hm        *hooks.Manager
}

// Hooks returns the HookManager so external coordinators can register listeners.
func (s *REST) Hooks() *hooks.Manager { return s.hm }

func NewREST(cfg *config.Config, val cache.Validator, c cache.Cache, cfgPath string, log *slog.Logger, notifier *Notifier) *REST {
	outEng, _ := engine.NewOutputEngine(cfg) // errors surface at validate time

	var pub *EventPublisher
	if cfg.Events.NATSUrl != "" {
		pub = NewEventPublisher(cfg.Events.NATSUrl)
	}

	s := &REST{
		cfg:       cfg,
		val:       val,
		cacheRef:  c,
		cfgPath:   cfgPath,
		started:   time.Now(),
		log:       log,
		notifier:  notifier,
		outputEng: outEng,
		pub:       pub,
		hm:        hooks.New(),
	}

	mux := http.NewServeMux()
	// Core (Standalone) — §3 of Sentinel SRS
	mux.HandleFunc("/v1/validate", s.handleValidate)
	mux.HandleFunc("/v1/validate/batch", s.handleBatch)
	mux.HandleFunc("/v1/validate/output", s.handleOutputValidate)
	mux.HandleFunc("/v1/validate/output/batch", s.handleOutputBatch)
	// Enhanced (Composition) — §4 of Sentinel SRS
	mux.HandleFunc("/v1/validate/input/contextual", s.handleValidateWithContext)
	mux.HandleFunc("/v1/validate/output/mapped", s.handleOutputWithMappings)
	// SRS-aligned aliases: POST /v1/sentinel/validate/... (SRS §6.3)
	mux.HandleFunc("/v1/sentinel/validate/input", s.handleValidate)
	mux.HandleFunc("/v1/sentinel/validate/output", s.handleOutputValidate)
	mux.HandleFunc("/v1/sentinel/validate/input/contextual", s.handleValidateWithContext)
	mux.HandleFunc("/v1/sentinel/validate/output/mapped", s.handleOutputWithMappings)
	// Standard
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
	outEng, _ := engine.NewOutputEngine(cfg)
	s.mu.Lock()
	s.cfg = cfg
	s.outputEng = outEng
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

	// Emit Foundation events (doc 02) — non-blocking.
	tc := extractTraceContext(
		r.Header.Get("X-Trace-ID"),
		r.Header.Get("X-Span-ID"),
		r.Header.Get("X-Parent-Span-ID"),
		req.Metadata["tenant_id"],
		req.Metadata["user_id"],
		req.RequestID,
	)
	if resp.Status == types.StatusBlocked {
		s.pub.Publish(EventInjectionBlocked(tc, resp.PromptCheck.RiskScore, strings.Join(resp.PromptCheck.MatchedPatterns, ",")))
		s.hm.Fire(hooks.Event{
			Type: hooks.EventInjectionBlocked, RequestID: req.RequestID,
			TenantID: req.Metadata["tenant_id"], TraceID: tc.TraceID, SpanID: tc.SpanID,
			Data: map[string]interface{}{"score": resp.PromptCheck.RiskScore},
			Ctx:  r.Context(),
		})
	} else if resp.PromptCheck.RiskScore > 0.3 {
		s.pub.Publish(EventInjectionDetected(tc, resp.PromptCheck.RiskScore, resp.PromptCheck.MatchedPatterns))
		s.hm.Fire(hooks.Event{
			Type: hooks.EventInjectionDetected, RequestID: req.RequestID,
			TenantID: req.Metadata["tenant_id"], TraceID: tc.TraceID, SpanID: tc.SpanID,
			Data: map[string]interface{}{"score": resp.PromptCheck.RiskScore},
			Ctx:  r.Context(),
		})
	}
	s.pub.Publish(EventInputValidated(tc, resp.PromptCheck.RiskScore, "full"))
	s.pub.Publish(EventPipelineRoutingDecided(tc, "full", "input_validated"))
	s.hm.Fire(hooks.Event{
		Type: hooks.EventInputValidated, RequestID: req.RequestID,
		TenantID: req.Metadata["tenant_id"], TraceID: tc.TraceID, SpanID: tc.SpanID,
		Data: map[string]interface{}{"score": resp.PromptCheck.RiskScore, "status": string(resp.Status)},
		Ctx:  r.Context(),
	})

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

// ─── POST /v1/validate/output ─────────────────────────────────────────────────

type outputValidateReq struct {
	RequestID   string                      `json:"request_id"`
	TraceID     string                      `json:"trace_id"`
	LLMResponse string                      `json:"llm_response"`
	User        types.UserContext            `json:"user"`
	Retrieval   types.RetrievalContext      `json:"retrieval"`
	Options     types.OutputValidationOptions `json:"options"`
}

func (s *REST) handleOutputValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "use POST")
		return
	}
	if !isJSONContent(r) {
		writeError(w, http.StatusUnsupportedMediaType, "INVALID_CONTENT_TYPE", "Content-Type must be application/json")
		return
	}

	var req outputValidateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if req.RequestID == "" {
		req.RequestID = r.Header.Get("X-Request-ID")
	}

	s.mu.RLock()
	outEng := s.outputEng
	s.mu.RUnlock()

	if outEng == nil {
		writeError(w, http.StatusInternalServerError, "ENGINE_ERROR", "output engine not initialised")
		return
	}

	resp := outEng.Validate(types.OutputValidateRequest{
		RequestID:   req.RequestID,
		TraceID:     req.TraceID,
		LLMResponse: req.LLMResponse,
		User:        req.User,
		Retrieval:   req.Retrieval,
		Options:     req.Options,
	})

	s.log.Info("validate_output",
		"request_id", resp.RequestID,
		"status", resp.Status,
		"processing_time_ms", resp.ProcessingTimeMs,
		"pii_incidents", resp.Checks.PIICheck.RedactionsApplied,
		"grounding_score", resp.Checks.HallucinationCheck.GroundingScore,
		"permission_violated", resp.Checks.PermissionCheck.BoundaryViolated,
	)

	// Emit Foundation events (doc 02).
	tc := extractTraceContext(
		req.TraceID,
		r.Header.Get("X-Span-ID"),
		r.Header.Get("X-Parent-Span-ID"),
		req.User.TenantID,
		req.User.UserID,
		req.RequestID,
	)
	action := ""
	if resp.Checks.PIICheck.RedactionsApplied > 0 {
		piiTypes := make([]string, 0, len(resp.Checks.PIICheck.Incidents))
		for _, f := range resp.Checks.PIICheck.Incidents {
			piiTypes = append(piiTypes, f.PIIType)
		}
		s.pub.Publish(EventPIIPrevented(tc, piiTypes, resp.Checks.PIICheck.RedactionsApplied))
		action = "pii_redacted"
	}
	s.pub.Publish(EventOutputValidated(tc, string(resp.Status), action))

	httpStatus := http.StatusOK
	if resp.Status == types.OutputStatusBlocked {
		httpStatus = http.StatusForbidden
	}
	writeJSON(w, httpStatus, resp)
}

// ─── POST /v1/validate/input/contextual ──────────────────────────────────────
// Enhanced (Composition) endpoint: validates query AND scans retrieved documents
// for indirect injection. The caller (orchestrator) assembles the retrieved docs;
// Sentinel never fetches them directly.

type contextualValidateReq struct {
	RequestID          string            `json:"request_id"`
	Query              string            `json:"query"`
	Metadata           map[string]string `json:"metadata"`
	RetrievedDocuments []string          `json:"retrieved_documents"`
	HoneyTokenRefs     []string          `json:"honey_token_refs,omitempty"` // supplied by orchestrator from Vault
	Options            *reqOptions       `json:"options,omitempty"`
}

type contextualValidateResp struct {
	apiResponse
	DocumentFindings []documentFinding `json:"document_findings"`
}

type documentFinding struct {
	Index     int      `json:"index"`
	RiskScore float64  `json:"risk_score"`
	Patterns  []string `json:"patterns"`
	Blocked   bool     `json:"blocked"`
}

func (s *REST) handleValidateWithContext(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "use POST")
		return
	}
	if !isJSONContent(r) {
		writeError(w, http.StatusUnsupportedMediaType, "INVALID_CONTENT_TYPE", "Content-Type must be application/json")
		return
	}

	var req contextualValidateReq
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

	// Validate the primary query.
	queryResp := val.Validate(types.ValidateRequest{
		RequestID: req.RequestID,
		Query:     req.Query,
		Metadata:  req.Metadata,
		Options:   opts,
	})

	// Scan each retrieved document for indirect injection.
	docFindings := make([]documentFinding, 0, len(req.RetrievedDocuments))
	docBlocked := false
	for i, doc := range req.RetrievedDocuments {
		docResp := val.Validate(types.ValidateRequest{
			RequestID: fmt.Sprintf("%s-doc-%d", req.RequestID, i),
			Query:     doc,
			Metadata:  req.Metadata,
			Options:   opts,
		})
		if docResp.PromptCheck.RiskScore > 0.3 || docResp.Status == types.StatusBlocked {
			blocked := docResp.Status == types.StatusBlocked
			if blocked {
				docBlocked = true
			}
			docFindings = append(docFindings, documentFinding{
				Index:     i,
				RiskScore: docResp.PromptCheck.RiskScore,
				Patterns:  docResp.PromptCheck.MatchedPatterns,
				Blocked:   blocked,
			})
		}
	}

	tc := extractTraceContext(
		r.Header.Get("X-Trace-ID"),
		r.Header.Get("X-Span-ID"),
		r.Header.Get("X-Parent-Span-ID"),
		req.Metadata["tenant_id"],
		req.Metadata["user_id"],
		req.RequestID,
	)

	finalStatus := queryResp.Status
	if docBlocked {
		finalStatus = types.StatusBlocked
	}

	// Honey-token input detection: check query against orchestrator-supplied refs.
	for _, ref := range req.HoneyTokenRefs {
		if ref != "" && strings.Contains(req.Query, ref) {
			s.pub.Publish(EventHoneyTokenReferenced(tc, "", ref))
			if finalStatus != types.StatusBlocked {
				finalStatus = types.StatusBlocked
			}
		}
	}

	if finalStatus == types.StatusBlocked {
		s.pub.Publish(EventInjectionBlocked(tc, queryResp.PromptCheck.RiskScore, strings.Join(queryResp.PromptCheck.MatchedPatterns, ",")))
	} else if queryResp.PromptCheck.RiskScore > 0.3 || len(docFindings) > 0 {
		s.pub.Publish(EventInjectionDetected(tc, queryResp.PromptCheck.RiskScore, queryResp.PromptCheck.MatchedPatterns))
	}
	s.pub.Publish(EventInputValidated(tc, queryResp.PromptCheck.RiskScore, "contextual"))
	s.pub.Publish(EventPipelineRoutingDecided(tc, "contextual", "input_validated"))

	s.log.Info("validate_contextual",
		"request_id", req.RequestID,
		"query_status", queryResp.Status,
		"final_status", finalStatus,
		"doc_count", len(req.RetrievedDocuments),
		"doc_findings", len(docFindings),
	)

	httpStatus := http.StatusOK
	if finalStatus == types.StatusBlocked {
		httpStatus = http.StatusForbidden
	}
	base := toAPIResponse(queryResp)
	base.Status = string(finalStatus)
	writeJSON(w, httpStatus, contextualValidateResp{
		apiResponse:      base,
		DocumentFindings: docFindings,
	})
}

// ─── POST /v1/validate/output/mapped ─────────────────────────────────────────
// Enhanced (Composition) endpoint: runs standard output validation and also
// checks the response against Vault-supplied token→real_value mappings to catch
// PII re-emergence that pattern matching alone may miss.

type mappedOutputValidateReq struct {
	RequestID      string                        `json:"request_id"`
	TraceID        string                        `json:"trace_id"`
	LLMResponse    string                        `json:"llm_response"`
	User           types.UserContext              `json:"user"`
	Retrieval      types.RetrievalContext         `json:"retrieval"`
	Options        types.OutputValidationOptions  `json:"options"`
	KnownMappings  map[string]string              `json:"known_mappings"`  // token→real_value from Vault
	HoneyTokenRefs []string                       `json:"honey_token_refs,omitempty"` // supplied by orchestrator from Vault
}

func (s *REST) handleOutputWithMappings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "use POST")
		return
	}
	if !isJSONContent(r) {
		writeError(w, http.StatusUnsupportedMediaType, "INVALID_CONTENT_TYPE", "Content-Type must be application/json")
		return
	}

	var req mappedOutputValidateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if req.RequestID == "" {
		req.RequestID = r.Header.Get("X-Request-ID")
	}

	s.mu.RLock()
	outEng := s.outputEng
	s.mu.RUnlock()

	if outEng == nil {
		writeError(w, http.StatusInternalServerError, "ENGINE_ERROR", "output engine not initialised")
		return
	}

	resp := outEng.Validate(types.OutputValidateRequest{
		RequestID:   req.RequestID,
		TraceID:     req.TraceID,
		LLMResponse: req.LLMResponse,
		User:        req.User,
		Retrieval:   req.Retrieval,
		Options:     req.Options,
	})

	// Deep PII check: scan the validated response for real values from Vault mappings.
	output := resp.ValidatedResponse
	if output == "" {
		output = req.LLMResponse
	}
	extraRedactions := 0
	extraPIITypes := make([]string, 0)
	for token, realValue := range req.KnownMappings {
		if realValue != "" && strings.Contains(output, realValue) {
			output = strings.ReplaceAll(output, realValue, token)
			extraRedactions++
			extraPIITypes = append(extraPIITypes, "vault_mapped_pii")
		}
	}
	if extraRedactions > 0 {
		resp.ValidatedResponse = output
		resp.Checks.PIICheck.RedactionsApplied += extraRedactions
		if resp.Status == types.OutputStatusPassed {
			resp.Status = types.OutputStatusSanitized
		}
	}

	tc := extractTraceContext(
		req.TraceID,
		r.Header.Get("X-Span-ID"),
		r.Header.Get("X-Parent-Span-ID"),
		req.User.TenantID,
		req.User.UserID,
		req.RequestID,
	)

	// Honey-token output leak detection: check LLM response against orchestrator-supplied refs.
	for _, ref := range req.HoneyTokenRefs {
		if ref != "" && strings.Contains(output, ref) {
			s.pub.Publish(EventHoneyTokenLeaked(tc, "", ref))
			if resp.Status == types.OutputStatusPassed || resp.Status == types.OutputStatusSanitized {
				resp.Status = types.OutputStatusBlocked
			}
		}
	}

	action := ""
	totalRedactions := resp.Checks.PIICheck.RedactionsApplied
	if totalRedactions > 0 {
		piiTypes := make([]string, 0, len(resp.Checks.PIICheck.Incidents)+len(extraPIITypes))
		for _, f := range resp.Checks.PIICheck.Incidents {
			piiTypes = append(piiTypes, f.PIIType)
		}
		piiTypes = append(piiTypes, extraPIITypes...)
		s.pub.Publish(EventPIIPrevented(tc, piiTypes, totalRedactions))
		action = "pii_redacted"
	}
	s.pub.Publish(EventOutputValidated(tc, string(resp.Status), action))

	s.log.Info("validate_output_mapped",
		"request_id", req.RequestID,
		"status", resp.Status,
		"standard_redactions", resp.Checks.PIICheck.RedactionsApplied-extraRedactions,
		"mapping_redactions", extraRedactions,
	)

	httpStatus := http.StatusOK
	if resp.Status == types.OutputStatusBlocked {
		httpStatus = http.StatusForbidden
	}
	writeJSON(w, httpStatus, resp)
}

// ─── POST /v1/validate/output/batch ──────────────────────────────────────────

func (s *REST) handleOutputBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "use POST")
		return
	}
	if !isJSONContent(r) {
		writeError(w, http.StatusUnsupportedMediaType, "INVALID_CONTENT_TYPE", "Content-Type must be application/json")
		return
	}

	var reqs []outputValidateReq
	if err := json.NewDecoder(r.Body).Decode(&reqs); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}

	s.mu.RLock()
	outEng := s.outputEng
	s.mu.RUnlock()

	if outEng == nil {
		writeError(w, http.StatusInternalServerError, "ENGINE_ERROR", "output engine not initialised")
		return
	}

	results := make([]types.OutputValidateResponse, len(reqs))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for i, req := range reqs {
		wg.Add(1)
		go func(idx int, req outputValidateReq) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if req.RequestID == "" {
				req.RequestID = fmt.Sprintf("out-batch-%d", idx+1)
			}
			resp := outEng.Validate(types.OutputValidateRequest{
				RequestID:   req.RequestID,
				TraceID:     req.TraceID,
				LLMResponse: req.LLMResponse,
				User:        req.User,
				Retrieval:   req.Retrieval,
				Options:     req.Options,
			})
			mu.Lock()
			results[idx] = resp
			mu.Unlock()
		}(i, req)
	}
	wg.Wait()

	passed, blocked, sanitized := 0, 0, 0
	for _, res := range results {
		switch res.Status {
		case types.OutputStatusPassed:
			passed++
		case types.OutputStatusBlocked:
			blocked++
		case types.OutputStatusSanitized, types.OutputStatusWarning:
			sanitized++
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"total":     len(results),
		"passed":    passed,
		"sanitized": sanitized,
		"blocked":   blocked,
		"results":   results,
	})
}
