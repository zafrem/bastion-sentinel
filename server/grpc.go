package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zafrem/bastion-sentinel/cache"
	"github.com/zafrem/bastion-sentinel/config"
	sentinelv1 "github.com/zafrem/bastion-sentinel/proto"
	"github.com/zafrem/bastion-sentinel/types"
)

// GRPC is the gRPC server for Bastion-Sentinel.
type GRPC struct {
	sentinelv1.UnimplementedSentinelServiceServer

	mu       sync.RWMutex
	val      cache.Validator
	cacheRef cache.Cache
	cfg      *config.Config
	cfgPath  string
	started  time.Time
	srv      *grpc.Server
	log      *slog.Logger
	notifier *Notifier
}

func NewGRPC(cfg *config.Config, val cache.Validator, c cache.Cache, cfgPath string, log *slog.Logger, notifier *Notifier) *GRPC {
	g := &GRPC{
		cfg:      cfg,
		val:      val,
		cacheRef: c,
		cfgPath:  cfgPath,
		started:  time.Now(),
		log:      log,
		notifier: notifier,
	}
	g.srv = grpc.NewServer(
		grpc.MaxRecvMsgSize(1 << 20),
	)
	sentinelv1.RegisterSentinelServiceServer(g.srv, g)
	return g
}

func (g *GRPC) Addr() string {
	return fmt.Sprintf(":%d", g.cfg.Server.GRPCPort)
}

func (g *GRPC) ListenAndServe() error {
	ln, err := net.Listen("tcp", g.Addr())
	if err != nil {
		return err
	}
	return g.srv.Serve(ln)
}

func (g *GRPC) Shutdown() {
	g.srv.GracefulStop()
}

// Reload swaps the engine and config atomically (mirrors REST /v1/config/reload).
func (g *GRPC) Reload(cfg *config.Config, newEng cache.Validator) {
	g.mu.Lock()
	g.cfg = cfg
	if cv, ok := g.val.(*cache.CachedValidator); ok {
		cv.SwapEngine(newEng)
	} else {
		g.val = newEng
		_ = g.cacheRef.Flush()
	}
	g.mu.Unlock()
}

// ─── RPC: Validate ────────────────────────────────────────────────────────────

func (g *GRPC) Validate(_ context.Context, req *sentinelv1.ValidateRequest) (*sentinelv1.ValidateResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request must not be nil")
	}

	g.mu.RLock()
	eng := g.val
	g.mu.RUnlock()

	resp := eng.Validate(toEngineRequest(req))
	requestsTotal.WithLabelValues(string(resp.Status)).Inc()
	requestDurationMs.Observe(resp.ProcessingTimeMs)
	injectionScore.Observe(resp.PromptCheck.RiskScore)
	g.log.Info("validate",
		"request_id", resp.RequestID,
		"status", resp.Status,
		"processing_time_ms", resp.ProcessingTimeMs,
		"prompt_injection_score", resp.PromptCheck.RiskScore,
		"metadata_valid", resp.MetadataCheck.Status == "PASSED",
		"method", resp.PromptCheck.Method,
	)
	g.notifier.Notify(resp)
	return toProtoResponse(resp), nil
}

// ─── RPC: ValidateBatch ───────────────────────────────────────────────────────

func (g *GRPC) ValidateBatch(_ context.Context, req *sentinelv1.BatchRequest) (*sentinelv1.BatchResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request must not be nil")
	}

	g.mu.RLock()
	eng := g.val
	g.mu.RUnlock()

	results := make([]*sentinelv1.ValidateResponse, len(req.Requests))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for i, r := range req.Requests {
		wg.Add(1)
		go func(idx int, r *sentinelv1.ValidateRequest) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if r.RequestId == "" {
				r.RequestId = fmt.Sprintf("batch-%d", idx+1)
			}
			resp := eng.Validate(toEngineRequest(r))
			mu.Lock()
			results[idx] = toProtoResponse(resp)
			mu.Unlock()
		}(i, r)
	}
	wg.Wait()

	var passed, blocked int32
	for _, r := range results {
		if r.Status == sentinelv1.ValidateResponse_PASSED {
			passed++
		} else {
			blocked++
		}
	}
	return &sentinelv1.BatchResponse{
		Total:   int32(len(results)),
		Passed:  passed,
		Blocked: blocked,
		Results: results,
	}, nil
}

// ─── RPC: Health ──────────────────────────────────────────────────────────────

func (g *GRPC) Health(_ context.Context, _ *sentinelv1.HealthRequest) (*sentinelv1.HealthResponse, error) {
	g.mu.RLock()
	version := g.cfg.Version
	g.mu.RUnlock()
	return &sentinelv1.HealthResponse{
		Status:        "ok",
		Version:       version,
		UptimeSeconds: time.Since(g.started).Seconds(),
		Engine:        "ready",
	}, nil
}

// ─── mapping helpers ──────────────────────────────────────────────────────────

func toEngineRequest(req *sentinelv1.ValidateRequest) types.ValidateRequest {
	meta := req.Metadata
	if meta == nil {
		meta = map[string]string{}
	}
	var opts types.ValidateOptions
	if req.Options != nil {
		opts.StrictMode = req.Options.StrictMode
		opts.TimeoutMs = int(req.Options.TimeoutMs)
		opts.IncludeDetails = req.Options.IncludeDetails
	}
	return types.ValidateRequest{
		RequestID: req.RequestId,
		Query:     req.Query,
		Metadata:  meta,
		Options:   opts,
	}
}

func toProtoResponse(resp types.ValidateResponse) *sentinelv1.ValidateResponse {
	pbStatus := sentinelv1.ValidateResponse_UNKNOWN
	switch resp.Status {
	case types.StatusPassed:
		pbStatus = sentinelv1.ValidateResponse_PASSED
	case types.StatusBlocked:
		pbStatus = sentinelv1.ValidateResponse_BLOCKED
	case types.StatusError:
		pbStatus = sentinelv1.ValidateResponse_ERROR
	}

	return &sentinelv1.ValidateResponse{
		RequestId:        resp.RequestID,
		Status:           pbStatus,
		ProcessingTimeMs: float32(resp.ProcessingTimeMs),
		ErrorMessage:     resp.ErrorMessage,
		Timestamp:        resp.Timestamp.UTC().Format(time.RFC3339Nano),
		PromptCheck: &sentinelv1.PromptCheck{
			Status:          string(resp.PromptCheck.Status),
			RiskScore:       float32(resp.PromptCheck.RiskScore),
			Method:          resp.PromptCheck.Method,
			MatchedPatterns: nilSafeProto(resp.PromptCheck.MatchedPatterns),
		},
		MetadataCheck: &sentinelv1.MetadataCheck{
			Status:                string(resp.MetadataCheck.Status),
			RequiredFieldsPresent: len(resp.MetadataCheck.MissingFields) == 0,
			MissingFields:         nilSafeProto(resp.MetadataCheck.MissingFields),
			FormatErrors:          nilSafeProto(resp.MetadataCheck.FormatErrors),
		},
		ExtractedData: &sentinelv1.ExtractedData{
			TenantId:     resp.ExtractedData.TenantID,
			UserId:       resp.ExtractedData.UserID,
			CleanedQuery: resp.ExtractedData.CleanedQuery,
		},
	}
}

func nilSafeProto(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
