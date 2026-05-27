package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/zafrem/bastion-sentinel/cache"
	"github.com/zafrem/bastion-sentinel/config"
	"github.com/zafrem/bastion-sentinel/engine"
	"github.com/zafrem/bastion-sentinel/hooks"
	sentinelv1 "github.com/zafrem/bastion-sentinel/proto"
	"github.com/zafrem/bastion-sentinel/types"
)

type grpcTraceKey struct{}

func grpcTraceInterceptor(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	tc := TraceContext{
		TraceID: uuid.New().String(),
		SpanID:  uuid.New().String()[:16],
	}
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if v := md.Get("x-trace-id"); len(v) > 0 {
			tc.TraceID = v[0]
		}
		if v := md.Get("x-span-id"); len(v) > 0 {
			tc.SpanID = v[0]
		}
		if v := md.Get("x-parent-span-id"); len(v) > 0 {
			tc.ParentSpanID = v[0]
		}
		if v := md.Get("x-tenant-id"); len(v) > 0 {
			tc.TenantID = v[0]
		}
		if v := md.Get("x-user-id"); len(v) > 0 {
			tc.UserID = v[0]
		}
		if v := md.Get("x-request-id"); len(v) > 0 {
			tc.RequestID = v[0]
		}
	}
	ctx = context.WithValue(ctx, grpcTraceKey{}, tc)
	return handler(ctx, req)
}

func traceFromGRPCCtx(ctx context.Context) TraceContext {
	if tc, ok := ctx.Value(grpcTraceKey{}).(TraceContext); ok {
		return tc
	}
	return TraceContext{TraceID: uuid.New().String(), SpanID: uuid.New().String()[:16]}
}

// GRPC is the gRPC server for Bastion-Sentinel.
type GRPC struct {
	sentinelv1.UnimplementedSentinelServiceServer

	mu        sync.RWMutex
	val       cache.Validator
	cacheRef  cache.Cache
	cfg       *config.Config
	cfgPath   string
	started   time.Time
	srv       *grpc.Server
	log       *slog.Logger
	notifier  *Notifier
	outputEng *engine.OutputEngine
	pub       *EventPublisher
	hm        *hooks.Manager
}

// Hooks returns the hook manager so external coordinators can register listeners.
func (g *GRPC) Hooks() *hooks.Manager { return g.hm }

func NewGRPC(cfg *config.Config, val cache.Validator, c cache.Cache, cfgPath string, log *slog.Logger, notifier *Notifier) *GRPC {
	var pub *EventPublisher
	if cfg.Events.NATSUrl != "" {
		pub = NewEventPublisher(cfg.Events.NATSUrl)
	}
	outEng, _ := engine.NewOutputEngine(cfg) // best-effort; nil means ValidateOutputStream returns Unimplemented
	g := &GRPC{
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
	g.srv = grpc.NewServer(
		grpc.MaxRecvMsgSize(1<<20),
		grpc.ChainUnaryInterceptor(grpcTraceInterceptor),
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

func (g *GRPC) Validate(ctx context.Context, req *sentinelv1.ValidateRequest) (*sentinelv1.ValidateResponse, error) {
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

	// Emit Foundation events via trace context from gRPC metadata.
	tc := traceFromGRPCCtx(ctx)
	if tc.TenantID == "" {
		tc.TenantID = req.GetMetadata()["tenant_id"]
	}
	tc.RequestID = resp.RequestID
	if resp.Status == types.StatusBlocked {
		g.pub.Publish(EventInjectionBlocked(tc, resp.PromptCheck.RiskScore, strings.Join(resp.PromptCheck.MatchedPatterns, ",")))
		g.hm.Fire(hooks.Event{
			Type:      hooks.EventInjectionBlocked,
			RequestID: resp.RequestID,
			TenantID:  tc.TenantID,
			TraceID:   tc.TraceID,
			SpanID:    tc.SpanID,
			Data:      map[string]interface{}{"score": resp.PromptCheck.RiskScore},
		})
	} else if resp.PromptCheck.RiskScore > 0.3 {
		g.pub.Publish(EventInjectionDetected(tc, resp.PromptCheck.RiskScore, resp.PromptCheck.MatchedPatterns))
		g.hm.Fire(hooks.Event{
			Type:      hooks.EventInjectionDetected,
			RequestID: resp.RequestID,
			TenantID:  tc.TenantID,
			TraceID:   tc.TraceID,
			SpanID:    tc.SpanID,
			Data:      map[string]interface{}{"score": resp.PromptCheck.RiskScore},
		})
	}
	g.pub.Publish(EventInputValidated(tc, resp.PromptCheck.RiskScore, "grpc"))
	g.pub.Publish(EventPipelineRoutingDecided(tc, "grpc", "input_validated"))
	g.hm.Fire(hooks.Event{
		Type:      hooks.EventInputValidated,
		RequestID: resp.RequestID,
		TenantID:  tc.TenantID,
		TraceID:   tc.TraceID,
		SpanID:    tc.SpanID,
		Data:      map[string]interface{}{"score": resp.PromptCheck.RiskScore, "status": string(resp.Status)},
	})

	return toProtoResponse(resp), nil
}

// ─── RPC: ValidateInputStream ────────────────────────────────────────────────
// Bidirectional streaming: client sends ValidateRequests, server responds with
// a ValidateResponse for each one. Useful for low-latency batch pipelines that
// need per-item results without the full batch round-trip.

func (g *GRPC) ValidateInputStream(stream sentinelv1.SentinelService_ValidateInputStreamServer) error {
	g.mu.RLock()
	eng := g.val
	g.mu.RUnlock()

	for {
		req, err := stream.Recv()
		if err != nil {
			return err // io.EOF → normal stream close
		}
		resp := eng.Validate(toEngineRequest(req))
		requestsTotal.WithLabelValues(string(resp.Status)).Inc()
		injectionScore.Observe(resp.PromptCheck.RiskScore)

		tc := traceFromGRPCCtx(stream.Context())
		tc.RequestID = resp.RequestID
		if resp.Status == types.StatusBlocked {
			g.pub.Publish(EventInjectionBlocked(tc, resp.PromptCheck.RiskScore, strings.Join(resp.PromptCheck.MatchedPatterns, ",")))
		}
		g.pub.Publish(EventInputValidated(tc, resp.PromptCheck.RiskScore, "stream"))

		if err := stream.Send(toProtoResponse(resp)); err != nil {
			return err
		}
	}
}

// ─── RPC: ValidateOutputStream ───────────────────────────────────────────────
// Bidirectional streaming for output validation. The client sends output
// payloads encoded as ValidateRequest.query (LLM response text) with metadata
// carrying user and retrieval context. Returns ValidateResponse per item.

func (g *GRPC) ValidateOutputStream(stream sentinelv1.SentinelService_ValidateOutputStreamServer) error {
	g.mu.RLock()
	outEng := g.outputEng
	g.mu.RUnlock()

	if outEng == nil {
		return status.Error(codes.Unavailable, "output engine not initialised")
	}

	for {
		req, err := stream.Recv()
		if err != nil {
			return err
		}
		meta := req.GetMetadata()
		if meta == nil {
			meta = map[string]string{}
		}
		outResp := outEng.Validate(types.OutputValidateRequest{
			RequestID:   req.GetRequestId(),
			LLMResponse: req.GetQuery(),
			User: types.UserContext{
				TenantID: meta["tenant_id"],
				UserID:   meta["user_id"],
			},
		})

		tc := traceFromGRPCCtx(stream.Context())
		tc.RequestID = req.GetRequestId()
		tc.TenantID = meta["tenant_id"]
		g.pub.Publish(EventOutputValidated(tc, string(outResp.Status), ""))

		pbStatus := sentinelv1.ValidateResponse_PASSED
		if outResp.Status == types.OutputStatusBlocked {
			pbStatus = sentinelv1.ValidateResponse_BLOCKED
		}
		if err := stream.Send(&sentinelv1.ValidateResponse{
			RequestId: req.GetRequestId(),
			Status:    pbStatus,
		}); err != nil {
			return err
		}
	}
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
