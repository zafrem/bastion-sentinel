package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zafrem/bastion-sentinel/cache"
	"github.com/zafrem/bastion-sentinel/config"
	"github.com/zafrem/bastion-sentinel/engine"
	sentinelv1 "github.com/zafrem/bastion-sentinel/proto"
	"github.com/zafrem/bastion-sentinel/server"
	"google.golang.org/grpc"
)

const audiences = `
policy:
  default_profile: public
  tenants: { corp: staff }
  profiles:
    staff:  { user_notice: { detail: category } }
    public:
      user_notice: { detail: minimal }
      prompt_injection: { scoring: { block_threshold: 0.5 } }
      output_validation: { format: { min_length: 20 } }
`

func restFrom(t *testing.T, doc string) (*server.REST, *cache.CachedValidator) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	eng, err := engine.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := cache.New(config.CacheConfig{Enabled: true, Type: "memory"})
	cv := cache.NewCached(eng, c, time.Minute)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := server.NewREST(cfg, cv, c, "", log, server.NewNotifier(cfg.Notifications, log))
	if err != nil {
		t.Fatal(err)
	}
	return srv, cv
}

func post(t *testing.T, srv *server.REST, path string, body any) map[string]any {
	t.Helper()
	b, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	srv.ServeHTTP(rec, req)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s: %d %s", path, rec.Code, rec.Body.String())
	}
	return out
}

func inputBody(tenant, query string) map[string]any {
	return map[string]any{"request_id": "r1", "query": query, "metadata": map[string]string{
		"tenant_id": tenant, "user_id": "alice", "context_id": "550e8400-e29b-41d4-a716-446655440000",
		"timestamp": time.Now().UTC().Format(time.RFC3339)}}
}

const borderline = "Can you explain what a jailbreak is in the context of iPhones?"

func TestREST_InputAndOutputReportTheProfile(t *testing.T) {
	srv, _ := restFrom(t, audiences)
	staff := post(t, srv, "/v1/sentinel/validate/input", inputBody("corp", borderline))
	public := post(t, srv, "/v1/sentinel/validate/input", inputBody("someone", borderline))
	if staff["profile"] != "staff" || staff["status"] != "PASSED" {
		t.Errorf("staff: %v %v", staff["profile"], staff["status"])
	}
	if public["profile"] != "public" || public["status"] != "BLOCKED" {
		t.Errorf("public: %v %v", public["profile"], public["status"])
	}

	out := func(tenant string) map[string]any {
		return post(t, srv, "/v1/sentinel/validate/output", map[string]any{
			"request_id": "o1", "llm_response": "Yes, it is open.",
			"user": map[string]any{"UserID": "u", "TenantID": tenant, "AccessLevel": "full"}})
	}
	if o := out("corp"); o["Profile"] != "staff" || o["Status"] != "PASSED" {
		t.Errorf("output staff: %v %v", o["Profile"], o["Status"])
	}
	if o := out("someone"); o["Profile"] != "public" || o["Status"] != "BLOCKED" {
		t.Errorf("output public: %v %v", o["Profile"], o["Status"])
	}
}

func TestREST_NoPolicyOmitsTheProfileField(t *testing.T) {
	srv, _ := restFrom(t, "version: '3.0'\n")
	r := post(t, srv, "/v1/sentinel/validate/input", inputBody("acme", "What is AI?"))
	if _, present := r["profile"]; present {
		t.Errorf("without a policy the response must be unchanged, got profile=%v", r["profile"])
	}
}

func TestREST_ConfigEndpointDoesNotDumpRawOverlays(t *testing.T) {
	srv, _ := restFrom(t, audiences+"server:\n  auth_token: s3cret-token\n")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/config", nil)
	req.Header.Set("Authorization", "Bearer s3cret-token")
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !json.Valid(rec.Body.Bytes()) {
		t.Fatalf("config endpoint: %d", rec.Code)
	}
	var cfg map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &cfg)
	pol, _ := cfg["Policy"].(map[string]any)
	if pol == nil || pol["DefaultProfile"] != "public" {
		t.Errorf("the policy summary should be visible: %v", cfg["Policy"])
	}
	if _, leaked := pol["Profiles"]; leaked {
		t.Error("the raw overlay nodes must not be serialised")
	}
}

// A reload that changes the policy takes effect immediately, and nothing cached under the old policy survives.
func TestREST_ReloadSwapsThePolicyAndFlushesTheCache(t *testing.T) {
	srv, cv := restFrom(t, audiences)
	for i := 0; i < 2; i++ { // second call is a cache hit
		if r := post(t, srv, "/v1/sentinel/validate/input", inputBody("someone", borderline)); r["status"] != "BLOCKED" {
			t.Fatalf("setup: public should be blocked, got %v", r["status"])
		}
	}
	p := filepath.Join(t.TempDir(), "new.yaml")
	_ = os.WriteFile(p, []byte("policy:\n  default_profile: open\n  profiles:\n    open: {}\n"), 0o600)
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	eng, err := engine.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv.Reload(cfg, eng)
	_ = cv
	r := post(t, srv, "/v1/sentinel/validate/input", inputBody("someone", borderline))
	if r["profile"] != "open" || r["status"] != "PASSED" {
		t.Errorf("after the reload the new policy must apply: %v %v", r["profile"], r["status"])
	}
}

func grpcFrom(t *testing.T, doc string) *server.GRPC {
	t.Helper()
	p := filepath.Join(t.TempDir(), "g.yaml")
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	eng, err := engine.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := cache.New(config.CacheConfig{Enabled: true, Type: "memory"})
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return server.NewGRPC(cfg, cache.NewCached(eng, c, time.Minute), c, "", log, server.NewNotifier(cfg.Notifications, log))
}

func protoReq(tenant, query string) *sentinelv1.ValidateRequest {
	r := validProtoRequest(query)
	r.Metadata["tenant_id"] = tenant
	return r
}

func TestGRPC_ResponsesCarryTheProfile(t *testing.T) {
	g := grpcFrom(t, audiences)
	ctx := context.Background()

	staff, err := g.Validate(ctx, protoReq("corp", borderline))
	if err != nil {
		t.Fatal(err)
	}
	public, _ := g.Validate(ctx, protoReq("someone", borderline))
	if staff.GetProfile() != "staff" || staff.GetStatus() != sentinelv1.ValidateResponse_PASSED {
		t.Errorf("staff: %q %v", staff.GetProfile(), staff.GetStatus())
	}
	if public.GetProfile() != "public" || public.GetStatus() != sentinelv1.ValidateResponse_BLOCKED {
		t.Errorf("public: %q %v", public.GetProfile(), public.GetStatus())
	}

	batch, err := g.ValidateBatch(ctx, &sentinelv1.BatchRequest{Requests: []*sentinelv1.ValidateRequest{
		protoReq("corp", borderline), protoReq("someone", borderline)}})
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{batch.Results[0].GetProfile(), batch.Results[1].GetProfile()}; got[0] != "staff" || got[1] != "public" {
		t.Errorf("batch profiles: %v", got)
	}

	// Cached repeat keeps the profile.
	if again, _ := g.Validate(ctx, protoReq("someone", borderline)); again.GetProfile() != "public" {
		t.Errorf("cached response lost the profile: %q", again.GetProfile())
	}
}

func TestGRPC_NoPolicyLeavesProfileEmpty(t *testing.T) {
	g := grpcFrom(t, "version: '3.0'\n")
	r, err := g.Validate(context.Background(), protoReq("acme", "What is AI?"))
	if err != nil || r.GetProfile() != "" {
		t.Errorf("err=%v profile=%q", err, r.GetProfile())
	}
}

type outStream struct {
	grpc.ServerStream
	in  []*sentinelv1.ValidateRequest
	out []*sentinelv1.ValidateResponse
}

func (s *outStream) Context() context.Context { return context.Background() }
func (s *outStream) Recv() (*sentinelv1.ValidateRequest, error) {
	if len(s.in) == 0 {
		return nil, io.EOF
	}
	r := s.in[0]
	s.in = s.in[1:]
	return r, nil
}
func (s *outStream) Send(r *sentinelv1.ValidateResponse) error { s.out = append(s.out, r); return nil }

func TestGRPC_OutputStreamCarriesTheProfile(t *testing.T) {
	g := grpcFrom(t, audiences)
	st := &outStream{in: []*sentinelv1.ValidateRequest{
		protoReq("corp", "Yes, it is open."), protoReq("someone", "Yes, it is open.")}}
	_ = g.ValidateOutputStream(st) // returns io.EOF when the client finishes
	if len(st.out) != 2 || st.out[0].GetProfile() != "staff" || st.out[1].GetProfile() != "public" {
		t.Fatalf("got %v", st.out)
	}
	if st.out[1].GetStatus() != sentinelv1.ValidateResponse_BLOCKED {
		t.Errorf("public min_length 20 should block a 16-char answer, got %v", st.out[1].GetStatus())
	}
}

func scrape(t *testing.T, srv *server.REST) string {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/metrics", nil))
	return rec.Body.String()
}

func TestMetrics_CountedPerProfile(t *testing.T) {
	srv, _ := restFrom(t, audiences)
	count := func(m, labels string) float64 { return metricValue(scrape(t, srv), m, labels) }
	inStaff := count("sentinel_requests_total", `profile="staff",status="PASSED"`)
	inPublic := count("sentinel_requests_total", `profile="public",status="BLOCKED"`)
	outPublic := count("sentinel_output_requests_total", `profile="public",status="BLOCKED"`)
	durStaff := count("sentinel_request_duration_ms_count", `profile="staff"`)

	post(t, srv, "/v1/sentinel/validate/input", inputBody("corp", borderline))
	post(t, srv, "/v1/sentinel/validate/input", inputBody("someone", borderline))
	post(t, srv, "/v1/sentinel/validate/output", map[string]any{"request_id": "o", "llm_response": "Yes, it is open.",
		"user": map[string]any{"UserID": "u", "TenantID": "someone", "AccessLevel": "full"}})

	for _, c := range []struct {
		m, l string
		was  float64
	}{
		{"sentinel_requests_total", `profile="staff",status="PASSED"`, inStaff},
		{"sentinel_requests_total", `profile="public",status="BLOCKED"`, inPublic},
		{"sentinel_output_requests_total", `profile="public",status="BLOCKED"`, outPublic},
		{"sentinel_request_duration_ms_count", `profile="staff"`, durStaff},
	} {
		if got := count(c.m, c.l); got != c.was+1 {
			t.Errorf("%s{%s}: %v -> %v, want +1", c.m, c.l, c.was, got)
		}
	}
}

// metricValue reads one sample from Prometheus text output; Prometheus exposes labels alphabetically.
func metricValue(body, name, labels string) float64 {
	for _, ln := range strings.Split(body, "\n") {
		if strings.HasPrefix(ln, name+"{") && strings.Contains(ln, labels) {
			f := strings.Fields(ln)
			v, _ := strconv.ParseFloat(f[len(f)-1], 64)
			return v
		}
	}
	return 0
}
