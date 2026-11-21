package server_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zafrem/bastion-sentinel/cache"
	"github.com/zafrem/bastion-sentinel/config"
	"github.com/zafrem/bastion-sentinel/engine"
	"github.com/zafrem/bastion-sentinel/server"
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
