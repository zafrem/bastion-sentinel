package server_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/zafrem/bastion-sentinel/cache"
	"github.com/zafrem/bastion-sentinel/config"
	"github.com/zafrem/bastion-sentinel/engine"
	"github.com/zafrem/bastion-sentinel/exceptions"
	"github.com/zafrem/bastion-sentinel/server"
)

func industryREST(t *testing.T) *server.REST {
	t.Helper()
	cfg := config.Default()
	cfg.Industry = config.IndustryConfig{Enabled: true, Filters: []config.IndustryFilterConfig{
		{ID: "gdpr", Builtin: "gdpr", Mode: "blocking", ActionOnMatch: "block"},
	}}
	eng, err := engine.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := cache.New(config.CacheConfig{Enabled: true, Type: "memory"})
	val := cache.NewCached(eng, c, time.Minute)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := server.NewREST(cfg, val, c, "", log, server.NewNotifier(cfg.Notifications, log))
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func postValidate(srv *server.REST, tenant string) (int, map[string]any) {
	body, _ := json.Marshal(map[string]any{
		"request_id": "ind-1",
		"query":      "We collected personal data without lawful basis",
		"metadata": map[string]string{
			"tenant_id": tenant, "user_id": "alice",
			"context_id": "550e8400-e29b-41d4-a716-446655440000",
			"timestamp":  time.Now().UTC().Format(time.RFC3339),
		},
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	srv.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&out)
	return rec.Code, out
}

func TestIndustryFilter_BlockCarriesNoticeAndCanBeExempted(t *testing.T) {
	srv := industryREST(t)

	code, out := postValidate(srv, "acme")
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("setup: GDPR filter should block, got %d %v", code, out)
	}
	n, _ := out["user_notice"].(map[string]any)
	if n == nil || n["code"] != "INDUSTRY_POLICY" || n["reference_id"] != "ind-1" {
		t.Fatalf("industry block must carry a user notice, got %v", out)
	}

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	c, _ := exceptions.NewClient("sentinel", base64.StdEncoding.EncodeToString(pub), filepath.Join(t.TempDir(), "e.json"))
	engine.SetExceptions(c)
	t.Cleanup(func() { engine.SetExceptions(nil) })
	env, _ := exceptions.Sign(priv, exceptions.Payload{Kind: "update", IssuedAt: time.Now(), Exceptions: []exceptions.Exception{{
		ID: "exc-ind", Version: 1, Rule: "sentinel.industry:gdpr", Modules: []string{"sentinel"},
		TenantID: "acme", ExpiresAt: time.Now().Add(time.Hour)}}})
	if err := c.Apply(env); err != nil {
		t.Fatal(err)
	}

	code, out = postValidate(srv, "acme")
	if code != http.StatusOK {
		t.Fatalf("exempted tenant should pass the industry filter, got %d %v", code, out)
	}
	if ids, _ := out["exceptions_applied"].([]any); len(ids) != 1 || ids[0] != "exc-ind" {
		t.Errorf("use of the exception must be reported: %v", out["exceptions_applied"])
	}
	if code, _ := postValidate(srv, "globex"); code != http.StatusUnprocessableEntity {
		t.Errorf("another tenant must still be blocked, got %d", code)
	}
}
