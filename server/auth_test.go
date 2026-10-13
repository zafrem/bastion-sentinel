package server_test

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zafrem/bastion-sentinel/cache"
	"github.com/zafrem/bastion-sentinel/config"
	"github.com/zafrem/bastion-sentinel/engine"
	"github.com/zafrem/bastion-sentinel/server"
)

func newAuthREST(t *testing.T, token string) *server.REST {
	t.Helper()
	cfg := config.Default()
	cfg.Server.AuthToken = token
	eng, err := engine.New(cfg)
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	c, _ := cache.New(config.CacheConfig{Enabled: true, Type: "memory"})
	val := cache.NewCached(eng, c, time.Minute)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := server.NewREST(cfg, val, c, "", log, server.NewNotifier(cfg.Notifications, log))
	if err != nil {
		t.Fatalf("server.NewREST: %v", err)
	}
	return srv
}

func do(srv *server.REST, method, path, authHeader string) *httptest.ResponseRecorder {
	var body io.Reader
	if method == http.MethodPost {
		body = bytes.NewReader(validBody())
	}
	req := httptest.NewRequest(method, path, body)
	req.Header.Set("Content-Type", "application/json")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func TestAuth_AdminRoutesDisabledWithoutToken(t *testing.T) {
	srv := newAuthREST(t, "")
	for _, p := range []string{"/v1/config", "/v1/config/reload"} {
		m := http.MethodGet
		if strings.HasSuffix(p, "reload") {
			m = http.MethodPost
		}
		if rec := do(srv, m, p, ""); rec.Code != http.StatusForbidden {
			t.Errorf("%s without configured token: want 403, got %d", p, rec.Code)
		}
	}
}

func TestAuth_AdminRoutesRequireToken(t *testing.T) {
	srv := newAuthREST(t, "s3cret-token")
	cases := []struct {
		name, header string
		want         int
	}{
		{"missing", "", http.StatusUnauthorized},
		{"wrong", "Bearer nope", http.StatusUnauthorized},
		{"wrong scheme", "Basic s3cret-token", http.StatusUnauthorized},
		{"correct", "Bearer s3cret-token", http.StatusOK},
	}
	for _, tc := range cases {
		if rec := do(srv, http.MethodGet, "/v1/config", tc.header); rec.Code != tc.want {
			t.Errorf("%s: want %d, got %d", tc.name, tc.want, rec.Code)
		}
	}
}

func TestAuth_ConfigResponseNeverLeaksToken(t *testing.T) {
	srv := newAuthREST(t, "s3cret-token")
	rec := do(srv, http.MethodGet, "/v1/config", "Bearer s3cret-token")
	if strings.Contains(rec.Body.String(), "s3cret-token") {
		t.Error("GET /v1/config response contains the auth token")
	}
}

func TestAuth_ValidateRequiresTokenWhenConfigured(t *testing.T) {
	srv := newAuthREST(t, "s3cret-token")
	if rec := do(srv, http.MethodPost, "/v1/validate", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: want 401, got %d", rec.Code)
	}
	if rec := do(srv, http.MethodPost, "/v1/validate", "Bearer s3cret-token"); rec.Code != http.StatusOK {
		t.Errorf("valid token: want 200, got %d", rec.Code)
	}
}

func TestAuth_ValidateOpenWhenNoTokenConfigured(t *testing.T) {
	srv := newAuthREST(t, "")
	if rec := do(srv, http.MethodPost, "/v1/validate", ""); rec.Code != http.StatusOK {
		t.Errorf("want 200 (backward compatible), got %d", rec.Code)
	}
}

func TestAuth_ProbesStayPublic(t *testing.T) {
	srv := newAuthREST(t, "s3cret-token")
	for _, p := range []string{"/health/live", "/health/ready", "/v1/health"} {
		if rec := do(srv, http.MethodGet, p, ""); rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
			t.Errorf("%s must be reachable without a token, got %d", p, rec.Code)
		}
	}
}
