package server

import (
	"crypto/subtle"
	"net/http"
	"os"
	"strings"
)

// publicPaths stay reachable without a token so orchestrators can probe them.
var publicPaths = map[string]bool{
	"/health/live":  true,
	"/health/ready": true,
	"/v1/health":    true,
	"/v1/metrics":   true,
}

// adminPaths expose or change the running security configuration. They are
// never served unless an auth token is configured.
var adminPaths = map[string]bool{
	"/v1/config":        true,
	"/v1/config/reload": true,
}

// authToken returns the configured shared token (config first, then env).
func (s *REST) authToken() string {
	s.mu.RLock()
	tok := s.cfg.Server.AuthToken
	s.mu.RUnlock()
	if tok == "" {
		tok = os.Getenv("SENTINEL_AUTH_TOKEN")
	}
	return tok
}

func (s *REST) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if publicPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		token := s.authToken()
		if token == "" {
			if adminPaths[r.URL.Path] {
				writeError(w, http.StatusForbidden, "ADMIN_DISABLED",
					"admin endpoints are disabled: set server.auth_token (or SENTINEL_AUTH_TOKEN)")
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="sentinel"`)
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing or invalid bearer token")
			return
		}
		next.ServeHTTP(w, r)
	})
}
