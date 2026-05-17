package server

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/zafrem/bastion-sentinel/config"
)

// NewLogger builds a slog.Logger pre-populated with service/version fields.
// When cfg.Destination is "elasticsearch", log records are also shipped
// asynchronously to cfg.ElasticsearchURL via HTTP.
func NewLogger(cfg config.LoggingConfig, version string) *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(cfg.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	opts := &slog.HandlerOptions{Level: level}
	var base slog.Handler
	if strings.ToLower(cfg.Format) == "json" {
		base = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		base = slog.NewTextHandler(os.Stdout, opts)
	}

	if strings.ToLower(cfg.Destination) == "elasticsearch" && cfg.ElasticsearchURL != "" {
		base = newMultiHandler(base, newESHandler(cfg.ElasticsearchURL, level))
	}

	return slog.New(base).With(
		"service", "sentinel",
		"version", version,
	)
}

// ─── multi-handler (fan-out to two handlers) ──────────────────────────────────

type multiHandler struct{ a, b slog.Handler }

func newMultiHandler(a, b slog.Handler) *multiHandler { return &multiHandler{a, b} }

func (m *multiHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return m.a.Enabled(ctx, l) || m.b.Enabled(ctx, l)
}
func (m *multiHandler) Handle(ctx context.Context, r slog.Record) error {
	_ = m.a.Handle(ctx, r)
	_ = m.b.Handle(ctx, r)
	return nil
}
func (m *multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &multiHandler{m.a.WithAttrs(attrs), m.b.WithAttrs(attrs)}
}
func (m *multiHandler) WithGroup(name string) slog.Handler {
	return &multiHandler{m.a.WithGroup(name), m.b.WithGroup(name)}
}

// ─── Elasticsearch async handler ──────────────────────────────────────────────

type esHandler struct {
	url    string
	level  slog.Level
	client *http.Client
	queue  chan []byte
}

func newESHandler(url string, level slog.Level) *esHandler {
	h := &esHandler{
		url:    strings.TrimRight(url, "/") + "/sentinel-logs/_doc",
		level:  level,
		client: &http.Client{Timeout: 3 * time.Second},
		queue:  make(chan []byte, 512),
	}
	go h.ship()
	return h
}

func (h *esHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level }

func (h *esHandler) Handle(_ context.Context, r slog.Record) error {
	doc := map[string]any{
		"@timestamp": r.Time.UTC().Format(time.RFC3339Nano),
		"level":      r.Level.String(),
		"message":    r.Message,
	}
	r.Attrs(func(a slog.Attr) bool {
		doc[a.Key] = a.Value.Any()
		return true
	})
	data, err := json.Marshal(doc)
	if err != nil {
		return nil
	}
	select {
	case h.queue <- data:
	default: // drop if queue full rather than block
	}
	return nil
}

func (h *esHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	// simplified: return self (attrs are captured per-record via Handle)
	return h
}
func (h *esHandler) WithGroup(name string) slog.Handler { return h }

func (h *esHandler) ship() {
	for doc := range h.queue {
		req, err := http.NewRequest(http.MethodPost, h.url, bytes.NewReader(doc))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := h.client.Do(req)
		if err == nil {
			resp.Body.Close()
		}
	}
}
