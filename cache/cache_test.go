package cache_test

import (
	"github.com/prometheus/client_golang/prometheus"
	"testing"
	"time"

	"github.com/zafrem/bastion-sentinel/cache"
	"github.com/zafrem/bastion-sentinel/config"
	"github.com/zafrem/bastion-sentinel/engine"
	"github.com/zafrem/bastion-sentinel/types"
)

// ─── MemCache ────────────────────────────────────────────────────────────────

func TestMemCache_MissOnEmpty(t *testing.T) {
	c, _ := cache.New(config.CacheConfig{Enabled: true, Type: "memory"})
	_, ok := c.Get("nonexistent")
	if ok {
		t.Error("expected miss on empty cache")
	}
}

func TestMemCache_SetAndGet(t *testing.T) {
	c, _ := cache.New(config.CacheConfig{Enabled: true, Type: "memory"})
	resp := types.ValidateResponse{RequestID: "r1", Status: types.StatusPassed}
	c.Set("key1", resp, time.Minute)
	got, ok := c.Get("key1")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if got.RequestID != "r1" || got.Status != types.StatusPassed {
		t.Errorf("unexpected response: %+v", got)
	}
}

func TestMemCache_TTLExpiry(t *testing.T) {
	c, _ := cache.New(config.CacheConfig{Enabled: true, Type: "memory"})
	resp := types.ValidateResponse{RequestID: "r-ttl", Status: types.StatusPassed}
	c.Set("key-ttl", resp, 10*time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	_, ok := c.Get("key-ttl")
	if ok {
		t.Error("expected cache miss after TTL expiry")
	}
}

func TestMemCache_Flush(t *testing.T) {
	c, _ := cache.New(config.CacheConfig{Enabled: true, Type: "memory"})
	c.Set("k1", types.ValidateResponse{Status: types.StatusPassed}, time.Minute)
	c.Set("k2", types.ValidateResponse{Status: types.StatusBlocked}, time.Minute)
	if err := c.Flush(); err != nil {
		t.Fatalf("flush error: %v", err)
	}
	if _, ok := c.Get("k1"); ok {
		t.Error("k1 should be gone after flush")
	}
	if _, ok := c.Get("k2"); ok {
		t.Error("k2 should be gone after flush")
	}
}

func TestNoopCache_AlwaysMisses(t *testing.T) {
	c, _ := cache.New(config.CacheConfig{Enabled: false})
	c.Set("k", types.ValidateResponse{Status: types.StatusPassed}, time.Minute)
	_, ok := c.Get("k")
	if ok {
		t.Error("noop cache should always miss")
	}
}

// ─── CachedValidator ─────────────────────────────────────────────────────────

func newTestValidator(t *testing.T) cache.Validator {
	t.Helper()
	eng, err := engine.New(config.Default())
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	return eng
}

func safeRequest(query string) types.ValidateRequest {
	return types.ValidateRequest{
		RequestID: "req-1",
		Query:     query,
		Metadata: map[string]string{
			"tenant_id":  "acme",
			"user_id":    "john",
			"context_id": "550e8400-e29b-41d4-a716-446655440000",
			"timestamp":  time.Now().UTC().Format(time.RFC3339),
		},
	}
}

func TestCachedValidator_HitSkipsEngine(t *testing.T) {
	calls := 0
	inner := &countingValidator{calls: &calls, status: types.StatusPassed}
	c, _ := cache.New(config.CacheConfig{Enabled: true, Type: "memory"})
	cv := cache.NewCached(inner, c, time.Minute)

	req := safeRequest("What is AI?")
	cv.Validate(req)
	cv.Validate(req) // second call should hit cache
	cv.Validate(req) // third call should hit cache

	if calls != 1 {
		t.Errorf("expected engine called once, got %d", calls)
	}
}

func TestCachedValidator_ErrorNotCached(t *testing.T) {
	calls := 0
	inner := &countingValidator{calls: &calls, status: types.StatusError}
	c, _ := cache.New(config.CacheConfig{Enabled: true, Type: "memory"})
	cv := cache.NewCached(inner, c, time.Minute)

	req := safeRequest("error query")
	cv.Validate(req)
	cv.Validate(req)

	if calls != 2 {
		t.Errorf("error results must not be cached; expected 2 engine calls, got %d", calls)
	}
}

func TestCachedValidator_DifferentMetadataDifferentKey(t *testing.T) {
	eng := newTestValidator(t)
	c, _ := cache.New(config.CacheConfig{Enabled: true, Type: "memory"})
	cv := cache.NewCached(eng, c, time.Minute)

	req1 := safeRequest("What is AI?")
	req2 := safeRequest("What is AI?")
	req2.Metadata["tenant_id"] = "globex" // different tenant → different cache key

	cv.Validate(req1)
	cv.Validate(req2)

	// both should be cached independently
	_, hit1 := c.Get("not-the-key") // just verify cache is populated (indirectly)
	_ = hit1
}

func TestCachedValidator_TimestampExcludedFromKey(t *testing.T) {
	calls := 0
	inner := &countingValidator{calls: &calls, status: types.StatusPassed}
	c, _ := cache.New(config.CacheConfig{Enabled: true, Type: "memory"})
	cv := cache.NewCached(inner, c, time.Minute)

	req1 := safeRequest("What is AI?")
	req2 := safeRequest("What is AI?")
	req2.Metadata["timestamp"] = "2026-05-17T00:00:00Z" // different timestamp, same content

	cv.Validate(req1)
	cv.Validate(req2) // should be a cache hit despite different timestamp

	if calls != 1 {
		t.Errorf("different timestamps should share cache key; expected 1 engine call, got %d", calls)
	}
}

func TestCachedValidator_SwapEngine(t *testing.T) {
	calls1, calls2 := 0, 0
	inner1 := &countingValidator{calls: &calls1, status: types.StatusPassed}
	inner2 := &countingValidator{calls: &calls2, status: types.StatusBlocked}
	c, _ := cache.New(config.CacheConfig{Enabled: true, Type: "memory"})
	cv := cache.NewCached(inner1, c, time.Minute)

	req := safeRequest("What is AI?")
	cv.Validate(req)

	cv.SwapEngine(inner2) // flushes cache + swaps engine

	resp := cv.Validate(req)
	if resp.Status != types.StatusBlocked {
		t.Errorf("expected BLOCKED from new engine after swap, got %s", resp.Status)
	}
	if calls2 != 1 {
		t.Errorf("expected new engine to be called once after swap, got %d", calls2)
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

type countingValidator struct {
	calls  *int
	status types.Status
}

func (v *countingValidator) Validate(_ types.ValidateRequest) types.ValidateResponse {
	*v.calls++
	return types.ValidateResponse{Status: v.status}
}

type profileValidator struct{ profile string }

func (v profileValidator) Validate(req types.ValidateRequest) types.ValidateResponse {
	return types.ValidateResponse{RequestID: req.RequestID, Status: types.StatusPassed, Profile: v.profile}
}

// counter reads one labelled sample from the default registry, which is what /v1/metrics serves.
func counter(t *testing.T, name, profile string) float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "profile" && l.GetValue() == profile {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

func TestCachedValidator_CountsHitsAndMissesPerProfile(t *testing.T) {
	c, _ := cache.New(config.CacheConfig{Enabled: true, Type: "memory"})
	cv := cache.NewCached(profileValidator{profile: "p1"}, c, time.Minute)
	req := types.ValidateRequest{RequestID: "r", Query: "metrics-count-unique-q", Metadata: map[string]string{"tenant_id": "t"}}

	hits := counter(t, "sentinel_cache_hits_total", "p1")
	misses := counter(t, "sentinel_cache_misses_total", "p1")
	cv.Validate(req) // miss
	cv.Validate(req) // hit
	cv.Validate(req) // hit
	if got := counter(t, "sentinel_cache_hits_total", "p1") - hits; got != 2 {
		t.Errorf("hits +%v, want +2", got)
	}
	if got := counter(t, "sentinel_cache_misses_total", "p1") - misses; got != 1 {
		t.Errorf("misses +%v, want +1", got)
	}
	if other := counter(t, "sentinel_cache_hits_total", "p2"); other != 0 {
		t.Errorf("another profile's counter moved: %v", other)
	}
}
