// Package cache provides validation result caching with Redis and in-memory backends.
// Redis is optional; the service falls back to in-memory automatically if unavailable.
package cache

import (
	"sync"
	"time"

	"github.com/zafrem/bastion-sentinel/config"
	"github.com/zafrem/bastion-sentinel/types"
)

// Cache is the storage backend for validation results.
type Cache interface {
	Get(key string) (types.ValidateResponse, bool)
	Set(key string, resp types.ValidateResponse, ttl time.Duration)
	Flush() error
	Close() error
}

// New returns a cache backend based on cfg.
// If cfg.Enabled is false, a no-op cache is returned.
// If cfg.Type is "redis" but the connection fails, falls back to in-memory.
func New(cfg config.CacheConfig) (Cache, error) {
	if !cfg.Enabled {
		return &noopCache{}, nil
	}

	if cfg.Type == "redis" {
		rc, err := newRedisCache(cfg.Address)
		if err == nil {
			return rc, nil
		}
		// Redis unavailable — fall through to memory cache
	}

	return newMemCache(), nil
}

// ─── no-op cache (used when caching is disabled) ─────────────────────────────

type noopCache struct{}

func (c *noopCache) Get(_ string) (types.ValidateResponse, bool) { return types.ValidateResponse{}, false }
func (c *noopCache) Set(_ string, _ types.ValidateResponse, _ time.Duration) {}
func (c *noopCache) Flush() error                                             { return nil }
func (c *noopCache) Close() error                                             { return nil }

// ─── in-memory cache ──────────────────────────────────────────────────────────

type memEntry struct {
	resp      types.ValidateResponse
	expiresAt time.Time
}

type memCache struct {
	mu sync.RWMutex
	m  map[string]memEntry
}

func newMemCache() *memCache {
	return &memCache{m: make(map[string]memEntry)}
}

func (c *memCache) Get(key string) (types.ValidateResponse, bool) {
	c.mu.RLock()
	e, ok := c.m[key]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.expiresAt) {
		return types.ValidateResponse{}, false
	}
	return e.resp, true
}

func (c *memCache) Set(key string, resp types.ValidateResponse, ttl time.Duration) {
	c.mu.Lock()
	c.m[key] = memEntry{resp: resp, expiresAt: time.Now().Add(ttl)}
	c.mu.Unlock()
}

func (c *memCache) Flush() error {
	c.mu.Lock()
	c.m = make(map[string]memEntry)
	c.mu.Unlock()
	return nil
}

func (c *memCache) Close() error { return nil }
