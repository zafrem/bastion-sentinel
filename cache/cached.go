package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/text/unicode/norm"

	"github.com/zafrem/bastion-sentinel/types"
)

// Validator is satisfied by *engine.Engine and any other type with a Validate method.
type Validator interface {
	Validate(req types.ValidateRequest) types.ValidateResponse
}

// CachedValidator wraps a Validator with a Cache.
// Cache misses fall through to the inner validator; results are stored for ttl.
// Error responses are never cached.
type CachedValidator struct {
	mu    sync.RWMutex
	inner Validator
	cache Cache
	ttl   time.Duration
}

func NewCached(inner Validator, c Cache, ttl time.Duration) *CachedValidator {
	return &CachedValidator{inner: inner, cache: c, ttl: ttl}
}

func (cv *CachedValidator) Validate(req types.ValidateRequest) types.ValidateResponse {
	key := cacheKey(req)

	if cached, ok := cv.cache.Get(key); ok {
		// preserve the caller's request ID in the returned response
		cached.RequestID = req.RequestID
		return cached
	}

	cv.mu.RLock()
	inner := cv.inner
	cv.mu.RUnlock()

	resp := inner.Validate(req)

	if resp.Status != types.StatusError {
		cv.cache.Set(key, resp, cv.ttl)
	}
	return resp
}

// SwapEngine replaces the inner validator and flushes the cache.
// Used during hot config reload so stale results from old rules are evicted.
func (cv *CachedValidator) SwapEngine(newInner Validator) {
	cv.mu.Lock()
	cv.inner = newInner
	cv.mu.Unlock()
	_ = cv.cache.Flush()
}

// Flush removes all cached entries.
func (cv *CachedValidator) Flush() error {
	return cv.cache.Flush()
}

// cacheKey hashes the NFC-normalised query and all metadata fields except
// "timestamp" (timestamps vary per request but do not affect the verdict
// within the 5-minute TTL / ±1-hour freshness window).
func cacheKey(req types.ValidateRequest) string {
	query := norm.NFC.String(req.Query)

	keys := make([]string, 0, len(req.Metadata))
	for k := range req.Metadata {
		if k != "timestamp" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	var sb strings.Builder
	sb.WriteString(query)
	sb.WriteByte('\n')
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(req.Metadata[k])
		sb.WriteByte('\n')
	}

	h := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(h[:])
}
