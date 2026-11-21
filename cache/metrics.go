package cache

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// The profile label is the policy profile of the verdict (empty when no policy is configured).
var (
	cacheHitsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "sentinel",
		Name:      "cache_hits_total",
		Help:      "Input validations answered from the cache, by policy profile.",
	}, []string{"profile"})

	cacheMissesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "sentinel",
		Name:      "cache_misses_total",
		Help:      "Input validations that were not in the cache and ran the engine, by policy profile.",
	}, []string{"profile"})
)
