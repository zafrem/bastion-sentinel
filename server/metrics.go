package server

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
)

var (
	requestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "sentinel",
		Name:      "requests_total",
		Help:      "Total validation requests by status.",
	}, []string{"status"})

	requestDurationMs = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "sentinel",
		Name:      "request_duration_ms",
		Help:      "Validation processing time in milliseconds.",
		Buckets:   []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10, 25, 50, 100},
	})

	cacheHitsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "sentinel",
		Name:      "cache_hits_total",
		Help:      "Total cache hits.",
	})

	cacheMissesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "sentinel",
		Name:      "cache_misses_total",
		Help:      "Total cache misses.",
	})

	injectionScore = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "sentinel",
		Name:      "injection_score",
		Help:      "Distribution of prompt injection risk scores.",
		Buckets:   []float64{0.1, 0.3, 0.5, 0.7, 0.8, 0.9, 1.0},
	})
)

func metricsHandler() http.Handler {
	return promhttp.Handler()
}
