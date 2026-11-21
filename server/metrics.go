package server

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/zafrem/bastion-sentinel/engine"
	"github.com/zafrem/bastion-sentinel/types"
	"net/http"
)

var (
	requestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "sentinel",
		Name:      "requests_total",
		Help:      "Total validation requests by status.",
	}, []string{"status", "profile"})

	requestDurationMs = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "sentinel",
		Name:      "request_duration_ms",
		Help:      "Validation processing time in milliseconds.",
		Buckets:   []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10, 25, 50, 100},
	}, []string{"profile"})

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

	injectionScore = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "sentinel",
		Name:      "injection_score",
		Help:      "Distribution of prompt injection risk scores.",
		Buckets:   []float64{0.1, 0.3, 0.5, 0.7, 0.8, 0.9, 1.0},
	}, []string{"profile"})

	outputRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "sentinel",
		Name:      "output_requests_total",
		Help:      "Total output validations by status and policy profile.",
	}, []string{"status", "profile"})
)

// The profile label is the operator-defined policy profile name, so its cardinality is bounded by the
// config. It is empty when no policy is configured, which Prometheus treats as the label being absent.

func observeInput(status, profile string, ms, score float64) {
	requestsTotal.WithLabelValues(status, profile).Inc()
	requestDurationMs.WithLabelValues(profile).Observe(ms)
	injectionScore.WithLabelValues(profile).Observe(score)
}

func validateOutput(e *engine.OutputEngine, req types.OutputValidateRequest) types.OutputValidateResponse {
	r := e.Validate(req)
	outputRequestsTotal.WithLabelValues(string(r.Status), r.Profile).Inc()
	return r
}

func metricsHandler() http.Handler {
	return promhttp.Handler()
}
