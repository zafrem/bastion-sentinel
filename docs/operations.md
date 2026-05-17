# Operations

## Starting the server

```bash
# Built-in defaults — no Redis, stdout JSON logging, no alerts
sentinel-cli server

# With a custom config file
sentinel-cli server --config /etc/sentinel/config.yaml

# With verbose text logging (useful during development)
sentinel-cli server --config config/dev.yaml
```

On startup the server prints a summary to stdout:

```
REST  listening on :8080
  POST /v1/validate  POST /v1/validate/batch
  GET  /v1/health    GET  /v1/config  GET /v1/metrics
  POST /v1/config/reload
  GET  /health/live  GET  /health/ready
gRPC  listening on :9090
  Validate  ValidateBatch  Health
Press Ctrl+C to stop.
```

Structured log records then follow, one per validated request.

---

## Graceful shutdown

Send `SIGINT` (Ctrl+C) or `SIGTERM` to begin graceful shutdown. The server:

1. Stops accepting new connections.
2. Waits up to `features.shutdown_timeout` (default 30 s) for in-flight requests to complete.
3. Closes the Redis connection and exits with code 0.

```bash
# Docker
docker stop <container>           # sends SIGTERM

# Kubernetes
kubectl delete pod <pod>          # sends SIGTERM; terminationGracePeriodSeconds=30
```

---

## Configuration hot-reload

Two mechanisms — both rebuild the engine from the new config file and flush the cache:

### Via REST endpoint

```bash
curl -X POST http://localhost:8080/v1/config/reload
# {"status":"ok","message":"config reloaded","source":"/etc/sentinel/config.yaml"}
```

Returns an error if the new config is invalid — the running config is left unchanged.

### Via SIGHUP

```bash
kill -HUP $(pgrep sentinel)
```

The process logs:

```json
{"level":"INFO","msg":"SIGHUP received, reloading config","path":"/etc/sentinel/config.yaml"}
{"level":"INFO","msg":"config reloaded successfully"}
```

SIGHUP is a no-op if the server was started without `--config`.

---

## Monitoring

### Prometheus metrics

Scrape target: `GET http://<host>:8080/v1/metrics`

| Metric | Type | Description |
|--------|------|-------------|
| `sentinel_requests_total{status}` | Counter | Total requests by status (PASSED / BLOCKED / ERROR) |
| `sentinel_request_duration_ms` | Histogram | End-to-end processing time in milliseconds |
| `sentinel_injection_score` | Histogram | Distribution of prompt injection risk scores |
| `sentinel_cache_hits_total` | Counter | Cache hits |
| `sentinel_cache_misses_total` | Counter | Cache misses |

Standard Go runtime metrics (`go_goroutines`, `go_memstats_*`, etc.) are also exported by the default Prometheus registry.

**Alert rules** (add to `prometheus/alerts/sentinel.yaml`):

```yaml
groups:
  - name: sentinel
    rules:
      - alert: SentinelHighLatency
        expr: histogram_quantile(0.95, rate(sentinel_request_duration_ms_bucket[5m])) > 1.0
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "p95 latency exceeds 1 ms"

      - alert: SentinelHighErrorRate
        expr: rate(sentinel_requests_total{status="ERROR"}[5m]) / rate(sentinel_requests_total[5m]) > 0.001
        for: 1m
        labels:
          severity: critical

      - alert: SentinelHighBlockRate
        expr: rate(sentinel_requests_total{status="BLOCKED"}[5m]) / rate(sentinel_requests_total[5m]) > 0.10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "More than 10% of requests are being blocked"
```

### Structured logging

All log records include `service=sentinel` and `version=<cfg.Version>`.

**Request log record** (JSON format):

```json
{
  "time": "2026-05-17T10:30:00.001234Z",
  "level": "INFO",
  "msg": "validate",
  "service": "sentinel",
  "version": "1.0",
  "request_id": "req-001",
  "status": "PASSED",
  "processing_time_ms": 0.48,
  "prompt_injection_score": 0.0,
  "metadata_valid": true,
  "method": "regex+keyword",
  "tenant_id": "acme",
  "user_id": "john"
}
```

**Elasticsearch** — set `logging.destination: elasticsearch` and `logging.elasticsearch_url` to ship logs asynchronously. Records are indexed at `POST <url>/sentinel-logs/_doc`. Elasticsearch connection failures are logged to stderr and silently dropped from the queue; the primary stdout stream is unaffected.

Query blocked requests in Kibana:

```
service:sentinel AND status:BLOCKED AND prompt_injection_score:>=0.9
```

### Out-of-band incident alerts

Configure `notifications.slack_webhook_url` and/or `notifications.pagerduty_routing_key` to receive immediate alerts when a request is blocked with a risk score at or above `notifications.critical_threshold` (default 0.9).

Alerts fire asynchronously — they never add latency to the request path. If the webhook call fails, a warning is logged to stderr and the next request proceeds normally.

---

## Troubleshooting

### High latency (p95 > 1 ms)

| Possible cause | Action |
|----------------|--------|
| Very long queries (approaching 10k chars) | Regex scanning is O(n). Check `sentinel_request_duration_ms` distribution. |
| ML model not stubbed — ONNX inference | `ml.OnnxStub` returns instantly; a real model adds inference time. |
| Cache disabled under heavy load | Enable Redis caching (`cache.enabled: true`). |
| Too many regex rules | Profile with `go test -bench=. ./engine/` against current ruleset. |

### High false-positive rate

1. Check `sentinel_injection_score` histogram — most safe requests should land in the `0.1` bucket.
2. Reduce `scoring.block_threshold` if the ML model is active, or audit keyword rules for overly broad terms.
3. Use the REPL to test individual queries: `sentinel-cli interactive`.

### Redis connection failures

Sentinel falls back to in-memory caching automatically. You will see a warning at startup:

```json
{"level":"WARN","msg":"redis unavailable, falling back to memory cache","err":"..."}
```

Check `redis-cli ping` from the same network namespace.

### `POST /v1/config/reload` returns CONFIG_ERROR

The new YAML file failed to parse. The running config is unchanged. Fix the YAML and retry.

### Elasticsearch logs not appearing

1. Confirm `logging.destination: elasticsearch` is set.
2. Verify `logging.elasticsearch_url` is reachable: `curl <url>/_cluster/health`.
3. The async shipper buffers up to 512 records; drops silently if the queue fills.

### Batch validation hangs

Check for goroutine leaks with `pprof`:

```bash
go tool pprof http://localhost:8080/debug/pprof/goroutine
```

(Requires adding `net/http/pprof` import to `main.go` — not enabled by default in production.)

---

## pprof profiling (development)

To enable `pprof` endpoints during development, add the following import to `cmd/sentinel/main.go`:

```go
import _ "net/http/pprof"
```

Then profile from the REST port:

```bash
# CPU profile (30 seconds)
go tool pprof http://localhost:8080/debug/pprof/profile?seconds=30

# Heap allocation
go tool pprof http://localhost:8080/debug/pprof/heap

# Goroutine dump
go tool pprof http://localhost:8080/debug/pprof/goroutine
```
