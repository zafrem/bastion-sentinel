# Architecture

## Overview

Bastion-Sentinel is a stateless, horizontally-scalable input-gateway service for RAG (Retrieval-Augmented Generation) pipelines. It occupies the first position in the five-module Bastion framework, intercepting every incoming query before it reaches the LLM or data stores.

```
Client (REST :8080 / gRPC :9090 / CLI)
  │
  ▼
┌──────────────────────────────────────────────────────────┐
│  Module A — SENTINEL                                     │
│                                                          │
│  ┌─────────────────────────────────────────────────┐     │
│  │  cache.CachedValidator  (SHA-256 key, TTL 5m)   │     │
│  │   Redis ──► in-memory fallback                  │     │
│  └────────────────────┬────────────────────────────┘     │
│                  cache miss                              │
│  ┌─────────────────────▼──────────────────────────┐      │
│  │  engine.Engine                                 │      │
│  │  ┌──────────────────────┐  ┌────────────────┐  │      │
│  │  │ validators/prompt    │  │validators/meta │  │      │
│  │  │  NFC normalise       │  │ required fields│  │      │
│  │  │  regex patterns (25) │  │ format rules   │  │      │
│  │  │  keyword rules  (25) │  │ business rules │  │      │
│  │  │  ml.Scorer (ONNX)    │  │ size limits    │  │      │
│  │  └──────────────────────┘  └────────────────┘  │      │
│  └────────────────────────────────────────────────┘      │
│                                                          │
│  server/rest.go   server/grpc.go   formatter/            │
│  server/metrics.go  server/logger.go  server/notifier.go │
└──────────────────────────────────────────────────────────┘
  │ PASSED
  ▼
Module C — Vault (Data Isolation)
```

---

## Package dependency order

```
types
  └── config
        └── ml
              └── validators/prompt
              └── validators/metadata
                    └── engine
                          └── cache
                                └── server
                                      └── formatter (CLI only)
                                      └── cmd/sentinel
```

`types` has no internal imports and owns all shared structs. Every other package imports `types` but nothing imports `cmd/`.

---

## Components

### `types/`

Defines the canonical Go structs shared across the entire codebase:

| Type | Purpose |
|------|---------|
| `ValidateRequest` | Input: query, metadata, request ID, options |
| `ValidateResponse` | Output: status, prompt check, metadata check, extracted data, timing |
| `PromptCheckResult` | Risk score, method, matched pattern IDs |
| `MetadataCheckResult` | Missing fields, format errors |
| `Status` | Enum: `PASSED`, `BLOCKED`, `ERROR` |

### `config/`

Loads and validates YAML configuration. `config.Default()` returns production-safe defaults used when no `--config` file is provided. `config.Load(path)` merges a YAML file on top of the defaults using `gopkg.in/yaml.v3`.

### `ml/`

Defines the `Scorer` interface:

```go
type Scorer interface {
    Score(query string) (float64, error)
}
```

`OnnxStub` satisfies the interface and always returns `0.0`. Replace it with a real ONNX implementation (`github.com/yalue/onnxruntime_go`) by creating a struct that implements `Score`.

### `validators/prompt/`

Three-stage detection pipeline:

1. **Regex** — compiled on startup from `cfg.RegexRules`. Each match records the rule ID (e.g. `pi-001`), not the raw pattern text.
2. **Keyword** — case-insensitive substring scan against `cfg.KeywordRules`. Operates on NFC-normalised lowercase text.
3. **ML** — calls `ml.Scorer.Score(query)`. Skipped if `cfg.MLModel.Enabled = false` or the scorer returns an error.

**Scoring aggregation** — controlled by `scoring.method`:
- `max` (default): `finalScore = max(ruleScore, mlScore)`
- `weighted_avg`: `finalScore = ruleScore * 0.6 + mlScore * 0.4`

Any regex or keyword match sets `ruleScore = 1.0`, which always exceeds the block threshold (0.7), so rule hits unconditionally block.

### `validators/metadata/`

Sequential checks, stopping early on missing required fields:

1. **Presence** — all four required fields (`tenant_id`, `user_id`, `context_id`, `timestamp`) must exist. Returns immediately if any are absent.
2. **Format** — regex pattern, UUID format, RFC3339 format, min/max length per field.
3. **Business rules**:
   - `timestamp_bounds`: rejects timestamps outside ±1 hour of current time.
   - `reserved_identifiers`: rejects `system`, `admin`, `root` in `tenant_id` / `user_id`.
4. **Size limits**: query ≤ 10,000 Unicode code points; metadata dict ≤ 4 KB.

### `engine/`

Orchestrates both validators. On each request:

1. NFC-normalises the query (`golang.org/x/text/unicode/norm`).
2. Calls `promptDetector.Detect(normalised)`.
3. Calls `metadataValidator.Validate(metadata, originalQuery)`.
4. Sets overall `Status = BLOCKED` if either sub-check is blocked.
5. Records `ProcessingTimeMs` with microsecond precision.

### `cache/`

Three implementations behind the `Cache` interface (`Get`, `Set`, `Flush`, `Close`):

| Implementation | Activated when |
|----------------|---------------|
| `noopCache` | `cfg.Cache.Enabled = false` |
| `memCache` | `cfg.Cache.Type = "memory"` or Redis unreachable |
| `redisCache` | `cfg.Cache.Type = "redis"` and Redis reachable |

`redisCache` uses a 500 ms connection timeout; if it fails at startup, the process automatically falls back to `memCache`.

**Cache key** — SHA-256 of `NFC(query) + sorted(metadata key=value pairs, excluding "timestamp")`. Timestamp is excluded intentionally: it varies per request but has no bearing on the security verdict within the 5-minute TTL.

**Error responses** (`StatusError`) are never cached. This prevents a transient failure from poisoning subsequent requests.

`CachedValidator.SwapEngine(newInner)` replaces the inner engine and flushes the cache atomically — used during hot config reload.

### `server/`

Both servers (`server.REST`, `server.GRPC`) share the same design:

- Hold a `cache.Validator` and `cache.Cache` under a `sync.RWMutex`.
- `Reload(cfg, newEng)` replaces both under the write lock (calls `SwapEngine` on the `CachedValidator`).
- Accept a `*slog.Logger` and `*Notifier` at construction — both are injected by `buildServerCmd`.

`server/metrics.go` — Prometheus counters and histograms defined with `promauto` (registered in the default registry, served at `/v1/metrics`).

`server/logger.go` — builds a `slog.Logger` pre-populated with `service` and `version` default fields. Supports a fan-out handler that ships records asynchronously to Elasticsearch via HTTP.

`server/notifier.go` — fires Slack webhook and/or PagerDuty event in a goroutine when a blocked request's risk score exceeds `notifications.critical_threshold`.

### `formatter/`

Three output formats for CLI and batch output:

| Format | Output |
|--------|--------|
| `text` | Human-readable boxed report with unicode symbols |
| `json` | Pretty-printed JSON object |
| `compact` | Single-line summary: `[req-id] PASSED prompt=0.15 meta=OK time=0.8ms` |

### `cmd/sentinel/`

The `sentinel-cli` binary. Bypasses the server layer entirely — calls `engine.Engine.Validate()` directly. All six sub-commands (`validate`, `try`, `interactive`, `testrun`, `config`, `server`) are registered on a single `cobra.Command` root.

---

## Request lifecycle (server mode)

```
1.  Client sends HTTP POST /v1/validate (JSON body)
2.  withMiddleware: generate / propagate X-Request-ID, set Content-Type, enforce 1 MB body limit
3.  handleValidate: decode JSON, build types.ValidateRequest
4.  CachedValidator.Validate(req)
      a. Compute SHA-256 cache key
      b. Cache hit? → return cached response (with caller's request_id patched in)
      c. Cache miss → engine.Engine.Validate(req)
           i.  prompt.Detector.Detect(nfc_query)
                 - regex scan
                 - keyword scan
                 - ml.Scorer.Score(nfc_query)
                 - aggregate → risk score → PASSED / BLOCKED
           ii. metadata.Validator.Validate(metadata, query)
                 - presence check (fast-fail)
                 - format checks
                 - business rules
                 - size limits
           iii. Merge statuses → ValidateResponse
      d. Store result in cache (unless StatusError)
5.  Observe Prometheus metrics (requests_total, duration_ms, injection_score)
6.  Emit slog log record (JSON to stdout ± async to Elasticsearch)
7.  notifier.Notify(resp) — goroutine fires Slack / PagerDuty if score ≥ threshold
8.  Write HTTP response: 200 PASSED, 403 BLOCKED
```

---

## Configuration hot reload

Two trigger mechanisms — both call the same `Reload` method on each server:

| Trigger | Handler |
|---------|---------|
| `POST /v1/config/reload` | `handleConfigReload` in `server/rest.go` |
| `kill -HUP <pid>` | goroutine in `buildServerCmd` (`cmd/sentinel/main.go`) |

Reload sequence:
1. `config.Load(cfgPath)` — parse new YAML
2. `engine.New(newCfg)` — compile regex rules, reload scorer
3. `restSrv.Reload(newCfg, newEng)` and `grpcSrv.Reload(newCfg, newEng)` — swap engine under write lock
4. `CachedValidator.SwapEngine(newEng)` — replace inner engine and flush cache

The flush is critical: cached verdicts based on old detection rules must be evicted.

---

## Concurrency model

| Location | Mechanism | Reason |
|----------|-----------|--------|
| `cache.memCache` | `sync.RWMutex` | Read-mostly; writes on Set/Flush only |
| `cache.CachedValidator` | `sync.RWMutex` | Protects `inner` during `SwapEngine` |
| `server.REST` / `server.GRPC` | `sync.RWMutex` | Protects `val` and `cfg` during reload |
| Batch endpoints | `sync.WaitGroup` + semaphore channel (size 8) | Bounded parallelism for batch RPCs |
| `server/notifier.go` | goroutine per alert | Non-blocking — never delays request path |
| `server/logger.go` ES handler | channel (buffer 512) + single shipper goroutine | Non-blocking log shipping |

---

## Scoring pipeline detail

```
query (raw)
  │
  └─ NFC normalise ──► lower
                         │
              ┌──────────┤
              │ regex    │ keyword
              │ scan     │ scan
              └──────────┤
                         │ ruleScore = 1.0 if any match, else 0.0
                         │
              ┌──────────┘
              │ ml.Scorer.Score(nfc_query)
              └──► mlScore ∈ [0.0, 1.0]
                         │
              aggregate(method, ruleScore, mlScore)
                   "max"          → max(ruleScore, mlScore)
                   "weighted_avg" → ruleScore * 0.6 + mlScore * 0.4
                         │
              finalScore ≥ 0.7? → BLOCKED
              finalScore < 0.7? → PASSED
```
