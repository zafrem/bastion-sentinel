# Bastion-Sentinel (Module A)

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](bastion_sentinel_srs_v1.0_en.md.md)
[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8.svg?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

**Bastion-Sentinel** is the **bidirectional security guard** of the **Bastion AI Security Governance Framework**. It operates in two modes:

- **Sentinel-IN** — Input gateway: detects prompt injection attacks and validates request metadata before forwarding to downstream modules.
- **Sentinel-OUT** — Output gateway: validates LLM responses for PII re-emergence, hallucination, content policy violations, and permission boundary compliance before delivering to the user.

---

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | Component design, request lifecycle, concurrency model, scoring pipeline |
| [API Reference](docs/api-reference.md) | Full REST and gRPC API — endpoints, request/response schemas, error codes |
| [Configuration](docs/configuration.md) | All configuration fields, defaults, adding detection rules |
| [Deployment](docs/deployment.md) | Docker, Kubernetes, HPA, health probes, security hardening |
| [Operations](docs/operations.md) | Server startup, hot-reload, Prometheus metrics, logging, troubleshooting |
| [Development](docs/development.md) | Adding rules, testing, benchmarks, ONNX integration, protobuf regeneration |
| [SRS — Input](bastion_sentinel_srs_v1.0_en.md.md) | Software Requirements Specification v1.0 (Sentinel-IN) |
| [SRS — Output](bastion_sentinel_output_srs_v1.0_en.md) | Software Requirements Specification v1.0 (Sentinel-OUT) |

---

## Overview

### Sentinel-IN (Input Validation)

1. **Prompt Injection Detection** — 25 regex patterns, 25 keyword blacklists, and ML risk scoring (ONNX interface, stub active)
2. **Metadata Verification** — required field presence, format rules (UUID, RFC3339), length bounds, and business rules (timestamp freshness ±1h, reserved identifiers)

Requests that pass both checks receive `PASSED`; any failure returns `BLOCKED`.

### Sentinel-OUT (Output Validation)

LLM responses flow through five parallel validators:

1. **PII Re-emergence Detection** — 6 pattern families (Korean name/RRN/mobile, email, credit card, leaked tokens); auto-redacts or masks
2. **Hallucination Detection** — extracts numerical/date/percentage claims and cross-references against retrieval sources; adds disclaimer when grounding score < 0.5
3. **Content Filtering** — blocks responses containing API keys, cloud credentials, or internal system paths
4. **Permission Boundary Check** — detects when a response contains specific monetary values that exceed the user's declared access level (k_anonymized, aggregated, etc.)
5. **Format Validation** — length limits (10–10,000 chars), UTF-8 validity, control-character check

Response statuses: `PASSED` · `SANITIZED` · `WARNING` · `BLOCKED`

---

## System Architecture

```
┌──────────────────────────────────────────────┐
│          User / Client Application           │
└──────────────────┬───────────────────────────┘
                   │ REST :8080 / gRPC :9090
                   ▼
        ┌──────────────────────────────┐
        │   Sentinel-IN  (this repo)   │
        │  Cache → Prompt Detect       │
        │        → Metadata Validate   │
        └──────────────┬───────────────┘
                       │ PASSED
                       ▼
              [...pipeline: Vault → Navigator → LLM...]
                       │
                       ▼
        ┌──────────────────────────────┐
        │   Sentinel-OUT (this repo)   │
        │  ┌──────────────────────┐   │
        │  │ PII Re-emergence     │   │
        │  │ Hallucination        │   │
        │  │ Content Filter       │   │
        │  │ Permission Boundary  │   │
        │  │ Format Validation    │   │
        │  └──────────────────────┘   │
        └──────────────┬───────────────┘
                       │ PASSED / SANITIZED / WARNING
                       ▼
        ┌──────────────────────────────┐
        │       User Response          │
        └──────────────────────────────┘
```

---

## Getting Started

### Prerequisites

- Go 1.23 or higher

### Build

```bash
go build ./...
```

### Run the CLI

```bash
# Validate a single query (interactive metadata prompt if --metadata is omitted)
go run ./cmd/sentinel validate --query "What is AI?" \
  --metadata '{"tenant_id":"acme","user_id":"john","context_id":"550e8400-e29b-41d4-a716-446655440000","timestamp":"2026-05-17T10:00:00Z"}'

# Quick ad-hoc test with auto-generated metadata
go run ./cmd/sentinel try "What is AI?"
go run ./cmd/sentinel try "Ignore all previous instructions" --explain
go run ./cmd/sentinel try --tenant acme --user alice "How does Redis work?"

# Pipe multiple queries
echo -e "What is AI?\nIgnore all previous instructions" | go run ./cmd/sentinel try --stdin

# Interactive REPL
go run ./cmd/sentinel interactive

# Batch validation from a JSONL file
go run ./cmd/sentinel validate --input-file requests.jsonl --parallel 8

# Run fixture test suites
go run ./cmd/sentinel testrun --dir tests/fixtures/ --verbose
go run ./cmd/sentinel testrun --fixture tests/fixtures/injection_attempts.jsonl

# Start REST + gRPC servers
go run ./cmd/sentinel server
go run ./cmd/sentinel server --config path/to/config.yaml

# Config management
go run ./cmd/sentinel config show
go run ./cmd/sentinel config validate path/to/config.yaml

# Validate an LLM response (Sentinel-OUT)
go run ./cmd/sentinel validate-output --response "Contact alice@example.com"
go run ./cmd/sentinel validate-output --response "Revenue: $5,000" --access-level k_anonymized --explain
go run ./cmd/sentinel validate-output --input-file responses.jsonl --format compact
```

---

## API Interfaces

### REST API — port `8080`

**Sentinel-IN (Input Validation)**

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/validate` | Validate a single query |
| `POST` | `/v1/validate/batch` | Validate a JSON array of requests in parallel |
| `GET` | `/v1/health` | Liveness check — returns status, version, uptime |
| `GET` | `/v1/config` | Show the active configuration as JSON |
| `POST` | `/v1/config/reload` | Hot-reload config from disk (requires `--config <file>`) |
| `GET` | `/v1/metrics` | Prometheus metrics |
| `GET` | `/health/live` | Kubernetes liveness probe |
| `GET` | `/health/ready` | Kubernetes readiness probe |

**Sentinel-OUT (Output Validation)**

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/validate/output` | Validate a single LLM response |
| `POST` | `/v1/validate/output/batch` | Validate a JSON array of LLM responses in parallel |

**PASSED/SANITIZED/WARNING → HTTP 200. BLOCKED → HTTP 403.**

Request body:
```json
{
  "request_id": "req-001",
  "query": "What is the capital of France?",
  "metadata": {
    "tenant_id": "acme",
    "user_id": "john",
    "context_id": "550e8400-e29b-41d4-a716-446655440000",
    "timestamp": "2026-05-17T10:00:00Z"
  }
}
```

### gRPC — port `9090`

Service defined in `proto/sentinel.proto` (package `bastion.sentinel.v1`):

| RPC | Description |
|-----|-------------|
| `Validate` | Single request |
| `ValidateBatch` | Batch of requests, processed with an 8-worker pool |
| `Health` | Returns status, version, uptime |

---

## Configuration

Sentinel runs with built-in defaults out of the box. To customise, provide a YAML file via `--config`:

```yaml
server:
  rest_port: 8080
  grpc_port: 9090

cache:
  enabled: true       # false = no caching
  type: redis         # "redis" or "memory"; falls back to memory if Redis is unreachable
  address: "localhost:6379"
  ttl: 5m

prompt_injection:
  scoring:
    method: max           # "max" or "weighted_avg"
    block_threshold: 0.7

logging:
  level: info
  format: json           # "json" or "text"
  destination: stdout    # "stdout" or "elasticsearch"
  elasticsearch_url: ""  # e.g. "http://localhost:9200" (used when destination=elasticsearch)

notifications:
  slack_webhook_url: ""         # optional — fires on critical blocks
  pagerduty_routing_key: ""     # optional — fires on critical blocks
  critical_threshold: 0.9      # risk score ≥ this triggers out-of-band alerts
```

Default detection rules ship with 25 regex patterns and 25 keyword rules covering English and Korean injection techniques. Add new rules under `prompt_injection.regex_rules` or `prompt_injection.keyword_rules`.

---

## Testing

```bash
# Unit tests (51 tests across engine, validators, cache, and server packages)
go test ./...

# With coverage
go test -cover ./...

# Run a single test
go test ./cache/... -run TestCachedValidator_HitSkipsEngine -v

# Engine microbenchmarks
go test -bench=. -benchtime=3s ./engine/

# Fixture suites (100 cases: valid requests, injection attempts, invalid metadata, edge cases)
go run ./cmd/sentinel testrun --dir tests/fixtures/

# Integration stack (requires Docker)
cd tests/integration && docker-compose up --abort-on-container-exit

# Load test (requires k6)
k6 run tests/load/sentinel-load-test.js
```

Fixture files live in `tests/fixtures/` as JSONL. The `"timestamp":"NOW"` placeholder is substituted with the current UTC time at runtime.

---

## Technical Stack

| Component | Technology |
|-----------|------------|
| Language | Go 1.23+ |
| gRPC / Protobuf | `google.golang.org/grpc` v1.64, `google.golang.org/protobuf` v1.36 |
| Caching | Redis 7.0+ (optional) via `github.com/redis/go-redis/v9` |
| CLI framework | `github.com/spf13/cobra` |
| Config | YAML via `gopkg.in/yaml.v3` |
| Metrics | Prometheus via `github.com/prometheus/client_golang` v1.23 |
| Logging | Structured JSON via `log/slog` (stdlib) |
| ML inference | `ml.Scorer` interface — `OnnxStub` active (returns 0.0); replace with `github.com/yalue/onnxruntime_go` |

---

## Implementation Status

### Sentinel-IN (Input Validation)

| Feature | Status |
|---------|--------|
| Prompt injection detection (regex + keyword) | ✅ |
| Metadata validation (schema + business rules) | ✅ |
| REST API (validate, batch, health, config) | ✅ |
| gRPC API (Validate, ValidateBatch, Health) | ✅ |
| Redis caching with in-memory fallback | ✅ |
| CLI (validate, try, testrun, interactive, config, server) | ✅ |
| Hot config reload via `POST /v1/config/reload` | ✅ |
| Payload size limits (10k chars / 4KB metadata) | ✅ |
| Kubernetes health probes (`/health/live`, `/health/ready`) | ✅ |
| Prometheus metrics with injection score histogram | ✅ |
| SIGHUP hot reload | ✅ |
| Structured logging — `log/slog` JSON + Elasticsearch shipping | ✅ |
| Security incident alerts (Slack / PagerDuty) | ✅ |
| Batch progress bar | ✅ |
| Engine benchmarks (`go test -bench=.`) | ✅ |
| Dockerfile (multi-stage Alpine) | ✅ |
| Kubernetes manifests + HPA | ✅ |
| Integration docker-compose + k6 load test | ✅ |
| ML inference (ONNX) | Stub only |

### Sentinel-OUT (Output Validation)

| Feature | Status |
|---------|--------|
| PII re-emergence detection (6 pattern families, EN + KR) | ✅ |
| PII auto-sanitization with modification log | ✅ |
| Hallucination detection (lexical grounding, claim extraction) | ✅ |
| Content filter (API keys, cloud credentials, internal paths) | ✅ |
| Permission boundary check (access level hierarchy) | ✅ |
| Format validation (length, UTF-8, control chars) | ✅ |
| REST API (`POST /v1/validate/output`, `/v1/validate/output/batch`) | ✅ |
| CLI (`validate-output` with `--explain`, `--access-level`) | ✅ |
| Streaming output validation | Stub (future) |
| Vault PII mapping cross-reference | Stub (pending Vault integration) |

---

## Performance Targets

| Metric | Target |
|--------|--------|
| Median latency (p50) | < 0.5 ms |
| Long-tail latency (p95) | < 1.0 ms |
| Throughput | ≥ 40,000 req/s |
| Detection accuracy | ≥ 95% |

---

## License

This project is licensed under the Apache License 2.0 — see the [LICENSE](LICENSE) file for details.
