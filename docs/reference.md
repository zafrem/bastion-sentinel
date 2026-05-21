# Reference

Full CLI command list, configuration quick-reference, testing guide, tech stack, implementation status, and performance targets.

---

## CLI commands

All commands run via `go run ./cmd/sentinel <command>` or the compiled `sentinel` binary.

### Sentinel-IN

```bash
# Validate a single query (prompts for metadata interactively if omitted)
sentinel validate --query "What is AI?" \
  --metadata '{"tenant_id":"acme","user_id":"john","context_id":"550e8400-e29b-41d4-a716-446655440000","timestamp":"2026-05-17T10:00:00Z"}'

# Quick test with auto-generated metadata
sentinel try "What is AI?"
sentinel try "Ignore all previous instructions" --explain
sentinel try --tenant acme --user alice "How does Redis work?"

# Pipe multiple queries
echo -e "What is AI?\nIgnore all previous instructions" | sentinel try --stdin

# Interactive REPL
sentinel interactive

# Batch validation from a JSONL file
sentinel validate --input-file requests.jsonl --parallel 8

# Fixture test suites
sentinel testrun --dir tests/fixtures/ --verbose
sentinel testrun --fixture tests/fixtures/injection_attempts.jsonl --stop-on-fail
```

### Sentinel-OUT

```bash
# Validate a single LLM response
sentinel validate-output --response "Contact alice@example.com"
sentinel validate-output --response "Revenue: $5,000" --access-level k_anonymized --explain

# Batch from file
sentinel validate-output --input-file responses.jsonl --format compact

# Output formats: text (default), json, compact
sentinel validate-output --response "..." --format json
```

### Server and config

```bash
# Start REST (:8080) + gRPC (:9090) servers
sentinel server
sentinel server --config /etc/sentinel/config.yaml

# Config management
sentinel config show
sentinel config show --config path/to/config.yaml
sentinel config validate path/to/config.yaml
```

---

## Configuration quick-reference

Sentinel runs with built-in defaults. Override any field by passing `--config <file>`:

```yaml
server:
  rest_port: 8080
  grpc_port: 9090

cache:
  enabled: true
  type: redis          # "redis" | "memory" — falls back to memory if Redis unreachable
  address: "localhost:6379"
  ttl: 5m

prompt_injection:
  scoring:
    method: max          # "max" | "weighted_avg"
    block_threshold: 0.7

logging:
  level: info
  format: json           # "json" | "text"
  destination: stdout    # "stdout" | "elasticsearch"
  elasticsearch_url: ""

notifications:
  slack_webhook_url: ""
  pagerduty_routing_key: ""
  critical_threshold: 0.9   # risk score ≥ this fires out-of-band alerts

output_validation:
  enabled: true
  pii_reemergence:
    enabled: true
  hallucination:
    enabled: true
    grounding_threshold: 0.5
    add_disclaimer: true
  content_filter:
    enabled: true
  permission_check:
    enabled: true
  format:
    min_length: 10
    max_length: 10000
```

Full schema with all fields and defaults: [Configuration](configuration.md).

---

## Testing

```bash
# All unit + system tests
go test ./...

# With coverage
go test -cover ./...

# End-to-end system tests (full stack, no mocks)
go test ./tests/system/... -v

# Single package
go test ./cache/... -run TestCachedValidator_HitSkipsEngine -v

# Engine microbenchmarks
go test -bench=. -benchtime=3s ./engine/
go test -bench=. -benchmem ./engine/

# Sentinel-IN fixture suites (100 cases)
sentinel testrun --dir tests/fixtures/ --verbose

# Sentinel-OUT fixture suites (18 cases)
sentinel testrun --dir tests/output/fixtures/ --verbose

# Integration stack (requires Docker)
cd tests/integration && docker-compose up --abort-on-container-exit

# Load test (requires k6)
k6 run tests/load/sentinel-load-test.js
```

---

## Technical stack

| Component | Technology |
|-----------|------------|
| Language | Go 1.23+ |
| gRPC / Protobuf | `google.golang.org/grpc` v1.64, `google.golang.org/protobuf` v1.36 |
| Caching | Redis 7.0+ (optional) via `github.com/redis/go-redis/v9` |
| CLI | `github.com/spf13/cobra` |
| Config | YAML via `gopkg.in/yaml.v3` |
| Metrics | Prometheus via `github.com/prometheus/client_golang` v1.23 |
| Logging | Structured JSON via `log/slog` (stdlib) |
| ML inference | `ml.Scorer` interface — `OnnxStub` active (returns 0.0); swap with `github.com/yalue/onnxruntime_go` |

---

## Implementation status

### Sentinel-IN

| Feature | Status |
|---------|--------|
| Prompt injection detection (regex + keyword) | ✅ |
| Metadata validation (schema + business rules) | ✅ |
| REST API (validate, batch, health, config) | ✅ |
| gRPC API (Validate, ValidateBatch, Health) | ✅ |
| Redis caching with in-memory fallback | ✅ |
| CLI (validate, try, testrun, interactive, config, server) | ✅ |
| Hot config reload (`POST /v1/config/reload` + SIGHUP) | ✅ |
| Payload size limits (10k chars / 4KB metadata) | ✅ |
| Kubernetes health probes | ✅ |
| Prometheus metrics with injection score histogram | ✅ |
| Structured logging — JSON + Elasticsearch shipping | ✅ |
| Security incident alerts (Slack / PagerDuty) | ✅ |
| Dockerfile (multi-stage Alpine) | ✅ |
| Kubernetes manifests + HPA | ✅ |
| Integration docker-compose + k6 load test | ✅ |
| ML inference (ONNX) | Stub only |

### Sentinel-OUT

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

## Performance targets

| Metric | Target |
|--------|--------|
| Median latency (p50) | < 0.5 ms |
| Long-tail latency (p95) | < 1.0 ms |
| Throughput | ≥ 40,000 req/s |
| Detection accuracy | ≥ 95% |
