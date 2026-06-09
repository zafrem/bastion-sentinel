# Bastion-Sentinel (Module A)

## Overview
**Bastion-Sentinel** is the bidirectional security gateway of the Bastion-RAG framework. It serves as both the entry point (Sentinel-IN) and the exit point (Sentinel-OUT) for all interactions with the AI system.

Sentinel protects the system from malicious inputs (Prompt Injection) and ensures the safety and privacy of AI outputs (PII re-emergence, Hallucination filtering).

## Key Features
### Sentinel-IN (Input Gateway)
- **Prompt Injection Detection:** Multi-layered detection using regex, keywords, and ML models to block unauthorized instructions.
- **Metadata Verification:** Validates the structure and content of request metadata (e.g., UUIDs, tenant identifiers).

### Sentinel-OUT (Output Gateway)
- **PII Re-emergence Check:** Prevents the AI from accidentally revealing original PII that was previously anonymized.
- **Hallucination Detection:** Compares LLM responses against retrieved context to identify ungrounded claims.
- **Content Filtering:** Blocks inappropriate content, hate speech, and sensitive advice.
- **Permission Boundary Enforcement:** Ensures the response level matches the user's access permissions (e.g., K-anonymity).

## Architecture
- **Validation Engine:** A shared core that executes detection rules in parallel.
- **ML Scorer:** ONNX-based inference for identifying complex injection patterns and hallucinations.
- **Unified API:** Single service handling both `/v1/validate/input` and `/v1/validate/output`.
- **Streaming Support:** Real-time token-by-token validation for LLM responses.

## Getting Started
### Prerequisites
- Go 1.25+
- ONNX Runtime 1.16+
- Redis (Optional, for caching)

### Installation
```bash
go build -o sentinel ./cmd/sentinel
```

### Running the Server
```bash
# Run from the module root: the engine loads PII patterns from the relative
# path external/pii-pattern-engine/regex, so the working directory matters.
./sentinel server
```
The server starts with a built-in default configuration (REST `:8080`, gRPC
`:9090`). To override it, pass a YAML file with `--config <path>`; see the
configurable keys below.

### Configurable detection patterns
The regexes used by the output validators and industry compliance filters are
externalized to the YAML config — override them without touching code. Every
field is optional; when omitted the built-in default is used, and an invalid
override falls back to the default. Available keys:

```yaml
output_validation:
  hallucination:
    claim_patterns:
      numerical:  ""   # default: \b\d{1,3}(?:,\d{3})*(?:\.\d+)?(?:\s*(?:만|억|천|M|K|B))?\b
      date:       ""   # default: \b\d{4}[-./]\d{1,2}[-./]\d{1,2}\b|\b\d{1,2}[-./]\d{1,2}[-./]\d{4}\b
      percentage: ""   # default: \b\d+(?:\.\d+)?%\b
  permission_check:
    specific_amount_pattern: ""   # default amount-detection regex

# Industry compliance filters accept per-filter regex/keyword overrides.
# When patterns/keywords are empty the built-in HIPAA/GDPR/PCI/ITAR sets apply.
industry:
  filters:
    - builtin: hipaa
      action_on_match: redact
      patterns: []     # empty → DefaultHIPAAPatterns
      keywords: []
```

## Documentation
- [Design Document](DESIGN.md)
- [SRS Document](docs/bastion_sentinel_srs_v1.0_en.md)
- [Output SRS Document](docs/bastion_sentinel_output_srs_v1.0_en.md)

**Technical deep-dives (code-based):**
- [Prompt Injection Detection](docs/prompt-injection-detection.md)
- [Metadata Filtering](docs/metadata-filtering.md)

## Testing & Fixtures
Fixture files live in `tests/fixtures/` as JSONL. The `"timestamp":"NOW"` placeholder is substituted with the current UTC time at runtime.

---

## Technical Stack

| Component | Technology |
|-----------|------------|
| Language | Go 1.25+ |
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

## Other modules
* [Vault](../vault)
* [Navigator](../navigator)
* [Anchor](../anchor)
* [Tracker](../tracker)

---


## License
Apache License 2.0
