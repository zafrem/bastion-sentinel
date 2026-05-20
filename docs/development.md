# Development Guide

## Prerequisites

- Go 1.23+
- `protoc` + Go plugins (only if modifying the proto schema)
- Docker (for integration tests)
- k6 (for load tests)

---

## Build

```bash
go build ./...

# Production binary
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o sentinel ./cmd/sentinel
```

---

## Running tests

```bash
# All unit tests
go test ./...

# With coverage report
go test -cover ./...

# Single package, verbose
go test ./server/... -v

# Single test by name
go test ./cache/... -run TestCachedValidator_HitSkipsEngine -v

# Fixture-based integration tests (100 cases)
go run ./cmd/sentinel testrun --dir tests/fixtures/ --verbose

# Stop on first failure
go run ./cmd/sentinel testrun --dir tests/fixtures/ --stop-on-fail
```

### Test packages

| Package | Tests | What is tested |
|---------|-------|----------------|
| `validators/prompt` | 12 | Regex matching, keyword detection, ML stub, scoring aggregation |
| `validators/metadata` | 12 | Required fields, format rules, UUID, RFC3339, business rules, size limits |
| `validators/output` | — | PII detection/sanitisation, hallucination grounding, content filter, permission check, format validation |
| `engine` | 6 | Full engine orchestration, edge cases |
| `cache` | 10 | memCache TTL, noop cache, CachedValidator hit/miss/error/swap |
| `server` | 8+ | REST endpoints, output endpoints, metrics, health probes, reload |
| `formatter` | 11+ | JSON/compact/text for Sentinel-IN and Sentinel-OUT responses |

### Fixture format — Sentinel-IN

Files live in `tests/fixtures/` as JSONL — one JSON object per line:

```json
{"request_id":"v-001","description":"safe English query","query":"What is AI?","metadata":{"tenant_id":"acme","user_id":"alice","context_id":"550e8400-e29b-41d4-a716-446655440000","timestamp":"NOW"},"expected":"PASSED"}
```

- `"timestamp":"NOW"` is substituted with the current UTC time at runtime.
- `expected` must be `"PASSED"` or `"BLOCKED"`.

### Fixture format — Sentinel-OUT

Files live in `tests/output/fixtures/` as JSONL:

```json
{"request_id":"out-pii-001","description":"response with email address","llm_response":"Contact alice@example.com for help.","user":{"access_level":"full"},"expected":"SANITIZED"}
```

| Field | Type | Description |
|-------|------|-------------|
| `request_id` | string | Unique test case ID |
| `description` | string | Human-readable description |
| `llm_response` | string | Raw LLM response to validate |
| `user` | object | `access_level` and optional `user_id` |
| `retrieval` | object | Optional `source_documents` list for grounding |
| `expected` | string | `"PASSED"`, `"SANITIZED"`, `"WARNING"`, or `"BLOCKED"` |

Output fixture files:

| File | Cases | What it tests |
|------|-------|---------------|
| `clean_responses.jsonl` | 5 | Safe responses that must pass |
| `pii_responses.jsonl` | 6 | Email, RRN, mobile, credit card, leaked token |
| `inappropriate_responses.jsonl` | 4 | API keys, GitHub tokens, AWS keys, internal paths |
| `permission_violations.jsonl` | 3 | Specific amounts to restricted users |

Run the output fixture suite:

```bash
go run ./cmd/sentinel testrun --dir tests/output/fixtures/ --verbose
```

---

## Benchmarks

```bash
# All benchmarks
go test -bench=. -benchtime=3s ./engine/

# Single benchmark
go test -bench=BenchmarkValidate_Parallel -benchtime=5s ./engine/

# With memory allocation stats
go test -bench=. -benchmem ./engine/
```

Available benchmarks in `engine/engine_bench_test.go`:

| Benchmark | Description |
|-----------|-------------|
| `BenchmarkValidate_Safe` | Clean English query |
| `BenchmarkValidate_Injection` | English injection attempt (regex + keyword match) |
| `BenchmarkValidate_Korean` | Korean injection attempt |
| `BenchmarkValidate_Parallel` | Throughput under `GOMAXPROCS` goroutines |
| `BenchmarkValidate_LongQuery` | Near 10k-char query (worst-case regex scan) |

Performance reference on a 2-core development machine:

```
BenchmarkValidate_Safe-2          14686   82686 ns/op   114 B/op   3 allocs/op
BenchmarkValidate_Injection-2      7748  152931 ns/op   196 B/op   5 allocs/op
BenchmarkValidate_Parallel-2     117330   11951 ns/op    96 B/op   3 allocs/op
```

`BenchmarkValidate_Parallel` represents throughput — `GOMAXPROCS / 11951 ns ≈ 167,000 req/s` on a 2-core machine.

---

## Adding a detection rule

### 1. Add the rule to `config/config.go`

```go
// In Default() → PromptInjection.RegexRules:
{ID: "pi-026", Pattern: `(?i)my\s+new\s+attack`, Severity: "high"},

// In Default() → PromptInjection.KeywordRules:
{ID: "kw-026", Keyword: "my trigger phrase", Severity: "critical"},
```

**ID conventions:**
- Regex rules: `pi-NNN` (English), same prefix for Korean
- Keyword rules: `kw-NNN`
- Severity: `critical`, `high`, or `medium`

### 2. Add a fixture test case

Append to `tests/fixtures/injection_attempts.jsonl`:

```json
{"request_id":"i-041","description":"new attack pattern","query":"my new attack phrase","metadata":{"tenant_id":"acme","user_id":"tester","context_id":"550e8400-e29b-41d4-a716-446655440000","timestamp":"NOW"},"expected":"BLOCKED"}
```

### 3. Run the full fixture suite

```bash
go run ./cmd/sentinel testrun --dir tests/fixtures/ --verbose
```

All 100+ cases must pass.

### 4. Run the unit tests

```bash
go test ./validators/prompt/... -v
```

---

## Adding a Sentinel-OUT rule

### Adding a PII pattern

1. Add the pattern in `config/config.go` → `Default()` → `OutputValidation.PIIReemergence.Patterns`:

   ```go
   {ID: "pii-007", Name: "passport_number", Pattern: `[A-Z]{1,2}\d{6,9}`, Severity: "high", Action: "redacted"},
   ```

   - `action`: `"redacted"` replaces the value with `[REDACTED]`; `"masked"` replaces it with `[TYPE_NAME]`.
   - `severity`: `"critical"`, `"high"`, or `"medium"`.

2. Add a fixture case to `tests/output/fixtures/pii_responses.jsonl`:

   ```json
   {"request_id":"out-pii-007","description":"response with passport number","llm_response":"Passport AB1234567 was verified.","user":{"access_level":"full"},"expected":"SANITIZED"}
   ```

3. Run the output fixture suite and unit tests:

   ```bash
   go run ./cmd/sentinel testrun --dir tests/output/fixtures/ --verbose
   go test ./validators/output/... -v
   ```

### Adding a content filter pattern

1. Add the pattern in `config/config.go` → `Default()` → `OutputValidation.ContentFilter.Patterns`:

   ```go
   {ID: "cf-005", Name: "stripe_key", Pattern: `sk_live_[A-Za-z0-9]{24,}`, Severity: "critical", Action: "block"},
   ```

   - `action`: `"block"` → response is `BLOCKED` (HTTP 403); `"warn"` → response is `WARNING` (HTTP 200).

2. Add a fixture case to `tests/output/fixtures/inappropriate_responses.jsonl`:

   ```json
   {"request_id":"out-cf-005","description":"response containing Stripe live key","llm_response":"Use sk_live_abc123xyz456def789ghi012 to process payments.","user":{"access_level":"full"},"expected":"BLOCKED"}
   ```

3. Run the output fixture suite:

   ```bash
   go run ./cmd/sentinel testrun --dir tests/output/fixtures/ --verbose
   ```

---

## Adding a metadata business rule

Business rules live in `validators/metadata/validator.go`, in the `checkBusinessRules` method.

```go
case "my_new_rule":
    // implement rule logic
    if violated {
        errs = append(errs, "field: reason for block")
    }
```

Then enable it in `config.Default()`:

```go
BusinessRules: []BusinessRule{
    {ID: "br-001", Name: "timestamp_bounds",     Enabled: true},
    {ID: "br-002", Name: "reserved_identifiers", Enabled: true},
    {ID: "br-003", Name: "my_new_rule",           Enabled: true},
},
```

Add corresponding fixture cases to `tests/fixtures/invalid_metadata.jsonl`.

---

## Implementing real ONNX inference

1. Add the dependency:

   ```bash
   go get github.com/yalue/onnxruntime_go
   ```

2. Create `ml/onnx_scorer.go`:

   ```go
   package ml

   import ort "github.com/yalue/onnxruntime_go"

   type OnnxScorer struct {
       session *ort.DynamicAdvancedSession
   }

   func NewOnnxScorer(modelPath string) (*OnnxScorer, error) {
       // initialise ort environment and create session
       // ...
   }

   func (s *OnnxScorer) Score(query string) (float64, error) {
       // tokenise query, run inference, return probability
       // ...
   }
   ```

3. Wire it in `engine/engine.go`:

   ```go
   var scorer ml.Scorer
   if cfg.PromptInjection.MLModel.Enabled && cfg.PromptInjection.MLModel.Path != "" {
       s, err := ml.NewOnnxScorer(cfg.PromptInjection.MLModel.Path)
       if err != nil {
           return nil, fmt.Errorf("onnx scorer: %w", err)
       }
       scorer = s
   } else {
       scorer = &ml.OnnxStub{}
   }
   ```

   The engine already calls `scorer.Score(query)` — no other changes needed.

---

## Regenerating protobuf files

```bash
# Download protoc (adjust version and platform as needed)
PROTOC_VERSION=27.0
wget https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip
unzip protoc-${PROTOC_VERSION}-linux-x86_64.zip -d /tmp/protoc-bin

# Install Go plugins
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Regenerate
/tmp/protoc-bin/bin/protoc \
  --proto_path=proto \
  --go_out=proto --go_opt=paths=source_relative \
  --go-grpc_out=proto --go-grpc_opt=paths=source_relative \
  proto/sentinel.proto \
  -I /tmp/protoc-bin/include
```

Commit the generated `sentinel.pb.go` and `sentinel_grpc.pb.go` files. Regenerate only when `sentinel.proto` changes.

---

## Code style

- **No comments** unless the _why_ is non-obvious (hidden constraint, subtle invariant, workaround for a specific bug).
- **No feature flags** or backwards-compatibility shims — change the code.
- **No error handling for scenarios that can't happen** — trust Go's type system and framework guarantees.
- Run `golangci-lint run` before opening a PR.
- Target ≥ 80% test coverage across all packages.

---

## Project layout

```
bastion-sentinel/
├── cmd/sentinel/        # CLI binary; imports everything below
│   ├── main.go          # cobra commands: validate, try, interactive, server, config, testrun
│   ├── testrun.go       # testrun command implementation
│   └── try.go           # try command implementation
├── cache/               # Cache interface + memCache, redisCache, noopCache, CachedValidator
├── config/              # YAML config loading, Default(), all structs
├── docs/                # Project documentation (you are here)
├── engine/              # Orchestrates prompt + metadata validators
├── formatter/           # text, json, compact output formatters
├── k8s/                 # Kubernetes manifests
├── ml/                  # Scorer interface + OnnxStub
├── proto/               # sentinel.proto + generated Go files
├── server/              # REST and gRPC servers, metrics, logger, notifier
├── tests/
│   ├── fixtures/        # JSONL test fixtures (100 cases, Sentinel-IN)
│   ├── output/
│   │   └── fixtures/    # JSONL test fixtures (18 cases, Sentinel-OUT)
│   ├── integration/     # docker-compose stack for integration testing
│   └── load/            # k6 load test script
├── types/               # Shared Go structs (ValidateRequest, OutputValidateRequest, ...)
└── validators/
    ├── metadata/        # Metadata schema + business rule validator
    ├── output/          # Sentinel-OUT: pii, hallucination, content, permission, format
    └── prompt/          # Prompt injection detector (regex + keyword + ML)
```
