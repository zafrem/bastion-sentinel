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
| `engine` | 6 | Full engine orchestration, edge cases |
| `cache` | 10 | memCache TTL, noop cache, CachedValidator hit/miss/error/swap |
| `server` | 8 | REST endpoints, metrics, health probes, reload |

### Fixture format

Files live in `tests/fixtures/` as JSONL — one JSON object per line:

```json
{"request_id":"v-001","description":"safe English query","query":"What is AI?","metadata":{"tenant_id":"acme","user_id":"alice","context_id":"550e8400-e29b-41d4-a716-446655440000","timestamp":"NOW"},"expected":"PASSED"}
```

- `"timestamp":"NOW"` is substituted with the current UTC time at runtime.
- `expected` must be `"PASSED"` or `"BLOCKED"`.

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
│   ├── fixtures/        # JSONL test fixtures (100 cases)
│   ├── integration/     # docker-compose stack for integration testing
│   └── load/            # k6 load test script
├── types/               # Shared Go structs (ValidateRequest, ValidateResponse, ...)
└── validators/
    ├── metadata/        # Metadata schema + business rule validator
    └── prompt/          # Prompt injection detector (regex + keyword + ML)
```
