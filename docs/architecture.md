# Architecture

## Overview

Bastion-Sentinel is a high-performance, bidirectional security gateway for RAG (Retrieval-Augmented Generation) pipelines. It serves as both the entry point (**Sentinel-IN**) and the exit point (**Sentinel-OUT**), ensuring that LLM interactions are secure, private, and grounded.

```
Client (REST :8080 / gRPC :9090 / CLI)
  │
  ▼
┌──────────────────────────────────────────────────────────┐
│  SENTINEL SERVICE (Unified)                              │
│                                                          │
│  ┌─────────────────────────────────────────────────┐     │
│  │  cache.CachedValidator  (SHA-256 key, TTL 5m)   │     │
│  │   Redis ──► in-memory fallback                  │     │
│  └────────────────────┬────────────────────────────┘     │
│                  cache miss                              │
│  ┌─────────────────────▼──────────────────────────┐      │
│  │  Validation Engine (IN or OUT mode)            │      │
│  │                                                │      │
│  │  ┌──────────────────────┐  ┌────────────────┐  │      │
│  │  │  Sentinel-IN (Input) │  │ Sentinel-OUT   │  │      │
│  │  │  - Prompt Injection  │  │ - PII Re-emerge│  │      │
│  │  │  - Metadata Valid    │  │ - Hallucination│  │      │
│  │  │  - ML Scoring (ONNX) │  │ - Content Filt │  │      │
│  │  │                      │  │ - Perm Boundary│  │      │
│  │  └──────────────────────┘  └────────────────┘  │      │
│  └────────────────────────────────────────────────┘      │
│                                                          │
│  server/rest.go   server/grpc.go   formatter/            │
│  server/metrics.go  server/logger.go  server/notifier.go │
└──────────────────────────────────────────────────────────┘
  │ 
  ▼
Bidirectional Pipeline (Vault, Navigator, Anchor, LLM)
```

---

## Package dependency order

```
types
  └── config
        └── ml
              └── validators/prompt
              └── validators/metadata
              └── validators/output
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

Defines the canonical Go structs shared across the entire codebase.

**Input Types:** `ValidateRequest`, `ValidateResponse`, `PromptCheckResult`, `MetadataCheckResult`.
**Output Types:** `OutputValidateRequest`, `OutputValidateResponse`, `PIICheckResult`, `HallucinationCheckResult`.

### `config/`

Loads and validates YAML configuration. Supports both `PromptInjection` (Input) and `OutputValidation` (Output) configurations. Supports hot-reloading via `SIGHUP` or API calls.

### `ml/`

Defines the `Scorer` interface for in-process ML inference (ONNX Runtime). Used primarily by Sentinel-IN for prompt injection detection.

### `validators/prompt/` (Sentinel-IN)

Three-stage detection pipeline for input queries:
1. **Regex** — compiled on startup.
2. **Keyword** — case-insensitive substring scan.
3. **ML** — scalar risk scoring via ONNX.

### `validators/metadata/` (Sentinel-IN)

Validates request context (tenant, user, timestamps) and enforces volumetric constraints.

### `validators/output/` (Sentinel-OUT)

Multi-layered validation for LLM responses:
1. **PII Re-emergence** — Detects original PII in responses using regex patterns (internal + external from [pii-pattern-engine](https://github.com/zafrem/pii-pattern-engine)) and Vault cross-referencing.
2. **Hallucination** — Heuristic grounding check against retrieved source documents.
3. **Content Filter** — Blocks secrets, credentials, and inappropriate content.
4. **Permission Boundary** — Enforces data access levels (e.g., k-anonymity) on the response content.
5. **Format** — Enforces length, encoding, and character constraints.

### `engine/`

Orchestrates the validation logic.
- `engine.Engine`: Handles the input validation (Sentinel-IN).
- `engine.OutputEngine`: Handles the output validation (Sentinel-OUT).

Both engines are decoupled but share detection primitives where applicable.

### `cache/`

Hybrid caching layer (Redis + local in-memory) for storing and retrieving validation verdicts based on input signatures.

### `server/`

Exposes REST and gRPC endpoints for bidirectional validation. Includes observability (Prometheus), logging (Elasticsearch), and alerting (Slack/PagerDuty) components.

### `formatter/`

Human-readable and machine-parsable formatters for CLI and batch results.

### `cmd/sentinel/`

The main CLI application providing server management, interactive REPL, and batch processing tools.

---

## Request lifecycle (Sentinel-OUT example)

```
1.  LLM generates a response.
2.  Pipeline sends POST /v1/validate/output with response and retrieval context.
3.  OutputEngine.Validate(req):
      a. Format check (fast-fail if invalid).
      b. PII re-emergence check (regex + Vault).
      c. Hallucination grounding check against sources.
      d. Content filtering (secrets, profanity).
      e. Permission boundary check (user access level vs content detail).
      f. Synthesis: Status = PASSED, SANITIZED, or BLOCKED.
4.  If SANITIZED, apply redactions and modifications.
5.  Emit metrics, logs, and optional alerts.
6.  Return validated/sanitized response to the pipeline/user.
```
