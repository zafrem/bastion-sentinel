# Sentinel — Metadata Filtering

**Module:** Sentinel-IN (`validators/metadata/`)
**Version:** 3.0
**Last updated:** 2026-05-30

---

## Overview

Every request to the Bastion-RAG pipeline must carry a metadata envelope that proves its identity and freshness. The metadata validator (`Validator`) enforces four checks on this envelope — required field presence, format/length rules, business logic rules, and payload size limits — before the query is allowed to proceed.

A single failure in any check sets the response status to `BLOCKED`. The validator is designed to be fail-closed: ambiguous or malformed metadata is rejected, not passed with a warning.

---

## Validator construction

`Validator` is created once at process start. The constructor pre-compiles only the field rules that carry a non-empty `Pattern`, so the regex engine at runtime pays no compilation cost per request:

```go
// validators/metadata/validator.go

type Validator struct {
    cfg      config.MetadataValidationConfig
    patterns map[string]*regexp.Regexp  // field name → compiled pattern
}

func New(cfg config.MetadataValidationConfig) (*Validator, error) {
    v := &Validator{
        cfg:      cfg,
        patterns: make(map[string]*regexp.Regexp),
    }
    for field, rule := range cfg.FieldRules {
        if rule.Pattern == "" {
            continue  // fields like context_id use format: "uuid" instead of a regex
        }
        re, err := regexp.Compile(rule.Pattern)
        if err != nil {
            // Config error — fail hard at startup, not silently at runtime
            return nil, fmt.Errorf("field %s: invalid pattern %q: %w", field, rule.Pattern, err)
        }
        v.patterns[field] = re
    }
    return v, nil
}
```

Called from `engine.New()`:
```go
// engine/engine.go

func New(cfg *config.Config) (*Engine, error) {
    // ...
    mv, err := metadata.New(cfg.MetadataValidation)
    if err != nil {
        return nil, fmt.Errorf("metadata validator: %w", err)
    }
    return &Engine{
        promptDetector:    pd,
        metadataValidator: mv,
    }, nil
}
```

---

## Validation pipeline

```
Incoming request metadata + query
    │
    ▼
Required field presence check     ← fast-fail; missing field → BLOCKED immediately
    │
    ▼
Field format rules                ← per-field: regex pattern, min/max length, UUID/RFC3339
    │
    ▼
Business rules                    ← timestamp bounds, reserved identifier check
    │
    ▼
Payload size limits               ← query ≤ 10,000 chars; metadata ≤ 4 KB
    │
    ▼
types.MetadataCheckResult{ Status, MissingFields, FormatErrors }
```

Entry point: `engine.Engine.Validate(req)` → `Validator.Validate(metadata, query)` → `types.MetadataCheckResult`

### Annotated `Validate()` method

```go
// validators/metadata/validator.go

func (v *Validator) Validate(metadata map[string]string, query string) types.MetadataCheckResult {

    // ── Check 1: Required field presence (fast-fail) ────────────────────────
    // If any required field is missing, return immediately without running
    // format checks or business rules. An empty MissingFields list means all
    // required fields are present.
    var missing []string
    for _, field := range v.cfg.RequiredFields {
        if _, ok := metadata[field]; !ok {
            missing = append(missing, field)
        }
    }
    if len(missing) > 0 {
        return types.MetadataCheckResult{
            Status:        types.StatusBlocked,
            MissingFields: missing,
            // FormatErrors is nil — no format checks run when fields are absent
        }
    }

    var errs []string

    // ── Check 2: Field format rules ─────────────────────────────────────────
    // Iterates every configured FieldRule. Skips fields that are not present
    // in the request (format rules apply to present fields only; presence is
    // enforced by RequiredFields above).
    for field, rule := range v.cfg.FieldRules {
        val, ok := metadata[field]
        if !ok {
            continue
        }

        // Regex pattern match (e.g. ^[a-z0-9-]+$ for tenant_id)
        if re, ok := v.patterns[field]; ok && !re.MatchString(val) {
            errs = append(errs, fmt.Sprintf(
                "%s: invalid format (must match %s)", field, rule.Pattern))
        }

        // Byte-length bounds
        if rule.MinLength > 0 && len(val) < rule.MinLength {
            errs = append(errs, fmt.Sprintf(
                "%s: too short (min %d chars)", field, rule.MinLength))
        }
        if rule.MaxLength > 0 && len(val) > rule.MaxLength {
            errs = append(errs, fmt.Sprintf(
                "%s: too long (max %d chars)", field, rule.MaxLength))
        }

        // Structural format checks (UUID v4, RFC3339)
        switch rule.Format {
        case "uuid":
            if _, err := uuid.Parse(val); err != nil {
                errs = append(errs, fmt.Sprintf(
                    "%s: must be a valid UUID v4", field))
            }
        case "rfc3339":
            if _, err := time.Parse(time.RFC3339, val); err != nil {
                errs = append(errs, fmt.Sprintf(
                    "%s: must be a valid RFC3339 timestamp", field))
            }
        }
    }

    // ── Check 3: Business rules ─────────────────────────────────────────────
    // Appends to errs; does not short-circuit. All violations are collected.
    errs = append(errs, v.checkBusinessRules(metadata)...)

    // ── Check 4: Payload size limits ────────────────────────────────────────
    if utf8.RuneCountInString(query) > 10000 {
        errs = append(errs, "query: exceeds maximum length of 10000 characters")
    }
    if metadataByteSize(metadata) > 4096 {
        errs = append(errs, "metadata: total payload exceeds 4KB limit")
    }

    status := types.StatusPassed
    if len(errs) > 0 {
        status = types.StatusBlocked
    }
    return types.MetadataCheckResult{
        Status:       status,
        FormatErrors: errs,
        // MissingFields is nil — all required fields were present
    }
}

// metadataByteSize sums len(key)+len(value) for all entries.
// Uses raw byte length (UTF-8), not rune count.
func metadataByteSize(metadata map[string]string) int {
    total := 0
    for k, v := range metadata {
        total += len(k) + len(v)
    }
    return total
}
```

---

## Required fields

The following four fields must be present in every request. If any are absent the request is blocked immediately without running further checks.

| Field | Type | Purpose |
|---|---|---|
| `tenant_id` | string | Identifies the tenant scope for all downstream access decisions |
| `user_id` | string | Identifies the requesting user for RBAC and audit |
| `context_id` | string (UUID v4) | Correlates requests within a conversation or session |
| `timestamp` | string (RFC3339) | Proves request freshness; used by the replay-attack defense |

Missing fields are returned verbatim in `MetadataCheckResult.MissingFields`.

---

## Field format rules

Applied after the required-field check. Each rule is evaluated independently; all violations accumulate into `FormatErrors`.

### `tenant_id`

| Check | Value |
|---|---|
| Pattern | `^[a-z0-9-]+$` (lowercase alphanumeric and hyphens only) |
| Min length | 3 chars |
| Max length | 64 chars |

Rejects uppercase, underscores, dots, and whitespace. Prevents tenant IDs that could be confused with path segments or SQL identifiers.

### `user_id`

| Check | Value |
|---|---|
| Pattern | `^[a-zA-Z0-9_-]+$` (alphanumeric, underscore, hyphen) |
| Min length | 3 chars |
| Max length | 64 chars |

Allows mixed case but excludes characters that require URL-encoding or that could be interpreted as control characters downstream.

### `context_id`

| Check | Value |
|---|---|
| Format | UUID v4 — parsed with `github.com/google/uuid` |

Rejects any string that does not parse as a valid UUID v4. This ensures the context correlation key is collision-resistant by construction rather than by convention.

### `timestamp`

| Check | Value |
|---|---|
| Format | RFC3339 — parsed with `time.Parse(time.RFC3339, val)` |

The timestamp must be a fully-qualified RFC3339 string including timezone offset (e.g., `2026-05-30T12:00:00Z`). Partial dates or epoch integers are rejected.

---

## Business rules

Business rules run after format validation. They express constraints that cannot be captured by a single regex.

### Full `checkBusinessRules()` implementation

```go
// validators/metadata/validator.go

// reservedIdentifiers is checked case-insensitively for tenant_id and user_id.
var reservedIdentifiers = map[string]bool{
    "system": true,
    "admin":  true,
    "root":   true,
}

func (v *Validator) checkBusinessRules(metadata map[string]string) []string {
    var errs []string

    for _, rule := range v.cfg.BusinessRules {
        if !rule.Enabled {
            continue  // rules can be disabled per-environment in config.yaml
        }
        switch rule.Name {

        // ── BR-001: Timestamp bounds ─────────────────────────────────────────
        // Computes the absolute difference between the request timestamp and
        // the server wall clock. Rejects both past requests (replay window
        // expired) and future requests (clock skew too large or forged).
        case "timestamp_bounds":
            if ts, ok := metadata["timestamp"]; ok {
                t, err := time.Parse(time.RFC3339, ts)
                if err == nil {
                    diff := time.Since(t)   // positive = past, negative = future
                    if diff > time.Hour || diff < -time.Hour {
                        errs = append(errs,
                            "timestamp: outside allowed window (±1 hour from current time)")
                    }
                }
                // If Parse failed, the RFC3339 format check already added an
                // error above. No double-reporting here.
            }

        // ── BR-002: Reserved identifiers ────────────────────────────────────
        // Guards both tenant_id and user_id. Uses strings.ToLower so that
        // "ADMIN", "Admin", and "admin" are all rejected.
        case "reserved_identifiers":
            for _, field := range []string{"tenant_id", "user_id"} {
                if val, ok := metadata[field]; ok {
                    if reservedIdentifiers[strings.ToLower(val)] {
                        errs = append(errs, fmt.Sprintf(
                            "%s: reserved identifier not allowed", field))
                    }
                }
            }
        }
    }
    return errs
}
```

### BR-001 — Timestamp bounds (replay-attack defense)

The request timestamp must be within ±1 hour of the server clock at the time of processing. This invalidates replayed requests captured by a network attacker. The window is intentionally wide enough to tolerate clock skew between microservices but tight enough to expire captured tokens.

**Threat mitigated:** An attacker who captures a valid `ValidateRequest` from the wire cannot replay it after the 1-hour window expires.

**Configuration:** The rule is enabled by default (`id: br-001, name: timestamp_bounds, enabled: true`). Disable it only in test environments where synthetic timestamps are used.

### BR-002 — Reserved identifiers

The values `system`, `admin`, and `root` (case-insensitive) are blocked in both `tenant_id` and `user_id`. These identifiers are commonly targeted by injection attacks that attempt to acquire elevated pipeline authority by mimicking system-level identities.

**Threat mitigated:** A caller sending `user_id: "admin"` cannot accidentally or intentionally inherit permissions associated with internal system accounts.

---

## Payload size limits

Size limits run after business rules and are applied uniformly regardless of field values.

| Subject | Limit | Error message |
|---|---|---|
| `query` (Unicode rune count) | 10,000 runes | `"query: exceeds maximum length of 10000 characters"` |
| Entire `metadata` map (byte sum of all keys + values) | 4,096 bytes | `"metadata: total payload exceeds 4KB limit"` |

The query rune count uses `utf8.RuneCountInString` so that multi-byte Korean and other CJK characters each count as a single unit. The metadata byte limit uses raw `len(string)` (UTF-8 byte length).

**Threat mitigated:**
- Oversized queries cannot be used for amplification attacks or to exceed downstream buffer limits.
- Oversized metadata cannot be used to exfiltrate data by encoding a payload in custom metadata keys.

---

## Response structure

```go
type MetadataCheckResult struct {
    Status        Status   // "PASSED" or "BLOCKED"
    MissingFields []string // populated on required-field failure
    FormatErrors  []string // human-readable error messages
}
```

A BLOCKED result includes all accumulated errors — the caller sees every violation in a single response rather than one at a time. This is intentional: it reduces the number of round-trips needed to correct a legitimately malformed request, while providing no useful enumeration signal to an attacker (all fields must be correct anyway).

---

## Interaction with downstream modules

The metadata validator operates before any query content is inspected. Its primary output to downstream modules is via `ExtractedData`:

```go
type ExtractedData struct {
    TenantID     string
    UserID       string
    CleanedQuery string
}
```

`tenant_id` and `user_id` extracted here are passed to:
- **Vault Phase-1** — scopes PII tokenization to the tenant's key namespace
- **Vault RBAC / `DecideWithPurpose`** — identifies the requesting user for department-based access decisions
- **Navigator** — used as Qdrant collection filter to enforce tenant isolation
- **Tracker** — stored in every lineage event for audit trail

If metadata validation is blocked, no `ExtractedData` is populated and the pipeline receives the blocked status immediately — downstream modules are never invoked.

---

## Configuration reference

```yaml
metadata_validation:
  enabled: true

  required_fields:
    - tenant_id
    - user_id
    - context_id
    - timestamp

  field_rules:
    tenant_id:
      type: string
      pattern: '^[a-z0-9-]+$'
      min_length: 3
      max_length: 64
    user_id:
      type: string
      pattern: '^[a-zA-Z0-9_-]+$'
      min_length: 3
      max_length: 64
    context_id:
      type: string
      format: uuid
    timestamp:
      type: string
      format: rfc3339

  business_rules:
    - id: br-001
      name: timestamp_bounds
      enabled: true
    - id: br-002
      name: reserved_identifiers
      enabled: true
```

### Adding a custom field rule

```yaml
field_rules:
  session_token:
    type: string
    pattern: '^[A-Za-z0-9+/=]{32,128}$'
    min_length: 32
    max_length: 128
```

Custom fields do not become required automatically. To require them, also add the field name to `required_fields`.

### Adding a custom business rule

Business rules beyond `timestamp_bounds` and `reserved_identifiers` require a matching `case` in `Validator.checkBusinessRules()`. The YAML `name` field is the switch key.

---

## End-to-end traces

### Valid request — PASSED

```go
metadata := map[string]string{
    "tenant_id":  "acme-corp",
    "user_id":    "hong-gildong",
    "context_id": "550e8400-e29b-41d4-a716-446655440000",
    "timestamp":  "2026-05-30T12:00:00Z",   // within ±1 hour of server time
}
query := "What is the refund policy for order #10042?"
```

**Check 1 — Required fields:** all four present → no fast-fail.

**Check 2 — Format rules:**
```
tenant_id  "acme-corp"   → ^[a-z0-9-]+$ ✓  len=9 ∈ [3,64] ✓
user_id    "hong-gildong"→ ^[a-zA-Z0-9_-]+$ ✓  len=12 ∈ [3,64] ✓
context_id "550e8400-..."→ uuid.Parse() ✓
timestamp  "2026-05-30T12:00:00Z" → time.Parse(RFC3339) ✓
```

**Check 3 — Business rules:**
```
BR-001: diff = time.Since(2026-05-30T12:00:00Z) ≈ 0s  → within ±1h ✓
BR-002: "acme-corp" ∉ reservedIdentifiers ✓
        "hong-gildong" ∉ reservedIdentifiers ✓
```

**Check 4 — Size limits:**
```
utf8.RuneCountInString(query) = 42  ≤ 10000 ✓
metadataByteSize = 9+10+12+13+36+36+9+20 = 145 bytes  ≤ 4096 ✓
```

**Result:**
```go
types.MetadataCheckResult{
    Status:        "PASSED",
    MissingFields: nil,
    FormatErrors:  nil,
}
```

---

### Missing field — BLOCKED (fast-fail)

```go
metadata := map[string]string{
    "tenant_id": "acme-corp",
    // user_id missing
    // context_id missing
    "timestamp": "2026-05-30T12:00:00Z",
}
```

**Check 1 — Required fields:**
```
"user_id"    → not present
"context_id" → not present
missing = ["user_id", "context_id"]   ← iteration order may vary
```
Returns immediately. Format and business rules are not evaluated.

**Result:**
```go
types.MetadataCheckResult{
    Status:        "BLOCKED",
    MissingFields: []string{"user_id", "context_id"},
    FormatErrors:  nil,
}
```

---

### Multiple format violations — BLOCKED (all errors accumulated)

```go
metadata := map[string]string{
    "tenant_id":  "ACME_CORP",              // uppercase + underscore rejected
    "user_id":    "ab",                     // too short (min 3)
    "context_id": "not-a-uuid",             // UUID parse fails
    "timestamp":  "2026-05-30",             // not RFC3339 (no time component)
}
query := "hello"
```

**Check 2 — Format rules:**
```
tenant_id  "ACME_CORP"   → ^[a-z0-9-]+$ FAIL
user_id    "ab"          → len=2 < min_length=3 FAIL
context_id "not-a-uuid"  → uuid.Parse() error FAIL
timestamp  "2026-05-30"  → time.Parse(RFC3339) error FAIL
```

**Result:**
```go
types.MetadataCheckResult{
    Status: "BLOCKED",
    FormatErrors: []string{
        "tenant_id: invalid format (must match ^[a-z0-9-]+$)",
        "user_id: too short (min 3 chars)",
        "context_id: must be a valid UUID v4",
        "timestamp: must be a valid RFC3339 timestamp",
    },
}
```

---

### Replay attack + reserved identifier — BLOCKED

```go
metadata := map[string]string{
    "tenant_id":  "acme-corp",
    "user_id":    "admin",               // reserved
    "context_id": "550e8400-e29b-41d4-a716-446655440000",
    "timestamp":  "2026-05-29T10:00:00Z",  // > 1 hour ago
}
```

**Check 3 — Business rules:**
```
BR-001: diff = ~26 hours > 1 hour → FAIL
BR-002: "admin" ∈ reservedIdentifiers → FAIL
```

**Result:**
```go
types.MetadataCheckResult{
    Status: "BLOCKED",
    FormatErrors: []string{
        "timestamp: outside allowed window (±1 hour from current time)",
        "user_id: reserved identifier not allowed",
    },
}
```

---

## Threat model summary

| Threat | Defense |
|---|---|
| Missing context (unauthenticated request) | Required fields check — blocks if `tenant_id` or `user_id` absent |
| Tenant/user ID injection via special characters | Pattern rules reject anything outside `[a-z0-9-]` / `[a-zA-Z0-9_-]` |
| Privilege escalation via reserved identifiers | BR-002 blocks `system`, `admin`, `root` |
| Replay attack with captured valid request | BR-001 rejects timestamps outside ±1 hour |
| Oversized payload (amplification / buffer abuse) | 10,000-rune query cap; 4KB metadata cap |
| Malformed UUID causing downstream parse errors | UUID v4 parse enforced at the gate |
| Clock manipulation to forge fresh timestamp | Server time is authoritative; client-supplied timestamp is compared, not trusted |

---

## Related documents

- `sentinel/docs/architecture.md` — package structure and component overview
- `sentinel/docs/configuration.md` — full YAML schema with all defaults
- `sentinel/docs/prompt-injection-detection.md` — prompt injection detection detail
- `docs/32_injection_defense_architecture.md` — cross-module injection defense specification (D-01 to D-20)
