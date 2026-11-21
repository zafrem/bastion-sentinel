# Configuration

Sentinel ships with safe built-in defaults and runs without any configuration file. To customise, pass a YAML file at startup:

```bash
sentinel-cli server --config /etc/sentinel/config.yaml
```

The YAML file is merged on top of the defaults — only the fields you specify are overridden.

---

## Full schema with defaults

```yaml
# ─── Server ───────────────────────────────────────────────────────────────────
server:
  rest_port: 8080        # HTTP listen port
  grpc_port: 9090        # gRPC listen port
  auth_token: ""         # bearer token for the REST API (or env SENTINEL_AUTH_TOKEN); see Authentication below
  # grpc_tls_cert: ""    # gRPC over TLS (PEM files); see gRPC TLS below
  # grpc_tls_key: ""
  # grpc_tls_client_ca: ""   # set to require client certificates (mutual TLS)

# ─── Prompt Injection Detection ───────────────────────────────────────────────
prompt_injection:
  enabled: true

  regex_rules:           # compiled on startup; hot-reloaded on SIGHUP or POST /v1/config/reload
    - id: pi-001
      pattern: "(?i)ignore\\s+all\\s+previous"
      severity: critical  # "critical" | "high" | "medium" | "low" (see Scoring)
    # ... 45 rules ship by default (English + Korean)

  keyword_rules:
    - id: kw-001
      keyword: "jailbreak"
      severity: critical
    # ... 25 rules ship by default

  ml_model:
    enabled: true
    backend: heuristic        # "heuristic" (built in, no network) | "llm" (ask a language model)
    # Only for backend: llm — see "prompt_injection.ml_model" below
    # provider: ollama        # "ollama" | "openai" (any OpenAI-compatible API)
    # endpoint: http://localhost:11434
    # model: qwen3.5:9b
    # api_key_env: JUDGE_API_KEY   # name of an environment variable, not the key
    # timeout_ms: 8000
    # cache_size: 1000        # -1 turns the cache off
    path: /models/injection-detector.onnx   # unused: neither backend loads a model file
    threshold: 0.7                          # unused

  scoring:
    method: max           # "max" or "weighted_avg"
    block_threshold: 0.7  # final score >= this → BLOCKED

# ─── Metadata Validation ──────────────────────────────────────────────────────
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
      pattern: "^[a-z0-9-]+$"
      min_length: 3
      max_length: 64
    user_id:
      type: string
      pattern: "^[a-zA-Z0-9_-]+$"
      min_length: 3
      max_length: 64
    context_id:
      type: string
      format: uuid        # "uuid" or "rfc3339"
    timestamp:
      type: string
      format: rfc3339

  business_rules:
    - id: br-001
      name: timestamp_bounds       # rejects timestamps outside ±1h
      enabled: true
    - id: br-002
      name: reserved_identifiers   # rejects system / admin / root
      enabled: true

# ─── Caching ──────────────────────────────────────────────────────────────────
cache:
  enabled: false          # set true to enable
  type: redis             # "redis" or "memory"
  address: "localhost:6379"
  ttl: 5m                 # Go duration string (e.g. 30s, 5m, 1h)

# ─── Logging ──────────────────────────────────────────────────────────────────
logging:
  level: info             # "debug" | "info" | "warn" | "error"
  format: json            # "json" | "text"
  destination: stdout     # "stdout" | "elasticsearch"
  elasticsearch_url: ""   # required when destination=elasticsearch
                          # e.g. "http://localhost:9200"
                          # logs are shipped asynchronously to index sentinel-logs

# ─── Prometheus Metrics ───────────────────────────────────────────────────────
metrics:
  enabled: true
  port: 9091              # (informational only; metrics served on REST port /v1/metrics)
  path: /metrics

# ─── Incident Notifications ───────────────────────────────────────────────────
notifications:
  slack_webhook_url: ""        # POST to this URL on critical blocks
  pagerduty_routing_key: ""    # PagerDuty Events API v2 routing key
  critical_threshold: 0.9     # risk score >= this triggers alerts

# ─── Features ─────────────────────────────────────────────────────────────────
features:
  hot_reload: true
  graceful_shutdown: true
  shutdown_timeout: 30s
```

---

## Field reference

### `server`

| Field | Default | Description |
|-------|---------|-------------|
| `rest_port` | `8080` | HTTP listen port |
| `grpc_port` | `9090` | gRPC listen port |

### `prompt_injection.scoring`

| Field | Default | Description |
|-------|---------|-------------|
| `method` | `max` | `max`: `max(ruleScore, mlScore)`. `weighted_avg`: `ruleScore * 0.6 + mlScore * 0.4` |
| `block_threshold` | `0.7` | Final score ≥ this value → BLOCKED |

A matching rule contributes by severity: `critical` and `high` (and a rule with no or an unknown
severity) count 1.0 and decide on their own; `medium` counts 0.5; `low` counts 0.25. With several
matches, `ruleScore` is the strongest one plus a quarter of the others, capped at 1.0. So one `medium`
rule alone (0.5) stays under the default 0.7 threshold, and two together (0.75) block. Use `medium` for
rules that only hint at an attack, such as a mention of the topic.

Rules are matched against the query as sent and against decoded or normalised views of it: base64, hex
and URL-encoded text (up to two layers), text with invisible characters removed, and full-width letters
folded to ASCII. A match inside decoded text is reported as `decoded(base64)` etc. in `method`. Only the
first 64 KiB of a query is scanned.

### `prompt_injection.ml_model`

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Run the scorer. `false` disables it (rules only) |
| `backend` | `heuristic` | `heuristic`: built-in feature scorer, no network. `llm`: also asks a language model and takes the higher score |
| `provider` | `ollama` | `llm` only. `ollama` (`/api/chat`) or `openai` (`/chat/completions`) |
| `endpoint` | — | `llm` only, required. Base URL, e.g. `http://localhost:11434` or `https://host/v1` |
| `model` | — | `llm` only, required |
| `api_key_env` | — | Name of an environment variable holding a bearer token |
| `timeout_ms` | `8000` | Per request |
| `cache_size` | `1000` | Verdicts kept in memory (LRU, keyed by a hash of the text); `-1` disables |

With `backend: llm` the model is asked, for each query the rules did not already block, whether it is an
injection attempt. It returns `{"injection": true|false, "score": 0..1}`; the boolean is authoritative
(a contradicting score is capped at 0.5), and any reply that is not exactly that JSON is an error. The
final score is `max(heuristic, model)`, so the model only adds detections. If the model is unreachable, too
slow or answers off-format, the query is scored by the rules and the heuristic and `method` contains
`ml-unavailable`; when the rules already blocked, the model is not called (`ml-skipped`). Only the first
4 000 characters are sent to the model, and the query text leaves Sentinel for `endpoint`. An invalid
`backend`, `provider`, or a missing `endpoint`/`model` stops startup, and on `SIGHUP` keeps the previous
configuration.

### `cache`

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable result caching |
| `type` | `redis` | Backend: `redis` or `memory` |
| `address` | `localhost:6379` | Redis address (only used when type=redis) |
| `ttl` | `5m` | Cache entry lifetime |

If `type=redis` but Redis is unreachable at startup, Sentinel automatically falls back to `memory` without failing.

The cache key is SHA-256 of the NFC-normalised query + sorted metadata key/value pairs, **excluding `timestamp`**. This means repeated requests from the same user for the same query share a cache entry even if timestamps differ.

### `logging`

| Field | Default | Description |
|-------|---------|-------------|
| `level` | `info` | Minimum log level |
| `format` | `json` | `json` (structured) or `text` (human-readable) |
| `destination` | `stdout` | `stdout` always writes to stdout. `elasticsearch` additionally ships to the configured URL asynchronously |
| `elasticsearch_url` | `""` | Elasticsearch base URL; logs ship to `<url>/sentinel-logs/_doc` |

Every log record includes the default fields `service=sentinel` and `version=<cfg.Version>`.

Structured log record example (JSON format):

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

### `notifications`

Fires asynchronously (never delays the request path) when `status = BLOCKED` and `risk_score >= critical_threshold`.

| Field | Default | Description |
|-------|---------|-------------|
| `slack_webhook_url` | `""` | Incoming Webhook URL; disabled if empty |
| `pagerduty_routing_key` | `""` | PagerDuty Events API v2 key; disabled if empty |
| `critical_threshold` | `0.9` | Risk score at or above this triggers alerts |

### `features`

| Field | Default | Description |
|-------|---------|-------------|
| `hot_reload` | `true` | Enable config reload via `POST /v1/config/reload` and SIGHUP |
| `graceful_shutdown` | `true` | Drain in-flight requests before exit |
| `shutdown_timeout` | `30s` | Maximum wait time for graceful drain |

---

### `output_validation`

Controls the Sentinel-OUT pipeline. All sub-sections are enabled by default.

```yaml
output_validation:
  enabled: true

  pii_reemergence:
    enabled: true
    honor_report_action: true   # rules declared "report" are listed under Reported but not masked
    always_enforce: []          # rule IDs masked even if declared "report"
    patterns:
      - id: pii-001
        name: korean_name
        pattern: "[가-힣]{2,4}\\s*(?:씨|님|선생님|교수님|박사님)"
        severity: high
        action: redact
      - id: pii-002
        name: korean_rrn
        pattern: "\\b\\d{6}-[1-4]\\d{6}\\b"
        severity: critical
        action: redact
      - id: pii-003
        name: korean_mobile
        pattern: "\\b01[016789]-\\d{3,4}-\\d{4}\\b"
        severity: high
        action: redact
      - id: pii-004
        name: email
        pattern: "[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}"
        severity: high
        action: redact
      - id: pii-005
        name: credit_card
        pattern: "\\b(?:4[0-9]{12}(?:[0-9]{3})?|[25][1-7][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\\d{3})\\d{11})[\\s\\-]?\\b"
        severity: critical
        action: redact
      - id: pii-006
        name: leaked_token
        pattern: "USER_DATA_[A-Za-z0-9]{16}"
        severity: critical
        action: redact

  hallucination:
    enabled: true
    grounding_threshold: 0.5   # grounding score below this is SUSPICIOUS (disclaimer added)
    low_score_threshold: 0.3   # grounding score below this is FAILED
    add_disclaimer: true       # append a disclaimer when SUSPICIOUS or FAILED
    block_on_low_score: false  # block instead when FAILED
    content_support: true      # also score the answer's ordinary words against the sources
    min_content_words: 3       # answers with fewer content words are not judged this way

  content_filter:      # severity "critical" blocks the response; lower severities warn
    enabled: true
    patterns:
      - id: cf-001
        name: openai_api_key
        pattern: "sk-[A-Za-z0-9]{32,}"
        severity: critical
      - id: cf-002
        name: github_token
        pattern: "ghp_[A-Za-z0-9]{36}"
        severity: critical
      - id: cf-003
        name: aws_access_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
      - id: cf-004
        name: internal_path
        pattern: "(?:/etc/|/var/|/home/|/root/|/srv/)[a-zA-Z0-9/_\\-.]+"
        severity: medium

  permission_check:
    enabled: true
    # specific_amount_pattern: ""   # regex for concrete amounts that imply full access (default built in)
    # Access levels, most to least permissive: full, read, anonymized, k_anonymized, slice, aggregated.

  format:
    min_length: 1         # fewer characters (after trimming whitespace) is rejected; counts characters, not bytes
    max_length: 10000     # more characters is rejected
    utf8_required: true
    no_control_chars: true   # \n \r \t are always permitted; other control chars are not
```

| Sub-section | Field | Default | Description |
|-------------|-------|---------|-------------|
| `pii_reemergence` | `enabled` | `true` | Enable PII detection and sanitisation |
| `pii_reemergence` | `patterns` | 6 patterns | Regex pattern list; `action` is `redact` (default) or `report` |
| `pii_reemergence` | `honor_report_action` | `true` | Matches of rules whose `action` is `report` (low-signal patterns such as bare numbers, dates, common names) are detected and listed in `Reported` for audit, but the text is not changed. `false` masks every match |
| `pii_reemergence` | `always_enforce` | `[]` | Rule IDs that are masked even when their `action` is `report` |
| `hallucination` | `enabled` | `true` | Enable hallucination grounding check |
| `hallucination` | `grounding_threshold` | `0.5` | Score below this adds a disclaimer to the response |
| `hallucination` | `low_score_threshold` | `0.3` | Score below this marks the check FAILED (below `grounding_threshold` is SUSPICIOUS) |
| `hallucination` | `add_disclaimer` | `true` | Append disclaimer text when grounding is low |
| `hallucination` | `block_on_low_score` | `false` | Block instead of disclaiming when the check is FAILED |
| `hallucination` | `content_support` | `true` | Score the share of the answer's content words found in the sources (first four letters, Latin script), alongside the number check; the lower score applies. Needs `min_content_words` |
| `hallucination` | `min_content_words` | `3` | Answers with fewer content words (stopwords excluded) are not judged by content support |
| `content_filter` | `enabled` | `true` | Enable credential/path content filtering |
| `content_filter` | `patterns` | 9 patterns | Regex pattern list: credentials and internal paths, plus abuse aimed at the user, threats and eliminationist hate. `critical` blocks; lower severities warn |
| `permission_check` | `enabled` | `true` | Enable access-level boundary enforcement |
| `format` | `min_length` | `1` | Minimum response length in characters, after trimming whitespace (rejects empty output only) |
| `format` | `max_length` | `10000` | Maximum response length in characters |
| `format` | `utf8_required` | `true` | Reject responses with invalid UTF-8 sequences |

---

## Adding detection rules

### Regex rule

```yaml
prompt_injection:
  regex_rules:
    - id: pi-026                              # unique ID, follow convention pi-NNN
      pattern: "(?i)my custom attack pattern"
      severity: high                          # critical | high | medium
```

IDs appear in `matched_patterns` in every blocked response — they are the only thing exposed to the client, not the raw pattern text.

### Keyword rule

```yaml
prompt_injection:
  keyword_rules:
    - id: kw-026
      keyword: "my trigger phrase"
      severity: critical
```

Keyword matching is case-insensitive and checks for substring presence after Unicode NFC normalisation.

After adding rules, run the fixture suite to catch regressions:

```bash
go run ./cmd/sentinel testrun --dir tests/fixtures/ --verbose
```

---

## Environment-based profiles

Sentinel does not have built-in profile support, but the pattern is straightforward:

```bash
# Development
sentinel-cli server --config config/dev.yaml

# Staging
sentinel-cli server --config config/staging.yaml

# Production (Kubernetes: mounted as ConfigMap)
sentinel-cli server --config /etc/sentinel/config.yaml
```

A minimal `config/dev.yaml` might disable Redis and enable debug logging:

```yaml
cache:
  enabled: false

logging:
  level: debug
  format: text
```

---

## Validating a config file

```bash
sentinel-cli config validate /path/to/config.yaml
# ✅ Config "/path/to/config.yaml" is valid

sentinel-cli config show --config /path/to/config.yaml
```

Invalid YAML or unknown fields cause `config validate` to return a non-zero exit code with the parse error.

---

## Authentication

Set `server.auth_token` (or the `SENTINEL_AUTH_TOKEN` environment variable) to a long random value, for example `openssl rand -hex 32`.

| Token configured? | `/v1/config`, `/v1/config/reload` | `/v1/validate*` and gRPC `Validate*` RPCs | Health / metrics probes |
|---|---|---|---|
| No | **403** (admin endpoints disabled) | open (backward compatible) | open |
| Yes | require `Authorization: Bearer <token>` | require the token (gRPC: `authorization: Bearer <token>` metadata, **Unauthenticated** otherwise) | open |

The probes `/health/live`, `/health/ready`, `/v1/health` and `/v1/metrics` never need a token. The token is compared in constant time and is never included in the `GET /v1/config` response. The gRPC `Health` RPC is public too; every other RPC, including both streaming RPCs, uses the same token check as REST. Without gRPC TLS (below) that token travels in plaintext on the gRPC port.

---

## gRPC TLS

By default the gRPC port is plaintext. Set a certificate and key (PEM files) to serve it over TLS:

```yaml
server:
  grpc_tls_cert: /etc/sentinel/tls/server.pem
  grpc_tls_key:  /etc/sentinel/tls/server.key
  grpc_tls_client_ca: /etc/sentinel/tls/ca.pem   # optional: require client certificates (mutual TLS)
```

- `grpc_tls_cert` and `grpc_tls_key` must be set together; `grpc_tls_client_ca` needs both. A missing, unreadable, mismatched or empty file makes Sentinel **refuse to start**.
- With `grpc_tls_client_ca`, every client must present a certificate signed by that CA; others are rejected during the handshake.
- The certificate files are re-read when they change, so rotating them (for example with cert-manager) needs no restart. If a replacement cannot be loaded, the previous working certificate keeps being served and a warning is logged.
- TLS 1.2 or newer. The bearer token (see Authentication) still applies inside the TLS connection.
- When a token is configured but gRPC is plaintext, Sentinel logs a warning at startup that the token travels unencrypted.
- These settings cover the gRPC port only. For the REST port, terminate TLS in front of Sentinel.
- To try it locally, run `scripts/gen-dev-certs.sh` from the repository root (development certificates only).
