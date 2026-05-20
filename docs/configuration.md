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

# ─── Prompt Injection Detection ───────────────────────────────────────────────
prompt_injection:
  enabled: true

  regex_rules:           # compiled on startup; hot-reloaded on SIGHUP or POST /v1/config/reload
    - id: pi-001
      pattern: "(?i)ignore\\s+all\\s+previous"
      severity: critical  # "critical" | "high" | "medium"
    # ... 25 rules ship by default (English + Korean)

  keyword_rules:
    - id: kw-001
      keyword: "jailbreak"
      severity: critical
    # ... 25 rules ship by default

  ml_model:
    enabled: true
    path: /models/injection-detector.onnx   # path to ONNX model file
    threshold: 0.7                          # ML-only block threshold (not used by stub)

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

Any regex or keyword match sets `ruleScore = 1.0`, which always exceeds the threshold.

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
    patterns:
      - id: pii-001
        name: korean_name
        pattern: "[가-힣]{2,4}\\s*(?:씨|님|선생님|교수님|박사님)"
        severity: high
        action: masked
      - id: pii-002
        name: korean_rrn
        pattern: "\\b\\d{6}-[1-4]\\d{6}\\b"
        severity: critical
        action: redacted
      - id: pii-003
        name: korean_mobile
        pattern: "\\b01[016789]-\\d{3,4}-\\d{4}\\b"
        severity: high
        action: masked
      - id: pii-004
        name: email
        pattern: "[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}"
        severity: high
        action: redacted
      - id: pii-005
        name: credit_card
        pattern: "\\b(?:4[0-9]{12}(?:[0-9]{3})?|[25][1-7][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\\d{3})\\d{11})[\\s\\-]?\\b"
        severity: critical
        action: redacted
      - id: pii-006
        name: leaked_token
        pattern: "USER_DATA_[A-Za-z0-9]{16}"
        severity: critical
        action: redacted

  hallucination:
    enabled: true
    grounding_threshold: 0.5   # grounding score below this adds a disclaimer
    low_score_threshold: 0.3   # grounding score below this returns SUSPICIOUS
    add_disclaimer: true       # prepend disclaimer when grounding score < grounding_threshold

  content_filter:
    enabled: true
    patterns:
      - id: cf-001
        name: openai_api_key
        pattern: "sk-[A-Za-z0-9]{32,}"
        severity: critical
        action: block
      - id: cf-002
        name: github_token
        pattern: "ghp_[A-Za-z0-9]{36}"
        severity: critical
        action: block
      - id: cf-003
        name: aws_access_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
        action: block
      - id: cf-004
        name: internal_path
        pattern: "(?:/etc/|/var/|/home/|/root/|/srv/)[a-zA-Z0-9/_\\-.]+"
        severity: medium
        action: warn

  permission_check:
    enabled: true
    access_levels:
      full:        0   # most permissive — sees all detail
      read:        1
      anonymized:  2
      k_anonymized: 3
      slice:       4
      aggregated:  5   # most restricted — no specific values

  format:
    enabled: true
    min_length: 10        # shorter responses are rejected
    max_length: 10000     # longer responses are rejected
    require_utf8: true
    allow_control_chars: false   # \n \r \t are always permitted; other control chars are not
```

| Sub-section | Field | Default | Description |
|-------------|-------|---------|-------------|
| `pii_reemergence` | `enabled` | `true` | Enable PII detection and sanitisation |
| `pii_reemergence` | `patterns` | 6 patterns | Regex pattern list; `action` is `redacted` or `masked` |
| `hallucination` | `enabled` | `true` | Enable hallucination grounding check |
| `hallucination` | `grounding_threshold` | `0.5` | Score below this adds a disclaimer to the response |
| `hallucination` | `low_score_threshold` | `0.3` | Score below this marks the check SUSPICIOUS |
| `hallucination` | `add_disclaimer` | `true` | Prepend disclaimer text when grounding is low |
| `content_filter` | `enabled` | `true` | Enable credential/path content filtering |
| `content_filter` | `patterns` | 4 patterns | Regex pattern list; `action` is `block` or `warn` |
| `permission_check` | `enabled` | `true` | Enable access-level boundary enforcement |
| `format` | `min_length` | `10` | Minimum response length in characters |
| `format` | `max_length` | `10000` | Maximum response length in characters |
| `format` | `require_utf8` | `true` | Reject responses with invalid UTF-8 sequences |

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
