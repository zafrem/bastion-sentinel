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
