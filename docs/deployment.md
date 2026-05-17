# Deployment

## Docker

### Build

```bash
docker build -t bastion/sentinel:1.0.0 .
```

The Dockerfile uses a two-stage build:

1. **Builder** — `golang:1.23-alpine`; downloads dependencies, compiles with `CGO_ENABLED=0 -trimpath -ldflags="-s -w"` for a minimal static binary.
2. **Runtime** — `alpine:3.20` + `ca-certificates` + `tzdata`; copies only the compiled binary.

Target image size is ≤ 50 MB.

### Run

```bash
# With built-in defaults (no Redis, stdout logging)
docker run --rm -p 8080:8080 -p 9090:9090 bastion/sentinel:1.0.0

# With a config file
docker run --rm \
  -p 8080:8080 -p 9090:9090 \
  -v /etc/sentinel/config.yaml:/etc/sentinel/config.yaml:ro \
  bastion/sentinel:1.0.0 server --config /etc/sentinel/config.yaml

# With Redis
docker run --rm \
  -p 8080:8080 -p 9090:9090 \
  --link redis:redis \
  -e SENTINEL_CACHE_ADDRESS=redis:6379 \
  bastion/sentinel:1.0.0
```

### Health check

The Dockerfile `HEALTHCHECK` polls `/health/live` every 10 seconds:

```
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s \
  CMD wget --quiet --spider http://localhost:8080/health/live || exit 1
```

---

## Docker Compose (integration stack)

The integration compose file at `tests/integration/docker-compose.yml` starts the full stack:

```bash
cd tests/integration
docker-compose up
```

Services started:

| Service | Port | Description |
|---------|------|-------------|
| `sentinel` | 8080 / 9090 | Sentinel with Redis + Elasticsearch logging |
| `redis` | 6379 | Verdict cache |
| `prometheus` | 9090 | Scrapes `/v1/metrics` |
| `elasticsearch` | 9200 | Receives structured logs |

---

## Kubernetes

The Kubernetes manifests are in `k8s/deployment.yaml`.

### Prerequisites

```bash
kubectl create namespace bastion

# Create config ConfigMap
kubectl create configmap sentinel-config \
  --from-file=config.yaml=/etc/sentinel/config.yaml \
  -n bastion

# Create models PVC (if using ONNX inference)
kubectl apply -f k8s/models-pvc.yaml
```

### Deploy

```bash
kubectl apply -f k8s/deployment.yaml -n bastion
```

This creates:
- **Deployment** — 3 replicas, resource limits 2 vCPU / 512 MB
- **Service** — ClusterIP exposing REST :8080 and gRPC :9090
- **HorizontalPodAutoscaler** — scales 3–50 pods on CPU ≥ 70% or memory ≥ 80%

### Health probes

```yaml
livenessProbe:
  httpGet:
    path: /health/live
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /health/ready
    port: 8080
  initialDelaySeconds: 3
  periodSeconds: 5
```

Kubernetes removes a pod from the load-balancer when the readiness probe fails (e.g. during an engine hot-swap) and restarts it when the liveness probe fails (process hang or crash).

### Prometheus scraping

The Deployment template includes annotations:

```yaml
annotations:
  prometheus.io/scrape: "true"
  prometheus.io/port: "8080"
  prometheus.io/path: "/v1/metrics"
```

Standard Prometheus Helm charts pick these up automatically.

### Config hot-reload via SIGHUP

```bash
# Get the pod name
POD=$(kubectl get pod -n bastion -l app=sentinel -o jsonpath='{.items[0].metadata.name}')

# Edit the ConfigMap
kubectl edit configmap sentinel-config -n bastion

# Signal the pod to reload
kubectl exec -n bastion $POD -- kill -HUP 1
```

Or via the REST endpoint (no SSH needed):

```bash
kubectl port-forward svc/bastion-sentinel 8080:8080 -n bastion &
curl -X POST http://localhost:8080/v1/config/reload
```

### Canary rollout

```bash
# Deploy canary revision
kubectl set image deployment/bastion-sentinel sentinel=bastion/sentinel:1.1.0 -n bastion

# Watch rollout
kubectl rollout status deployment/bastion-sentinel -n bastion

# Roll back if needed
kubectl rollout undo deployment/bastion-sentinel -n bastion
```

---

## Resource sizing

| Profile | Replicas | CPU request | CPU limit | Memory limit |
|---------|----------|-------------|-----------|-------------|
| dev | 1 | 250m | 1000m | 256Mi |
| staging | 3 | 500m | 2000m | 512Mi |
| prod | 10+ (HPA) | 500m | 2000m | 512Mi |

The engine is CPU-bound (regex scanning). Under the default configuration with 25 regex + 25 keyword rules, a single core sustains ≈ 80,000 req/s (warm path, no ML).

---

## Volumes

| Mount path | Content | Required |
|-----------|---------|----------|
| `/etc/sentinel/config.yaml` | YAML configuration file | No (built-in defaults) |
| `/models/injection-detector.onnx` | Pre-trained ONNX model | No (ML stub active when absent) |

---

## Security hardening

- Run as a **non-root user** (add `securityContext.runAsNonRoot: true` to the pod spec).
- Set `readOnlyRootFilesystem: true` — the binary only writes to stdout.
- Use **NetworkPolicies** to restrict ingress to authorised callers only.
- Enable **mTLS** between services using a service mesh (Istio, Linkerd) — Sentinel itself does not terminate TLS.
- Store `slack_webhook_url` and `pagerduty_routing_key` in a Kubernetes **Secret**, not in the ConfigMap.
