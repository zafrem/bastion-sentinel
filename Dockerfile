FROM golang:1.26-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o sentinel ./cmd/sentinel

# ─── runtime image ────────────────────────────────────────────────────────────
FROM alpine:3.22

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S -g 10001 app && adduser -S -u 10001 -G app app

WORKDIR /app

COPY --from=builder /app/sentinel /usr/local/bin/sentinel

# Optional: mount ONNX models at runtime via volume
RUN mkdir -p /models /etc/sentinel

USER app

EXPOSE 8080 9090

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s \
  CMD wget --quiet --spider http://localhost:8080/health/live || exit 1

ENTRYPOINT ["sentinel"]
CMD ["server"]
