// Package server — event publisher for Sentinel.
// Emits Foundation-standard events (doc 02) to bastion.events.sentinel.{event_type}.
package server

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

const (
	sentinelModule  = "sentinel"
	sentinelVersion = "2.0.0"
	schemaVersion   = "1.0"
	subjectPrefix   = "bastion.events.sentinel"
)

// SentinelEvent is a Foundation-standard event emitted by Sentinel (doc 02).
type SentinelEvent struct {
	EventID       string                 `json:"event_id"`
	EventType     string                 `json:"event_type"`
	SchemaVersion string                 `json:"schema_version"`
	TraceID       string                 `json:"trace_id"`
	SpanID        string                 `json:"span_id"`
	ParentSpanID  string                 `json:"parent_span_id,omitempty"`
	Module        string                 `json:"module"`
	ModuleVersion string                 `json:"module_version"`
	Timestamp     int64                  `json:"timestamp"`
	DurationMs    int64                  `json:"duration_ms,omitempty"`
	TenantID      string                 `json:"tenant_id"`
	UserID        string                 `json:"user_id,omitempty"`
	RequestID     string                 `json:"request_id,omitempty"`
	Severity      string                 `json:"severity"`
	Category      string                 `json:"category"`
	Data          map[string]interface{} `json:"data,omitempty"`
	Status        string                 `json:"status,omitempty"`
	ActionTaken   string                 `json:"action_taken,omitempty"`
}

// TraceContext carries distributed trace metadata for event emission.
type TraceContext struct {
	TraceID      string
	SpanID       string
	ParentSpanID string
	TenantID     string
	UserID       string
	RequestID    string
}

// EventPublisher publishes Sentinel events to NATS (or drops silently if unavailable).
type EventPublisher struct {
	nc *nats.Conn // nil = disabled
}

// NewEventPublisher connects to NATS. Returns a no-op publisher on error so
// Sentinel's core validation is never blocked by event bus issues.
func NewEventPublisher(natsURL string) *EventPublisher {
	if natsURL == "" {
		return &EventPublisher{}
	}
	nc, err := nats.Connect(natsURL,
		nats.MaxReconnects(5),
		nats.ReconnectWait(2e9),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			log.Printf("[sentinel-events] nats error: %v", err)
		}),
	)
	if err != nil {
		log.Printf("[sentinel-events] nats unavailable (%v), events disabled", err)
		return &EventPublisher{}
	}
	return &EventPublisher{nc: nc}
}

// Publish fires the event asynchronously; never blocks the caller.
func (p *EventPublisher) Publish(ev SentinelEvent) {
	if p == nil || p.nc == nil {
		return
	}
	go func() {
		data, err := json.Marshal(ev)
		if err != nil {
			return
		}
		subject := fmt.Sprintf("%s.%s", subjectPrefix, ev.EventType)
		_ = p.nc.Publish(subject, data)
	}()
}

func (p *EventPublisher) Close() {
	if p != nil && p.nc != nil {
		p.nc.Drain() //nolint:errcheck
	}
}

// ─── Event constructors ───────────────────────────────────────────────────────

func newEvent(tc TraceContext, eventType, severity, category string, data map[string]interface{}) SentinelEvent {
	return SentinelEvent{
		EventID:       uuid.New().String(),
		EventType:     eventType,
		SchemaVersion: schemaVersion,
		TraceID:       tc.TraceID,
		SpanID:        tc.SpanID,
		ParentSpanID:  tc.ParentSpanID,
		Module:        sentinelModule,
		ModuleVersion: sentinelVersion,
		Timestamp:     time.Now().UnixNano(),
		TenantID:      tc.TenantID,
		UserID:        tc.UserID,
		RequestID:     tc.RequestID,
		Severity:      severity,
		Category:      category,
		Data:          data,
	}
}

func EventInputValidated(tc TraceContext, injectionScore float64, pipelineDecision string) SentinelEvent {
	ev := newEvent(tc, "input_validated", "info", "operational", map[string]interface{}{
		"injection_score":   injectionScore,
		"pipeline_decision": pipelineDecision,
	})
	ev.Status = "passed"
	return ev
}

func EventPipelineRoutingDecided(tc TraceContext, pipelineType, reason string) SentinelEvent {
	ev := newEvent(tc, "pipeline_routing_decided", "info", "operational", map[string]interface{}{
		"pipeline_type": pipelineType,
		"reason":        reason,
	})
	ev.Status = "routed"
	ev.ActionTaken = "route"
	return ev
}

func EventInjectionDetected(tc TraceContext, score float64, patterns []string) SentinelEvent {
	ev := newEvent(tc, "injection_detected", "warning", "security", map[string]interface{}{
		"injection_score": score,
		"patterns":        patterns,
	})
	ev.Status = "detected"
	return ev
}

func EventInjectionBlocked(tc TraceContext, score float64, pattern string) SentinelEvent {
	ev := newEvent(tc, "injection_blocked", "critical", "security", map[string]interface{}{
		"injection_score": score,
		"pattern_matched": pattern,
	})
	ev.Status = "blocked"
	ev.ActionTaken = "request_blocked"
	return ev
}

func EventOutputValidated(tc TraceContext, status, actionTaken string) SentinelEvent {
	sev := "info"
	if status == "SANITIZED" {
		sev = "warning"
	} else if status == "BLOCKED" {
		sev = "critical"
	}
	ev := newEvent(tc, "output_validated", sev, "operational", nil)
	ev.Status = status
	ev.ActionTaken = actionTaken
	return ev
}

func EventPIIPrevented(tc TraceContext, piiTypes []string, redactions int) SentinelEvent {
	ev := newEvent(tc, "pii_re_emergence_prevented", "warning", "security", map[string]interface{}{
		"pii_types":  piiTypes,
		"redactions": redactions,
	})
	ev.Status = "sanitized"
	ev.ActionTaken = "pii_redacted"
	return ev
}

func EventContentFiltered(tc TraceContext, category string) SentinelEvent {
	ev := newEvent(tc, "content_filtered", "warning", "security", map[string]interface{}{
		"category": category,
	})
	ev.Status = "filtered"
	ev.ActionTaken = "content_removed"
	return ev
}

// EventHoneyTokenReferenced is emitted when an input query contains a known
// honey-token reference. Severity is critical: the querier has prior knowledge,
// implying a prior breach.
func EventHoneyTokenReferenced(tc TraceContext, honeyTokenID, matchedValue string) SentinelEvent {
	ev := newEvent(tc, "honey_token_referenced", "critical", "security", map[string]interface{}{
		"honey_token_id":  honeyTokenID,
		"matched_value":   matchedValue,
		"detection_layer": "input",
		"detecting_module": sentinelModule,
	})
	ev.Status = "detected"
	ev.ActionTaken = "request_blocked"
	return ev
}

// EventHoneyTokenLeaked is emitted when an LLM response contains honey-token data.
// Severity is critical: active data exfiltration.
func EventHoneyTokenLeaked(tc TraceContext, honeyTokenID, matchedValue string) SentinelEvent {
	ev := newEvent(tc, "honey_token_leaked", "critical", "security", map[string]interface{}{
		"honey_token_id":  honeyTokenID,
		"matched_value":   matchedValue,
		"detection_layer": "output",
		"detecting_module": sentinelModule,
	})
	ev.Status = "detected"
	ev.ActionTaken = "response_blocked"
	return ev
}

// extractTraceContext reads W3C traceparent and Bastion trace headers from the
// HTTP request, falling back to generating new IDs when absent.
func extractTraceContext(traceID, spanID, parentSpanID, tenantID, userID, requestID string) TraceContext {
	if traceID == "" {
		traceID = uuid.New().String()
	}
	if spanID == "" {
		spanID = uuid.New().String()[:16]
	}
	return TraceContext{
		TraceID:      traceID,
		SpanID:       spanID,
		ParentSpanID: parentSpanID,
		TenantID:     tenantID,
		UserID:       userID,
		RequestID:    requestID,
	}
}
