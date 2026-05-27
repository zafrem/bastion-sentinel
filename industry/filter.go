// Package industry provides the industry-specific filter extension for Sentinel.
// Filters operate in two modes:
//
//   - blocking: run synchronously in the validation chain; result can block/redact/flag.
//   - async: registered as hook handlers; fire-and-forget, zero critical-path latency.
//
// See docs/20_extension_sentinel_industry_v1.md.
package industry

import "context"

// FilterAction determines the outcome when a blocking filter matches.
type FilterAction int

const (
	// FilterBlock rejects the request immediately (HTTP 422).
	FilterBlock FilterAction = iota
	// FilterRedact replaces matched content in-place and continues the pipeline.
	FilterRedact
	// FilterFlag allows the request but appends a warning to the response flags.
	FilterFlag
)

// FilterRequest is the input to a blocking IndustryFilter.
type FilterRequest struct {
	Text         string
	TenantID     string
	UserID       string
	DataCategory string
	Metadata     map[string]string
}

// FilterDecision is the result of a blocking IndustryFilter.Filter call.
type FilterDecision struct {
	Allowed bool
	Action  FilterAction
	Reason  string
	// Modified is the redacted replacement text; non-empty only when Action == FilterRedact.
	Modified string
}

// IndustryFilter runs synchronously in the Sentinel validation chain.
// Priority >= 100 guarantees execution after Core filters (Core uses 0–99).
type IndustryFilter interface {
	ID() string
	Priority() int
	Filter(ctx context.Context, req FilterRequest) (FilterDecision, error)
}
