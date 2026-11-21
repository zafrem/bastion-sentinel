package types

import "time"

type Status string

const (
	StatusPassed  Status = "PASSED"
	StatusBlocked Status = "BLOCKED"
	StatusError   Status = "ERROR"
)

type ValidateRequest struct {
	RequestID string
	Query     string
	Metadata  map[string]string
	Options   ValidateOptions
}

type ValidateOptions struct {
	StrictMode     bool
	TimeoutMs      int
	IncludeDetails bool
	OutputFormat   string
}

type ValidateResponse struct {
	RequestID        string
	Status           Status
	Timestamp        time.Time
	PromptCheck      PromptCheckResult
	MetadataCheck    MetadataCheckResult
	ExtractedData    ExtractedData
	ProcessingTimeMs float64
	ErrorMessage     string
	// Notice is the end-user-safe explanation when the request is blocked.
	Notice *UserNotice `json:",omitempty"`
	// ExceptionsApplied lists IDs of exceptions that exempted a rule on this request.
	ExceptionsApplied []string `json:",omitempty"`
	// Profile is the policy profile this request was held to; empty for the base configuration.
	Profile string `json:",omitempty"`
}

type PromptCheckResult struct {
	Status          Status
	RiskScore       float64
	Method          string
	MatchedPatterns []string
	// ExemptedPatterns matched but were ignored because of an active exception.
	ExemptedPatterns []string `json:",omitempty"`
	ExceptionIDs     []string `json:",omitempty"`
}

type MetadataCheckResult struct {
	Status        Status
	MissingFields []string
	FormatErrors  []string
}

type ExtractedData struct {
	TenantID     string
	UserID       string
	CleanedQuery string
}
