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
}

type PromptCheckResult struct {
	Status          Status
	RiskScore       float64
	Method          string
	MatchedPatterns []string
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
