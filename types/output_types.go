package types

// OutputStatus is the result of output validation.
type OutputStatus string

const (
	OutputStatusPassed    OutputStatus = "PASSED"
	OutputStatusSanitized OutputStatus = "SANITIZED"
	OutputStatusBlocked   OutputStatus = "BLOCKED"
	OutputStatusWarning   OutputStatus = "WARNING"
)

// UserContext carries the requesting user's identity and access level.
type UserContext struct {
	UserID            string
	TenantID          string
	Department        string
	Roles             []string
	AllowedCategories []string
	// AccessLevel controls how much detail the user may see.
	// Hierarchy (most permissive → most restricted):
	//   full > read > anonymized > k_anonymized > slice > aggregated
	AccessLevel string
}

// DocumentSource is a single retrieval result used for grounding checks.
type DocumentSource struct {
	DocID          string
	Snippet        string
	RelevanceScore float64
	Metadata       map[string]string
}

// RetrievalContext holds the documents retrieved by Navigator for this request.
type RetrievalContext struct {
	Query           string
	AnonymizedQuery string
	SourceDocuments []string // plain-text snippets for grounding
	Sources         []DocumentSource
}

// OutputValidationOptions selects which checks to run.
// Zero value (all false) enables all configured checks.
type OutputValidationOptions struct {
	CheckPIIReemergence bool
	CheckHallucination  bool
	CheckContent        bool
	CheckPermission     bool
	EnforceCitation     bool
	StrictMode          bool
	TimeoutMs           int
}

// OutputValidateRequest is the payload for Sentinel-OUT validation.
type OutputValidateRequest struct {
	RequestID   string
	TraceID     string
	LLMResponse string
	User        UserContext
	Retrieval   RetrievalContext
	Options     OutputValidationOptions
}

// PIIIncident describes a single PII finding in the LLM response.
type PIIIncident struct {
	PIIType       string // e.g. "email", "korean_rrn", "korean_name"
	OriginalValue string
	Start         int // byte offset in original response
	End           int // byte offset in original response
	ActionTaken   string // "redacted", "masked", "blocked"
}

// PIICheckResult aggregates PII detection outcomes.
type PIICheckResult struct {
	Status            string // "PASSED", "VIOLATIONS_DETECTED"
	Incidents         []PIIIncident
	RedactionsApplied int
}

// HallucinationCheckResult reports how well the response is grounded.
type HallucinationCheckResult struct {
	Status           string // "PASSED", "SUSPICIOUS", "FAILED"
	GroundingScore   float64
	UngroundedClaims []string
	Method           string
}

// ContentCheckResult reports content policy violations.
type ContentCheckResult struct {
	Status     string // "PASSED", "WARNING", "BLOCKED"
	Violations []string
	Severity   string
}

// PermissionCheckResult reports access-level boundary outcomes.
type PermissionCheckResult struct {
	Status              string
	UserAccessLevel     string
	ResponseAccessLevel string
	BoundaryViolated    bool
}

// FormatCheckResult reports response format compliance.
type FormatCheckResult struct {
	Status      string // "PASSED", "FAILED"
	LengthOK    bool
	StructureOK bool
	Issues      []string
}

// OutputValidationResults is the union of all check results.
type OutputValidationResults struct {
	PIICheck           PIICheckResult
	HallucinationCheck HallucinationCheckResult
	ContentCheck       ContentCheckResult
	PermissionCheck    PermissionCheckResult
	FormatCheck        FormatCheckResult
}

// Modification records a single edit made to the LLM response.
type Modification struct {
	Type        string // "redacted", "masked", "filtered", "disclaimer_added"
	Position    string // "start-end" byte offsets
	Original    string
	Replacement string
}

// OutputValidateResponse is returned by Sentinel-OUT validation.
type OutputValidateResponse struct {
	RequestID         string
	Status            OutputStatus
	ValidatedResponse string // may differ from LLM response if sanitized
	Checks            OutputValidationResults
	Modifications     []Modification
	ProcessingTimeMs  float64
	ErrorMessage      string
}
