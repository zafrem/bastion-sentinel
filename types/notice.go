package types

// Notice actions.
const (
	NoticeBlocked = "blocked"
	NoticeMasked  = "masked"
	NoticeWarned  = "warned"
)

// Notice reason codes. They are stable so a front end can localise and style
// them. A code names the category of the decision, never the rule, matched
// text or score, so it does not help an attacker tune around a detector.
const (
	CodeInjectionSuspected = "INJECTION_SUSPECTED"
	CodeMetadataInvalid    = "METADATA_INVALID"
	CodePIIRedacted        = "PII_REDACTED"
	CodePermissionDenied   = "PERMISSION_DENIED"
	CodeContentPolicy      = "CONTENT_POLICY"
	CodeNotGrounded        = "NOT_GROUNDED"
	CodeFormatInvalid      = "FORMAT_INVALID"
	// Used when notice detail is "minimal".
	CodeRequestBlocked   = "REQUEST_BLOCKED"
	CodeResponseModified = "RESPONSE_MODIFIED"
)

// Notice detail levels (config user_notice.detail).
const (
	DetailMinimal  = "minimal"  // generic message and code only
	DetailCategory = "category" // default: reason category, no rule detail
)

// UserNotice tells the end user that something was blocked, masked or flagged,
// and why, in terms that are safe to show. The detailed reasons (rule IDs,
// scores, matched values) stay in the response checks and the Tracker log.
type UserNotice struct {
	Action  string `json:"action"`
	Code    string `json:"code"`
	Message string `json:"message"`
	// ReferenceID lets support find the Tracker record for this decision.
	ReferenceID string `json:"reference_id,omitempty"`
	// Count is how many items were masked, when that applies. Never the values.
	Count int `json:"count,omitempty"`
}

var noticeText = map[string]map[string]string{
	CodeInjectionSuspected: {NoticeBlocked: "Your request could not be processed because it looks like an attempt to override the assistant's instructions. Please rephrase it and try again."},
	CodeMetadataInvalid:    {NoticeBlocked: "Your request could not be processed because required information is missing or invalid."},
	CodePIIRedacted: {
		NoticeMasked:  "Some personal information in this answer was hidden.",
		NoticeBlocked: "This answer was withheld because it contained sensitive personal information.",
	},
	CodePermissionDenied: {NoticeBlocked: "This answer needs a higher access level than your account has."},
	CodeContentPolicy:    {NoticeBlocked: "This answer was withheld because it did not meet the content policy."},
	CodeNotGrounded: {
		NoticeBlocked: "This answer was withheld because it could not be verified against the source documents.",
		NoticeWarned:  "Some statements in this answer could not be verified against the source documents.",
	},
	CodeFormatInvalid: {NoticeBlocked: "This answer was withheld because it was not in a valid format."},
}

// NewNotice builds the user-facing notice for a decision. At the "minimal"
// detail level the specific category is replaced by a generic one.
func NewNotice(detail, action, code, referenceID string, count int) *UserNotice {
	n := &UserNotice{Action: action, Code: code, ReferenceID: referenceID, Count: count}
	if detail == DetailMinimal {
		if action == NoticeBlocked {
			n.Code, n.Message = CodeRequestBlocked, "This request could not be completed."
		} else {
			n.Code, n.Message = CodeResponseModified, "This answer was modified before it was shown."
		}
		n.Count = 0
		return n
	}
	n.Message = noticeText[code][action]
	if n.Message == "" {
		n.Message = "This request could not be completed."
	}
	return n
}
