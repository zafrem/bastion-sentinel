package output

import (
	"regexp"

	"github.com/zafrem/bastion-sentinel/types"
)

// accessRank maps access level names to integers — lower rank = broader access.
// full(0) > read(1) > anonymized(2) > k_anonymized(3) > slice(4) > aggregated(5)
var accessRank = map[string]int{
	"full":         0,
	"read":         1,
	"anonymized":   2,
	"k_anonymized": 3,
	"slice":        4,
	"aggregated":   5,
}

// specificAmountRE detects concrete monetary figures that should only appear
// in responses for users with full or read access.
var specificAmountRE = regexp.MustCompile(
	`\b\d{1,3}(?:,\d{3})+(?:\.\d+)?\s*(?:원|만원|억원|won|KRW|USD|\$|€|£)\b` + `|` +
		`\$\s*\d{1,3}(?:,\d{3})+(?:\.\d+)?\b` + `|` +
		`\b\d+(?:만|억)\s*원\b`,
)

// PermissionChecker enforces data access-level boundaries in LLM responses.
type PermissionChecker struct{}

func NewPermissionChecker() *PermissionChecker { return &PermissionChecker{} }

// Check compares the information level inferred from the response against the
// user's declared access level and flags boundary violations.
func (c *PermissionChecker) Check(response string, user types.UserContext) types.PermissionCheckResult {
	if user.AccessLevel == "" || user.AccessLevel == "full" {
		return types.PermissionCheckResult{
			Status:              "PASSED",
			UserAccessLevel:     user.AccessLevel,
			ResponseAccessLevel: "full",
		}
	}

	responseLevel := c.analyzeResponseLevel(response)

	userRank := rankOf(user.AccessLevel)
	responseRank := rankOf(responseLevel)

	// Violation: response contains detail that requires more permissive access.
	if responseRank < userRank {
		return types.PermissionCheckResult{
			Status:              "VIOLATION_PREVENTED",
			UserAccessLevel:     user.AccessLevel,
			ResponseAccessLevel: responseLevel,
			BoundaryViolated:    true,
		}
	}
	return types.PermissionCheckResult{
		Status:              "PASSED",
		UserAccessLevel:     user.AccessLevel,
		ResponseAccessLevel: responseLevel,
		BoundaryViolated:    false,
	}
}

// analyzeResponseLevel heuristically determines what access level the response
// content implies. Returns "full" if specific monetary amounts are detected,
// otherwise "k_anonymized" as a conservative estimate.
func (c *PermissionChecker) analyzeResponseLevel(response string) string {
	if specificAmountRE.MatchString(response) {
		return "full"
	}
	return "k_anonymized"
}

func rankOf(level string) int {
	r, ok := accessRank[level]
	if !ok {
		return 0 // unknown level treated as full access
	}
	return r
}
