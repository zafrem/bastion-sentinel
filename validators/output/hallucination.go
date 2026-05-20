package output

import (
	"regexp"
	"strings"

	"github.com/zafrem/bastion-sentinel/config"
	"github.com/zafrem/bastion-sentinel/types"
)

var (
	// Numerical values: integers, decimals, thousands-separated, with optional suffixes.
	numericalRE = regexp.MustCompile(`\b\d{1,3}(?:,\d{3})*(?:\.\d+)?(?:\s*(?:만|억|천|M|K|B))?\b`)
	// Dates: YYYY-MM-DD or DD/MM/YYYY etc.
	dateRE = regexp.MustCompile(`\b\d{4}[-./]\d{1,2}[-./]\d{1,2}\b|\b\d{1,2}[-./]\d{1,2}[-./]\d{4}\b`)
	// Percentages.
	percentRE = regexp.MustCompile(`\b\d+(?:\.\d+)?%\b`)
)

type claim struct {
	kind  string // "numerical", "date", "percentage"
	value string
}

// HallucinationDetector verifies that factual claims in an LLM response are
// grounded in the retrieved source documents using lexical overlap heuristics.
type HallucinationDetector struct {
	cfg config.HallucinationConfig
}

func NewHallucinationDetector(cfg config.HallucinationConfig) *HallucinationDetector {
	return &HallucinationDetector{cfg: cfg}
}

// Check returns a grounding score and list of unverified claims.
func (d *HallucinationDetector) Check(response string, sources []string) types.HallucinationCheckResult {
	claims := extractClaims(response)
	if len(claims) == 0 || len(sources) == 0 {
		return types.HallucinationCheckResult{
			Status:         "PASSED",
			GroundingScore: 1.0,
			Method:         "heuristic",
		}
	}

	grounded := 0
	var ungrounded []string
	for _, c := range claims {
		if isGrounded(c, sources) {
			grounded++
		} else {
			ungrounded = append(ungrounded, c.value)
		}
	}

	score := float64(grounded) / float64(len(claims))

	status := "PASSED"
	switch {
	case score < d.cfg.LowScoreThreshold:
		status = "FAILED"
	case score < d.cfg.GroundingThreshold:
		status = "SUSPICIOUS"
	}

	return types.HallucinationCheckResult{
		Status:           status,
		GroundingScore:   score,
		UngroundedClaims: ungrounded,
		Method:           "heuristic",
	}
}

func extractClaims(text string) []claim {
	var claims []claim
	for _, m := range numericalRE.FindAllString(text, -1) {
		claims = append(claims, claim{"numerical", m})
	}
	for _, m := range dateRE.FindAllString(text, -1) {
		claims = append(claims, claim{"date", m})
	}
	for _, m := range percentRE.FindAllString(text, -1) {
		claims = append(claims, claim{"percentage", m})
	}
	return claims
}

func isGrounded(c claim, sources []string) bool {
	for _, src := range sources {
		if strings.Contains(src, c.value) {
			return true
		}
	}
	return false
}
