package output

import (
	"regexp"
	"strings"

	"github.com/zafrem/bastion-sentinel/config"
	"github.com/zafrem/bastion-sentinel/types"
)

// DefaultClaimPatterns holds the built-in claim-extraction regexes. They are
// used when the corresponding config field is empty, so behaviour is unchanged
// unless an operator overrides a pattern in output_validation.hallucination.claim_patterns.
var DefaultClaimPatterns = config.ClaimPatternsConfig{
	// Numerical values: integers, decimals, thousands-separated, with optional suffixes.
	Numerical: `\b\d{1,3}(?:,\d{3})*(?:\.\d+)?(?:\s*(?:만|억|천|M|K|B))?\b`,
	// Dates: YYYY-MM-DD or DD/MM/YYYY etc.
	Date: `\b\d{4}[-./]\d{1,2}[-./]\d{1,2}\b|\b\d{1,2}[-./]\d{1,2}[-./]\d{4}\b`,
	// Percentages.
	Percentage: `\b\d+(?:\.\d+)?%\b`,
}

type claim struct {
	kind  string // "numerical", "date", "percentage"
	value string
}

// HallucinationDetector verifies that factual claims in an LLM response are
// grounded in the retrieved source documents using lexical overlap heuristics.
type HallucinationDetector struct {
	cfg        config.HallucinationConfig
	numericalRE *regexp.Regexp
	dateRE      *regexp.Regexp
	percentRE   *regexp.Regexp
}

func NewHallucinationDetector(cfg config.HallucinationConfig) *HallucinationDetector {
	p := cfg.ClaimPatterns
	return &HallucinationDetector{
		cfg:         cfg,
		numericalRE: compileOrDefault(p.Numerical, DefaultClaimPatterns.Numerical),
		dateRE:      compileOrDefault(p.Date, DefaultClaimPatterns.Date),
		percentRE:   compileOrDefault(p.Percentage, DefaultClaimPatterns.Percentage),
	}
}

// compileOrDefault compiles pattern, falling back to def if pattern is empty or
// fails to compile (a bad override must never crash the validator).
func compileOrDefault(pattern, def string) *regexp.Regexp {
	if pattern != "" {
		if re, err := regexp.Compile(pattern); err == nil {
			return re
		}
	}
	return regexp.MustCompile(def)
}

// Check returns a grounding score and list of unverified claims.
func (d *HallucinationDetector) Check(response string, sources []string) types.HallucinationCheckResult {
	claims := d.extractClaims(response)
	method := "heuristic"
	if len(sources) == 0 {
		return types.HallucinationCheckResult{Status: "PASSED", GroundingScore: 1.0, Method: method}
	}

	score := 1.0
	haveSignal := false
	var ungrounded []string
	if len(claims) > 0 {
		grounded := 0
		for _, c := range claims {
			if isGrounded(c, sources) {
				grounded++
			} else {
				ungrounded = append(ungrounded, c.value)
			}
		}
		score = float64(grounded) / float64(len(claims))
		haveSignal = true
	}
	// Words as well as numbers: the answer is only as grounded as its weaker part.
	if d.cfg.ContentSupport {
		minWords := d.cfg.MinContentWords
		if minWords <= 0 {
			minWords = 3
		}
		if support, missing, ok := contentSupport(response, sources, minWords); ok {
			haveSignal = true
			method = "heuristic+content"
			if support < score {
				score = support
			}
			for _, w := range missing {
				ungrounded = append(ungrounded, "unsupported:"+w)
			}
		}
	}
	if !haveSignal {
		return types.HallucinationCheckResult{Status: "PASSED", GroundingScore: 1.0, Method: method}
	}

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
		Method:           method,
	}
}

func (d *HallucinationDetector) extractClaims(text string) []claim {
	var claims []claim
	for _, m := range d.numericalRE.FindAllString(text, -1) {
		claims = append(claims, claim{"numerical", m})
	}
	for _, m := range d.dateRE.FindAllString(text, -1) {
		claims = append(claims, claim{"date", m})
	}
	for _, m := range d.percentRE.FindAllString(text, -1) {
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
