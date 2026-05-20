package output

import (
	"fmt"
	"regexp"

	"github.com/zafrem/bastion-sentinel/config"
	"github.com/zafrem/bastion-sentinel/types"
)

type contentRule struct {
	id       string
	name     string
	re       *regexp.Regexp
	severity string
}

// ContentFilter blocks LLM responses that contain secrets, credentials, or
// other policy-violating patterns.
type ContentFilter struct {
	rules []contentRule
}

func NewContentFilter(cfg config.ContentFilterConfig) (*ContentFilter, error) {
	var rules []contentRule
	for _, r := range cfg.Patterns {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid content filter pattern %s (%s): %w", r.ID, r.Pattern, err)
		}
		rules = append(rules, contentRule{id: r.ID, name: r.Name, re: re, severity: r.Severity})
	}
	return &ContentFilter{rules: rules}, nil
}

// Check scans the response text against all content filter rules.
func (f *ContentFilter) Check(response string) types.ContentCheckResult {
	var violations []string
	maxSeverity := ""

	for _, rule := range f.rules {
		if rule.re.MatchString(response) {
			violations = append(violations, rule.id+": "+rule.name)
			maxSeverity = higherSeverity(maxSeverity, rule.severity)
		}
	}

	if len(violations) == 0 {
		return types.ContentCheckResult{Status: "PASSED"}
	}

	status := "WARNING"
	if maxSeverity == "critical" {
		status = "BLOCKED"
	}
	return types.ContentCheckResult{
		Status:     status,
		Violations: violations,
		Severity:   maxSeverity,
	}
}

func higherSeverity(a, b string) string {
	rank := map[string]int{"": 0, "medium": 1, "high": 2, "critical": 3}
	if rank[b] > rank[a] {
		return b
	}
	return a
}
