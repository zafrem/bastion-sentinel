// Package output provides validators for LLM response (Sentinel-OUT).
package output

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/zafrem/bastion-sentinel/config"
	"github.com/zafrem/bastion-sentinel/types"
)

type piiRule struct {
	id       string
	name     string
	re       *regexp.Regexp
	severity string
}

// PIIDetector finds and sanitizes PII re-emergence in LLM responses.
type PIIDetector struct {
	rules           []piiRule
	blockOnCritical bool
}

func NewPIIDetector(cfg config.PIIReemergenceConfig) (*PIIDetector, error) {
	var rules []piiRule
	for _, r := range cfg.Patterns {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid PII pattern %s (%s): %w", r.ID, r.Pattern, err)
		}
		rules = append(rules, piiRule{id: r.ID, name: r.Name, re: re, severity: r.Severity})
	}
	return &PIIDetector{rules: rules, blockOnCritical: cfg.BlockOnCritical}, nil
}

// Check scans response for PII patterns and returns all incidents found.
func (d *PIIDetector) Check(response string) types.PIICheckResult {
	var incidents []types.PIIIncident

	for _, rule := range d.rules {
		matches := rule.re.FindAllStringIndex(response, -1)
		for _, loc := range matches {
			action := "masked"
			if rule.severity == "critical" {
				action = "redacted"
			}
			incidents = append(incidents, types.PIIIncident{
				PIIType:       rule.name,
				OriginalValue: response[loc[0]:loc[1]],
				Start:         loc[0],
				End:           loc[1],
				ActionTaken:   action,
			})
		}
	}

	status := "PASSED"
	if len(incidents) > 0 {
		status = "VIOLATIONS_DETECTED"
	}
	return types.PIICheckResult{
		Status:            status,
		Incidents:         incidents,
		RedactionsApplied: len(incidents),
	}
}

// Sanitize applies replacements for every incident and returns the cleaned text
// along with a log of modifications. Replacements are applied right-to-left so
// byte offsets remain valid throughout.
func (d *PIIDetector) Sanitize(response string, incidents []types.PIIIncident) (string, []types.Modification) {
	if len(incidents) == 0 {
		return response, nil
	}

	sorted := make([]types.PIIIncident, len(incidents))
	copy(sorted, incidents)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Start > sorted[j].Start
	})

	b := []byte(response)
	var mods []types.Modification

	for _, inc := range sorted {
		replacement := "[REDACTED]"
		if inc.ActionTaken == "masked" {
			replacement = "[" + strings.ToUpper(inc.PIIType) + "]"
		}
		mods = append(mods, types.Modification{
			Type:        inc.ActionTaken,
			Position:    fmt.Sprintf("%d-%d", inc.Start, inc.End),
			Original:    inc.OriginalValue,
			Replacement: replacement,
		})
		rep := []byte(replacement)
		b = append(b[:inc.Start], append(rep, b[inc.End:]...)...)
	}

	return string(b), mods
}

// HasCritical returns true if any incident is severity=critical (redacted action).
func HasCritical(incidents []types.PIIIncident) bool {
	for _, inc := range incidents {
		if inc.ActionTaken == "redacted" {
			return true
		}
	}
	return false
}
