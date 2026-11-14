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
	// ── Add internal patterns from config ──────────────────────────────────
	for _, r := range cfg.Patterns {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid PII pattern %s (%s): %w", r.ID, r.Pattern, err)
		}
		rules = append(rules, piiRule{id: r.ID, name: r.Name, re: re, severity: r.Severity})
	}

	// ── Add external patterns if directory is provided ─────────────────────
	if cfg.ExternalPatternsDir != "" {
		extPatterns, err := LoadExternalPatterns(cfg.ExternalPatternsDir)
		if err != nil {
			return nil, fmt.Errorf("failed to load external PII patterns: %w", err)
		}
		for _, r := range extPatterns {
			re, err := regexp.Compile(r.Pattern)
			if err != nil {
				return nil, fmt.Errorf("invalid external PII pattern %s (%s): %w", r.ID, r.Pattern, err)
			}
			rules = append(rules, piiRule{id: r.ID, name: r.Name, re: re, severity: r.Severity})
		}
	}

	return &PIIDetector{rules: rules, blockOnCritical: cfg.BlockOnCritical}, nil
}

// Check scans response for PII patterns and returns all incidents found.
func (d *PIIDetector) Check(response string) types.PIICheckResult {
	return d.CheckWithMappings(response, nil)
}

// CheckWithMappings scans response for configured PII regexes and cross-references
// any Vault token -> real_value mappings supplied in knownMappings.
func (d *PIIDetector) CheckWithMappings(response string, knownMappings map[string]string) types.PIICheckResult {
	var raw []types.PIIIncident

	for _, rule := range d.rules {
		matches := rule.re.FindAllStringIndex(response, -1)
		for _, loc := range matches {
			action := "masked"
			if rule.severity == "critical" {
				action = "redacted"
			}
			raw = append(raw, types.PIIIncident{
				PIIType:       rule.name,
				OriginalValue: response[loc[0]:loc[1]],
				Start:         loc[0],
				End:           loc[1],
				ActionTaken:   action,
			})
		}
	}

	if len(knownMappings) > 0 {
		tokens := make([]string, 0, len(knownMappings))
		for tok := range knownMappings {
			tokens = append(tokens, tok)
		}
		sort.Strings(tokens)
		for _, tok := range tokens {
			realVal := knownMappings[tok]
			if realVal == "" {
				continue
			}
			searchFrom := 0
			for searchFrom < len(response) {
				idx := strings.Index(response[searchFrom:], realVal)
				if idx < 0 {
					break
				}
				start := searchFrom + idx
				end := start + len(realVal)
				raw = append(raw, types.PIIIncident{
					PIIType:       "vault_mapped_pii",
					OriginalValue: realVal,
					Start:         start,
					End:           end,
					ActionTaken:   "masked",
					Replacement:   tok,
				})
				searchFrom = end
			}
		}
	}

	incidents := deduplicateIncidents(raw)

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

// deduplicateIncidents removes overlapping spans, preferring longer matches
// and "redacted" (critical) actions over "masked" when spans share a start.
func deduplicateIncidents(raw []types.PIIIncident) []types.PIIIncident {
	if len(raw) <= 1 {
		return raw
	}
	sorted := make([]types.PIIIncident, len(raw))
	copy(sorted, raw)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Start != sorted[j].Start {
			return sorted[i].Start < sorted[j].Start
		}
		lenI := sorted[i].End - sorted[i].Start
		lenJ := sorted[j].End - sorted[j].Start
		if lenI != lenJ {
			return lenI > lenJ
		}
		if sorted[i].ActionTaken != sorted[j].ActionTaken {
			return sorted[i].ActionTaken == "redacted"
		}
		return sorted[i].Replacement != "" && sorted[j].Replacement == ""
	})

	out := make([]types.PIIIncident, 0, len(sorted))
	lastEnd := -1
	for _, inc := range sorted {
		if inc.Start < lastEnd {
			continue
		}
		out = append(out, inc)
		lastEnd = inc.End
	}
	return out
}

// Sanitize applies replacements for every incident and returns the cleaned text
// along with a log of modifications. Replacements are applied right-to-left so
// byte offsets remain valid throughout.
func (d *PIIDetector) Sanitize(response string, incidents []types.PIIIncident) (string, []types.Modification) {
	if len(incidents) == 0 {
		return response, nil
	}

	dedup := deduplicateIncidents(incidents)
	sorted := make([]types.PIIIncident, len(dedup))
	copy(sorted, dedup)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Start > sorted[j].Start
	})

	b := []byte(response)
	var mods []types.Modification

	for _, inc := range sorted {
		if inc.Start < 0 || inc.End > len(b) || inc.Start > inc.End {
			continue
		}
		replacement := inc.Replacement
		if replacement == "" {
			replacement = "[REDACTED]"
			if inc.ActionTaken == "masked" {
				replacement = "[" + strings.ToUpper(inc.PIIType) + "]"
			}
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
