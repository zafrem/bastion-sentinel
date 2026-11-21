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
				RuleIDs:       []string{rule.id},
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
					RuleIDs:       []string{"vault_mapped_pii"},
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

	incidents := deduplicateIncidents(response, raw)

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

// deduplicateIncidents resolves overlapping spans without leaving any covered byte unmasked.
//
// Vault-mapped spans (those carrying a token Replacement) are authoritative: they keep their token, and
// every other span is trimmed to the bytes they do not cover, so no part of a longer regex match is
// left exposed. The remaining spans are grouped by overlap; if one span covers its whole group it wins
// (the longer match, and "redacted" over "masked" on ties), otherwise the group is merged into the
// union of its spans, redacted if any member was.
func deduplicateIncidents(response string, raw []types.PIIIncident) []types.PIIIncident {
	if len(raw) <= 1 {
		return raw
	}
	var mapped, other []types.PIIIncident
	for _, inc := range raw {
		if inc.Replacement != "" {
			mapped = append(mapped, inc)
		} else {
			other = append(other, inc)
		}
	}
	if len(mapped) == 0 {
		return resolveOverlaps(response, other)
	}
	fixed := resolveOverlaps(response, mapped)
	var rest []types.PIIIncident
	for _, inc := range other {
		rest = append(rest, trimAround(response, inc, fixed)...)
	}
	out := append(fixed, resolveOverlaps(response, rest)...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out
}

// trimAround returns the parts of inc not covered by any span in fixed (sorted, non-overlapping).
func trimAround(response string, inc types.PIIIncident, fixed []types.PIIIncident) []types.PIIIncident {
	pieces := []types.PIIIncident{inc}
	for _, f := range fixed {
		var next []types.PIIIncident
		for _, p := range pieces {
			if f.End <= p.Start || f.Start >= p.End {
				next = append(next, p)
				continue
			}
			if p.Start < f.Start {
				next = append(next, subSpan(response, p, p.Start, f.Start))
			}
			if f.End < p.End {
				next = append(next, subSpan(response, p, f.End, p.End))
			}
		}
		pieces = next
	}
	return pieces
}

func subSpan(response string, p types.PIIIncident, start, end int) types.PIIIncident {
	p.Start, p.End = start, end
	if start >= 0 && end <= len(response) {
		p.OriginalValue = response[start:end]
	}
	return p
}

// resolveOverlaps groups overlapping spans and keeps the covering span or the union of each group.
func resolveOverlaps(response string, raw []types.PIIIncident) []types.PIIIncident {
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
	for i := 0; i < len(sorted); {
		group := []types.PIIIncident{sorted[i]}
		end := sorted[i].End
		j := i + 1
		for j < len(sorted) && sorted[j].Start < end {
			group = append(group, sorted[j])
			if sorted[j].End > end {
				end = sorted[j].End
			}
			j++
		}
		i = j
		out = append(out, mergeGroup(response, group, end))
	}
	return out
}

// mergeGroup collapses a group of overlapping incidents (sorted by start, then longest first).
func mergeGroup(response string, group []types.PIIIncident, end int) types.PIIIncident {
	primary := group[0]
	if len(group) == 1 || primary.End == end {
		return primary // one span covers the whole group
	}
	merged := types.PIIIncident{PIIType: primary.PIIType, Start: primary.Start, End: end, ActionTaken: "masked"}
	for _, g := range group {
		for _, id := range g.RuleIDs {
			dup := false
			for _, have := range merged.RuleIDs {
				dup = dup || have == id
			}
			if !dup {
				merged.RuleIDs = append(merged.RuleIDs, id)
			}
		}
		if g.ActionTaken == "redacted" {
			merged.ActionTaken = "redacted"
		}
		if g.End-g.Start > merged.End-merged.Start {
			merged.PIIType = g.PIIType
		}
	}
	if merged.Start >= 0 && merged.End <= len(response) {
		merged.OriginalValue = response[merged.Start:merged.End]
	}
	return merged
}

// Sanitize applies replacements for every incident and returns the cleaned text
// along with a log of modifications. Replacements are applied right-to-left so
// byte offsets remain valid throughout.
func (d *PIIDetector) Sanitize(response string, incidents []types.PIIIncident) (string, []types.Modification) {
	if len(incidents) == 0 {
		return response, nil
	}

	dedup := deduplicateIncidents(response, incidents)
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
