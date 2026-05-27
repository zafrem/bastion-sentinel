package industry

import (
	"context"
	"regexp"
	"strings"
)

// ─── HIPAA ────────────────────────────────────────────────────────────────────

// HIPAAFilter detects US Protected Health Information (PHI) patterns.
type HIPAAFilter struct {
	action   FilterAction
	patterns []*regexp.Regexp
}

func NewHIPAAFilter(action FilterAction) *HIPAAFilter {
	raw := []string{
		`\b\d{3}-\d{2}-\d{4}\b`,                                                    // US SSN
		`\bMRN[-:\s]*\d{6,12}\b`,                                                    // medical record number
		`\bEncounter[-:\s]*\d{6,12}\b`,                                              // encounter number
		`\b[A-TV-Z][0-9][0-9A-Z]\.[0-9A-Z]{1,4}\b`,                                 // ICD-10 code
		`(?i)\b(diagnosis|prescription|medication|patient\s+id|medical\s+record)\b`, // PHI keywords
		`(?i)\b(health\s+condition|treatment|clinical\s+note|discharge\s+summary)\b`,
	}
	compiled := compilePatterns(raw)
	return &HIPAAFilter{action: action, patterns: compiled}
}

func (f *HIPAAFilter) ID() string    { return "hipaa" }
func (f *HIPAAFilter) Priority() int { return 100 }
func (f *HIPAAFilter) Filter(_ context.Context, req FilterRequest) (FilterDecision, error) {
	return matchAndDecide(req.Text, f.patterns, f.action, "hipaa_phi_detected", "[HIPAA-REDACTED]")
}

// ─── GDPR ─────────────────────────────────────────────────────────────────────

// GDPRFilter detects EU personal data and GDPR-specific terminology.
type GDPRFilter struct {
	action   FilterAction
	patterns []*regexp.Regexp
}

func NewGDPRFilter(action FilterAction) *GDPRFilter {
	raw := []string{
		`(?i)\b(right\s+to\s+erasure|data\s+subject|personal\s+data|lawful\s+basis)\b`,
		`(?i)\b(data\s+controller|data\s+processor|gdpr|dpa|dpo)\b`,
		`(?i)\b(consent\s+withdrawal|data\s+portability|privacy\s+by\s+design)\b`,
		// EU national ID patterns
		`\b[A-Z]{2}\d{6}[A-Z]?\b`, // generic EU ID
	}
	return &GDPRFilter{action: action, patterns: compilePatterns(raw)}
}

func (f *GDPRFilter) ID() string    { return "gdpr" }
func (f *GDPRFilter) Priority() int { return 110 }
func (f *GDPRFilter) Filter(_ context.Context, req FilterRequest) (FilterDecision, error) {
	return matchAndDecide(req.Text, f.patterns, f.action, "gdpr_personal_data_detected", "[GDPR-REDACTED]")
}

// ─── ITAR ─────────────────────────────────────────────────────────────────────

// ITARFilter blocks export-controlled and defense-related terms.
type ITARFilter struct {
	action   FilterAction
	keywords []string
}

func NewITARFilter(action FilterAction) *ITARFilter {
	return &ITARFilter{
		action: action,
		keywords: []string{
			"munitions", "usml", "export control", "eccn", "itar",
			"defense article", "defense service", "controlled technology",
			"technical data", "ear99", "dual use", "ccl", "commerce control list",
			"arms export", "international traffic", "defense trade",
		},
	}
}

func (f *ITARFilter) ID() string    { return "itar" }
func (f *ITARFilter) Priority() int { return 120 }
func (f *ITARFilter) Filter(_ context.Context, req FilterRequest) (FilterDecision, error) {
	lower := strings.ToLower(req.Text)
	for _, kw := range f.keywords {
		if strings.Contains(lower, kw) {
			return FilterDecision{
				Allowed: false,
				Action:  f.action,
				Reason:  "itar_controlled_term_detected",
			}, nil
		}
	}
	return FilterDecision{Allowed: true}, nil
}

// ─── PCI ─────────────────────────────────────────────────────────────────────

// PCIFilter detects payment card numbers and CVV patterns.
type PCIFilter struct {
	action   FilterAction
	patterns []*regexp.Regexp
}

func NewPCIFilter(action FilterAction) *PCIFilter {
	raw := []string{
		`\b4[0-9]{12}(?:[0-9]{3})?\b`,            // Visa
		`\b5[1-5][0-9]{14}\b`,                     // Mastercard
		`\b3[47][0-9]{13}\b`,                      // Amex
		`\b6(?:011|5[0-9]{2})[0-9]{12}\b`,         // Discover
		`\b[Cc][Vv][Vv2][-:\s]*\d{3,4}\b`,         // CVV
		`(?i)\b(card\s+number|pan|primary\s+account\s+number)\b`,
	}
	return &PCIFilter{action: action, patterns: compilePatterns(raw)}
}

func (f *PCIFilter) ID() string    { return "pci" }
func (f *PCIFilter) Priority() int { return 130 }
func (f *PCIFilter) Filter(_ context.Context, req FilterRequest) (FilterDecision, error) {
	return matchAndDecide(req.Text, f.patterns, f.action, "pci_card_data_detected", "[PCI-REDACTED]")
}

// ─── factory ──────────────────────────────────────────────────────────────────

// NewBuiltin constructs a built-in filter by name and action string.
// Returns nil if the builtin name is unknown.
func NewBuiltin(builtinName, actionStr string) IndustryFilter {
	action := actionFromString(actionStr)
	switch builtinName {
	case "hipaa":
		return NewHIPAAFilter(action)
	case "gdpr":
		return NewGDPRFilter(action)
	case "itar":
		return NewITARFilter(action)
	case "pci":
		return NewPCIFilter(action)
	}
	return nil
}

func actionFromString(s string) FilterAction {
	switch s {
	case "redact":
		return FilterRedact
	case "flag":
		return FilterFlag
	default:
		return FilterBlock
	}
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func compilePatterns(raw []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(raw))
	for _, p := range raw {
		if re, err := regexp.Compile(p); err == nil {
			out = append(out, re)
		}
	}
	return out
}

func matchAndDecide(text string, patterns []*regexp.Regexp, action FilterAction, reason, placeholder string) (FilterDecision, error) {
	for _, re := range patterns {
		if re.MatchString(text) {
			if action == FilterRedact {
				redacted := re.ReplaceAllString(text, placeholder)
				return FilterDecision{Allowed: true, Action: FilterRedact, Reason: reason, Modified: redacted}, nil
			}
			return FilterDecision{Allowed: false, Action: action, Reason: reason}, nil
		}
	}
	return FilterDecision{Allowed: true}, nil
}
