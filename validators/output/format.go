package output

import (
	"fmt"
	"unicode"
	"unicode/utf8"

	"github.com/zafrem/bastion-sentinel/config"
	"github.com/zafrem/bastion-sentinel/types"
)

// FormatValidator enforces structural constraints on LLM responses: length,
// UTF-8 validity, and absence of raw control characters.
type FormatValidator struct {
	cfg config.OutputFormatConfig
}

func NewFormatValidator(cfg config.OutputFormatConfig) *FormatValidator {
	return &FormatValidator{cfg: cfg}
}

// Check validates the response against all configured format rules.
func (v *FormatValidator) Check(response string) types.FormatCheckResult {
	var issues []string
	lengthOK := true
	structureOK := true

	l := len(response)
	if l < v.cfg.MinLength {
		lengthOK = false
		issues = append(issues, fmt.Sprintf("response too short: %d chars (minimum %d)", l, v.cfg.MinLength))
	}
	if l > v.cfg.MaxLength {
		lengthOK = false
		issues = append(issues, fmt.Sprintf("response too long: %d chars (maximum %d)", l, v.cfg.MaxLength))
	}

	if v.cfg.UTF8Required && !utf8.ValidString(response) {
		structureOK = false
		issues = append(issues, "invalid UTF-8 encoding")
	}

	if v.cfg.NoControlChars {
		for _, r := range response {
			// Allow common whitespace: newline, carriage return, tab.
			if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
				structureOK = false
				issues = append(issues, "response contains disallowed control characters")
				break
			}
		}
	}

	status := "PASSED"
	if !lengthOK || !structureOK {
		status = "FAILED"
	}
	return types.FormatCheckResult{
		Status:      status,
		LengthOK:    lengthOK,
		StructureOK: structureOK,
		Issues:      issues,
	}
}
