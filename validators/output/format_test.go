package output_test

import (
	"strings"
	"testing"

	"github.com/zafrem/bastion-sentinel/config"
	"github.com/zafrem/bastion-sentinel/validators/output"
)

func defaultFormatValidator() *output.FormatValidator {
	return output.NewFormatValidator(config.Default().OutputValidation.Format)
}

func TestFormat_ValidResponse(t *testing.T) {
	v := defaultFormatValidator()
	result := v.Check("This is a perfectly valid response.")
	if result.Status != "PASSED" {
		t.Errorf("expected PASSED, got %s; issues: %v", result.Status, result.Issues)
	}
	if !result.LengthOK || !result.StructureOK {
		t.Error("expected both LengthOK and StructureOK to be true")
	}
}

func TestFormat_TooShort(t *testing.T) {
	v := defaultFormatValidator()
	result := v.Check("   \n") // whitespace only
	if result.LengthOK {
		t.Error("expected LengthOK=false for very short response")
	}
	if result.Status != "FAILED" {
		t.Errorf("expected FAILED, got %s", result.Status)
	}
}

func TestFormat_TooLong(t *testing.T) {
	v := defaultFormatValidator()
	result := v.Check(strings.Repeat("a", 10001))
	if result.LengthOK {
		t.Error("expected LengthOK=false for oversized response")
	}
	if result.Status != "FAILED" {
		t.Errorf("expected FAILED, got %s", result.Status)
	}
}

func TestFormat_ExactMinLength(t *testing.T) {
	v := defaultFormatValidator()
	result := v.Check("1234567890") // exactly 10 chars
	if !result.LengthOK {
		t.Error("expected LengthOK=true at exactly MinLength")
	}
}

func TestFormat_ExactMaxLength(t *testing.T) {
	v := defaultFormatValidator()
	result := v.Check(strings.Repeat("a", 10000)) // exactly 10000 chars
	if !result.LengthOK {
		t.Error("expected LengthOK=true at exactly MaxLength")
	}
}

func TestFormat_ControlCharacter(t *testing.T) {
	v := defaultFormatValidator()
	// Null byte is a control character (not allowed).
	result := v.Check("valid prefix \x00 invalid suffix")
	if result.StructureOK {
		t.Error("expected StructureOK=false for response with control character")
	}
	if result.Status != "FAILED" {
		t.Errorf("expected FAILED, got %s", result.Status)
	}
}

func TestFormat_NewlinesAndTabsAllowed(t *testing.T) {
	v := defaultFormatValidator()
	result := v.Check("Line 1\nLine 2\r\nTabbed:\tvalue")
	if !result.StructureOK {
		t.Errorf("newlines and tabs should be allowed, issues: %v", result.Issues)
	}
}

// A correct short answer is legitimate and must not be refused.
func TestFormat_ShortAnswersAreFine(t *testing.T) {
	v := defaultFormatValidator()
	for _, a := range []string{"Yes.", "네.", "42", "Paris"} {
		if r := v.Check(a); r.Status != "PASSED" {
			t.Errorf("%q should pass, got %s %v", a, r.Status, r.Issues)
		}
	}
}

// Length counts characters, not bytes: 10 000 Korean characters are within a 10 000 limit.
func TestFormat_LengthCountsCharactersNotBytes(t *testing.T) {
	v := defaultFormatValidator()
	if r := v.Check(strings.Repeat("가", 9000)); r.Status != "PASSED" {
		t.Errorf("9000 Korean characters must fit, got %s %v", r.Status, r.Issues)
	}
}

func TestFormat_IssuesPopulated(t *testing.T) {
	v := defaultFormatValidator()
	result := v.Check("") // empty
	if len(result.Issues) == 0 {
		t.Error("expected Issues to be populated for failed format check")
	}
}
