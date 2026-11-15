package output_test

import (
	"strings"
	"testing"

	"github.com/zafrem/bastion-sentinel/config"
	"github.com/zafrem/bastion-sentinel/validators/output"
)

func defaultPIIDetector(t *testing.T) *output.PIIDetector {
	t.Helper()
	d, err := output.NewPIIDetector(config.Default().OutputValidation.PIIReemergence)
	if err != nil {
		t.Fatalf("NewPIIDetector: %v", err)
	}
	return d
}

func TestPIIDetector_CleanResponse(t *testing.T) {
	d := defaultPIIDetector(t)
	result := d.Check("The product is available in three colours.")
	if result.Status != "PASSED" {
		t.Errorf("expected PASSED, got %s", result.Status)
	}
	if len(result.Incidents) != 0 {
		t.Errorf("expected no incidents, got %d", len(result.Incidents))
	}
}

func TestPIIDetector_Email(t *testing.T) {
	d := defaultPIIDetector(t)
	result := d.Check("Contact us at john.doe@example.com for more info.")
	if result.Status != "VIOLATIONS_DETECTED" {
		t.Fatalf("expected VIOLATIONS_DETECTED, got %s", result.Status)
	}
	found := false
	for _, inc := range result.Incidents {
		if inc.OriginalValue == "john.doe@example.com" {
			found = true
		}
	}
	if !found {
		t.Error("expected email incident for john.doe@example.com")
	}
}

func TestPIIDetector_KoreanRRN(t *testing.T) {
	d := defaultPIIDetector(t)
	result := d.Check("주민등록번호: 800101-1234567")
	hasCritical := false
	for _, inc := range result.Incidents {
		if inc.OriginalValue == "800101-1234567" && inc.ActionTaken == "redacted" {
			hasCritical = true
		}
	}
	if !hasCritical {
		t.Error("expected critical (redacted) incident for 800101-1234567")
	}
}

func TestPIIDetector_KoreanMobile(t *testing.T) {
	d := defaultPIIDetector(t)
	result := d.Check("연락처: 010-1234-5678")
	found := false
	for _, inc := range result.Incidents {
		if inc.OriginalValue == "010-1234-5678" {
			found = true
		}
	}
	if !found {
		t.Error("expected incident for 010-1234-5678")
	}
}

func TestPIIDetector_CreditCard(t *testing.T) {
	d := defaultPIIDetector(t)
	result := d.Check("Card: 4111111111111111")
	hasCritical := false
	for _, inc := range result.Incidents {
		if inc.OriginalValue == "4111111111111111" && inc.ActionTaken == "redacted" {
			hasCritical = true
		}
	}
	if !hasCritical {
		t.Logf("Incidents: %+v", result.Incidents)
		t.Error("expected critical incident for 4111111111111111")
	}
}

func TestPIIDetector_LeakedToken(t *testing.T) {
	d := defaultPIIDetector(t)
	text := "The record for USER_DATA_abc123def456gh78 shows..."
	result := d.Check(text)
	// Overlapping detectors (leaked_token and the generic high-entropy token rule) cover the same span;
	// overlap resolution keeps one incident for it, so assert the token is flagged and removed.
	found := false
	for _, inc := range result.Incidents {
		if inc.OriginalValue == "USER_DATA_abc123def456gh78" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an incident covering the leaked token, got %+v", result.Incidents)
	}
	if out, _ := d.Sanitize(text, result.Incidents); strings.Contains(out, "abc123def456gh78") {
		t.Errorf("leaked token survived sanitising: %q", out)
	}
}

func TestPIIDetector_Sanitize_Email(t *testing.T) {
	d := defaultPIIDetector(t)
	response := "Email is user@example.com please contact"
	result := d.Check(response)
	sanitized, mods := d.Sanitize(response, result.Incidents)
	if strings.Contains(sanitized, "user@example.com") {
		t.Error("original email should be removed from sanitized response")
	}
	if len(mods) == 0 {
		t.Error("expected modification log entries")
	}
}

func TestPIIDetector_Sanitize_MultipleIncidents(t *testing.T) {
	d := defaultPIIDetector(t)
	response := "Email: a@b.com and card 1234-5678-9012-3456"
	result := d.Check(response)
	sanitized, _ := d.Sanitize(response, result.Incidents)
	if strings.Contains(sanitized, "a@b.com") {
		t.Error("email should be removed")
	}
	if strings.Contains(sanitized, "1234-5678-9012-3456") {
		t.Error("card number should be removed")
	}
}

func TestPIIDetector_InvalidPattern(t *testing.T) {
	cfg := config.PIIReemergenceConfig{
		Patterns: []config.PIIPatternConfig{
			{ID: "bad", Name: "bad", Pattern: `[invalid(`, Severity: "high"},
		},
	}
	_, err := output.NewPIIDetector(cfg)
	if err == nil {
		t.Error("expected error for invalid regex pattern")
	}
}

func TestHasCritical_True(t *testing.T) {
	// Relies on RRN triggering "redacted" action
	d := defaultPIIDetector(t)
	result := d.Check("RRN: 800101-1234567")
	if !output.HasCritical(result.Incidents) {
		t.Error("expected HasCritical to return true for RRN")
	}
}

func TestHasCritical_False(t *testing.T) {
	if output.HasCritical(nil) {
		t.Error("expected HasCritical to return false for nil")
	}
}

func TestPIIDetector_CheckWithMappings(t *testing.T) {
	d := defaultPIIDetector(t)
	response := "Customer John Doe has an account balance of $500."
	mappings := map[string]string{
		"CUST_NAME_a1b2c3d4e5f60001": "John Doe",
	}
	res := d.CheckWithMappings(response, mappings)
	if res.Status != "VIOLATIONS_DETECTED" {
		t.Fatalf("expected VIOLATIONS_DETECTED, got %s", res.Status)
	}
	sanitized, mods := d.Sanitize(response, res.Incidents)
	if strings.Contains(sanitized, "John Doe") {
		t.Errorf("expected John Doe to be replaced by token, got %q", sanitized)
	}
	if !strings.Contains(sanitized, "CUST_NAME_a1b2c3d4e5f60001") {
		t.Errorf("expected Vault token in sanitized output, got %q", sanitized)
	}
	if len(mods) == 0 {
		t.Error("expected modifications to be recorded")
	}
}


// A Vault-mapped value that partially overlaps a longer regex match must not leave the tail exposed.
func TestPIIDetector_PartialOverlapDoesNotLeakTail(t *testing.T) {
	d := defaultPIIDetector(t)
	resp := "Mail jane.smith@example.com now"
	res := d.CheckWithMappings(resp, map[string]string{"TOK_1": "Mail jane.smith"})
	out, _ := d.Sanitize(resp, res.Incidents)
	if strings.Contains(out, "example.com") || strings.Contains(out, "@") {
		t.Errorf("tail of overlapping match leaked: %q", out)
	}
	if !strings.HasSuffix(out, " now") {
		t.Errorf("surrounding text was damaged: %q", out)
	}
}

// When the mapped value fully contains a regex match, its Vault token is still used.
func TestPIIDetector_MappingCoveringMatchKeepsToken(t *testing.T) {
	d := defaultPIIDetector(t)
	resp := "Owner: jane@example.com (verified)"
	res := d.CheckWithMappings(resp, map[string]string{"TOK_2": "jane@example.com"})
	out, _ := d.Sanitize(resp, res.Incidents)
	if strings.Contains(out, "example.com") || !strings.Contains(out, "TOK_2") {
		t.Errorf("expected token replacement, got %q", out)
	}
}
