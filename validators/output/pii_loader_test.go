package output

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadExternalPatterns(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "patterns")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	yamlContent := `
patterns:
  - id: "test_ssn_01"
    description: "TEST_SSN"
    pattern: "\\b\\d{3}-\\d{2}-\\d{4}\\b"
    policy:
      action_on_match: "redact"
      severity: "high"
  - id: "test_secret_01"
    description: "TEST_SECRET"
    pattern: "SECRET-[A-Z]+"
    policy:
      action_on_match: "block"
      severity: "critical"
`
	err = os.WriteFile(filepath.Join(tempDir, "test.yaml"), []byte(yamlContent), 0644)
	if err != nil {
		t.Fatal(err)
	}

	patterns, err := LoadExternalPatterns(tempDir)
	if err != nil {
		t.Fatalf("LoadExternalPatterns failed: %v", err)
	}

	if len(patterns) != 2 {
		t.Fatalf("expected 2 patterns, got %d", len(patterns))
	}

	if patterns[0].Name != "TEST_SSN" || patterns[0].Severity != "high" || patterns[0].ID != "test_ssn_01" {
		t.Errorf("unexpected pattern 0: %+v", patterns[0])
	}

	if patterns[1].Name != "TEST_SECRET" || patterns[1].Severity != "critical" || patterns[1].ID != "test_secret_01" {
		t.Errorf("unexpected pattern 1: %+v", patterns[1])
	}
}
