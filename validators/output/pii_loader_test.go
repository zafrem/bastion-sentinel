package output

import (
	"fmt"
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

const oneRule = "patterns:\n  - id: \"%s\"\n    description: \"D\"\n    pattern: \"X-[0-9]+\"\n    policy: { action_on_match: \"redact\", severity: \"high\" }\n"

func TestLoadExternalPatterns_SymlinkOutsideTheDirectoryIsRefused(t *testing.T) {
	outside := t.TempDir()
	secret := filepath.Join(outside, "other.yaml")
	if err := os.WriteFile(secret, []byte(fmt.Sprintf(oneRule, "from_outside")), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Symlink(secret, filepath.Join(dir, "link.yaml")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if got, err := LoadExternalPatterns(dir); err == nil {
		t.Fatalf("a symlink leaving the directory must be refused, loaded %d patterns", len(got))
	}
}

func TestLoadExternalPatterns_SymlinkInsideTheDirectoryStillWorks(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "real.yaml"), []byte(fmt.Sprintf(oneRule, "inside")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real.yaml", filepath.Join(dir, "alias.yml")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	got, err := LoadExternalPatterns(dir)
	if err != nil || len(got) != 2 {
		t.Fatalf("want both the file and its in-directory alias, got %d, err %v", len(got), err)
	}
}

func TestLoadExternalPatterns_SubdirectoriesAndMissingDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "a", "b"), 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "a", "b", "deep.yaml"), []byte(fmt.Sprintf(oneRule, "deep")), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "a", "notes.txt"), []byte("ignored"), 0o600)
	if got, err := LoadExternalPatterns(dir); err != nil || len(got) != 1 || got[0].ID != "deep" {
		t.Fatalf("nested yaml should load, others ignored: %v %v", got, err)
	}
	if _, err := LoadExternalPatterns(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing directory must be an error")
	}
}
