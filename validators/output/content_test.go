package output_test

import (
	"testing"

	"github.com/zafrem/bastion-sentinel/config"
	"github.com/zafrem/bastion-sentinel/validators/output"
)

func defaultContentFilter(t *testing.T) *output.ContentFilter {
	t.Helper()
	f, err := output.NewContentFilter(config.Default().OutputValidation.ContentFilter)
	if err != nil {
		t.Fatalf("NewContentFilter: %v", err)
	}
	return f
}

func TestContentFilter_CleanResponse(t *testing.T) {
	f := defaultContentFilter(t)
	result := f.Check("The weather in Seoul is sunny today.")
	if result.Status != "PASSED" {
		t.Errorf("expected PASSED, got %s", result.Status)
	}
}

func TestContentFilter_APIKey(t *testing.T) {
	f := defaultContentFilter(t)
	result := f.Check("Use sk-abcdefghijklmnopqrstuvwxyz01234567890 to authenticate.")
	if result.Status != "BLOCKED" {
		t.Errorf("expected BLOCKED for API key, got %s", result.Status)
	}
	if result.Severity != "critical" {
		t.Errorf("expected severity critical, got %s", result.Severity)
	}
}

func TestContentFilter_GithubToken(t *testing.T) {
	f := defaultContentFilter(t)
	result := f.Check("Token: ghp_abcdefghijklmnopqrstuvwxyz01234567890ab")
	if result.Status != "BLOCKED" {
		t.Errorf("expected BLOCKED for GitHub token, got %s", result.Status)
	}
}

func TestContentFilter_AWSKey(t *testing.T) {
	f := defaultContentFilter(t)
	result := f.Check("AWS key: AKIAIOSFODNN7EXAMPLE")
	if result.Status != "BLOCKED" {
		t.Errorf("expected BLOCKED for AWS access key, got %s", result.Status)
	}
}

func TestContentFilter_InternalPath(t *testing.T) {
	f := defaultContentFilter(t)
	result := f.Check("Config file at /etc/sentinel/config.yaml")
	if result.Status == "PASSED" {
		t.Error("expected non-PASSED for internal path")
	}
	if result.Severity != "medium" {
		t.Errorf("expected severity medium for internal path, got %s", result.Severity)
	}
}

func TestContentFilter_MultipleViolations(t *testing.T) {
	f := defaultContentFilter(t)
	result := f.Check("Key: sk-abcdefghijklmnopqrstuvwxyz01234567890 path: /etc/passwd")
	if len(result.Violations) < 2 {
		t.Errorf("expected ≥2 violations, got %d", len(result.Violations))
	}
	// Overall status should be BLOCKED (highest severity wins)
	if result.Status != "BLOCKED" {
		t.Errorf("expected BLOCKED when API key present, got %s", result.Status)
	}
}

func TestContentFilter_InvalidPattern(t *testing.T) {
	cfg := config.ContentFilterConfig{
		Patterns: []config.ContentFilterPatternConfig{
			{ID: "bad", Name: "bad", Pattern: `[bad(`, Severity: "high"},
		},
	}
	_, err := output.NewContentFilter(cfg)
	if err == nil {
		t.Error("expected error for invalid regex")
	}
}

func TestContentFilter_AbuseAndHate(t *testing.T) {
	f := defaultContentFilter(t)
	for _, bad := range []string{
		"You are a worthless idiot and nobody wants your help.",
		"You're so stupid, I can't believe you asked.",
		"I will kill you if you come back.",
		"Those people should all be deported or wiped out.",
		"너는 정말 멍청하구나.",
	} {
		if r := f.Check(bad); r.Status != "BLOCKED" {
			t.Errorf("should be blocked: %q -> %s %v", bad, r.Status, r.Violations)
		}
	}
	for _, ok := range []string{
		"Immigrants contribute significantly to the economy.",
		"The word 'stupid' is considered rude in formal writing.",
		"If you are stuck, do not feel stupid; this is a hard problem.",
		"Refugees should be treated according to international law.",
		"I hate waiting in line, don't you?",
		"그 영화는 정말 멍청한 줄거리였어요.",
	} {
		if r := f.Check(ok); r.Status != "PASSED" {
			t.Errorf("harmless text flagged: %q -> %s %v", ok, r.Status, r.Violations)
		}
	}
}
