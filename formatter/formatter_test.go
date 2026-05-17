package formatter_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/zafrem/bastion-sentinel/formatter"
	"github.com/zafrem/bastion-sentinel/types"
)

func passedResp() types.ValidateResponse {
	return types.ValidateResponse{
		RequestID:        "req-001",
		Status:           types.StatusPassed,
		Timestamp:        time.Date(2026, 5, 17, 10, 0, 0, 0, time.UTC),
		ProcessingTimeMs: 0.42,
		PromptCheck: types.PromptCheckResult{
			Status:    types.StatusPassed,
			RiskScore: 0.0,
			Method:    "regex+keyword",
		},
		MetadataCheck: types.MetadataCheckResult{
			Status: types.StatusPassed,
		},
		ExtractedData: types.ExtractedData{
			TenantID:     "acme",
			UserID:       "alice",
			CleanedQuery: "What is AI?",
		},
	}
}

func blockedResp() types.ValidateResponse {
	return types.ValidateResponse{
		RequestID:        "req-002",
		Status:           types.StatusBlocked,
		Timestamp:        time.Date(2026, 5, 17, 10, 0, 0, 0, time.UTC),
		ProcessingTimeMs: 0.85,
		PromptCheck: types.PromptCheckResult{
			Status:          types.StatusBlocked,
			RiskScore:       1.0,
			Method:          "regex+keyword",
			MatchedPatterns: []string{"pi-001"},
		},
		MetadataCheck: types.MetadataCheckResult{
			Status: types.StatusPassed,
		},
		ExtractedData: types.ExtractedData{
			TenantID: "acme",
			UserID:   "alice",
		},
	}
}

// ─── JSON format ──────────────────────────────────────────────────────────────

func TestWrite_JSON_Passed(t *testing.T) {
	var buf bytes.Buffer
	if err := formatter.Write(&buf, passedResp(), "json"); err != nil {
		t.Fatalf("Write: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if out["request_id"] != "req-001" {
		t.Errorf("request_id: got %v", out["request_id"])
	}
	if out["status"] != string(types.StatusPassed) {
		t.Errorf("status: got %v", out["status"])
	}
}

func TestWrite_JSON_Blocked(t *testing.T) {
	var buf bytes.Buffer
	if err := formatter.Write(&buf, blockedResp(), "json"); err != nil {
		t.Fatalf("Write: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if out["status"] != string(types.StatusBlocked) {
		t.Errorf("status: expected BLOCKED, got %v", out["status"])
	}
	checks := out["checks"].(map[string]any)
	pi := checks["prompt_injection"].(map[string]any)
	patterns := pi["matched_patterns"].([]any)
	if len(patterns) != 1 || patterns[0] != "pi-001" {
		t.Errorf("matched_patterns: got %v", patterns)
	}
}

func TestWrite_JSON_NilSlicesBecomEmptyArrays(t *testing.T) {
	resp := passedResp()
	resp.PromptCheck.MatchedPatterns = nil
	resp.MetadataCheck.MissingFields = nil
	resp.MetadataCheck.FormatErrors = nil

	var buf bytes.Buffer
	if err := formatter.Write(&buf, resp, "json"); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// Must be valid JSON and matched_patterns must be [] not null.
	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	checks := out["checks"].(map[string]any)
	pi := checks["prompt_injection"].(map[string]any)
	if _, ok := pi["matched_patterns"].([]any); !ok {
		t.Error("matched_patterns should be an empty array, not null")
	}
}

// ─── Compact format ───────────────────────────────────────────────────────────

func TestWrite_Compact_Passed(t *testing.T) {
	var buf bytes.Buffer
	if err := formatter.Write(&buf, passedResp(), "compact"); err != nil {
		t.Fatalf("Write: %v", err)
	}
	line := buf.String()
	if !strings.Contains(line, "PASSED") {
		t.Errorf("expected PASSED in compact output: %q", line)
	}
	if !strings.Contains(line, "req-001") {
		t.Errorf("expected request_id in compact output: %q", line)
	}
}

func TestWrite_Compact_Blocked(t *testing.T) {
	var buf bytes.Buffer
	if err := formatter.Write(&buf, blockedResp(), "compact"); err != nil {
		t.Fatalf("Write: %v", err)
	}
	line := buf.String()
	if !strings.Contains(line, "BLOCKED") {
		t.Errorf("expected BLOCKED in compact output: %q", line)
	}
	if !strings.Contains(line, "injection pattern") {
		t.Errorf("expected injection reason in compact output: %q", line)
	}
}

func TestWrite_Compact_BlockedMetadata(t *testing.T) {
	resp := passedResp()
	resp.Status = types.StatusBlocked
	resp.MetadataCheck.Status = types.StatusBlocked
	resp.MetadataCheck.MissingFields = []string{"user_id"}

	var buf bytes.Buffer
	if err := formatter.Write(&buf, resp, "compact"); err != nil {
		t.Fatalf("Write: %v", err)
	}
	line := buf.String()
	if !strings.Contains(line, "invalid metadata") {
		t.Errorf("expected metadata reason in compact output: %q", line)
	}
}

// ─── Text format ──────────────────────────────────────────────────────────────

func TestWrite_Text_Passed(t *testing.T) {
	var buf bytes.Buffer
	if err := formatter.Write(&buf, passedResp(), "text"); err != nil {
		t.Fatalf("Write: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"PASSED", "req-001", "Bastion-Sentinel", "acme", "alice"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in text output", want)
		}
	}
	if !strings.Contains(out, "Forward to Module C") {
		t.Errorf("expected forwarding action in text output")
	}
}

func TestWrite_Text_Blocked(t *testing.T) {
	var buf bytes.Buffer
	if err := formatter.Write(&buf, blockedResp(), "text"); err != nil {
		t.Fatalf("Write: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "BLOCKED") {
		t.Errorf("expected BLOCKED in text output")
	}
	if !strings.Contains(out, "pi-001") {
		t.Errorf("expected matched pattern pi-001 in text output")
	}
	if !strings.Contains(out, "HTTP 403") {
		t.Errorf("expected rejection action in text output")
	}
}

func TestWrite_Text_RiskLabels(t *testing.T) {
	cases := []struct {
		score float64
		label string
	}{
		{0.95, "Critical"},
		{0.75, "High"},
		{0.5, "Medium"},
		{0.1, "Low"},
	}
	for _, tc := range cases {
		resp := passedResp()
		resp.PromptCheck.RiskScore = tc.score
		var buf bytes.Buffer
		_ = formatter.Write(&buf, resp, "text")
		if !strings.Contains(buf.String(), tc.label) {
			t.Errorf("score %.2f: expected label %q in output", tc.score, tc.label)
		}
	}
}

// ─── Default (text) format ───────────────────────────────────────────────────

func TestWrite_DefaultIsText(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	_ = formatter.Write(&buf1, passedResp(), "text")
	_ = formatter.Write(&buf2, passedResp(), "unknown-format")
	if buf1.String() != buf2.String() {
		t.Error("unknown format should fall back to text")
	}
}
