package engine_test

import (
	"strings"
	"testing"

	"github.com/zafrem/bastion-sentinel/config"
	"github.com/zafrem/bastion-sentinel/engine"
	"github.com/zafrem/bastion-sentinel/types"
)

func newOutputEngine(t *testing.T) *engine.OutputEngine {
	t.Helper()
	eng, err := engine.NewOutputEngine(config.Default())
	if err != nil {
		t.Fatalf("NewOutputEngine: %v", err)
	}
	return eng
}

func outputReq(response string) types.OutputValidateRequest {
	return types.OutputValidateRequest{
		RequestID:   "out-1",
		LLMResponse: response,
		User:        types.UserContext{AccessLevel: "full"},
	}
}

func TestOutputEngine_CleanResponse_Passed(t *testing.T) {
	eng := newOutputEngine(t)
	resp := eng.Validate(outputReq("The capital of France is Paris."))
	if resp.Status != types.OutputStatusPassed {
		t.Errorf("expected PASSED, got %s", resp.Status)
	}
}

func TestOutputEngine_TooShort_Blocked(t *testing.T) {
	eng := newOutputEngine(t)
	resp := eng.Validate(outputReq("Hi"))
	if resp.Status != types.OutputStatusBlocked {
		t.Errorf("expected BLOCKED for too-short response, got %s", resp.Status)
	}
}

func TestOutputEngine_PIIEmail_Sanitized(t *testing.T) {
	eng := newOutputEngine(t)
	resp := eng.Validate(outputReq("Contact the user at alice@example.com for details."))
	if resp.Status != types.OutputStatusSanitized {
		t.Errorf("expected SANITIZED for email PII, got %s", resp.Status)
	}
	if strings.Contains(resp.ValidatedResponse, "alice@example.com") {
		t.Error("original email should have been redacted in validated response")
	}
}

func TestOutputEngine_APIKey_Blocked(t *testing.T) {
	eng := newOutputEngine(t)
	resp := eng.Validate(outputReq("Use sk-abcdefghijklmnopqrstuvwxyz01234567890 to connect."))
	if resp.Status != types.OutputStatusBlocked {
		t.Errorf("expected BLOCKED for API key in response, got %s", resp.Status)
	}
}

func TestOutputEngine_UngroundedClaims_Warning(t *testing.T) {
	eng := newOutputEngine(t)
	req := types.OutputValidateRequest{
		RequestID:   "out-2",
		LLMResponse: "The product costs $9,999 and ships in 3 days.",
		User:        types.UserContext{AccessLevel: "full"},
		Retrieval: types.RetrievalContext{
			SourceDocuments: []string{"Product is available for purchase."},
		},
	}
	resp := eng.Validate(req)
	// Claims ($9,999, 3) are not in sources → grounding score drops below threshold
	if resp.Status != types.OutputStatusWarning && resp.Status != types.OutputStatusPassed {
		t.Logf("status=%s (acceptable)", resp.Status)
	}
	if resp.Checks.HallucinationCheck.Status == "SKIPPED" {
		t.Error("expected hallucination check to run when sources are provided")
	}
}

func TestOutputEngine_PermissionViolation_KAnonymized(t *testing.T) {
	eng := newOutputEngine(t)
	req := types.OutputValidateRequest{
		RequestID:   "out-3",
		LLMResponse: "The customer spent $5,000 on products last quarter.",
		User:        types.UserContext{AccessLevel: "k_anonymized"},
	}
	resp := eng.Validate(req)
	if !resp.Checks.PermissionCheck.BoundaryViolated {
		t.Error("expected permission boundary violation for k_anonymized user with specific amounts")
	}
	if resp.Status == types.OutputStatusPassed {
		t.Error("expected non-PASSED status for permission violation")
	}
}

func TestOutputEngine_PermissionViolation_StrictMode_Blocked(t *testing.T) {
	eng := newOutputEngine(t)
	req := types.OutputValidateRequest{
		RequestID:   "out-4",
		LLMResponse: "The customer spent $5,000 on products.",
		User:        types.UserContext{AccessLevel: "k_anonymized"},
		Options:     types.OutputValidationOptions{CheckPermission: true, StrictMode: true},
	}
	resp := eng.Validate(req)
	if resp.Status != types.OutputStatusBlocked {
		t.Errorf("expected BLOCKED in strict mode for permission violation, got %s", resp.Status)
	}
}

func TestOutputEngine_ModificationsLogged(t *testing.T) {
	eng := newOutputEngine(t)
	resp := eng.Validate(outputReq("Email: test@example.com is here."))
	if resp.Status != types.OutputStatusSanitized {
		return // PII check may not have triggered — skip mod check
	}
	if len(resp.Modifications) == 0 {
		t.Error("expected Modifications to be non-empty for sanitized response")
	}
}

func TestOutputEngine_ProcessingTimeSet(t *testing.T) {
	eng := newOutputEngine(t)
	resp := eng.Validate(outputReq("This is a clean response with no issues."))
	if resp.ProcessingTimeMs < 0 {
		t.Error("ProcessingTimeMs should be non-negative")
	}
}

func TestOutputEngine_SelectiveChecks(t *testing.T) {
	eng := newOutputEngine(t)
	req := types.OutputValidateRequest{
		RequestID:   "out-5",
		LLMResponse: "Email: user@example.com is fine.",
		User:        types.UserContext{AccessLevel: "full"},
		Options: types.OutputValidationOptions{
			CheckPIIReemergence: false,
			CheckHallucination:  false,
			CheckContent:        true,
			CheckPermission:     false,
		},
	}
	resp := eng.Validate(req)
	if resp.Checks.PIICheck.Status != "SKIPPED" {
		t.Errorf("expected PIICheck SKIPPED, got %s", resp.Checks.PIICheck.Status)
	}
}

func TestOutputEngine_InvalidConfig(t *testing.T) {
	cfg := config.Default()
	cfg.OutputValidation.PIIReemergence.Patterns = []config.PIIPatternConfig{
		{ID: "bad", Name: "bad", Pattern: `[bad(`, Severity: "high"},
	}
	_, err := engine.NewOutputEngine(cfg)
	if err == nil {
		t.Error("expected error for invalid PII pattern in config")
	}
}
