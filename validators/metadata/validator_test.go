package metadata_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/zafrem/bastion-sentinel/config"
	"github.com/zafrem/bastion-sentinel/types"
	"github.com/zafrem/bastion-sentinel/validators/metadata"
)

func newValidator(t *testing.T) *metadata.Validator {
	t.Helper()
	v, err := metadata.New(config.Default().MetadataValidation)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}
	return v
}

func validMeta() map[string]string {
	return map[string]string{
		"tenant_id":  "acme",
		"user_id":    "john",
		"context_id": uuid.NewString(),
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
	}
}

func TestValidate_ValidRequest(t *testing.T) {
	v := newValidator(t)
	result := v.Validate(validMeta(), "What is AI?")
	if result.Status != types.StatusPassed {
		t.Errorf("expected PASSED, got %s: %v", result.Status, result.FormatErrors)
	}
}

func TestValidate_MissingRequiredFields(t *testing.T) {
	v := newValidator(t)
	tests := []struct {
		drop    string
	}{
		{"tenant_id"},
		{"user_id"},
		{"context_id"},
		{"timestamp"},
	}
	for _, tt := range tests {
		m := validMeta()
		delete(m, tt.drop)
		result := v.Validate(m, "query")
		if result.Status != types.StatusBlocked {
			t.Errorf("drop %s: expected BLOCKED, got %s", tt.drop, result.Status)
		}
		found := false
		for _, f := range result.MissingFields {
			if f == tt.drop {
				found = true
			}
		}
		if !found {
			t.Errorf("drop %s: missing field not reported; got %v", tt.drop, result.MissingFields)
		}
	}
}

func TestValidate_InvalidTenantIDFormat(t *testing.T) {
	v := newValidator(t)
	m := validMeta()
	m["tenant_id"] = "ACME Corp!" // uppercase and special chars
	result := v.Validate(m, "query")
	if result.Status != types.StatusBlocked {
		t.Errorf("expected BLOCKED for invalid tenant_id format, got %s", result.Status)
	}
}

func TestValidate_TenantIDTooShort(t *testing.T) {
	v := newValidator(t)
	m := validMeta()
	m["tenant_id"] = "ab" // 2 chars, min is 3
	result := v.Validate(m, "query")
	if result.Status != types.StatusBlocked {
		t.Errorf("expected BLOCKED for short tenant_id, got %s", result.Status)
	}
}

func TestValidate_InvalidContextID(t *testing.T) {
	v := newValidator(t)
	m := validMeta()
	m["context_id"] = "not-a-uuid"
	result := v.Validate(m, "query")
	if result.Status != types.StatusBlocked {
		t.Errorf("expected BLOCKED for invalid context_id UUID, got %s", result.Status)
	}
}

func TestValidate_InvalidTimestamp(t *testing.T) {
	v := newValidator(t)
	m := validMeta()
	m["timestamp"] = "2026-05-17 10:30:00" // missing timezone, not RFC3339
	result := v.Validate(m, "query")
	if result.Status != types.StatusBlocked {
		t.Errorf("expected BLOCKED for invalid timestamp, got %s", result.Status)
	}
}

func TestValidate_TimestampTooOld(t *testing.T) {
	v := newValidator(t)
	m := validMeta()
	m["timestamp"] = time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)
	result := v.Validate(m, "query")
	if result.Status != types.StatusBlocked {
		t.Errorf("expected BLOCKED for timestamp outside ±1 hour, got %s", result.Status)
	}
}

func TestValidate_ReservedIdentifiers(t *testing.T) {
	v := newValidator(t)
	reserved := []string{"system", "admin", "root", "ADMIN", "System"}
	for _, id := range reserved {
		m := validMeta()
		m["tenant_id"] = id
		result := v.Validate(m, "query")
		if result.Status != types.StatusBlocked {
			t.Errorf("tenant_id=%q: expected BLOCKED for reserved identifier, got %s", id, result.Status)
		}
	}
}

func TestValidate_QueryTooLong(t *testing.T) {
	v := newValidator(t)
	longQuery := strings.Repeat("a", 10001)
	result := v.Validate(validMeta(), longQuery)
	if result.Status != types.StatusBlocked {
		t.Errorf("expected BLOCKED for query > 10000 chars, got %s", result.Status)
	}
}

func TestValidate_MetadataTooLarge(t *testing.T) {
	v := newValidator(t)
	m := validMeta()
	m["extra"] = strings.Repeat("x", 4097)
	result := v.Validate(m, "query")
	if result.Status != types.StatusBlocked {
		t.Errorf("expected BLOCKED for metadata > 4KB, got %s", result.Status)
	}
}

func TestNew_InvalidPattern(t *testing.T) {
	cfg := config.Default().MetadataValidation
	cfg.FieldRules["tenant_id"] = config.FieldRule{Pattern: "[invalid("}
	_, err := metadata.New(cfg)
	if err == nil {
		t.Error("expected error for invalid field pattern, got nil")
	}
}

func TestValidate_UserIDFormat(t *testing.T) {
	v := newValidator(t)
	tests := []struct {
		userID string
		pass   bool
	}{
		{"john-doe", true},
		{"john_doe", true},
		{"JohnDoe123", true},
		{"john doe", false}, // space not allowed
		{"jo", false},       // too short
		{fmt.Sprintf("%s", strings.Repeat("a", 65)), false}, // too long
	}
	for _, tt := range tests {
		m := validMeta()
		m["user_id"] = tt.userID
		result := v.Validate(m, "query")
		if tt.pass && result.Status != types.StatusPassed {
			t.Errorf("user_id=%q: expected PASSED, got %s: %v", tt.userID, result.Status, result.FormatErrors)
		}
		if !tt.pass && result.Status != types.StatusBlocked {
			t.Errorf("user_id=%q: expected BLOCKED, got %s", tt.userID, result.Status)
		}
	}
}
