package industry

import (
	"context"
	"strings"
	"testing"
)

// ─── helpers ──────────────────────────────────────────────────────────────────

func req(text string) FilterRequest {
	return FilterRequest{Text: text, TenantID: "t1", UserID: "u1"}
}

func assertAllowed(t *testing.T, d FilterDecision, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !d.Allowed {
		t.Errorf("expected allowed=true, got reason=%q", d.Reason)
	}
}

func assertBlocked(t *testing.T, d FilterDecision, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Allowed {
		t.Error("expected allowed=false (blocked)")
	}
	if d.Action != FilterBlock {
		t.Errorf("expected action=FilterBlock, got %d", d.Action)
	}
}

func assertRedacted(t *testing.T, d FilterDecision, err error, wantSub string) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !d.Allowed {
		t.Error("expected allowed=true for redact action")
	}
	if d.Action != FilterRedact {
		t.Errorf("expected action=FilterRedact, got %d", d.Action)
	}
	if d.Modified == "" {
		t.Error("Modified must be non-empty for redact action")
	}
	if wantSub != "" && strings.Contains(d.Modified, wantSub) {
		t.Errorf("redacted text still contains %q: %q", wantSub, d.Modified)
	}
}

// ─── HIPAA ────────────────────────────────────────────────────────────────────

func TestHIPAA_CleanText_Passes(t *testing.T) {
	f := NewHIPAAFilter(FilterBlock)
	d, err := f.Filter(context.Background(), req("What are the quarterly sales figures?"))
	assertAllowed(t, d, err)
}

func TestHIPAA_SSN_Blocked(t *testing.T) {
	f := NewHIPAAFilter(FilterBlock)
	d, err := f.Filter(context.Background(), req("Patient SSN is 123-45-6789"))
	assertBlocked(t, d, err)
}

func TestHIPAA_MedicalRecordNumber_Blocked(t *testing.T) {
	f := NewHIPAAFilter(FilterBlock)
	d, err := f.Filter(context.Background(), req("MRN: 100234567"))
	assertBlocked(t, d, err)
}

func TestHIPAA_PHIKeyword_Blocked(t *testing.T) {
	f := NewHIPAAFilter(FilterBlock)
	d, err := f.Filter(context.Background(), req("clinical note from yesterday's appointment"))
	assertBlocked(t, d, err)
}

func TestHIPAA_SSN_Redacted(t *testing.T) {
	f := NewHIPAAFilter(FilterRedact)
	d, err := f.Filter(context.Background(), req("Patient SSN is 123-45-6789"))
	assertRedacted(t, d, err, "123-45-6789")
	if !strings.Contains(d.Modified, "[HIPAA-REDACTED]") {
		t.Errorf("expected [HIPAA-REDACTED] placeholder in %q", d.Modified)
	}
}

func TestHIPAA_ID(t *testing.T) {
	if NewHIPAAFilter(FilterBlock).ID() != "hipaa" {
		t.Error("ID mismatch")
	}
}

func TestHIPAA_Priority(t *testing.T) {
	if NewHIPAAFilter(FilterBlock).Priority() != 100 {
		t.Error("priority should be 100")
	}
}

// ─── GDPR ─────────────────────────────────────────────────────────────────────

func TestGDPR_CleanText_Passes(t *testing.T) {
	f := NewGDPRFilter(FilterBlock)
	d, err := f.Filter(context.Background(), req("Normal business inquiry about product availability"))
	assertAllowed(t, d, err)
}

func TestGDPR_DataSubject_Blocked(t *testing.T) {
	f := NewGDPRFilter(FilterBlock)
	d, err := f.Filter(context.Background(), req("This pertains to a data subject erasure request"))
	assertBlocked(t, d, err)
}

func TestGDPR_PersonalData_Blocked(t *testing.T) {
	f := NewGDPRFilter(FilterBlock)
	d, err := f.Filter(context.Background(), req("We collected personal data without lawful basis"))
	assertBlocked(t, d, err)
}

func TestGDPR_DPO_Flagged(t *testing.T) {
	f := NewGDPRFilter(FilterFlag)
	d, err := f.Filter(context.Background(), req("Please contact the DPO for further information"))
	if err != nil {
		t.Fatal(err)
	}
	if d.Allowed {
		t.Error("expected not allowed for flag action")
	}
	if d.Action != FilterFlag {
		t.Errorf("expected FilterFlag, got %d", d.Action)
	}
}

func TestGDPR_ID(t *testing.T) {
	if NewGDPRFilter(FilterBlock).ID() != "gdpr" {
		t.Error("ID mismatch")
	}
}

// ─── ITAR ─────────────────────────────────────────────────────────────────────

func TestITAR_CleanText_Passes(t *testing.T) {
	f := NewITARFilter(FilterBlock)
	d, err := f.Filter(context.Background(), req("Quarterly production forecast for consumer electronics"))
	assertAllowed(t, d, err)
}

func TestITAR_Munitions_Blocked(t *testing.T) {
	f := NewITARFilter(FilterBlock)
	d, err := f.Filter(context.Background(), req("Exporting munitions requires USML authorization"))
	assertBlocked(t, d, err)
}

func TestITAR_CaseInsensitive(t *testing.T) {
	f := NewITARFilter(FilterBlock)
	d, err := f.Filter(context.Background(), req("ITAR compliance review for defense article"))
	assertBlocked(t, d, err)
}

func TestITAR_ExportControl_Blocked(t *testing.T) {
	f := NewITARFilter(FilterBlock)
	d, err := f.Filter(context.Background(), req("This item is subject to export control regulations"))
	assertBlocked(t, d, err)
}

func TestITAR_ID(t *testing.T) {
	if NewITARFilter(FilterBlock).ID() != "itar" {
		t.Error("ID mismatch")
	}
}

func TestITAR_Priority(t *testing.T) {
	if NewITARFilter(FilterBlock).Priority() != 120 {
		t.Error("priority should be 120")
	}
}

// ─── PCI ─────────────────────────────────────────────────────────────────────

func TestPCI_CleanText_Passes(t *testing.T) {
	f := NewPCIFilter(FilterBlock)
	d, err := f.Filter(context.Background(), req("Please submit your purchase order reference number"))
	assertAllowed(t, d, err)
}

func TestPCI_VisaCard_Blocked(t *testing.T) {
	f := NewPCIFilter(FilterBlock)
	d, err := f.Filter(context.Background(), req("Charge card number 4111111111111111 for the order"))
	assertBlocked(t, d, err)
}

func TestPCI_Amex_Blocked(t *testing.T) {
	f := NewPCIFilter(FilterBlock)
	d, err := f.Filter(context.Background(), req("Amex number: 371449635398431"))
	assertBlocked(t, d, err)
}

func TestPCI_CVV_Blocked(t *testing.T) {
	f := NewPCIFilter(FilterBlock)
	d, err := f.Filter(context.Background(), req("CVV: 123"))
	assertBlocked(t, d, err)
}

func TestPCI_VisaCard_Redacted(t *testing.T) {
	f := NewPCIFilter(FilterRedact)
	d, err := f.Filter(context.Background(), req("Card: 4111111111111111"))
	assertRedacted(t, d, err, "4111111111111111")
}

func TestPCI_ID(t *testing.T) {
	if NewPCIFilter(FilterBlock).ID() != "pci" {
		t.Error("ID mismatch")
	}
}

// ─── NewBuiltin factory ───────────────────────────────────────────────────────

func TestNewBuiltin_KnownNames(t *testing.T) {
	for _, name := range []string{"hipaa", "gdpr", "itar", "pci"} {
		f := NewBuiltin(name, "block")
		if f == nil {
			t.Errorf("NewBuiltin(%q) returned nil", name)
		}
		if f.ID() != name {
			t.Errorf("NewBuiltin(%q).ID()=%q, want %q", name, f.ID(), name)
		}
	}
}

func TestNewBuiltin_Unknown_ReturnsNil(t *testing.T) {
	if NewBuiltin("unknown_filter", "block") != nil {
		t.Error("expected nil for unknown builtin")
	}
}

func TestNewBuiltin_ActionParsing(t *testing.T) {
	cases := []struct {
		actionStr string
		want      FilterAction
	}{
		{"block", FilterBlock},
		{"redact", FilterRedact},
		{"flag", FilterFlag},
		{"", FilterBlock},    // default
		{"bad", FilterBlock}, // unknown defaults to block
	}
	for _, tc := range cases {
		got := actionFromString(tc.actionStr)
		if got != tc.want {
			t.Errorf("actionFromString(%q)=%d, want %d", tc.actionStr, got, tc.want)
		}
	}
}
