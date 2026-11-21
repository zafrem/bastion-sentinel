package output_test

import (
	"strings"
	"testing"

	"github.com/zafrem/bastion-sentinel/config"
	"github.com/zafrem/bastion-sentinel/validators/output"
)

func piiWith(t *testing.T, mutate func(*config.PIIReemergenceConfig)) *output.PIIDetector {
	t.Helper()
	cfg := config.Default().OutputValidation.PIIReemergence
	mutate(&cfg)
	d, err := output.NewPIIDetector(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// Ordinary numbers, dates and times are declared "report" upstream: they must be
// listed for audit but must not rewrite the answer the user receives.
func TestReportOnlyRulesDoNotRewriteOrdinaryText(t *testing.T) {
	d := defaultPIIDetector(t)
	for _, text := range []string{
		"Refunds are issued within 14 days of purchase.",
		"Shipping takes 3 to 5 business days.",
		"The new store opens on 2026-03-01.",
		"The meeting starts at 10:30 in room 204.",
		"Please upgrade to version 2.4.1 or later.",
		"Your order number is 48213 and it ships tomorrow.",
	} {
		res := d.Check(text)
		if res.RedactionsApplied != 0 || len(res.Incidents) != 0 {
			t.Errorf("%q must not be rewritten, got %d incident(s): %+v", text, res.RedactionsApplied, res.Incidents)
		}
		if res.Status != "PASSED" {
			t.Errorf("%q: status %s, want PASSED", text, res.Status)
		}
	}
}

func TestReportedMatchesAreKeptForAudit(t *testing.T) {
	res := defaultPIIDetector(t).Check("Refunds are issued within 14 days of purchase.")
	if len(res.Reported) == 0 {
		t.Fatal("the match must still be reported")
	}
	for _, r := range res.Reported {
		if r.ActionTaken != "reported" || len(r.RuleIDs) != 1 || r.OriginalValue == "" {
			t.Errorf("bad reported incident: %+v", r)
		}
	}
}

// The protection that matters must be untouched.
func TestRealPersonalDataIsStillMasked(t *testing.T) {
	d := defaultPIIDetector(t)
	for _, secret := range []string{
		"john.doe@example.com", "900101-1234567", "4111 1111 1111 1111", "123-45-6789", "AKIAIOSFODNN7EXAMPLE",
	} {
		text := "Here it is: " + secret + " for you."
		res := d.Check(text)
		clean, _ := d.Sanitize(text, res.Incidents)
		if strings.Contains(clean, secret) {
			t.Errorf("%q leaked through: %q", secret, clean)
		}
	}
}

func TestSanitizeLeavesReportOnlyTextAlone(t *testing.T) {
	d := defaultPIIDetector(t)
	text := "Refunds are issued within 14 days. Email bob@example.com."
	res := d.Check(text)
	clean, _ := d.Sanitize(text, res.Incidents)
	if !strings.Contains(clean, "within 14 days") {
		t.Errorf("the number must survive: %q", clean)
	}
	if strings.Contains(clean, "bob@example.com") {
		t.Errorf("the email must not: %q", clean)
	}
}

func TestSwitchingHonorReportActionOffRestoresMaskingEverything(t *testing.T) {
	d := piiWith(t, func(c *config.PIIReemergenceConfig) { c.HonorReportAction = false })
	res := d.Check("Refunds are issued within 14 days of purchase.")
	if res.RedactionsApplied == 0 || len(res.Reported) != 0 {
		t.Errorf("with the switch off every match is masked, got redactions=%d reported=%d", res.RedactionsApplied, len(res.Reported))
	}
}

func TestAlwaysEnforceMasksAReportOnlyRuleByID(t *testing.T) {
	d := piiWith(t, func(c *config.PIIReemergenceConfig) { c.AlwaysEnforce = []string{"date_iso_01"} })
	res := d.Check("The new store opens on 2026-03-01.")
	if res.RedactionsApplied != 1 || len(res.Incidents[0].RuleIDs) == 0 || res.Incidents[0].RuleIDs[0] != "date_iso_01" {
		t.Errorf("date_iso_01 must be enforced, got %+v", res.Incidents)
	}
	if other := d.Check("Takes 14 days."); other.RedactionsApplied != 0 {
		t.Errorf("other report-only rules stay report-only, got %d", other.RedactionsApplied)
	}
}

func TestDefaultConfigHonorsReportAction(t *testing.T) {
	if !config.Default().OutputValidation.PIIReemergence.HonorReportAction {
		t.Error("the default must honour report-only rules, or ordinary numbers are rewritten")
	}
}

// Cards written with separators were previously caught only by chance. They are now covered
// deliberately, and a long run of ordinary words and numbers is not mistaken for one.
func TestGroupedCardNumbersAreMasked(t *testing.T) {
	d := defaultPIIDetector(t)
	for _, card := range []string{"4111 1111 1111 1111", "4111-1111-1111-1111", "5500 0000 0000 0004", "3782 822463 10005", "4111111111111111"} {
		text := "The card on file is " + card + " today."
		res := d.Check(text)
		clean, _ := d.Sanitize(text, res.Incidents)
		if strings.Contains(clean, card) || strings.Contains(clean, "1111 1111") {
			t.Errorf("%q leaked: %q", card, clean)
		}
	}
	for _, ok := range []string{"Ship in 3 to 5 days, order 48213.", "Call 555 1234 between 9 and 5.", "Version 1.2.3 and build 2026 0301."} {
		if res := d.Check(ok); res.RedactionsApplied != 0 {
			t.Errorf("%q must not be rewritten: %+v", ok, res.Incidents)
		}
	}
}
