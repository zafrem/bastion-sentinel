package output_test

import (
	"strings"
	"testing"

	"github.com/zafrem/bastion-sentinel/config"
	"github.com/zafrem/bastion-sentinel/validators/output"
)

func check(t *testing.T, mut func(*config.HallucinationConfig), answer string, sources ...string) (string, float64, []string) {
	t.Helper()
	cfg := config.Default().OutputValidation.Hallucination
	if mut != nil {
		mut(&cfg)
	}
	r := output.NewHallucinationDetector(cfg).Check(answer, sources)
	return r.Status, r.GroundingScore, r.UngroundedClaims
}

// An answer on a different subject from its sources has no digits for the number check to
// catch; the word check does.
func TestContentSupport_FlagsAnswersAboutSomethingElse(t *testing.T) {
	for name, tc := range map[string]struct{ ans, src string }{
		"opening hours":    {"We are open around the clock and never close.", "Opening hours are 9 to 6 on weekdays and closed on weekends."},
		"contact channels": {"You can reach us by phone at any time and visit our office downtown.", "Our support team is available by email and chat."},
		"overstated":       {"The device is fully waterproof and can be used for diving in deep oceans.", "The device is water resistant."},
	} {
		status, score, missing := check(t, nil, tc.ans, tc.src)
		if status == "PASSED" || score >= 0.5 {
			t.Errorf("%s: should not be grounded, got %s %.2f", name, status, score)
		}
		if len(missing) == 0 || !strings.HasPrefix(missing[0], "unsupported:") {
			t.Errorf("%s: the unsupported words should be listed, got %v", name, missing)
		}
	}
}

func TestContentSupport_LeavesFaithfulAnswersAlone(t *testing.T) {
	for name, tc := range map[string]struct{ ans, src string }{
		"restated":    {"The warranty covers manufacturing defects for twelve months.", "Our warranty covers manufacturing defects for twelve months."},
		"paraphrase":  {"You can send items back within two weeks of buying them.", "Items may be returned within two weeks of purchase."},
		"shipping":    {"Orders to Europe arrive in five to seven business days.", "Shipping to Europe takes five to seven business days."},
		"elaborated":  {"Your password needs a minimum of twelve characters, and it has to include at least one number.", "Passwords must be at least twelve characters long and include a number."},
		"short":       {"No, it is closed on public holidays.", "The store is closed on public holidays."},
		"pleasantry":  {"Happy to help with that!", "Use the reset link on the sign-in page to choose a new login."},
		"yes":         {"Yes.", "Anything at all."},
		"korean":      {"구매 후 14일 이내에 환불이 가능합니다.", "환불은 구매 후 14일 이내에 가능합니다."},
		"punctuation": {"Open Mon-Fri, 9-6 (closed weekends).", "Opening hours are 9 to 6 on weekdays and closed on weekends."},
	} {
		status, score, _ := check(t, nil, tc.ans, tc.src)
		if status != "PASSED" {
			t.Errorf("%s: faithful answer flagged: %s %.2f", name, status, score)
		}
	}
}

func TestContentSupport_NumbersStillCountAndTheWeakerSignalWins(t *testing.T) {
	// Words are all supported, the number is not: the number check still fails it.
	_, score, _ := check(t, nil, "The warranty lasts 99 years and covers manufacturing defects.", "Our warranty covers manufacturing defects for twelve months.")
	if score != 0 {
		t.Errorf("an invented number must still score 0, got %.2f", score)
	}
	// Korean has no Latin words to judge, but its numbers are still checked.
	if status, _, _ := check(t, nil, "구매 후 90일 이내에 환불이 가능합니다.", "환불은 구매 후 14일 이내에 가능합니다."); status == "PASSED" {
		t.Error("a wrong number in Korean must still be caught")
	}
}

func TestContentSupport_CanBeSwitchedOffAndNeedsSources(t *testing.T) {
	off := func(c *config.HallucinationConfig) { c.ContentSupport = false }
	if status, score, _ := check(t, off, "We are open around the clock and never close.", "Opening hours are 9 to 6 on weekdays."); status != "PASSED" || score != 1 {
		t.Errorf("with content support off the old behaviour applies, got %s %.2f", status, score)
	}
	if status, _, _ := check(t, nil, "We are open around the clock and never close."); status != "PASSED" {
		t.Error("with no sources nothing can be checked")
	}
}

func TestContentSupport_MinimumWordsIsConfigurable(t *testing.T) {
	strict := func(c *config.HallucinationConfig) { c.MinContentWords = 1 }
	if status, _, _ := check(t, strict, "Midnight.", "Opening hours are 9 to 6."); status == "PASSED" {
		t.Error("with a one-word minimum an unsupported word is judged")
	}
	if status, _, _ := check(t, nil, "Midnight.", "Opening hours are 9 to 6."); status != "PASSED" {
		t.Error("by default very short answers are not judged")
	}
}

func TestContentSupport_LongInputStaysBounded(t *testing.T) {
	long := strings.Repeat("alpha beta gamma delta ", 100000)
	_, _, _ = check(t, nil, long, long)
}
