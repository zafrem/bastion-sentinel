package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/zafrem/bastion-sentinel/config"
)

func load(t *testing.T, doc string) (*config.Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return config.Load(p)
}

const goodPolicy = `
policy:
  default_profile: external
  tenants:
    corp: internal
  profiles:
    internal:
      user_notice: { detail: category }
    external:
      user_notice: { detail: minimal }
      prompt_injection:
        scoring: { block_threshold: 0.5 }
      output_validation:
        format: { min_length: 20 }
`

func TestPolicy_NoneByDefaultAndEverythingStillLoads(t *testing.T) {
	c := config.Default()
	if err := c.CheckPolicy(); err != nil {
		t.Fatal(err)
	}
	if c.ProfileFor("anyone") != "" || len(c.ProfileNames()) != 0 {
		t.Error("with no policy every tenant gets the base configuration")
	}
}

func TestPolicy_OverlayChangesOnlyWhatItNames(t *testing.T) {
	c, err := load(t, goodPolicy)
	if err != nil {
		t.Fatal(err)
	}
	ext, err := c.ProfileConfig("external")
	if err != nil {
		t.Fatal(err)
	}
	if ext.PromptInjection.Scoring.BlockThreshold != 0.5 || ext.OutputValidation.Format.MinLength != 20 || ext.UserNotice.Detail != "minimal" {
		t.Errorf("overlay not applied: %+v", ext.PromptInjection.Scoring)
	}
	// Everything the overlay did not mention is inherited, including sibling fields in a touched section.
	if ext.PromptInjection.Scoring.Method != c.PromptInjection.Scoring.Method {
		t.Error("a sibling field in a touched section must be inherited")
	}
	if len(ext.PromptInjection.RegexRules) != len(c.PromptInjection.RegexRules) || ext.OutputValidation.Format.MaxLength != 10000 {
		t.Error("untouched settings must be inherited")
	}
	if ext.Server.RESTPort != c.Server.RESTPort {
		t.Error("global settings are inherited")
	}
}

func TestPolicy_ProfileNeverEditsTheBase(t *testing.T) {
	c, err := load(t, `
policy:
  profiles:
    odd:
      prompt_injection:
        scoring: { block_threshold: 0.1 }
        regex_rules:
          - { id: only-one, pattern: "x", severity: high }
`)
	if err != nil {
		t.Fatal(err)
	}
	baseRules, baseThreshold := len(c.PromptInjection.RegexRules), c.PromptInjection.Scoring.BlockThreshold
	odd, err := c.ProfileConfig("odd")
	if err != nil {
		t.Fatal(err)
	}
	if len(odd.PromptInjection.RegexRules) != 1 {
		t.Errorf("a list in an overlay replaces the base list, got %d rules", len(odd.PromptInjection.RegexRules))
	}
	if len(c.PromptInjection.RegexRules) != baseRules || c.PromptInjection.Scoring.BlockThreshold != baseThreshold {
		t.Error("building a profile must not change the base")
	}
	odd.PromptInjection.RegexRules[0].ID = "changed"
	if c.PromptInjection.RegexRules[0].ID == "changed" {
		t.Error("the copy must not share memory with the base")
	}
}

// The deep copy goes through YAML, so every field of the sections must survive the trip.
func TestPolicy_CopyOfDefaultsIsLossless(t *testing.T) {
	c, err := load(t, "policy:\n  profiles:\n    same: {}\n")
	if err != nil {
		t.Fatal(err)
	}
	same, err := c.ProfileConfig("same")
	if err != nil {
		t.Fatal(err)
	}
	type sections struct {
		P  config.PromptInjectionConfig    `yaml:"p"`
		M  config.MetadataValidationConfig `yaml:"m"`
		O  config.OutputValidationConfig   `yaml:"o"`
		UN config.UserNoticeConfig         `yaml:"u"`
	}
	a, _ := yaml.Marshal(sections{c.PromptInjection, c.MetadataValidation, c.OutputValidation, c.UserNotice})
	b, _ := yaml.Marshal(sections{same.PromptInjection, same.MetadataValidation, same.OutputValidation, same.UserNotice})
	if string(a) != string(b) {
		t.Error("an empty profile must be identical to the base")
	}
}

func TestPolicy_ProfileForUsesTenantThenDefault(t *testing.T) {
	c, err := load(t, goodPolicy)
	if err != nil {
		t.Fatal(err)
	}
	for tenant, want := range map[string]string{"corp": "internal", "unlisted": "external", "": "external"} {
		if got := c.ProfileFor(tenant); got != want {
			t.Errorf("tenant %q: got %q want %q", tenant, got, want)
		}
	}
}

func TestPolicy_BadConfigurationIsRefused(t *testing.T) {
	for name, tc := range map[string]struct{ doc, want string }{
		"default not defined": {"policy: { default_profile: nope, profiles: { a: {} } }", "default_profile"},
		"tenant not defined":  {"policy: { tenants: { t1: nope }, profiles: { a: {} } }", "not defined"},
		"bad name":            {"policy: { profiles: { 'Has Space': {} } }", "profile name"},
		"empty tenant id":     {"policy: { tenants: { '': a }, profiles: { a: {} } }", "empty tenant"},
		"global key":          {"policy: { profiles: { a: { server: { rest_port: 1 } } } }", "may set only"},
		"typo in a section":   {"policy: { profiles: { a: { prompt_injection: { scorring: {} } } } }", "scorring"},
		"typo in a field":     {"policy: { profiles: { a: { output_validation: { format: { min_lenth: 3 } } } } }", "min_lenth"},
		"wrong type":          {"policy: { profiles: { a: { user_notice: { detail: [1] } } } }", "profile"},
	} {
		_, err := load(t, tc.doc)
		if err == nil {
			t.Errorf("%s: should be refused", name)
		} else if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error should mention %q, got: %v", name, tc.want, err)
		}
	}
}
