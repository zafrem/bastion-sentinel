package config

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"sort"

	"gopkg.in/yaml.v3"
)

// PolicyConfig lets different callers be held to different controls by the same engine, for example
// employees and the public.
//
// Each profile is a partial overlay on the base configuration: it names only what differs, and
// everything else is inherited. A profile may change four sections, prompt_injection,
// metadata_validation, output_validation and user_notice; anything else (ports, cache, events,
// exceptions) is global and is rejected in a profile. A list in an overlay replaces the base list
// rather than extending it.
//
// The profile for a request is chosen by the operator, from the request's tenant_id and the Tenants map
// below. A request cannot name its own profile, since a caller that can choose would choose the weakest.
// A tenant that is not listed gets DefaultProfile, or the base configuration when that is empty, so set
// DefaultProfile to your strictest profile if you serve tenants you have not listed.
type PolicyConfig struct {
	DefaultProfile string            `yaml:"default_profile"`
	Tenants        map[string]string `yaml:"tenants"`
	// Profiles holds the raw overlays. They are decoded (strictly) when a profile is built.
	Profiles map[string]yaml.Node `yaml:"profiles" json:"-"`
}

var profileName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// overlaySections are the parts of the configuration a profile may override.
type overlaySections struct {
	PromptInjection    *PromptInjectionConfig    `yaml:"prompt_injection"`
	MetadataValidation *MetadataValidationConfig `yaml:"metadata_validation"`
	OutputValidation   *OutputValidationConfig   `yaml:"output_validation"`
	UserNotice         *UserNoticeConfig         `yaml:"user_notice"`
}

// ProfileNames lists the declared profiles, sorted.
func (c *Config) ProfileNames() []string {
	names := make([]string, 0, len(c.Policy.Profiles))
	for n := range c.Policy.Profiles {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// ProfileFor returns the profile a tenant is held to: its mapped profile, else the default. An empty
// result means the base configuration.
func (c *Config) ProfileFor(tenantID string) string {
	if p, ok := c.Policy.Tenants[tenantID]; ok {
		return p
	}
	return c.Policy.DefaultProfile
}

// CheckPolicy validates the policy block: names are well formed, every profile a tenant or the default
// points to exists, and every overlay decodes cleanly onto the base (unknown or global keys fail).
func (c *Config) CheckPolicy() error {
	p := c.Policy
	for name := range p.Profiles {
		if !profileName.MatchString(name) {
			return fmt.Errorf("policy: profile name %q must be lower-case letters, digits, '-' or '_'", name)
		}
	}
	if p.DefaultProfile != "" {
		if _, ok := p.Profiles[p.DefaultProfile]; !ok {
			return fmt.Errorf("policy: default_profile %q is not defined under profiles", p.DefaultProfile)
		}
	}
	for tenant, name := range p.Tenants {
		if tenant == "" {
			return errors.New("policy: a tenants entry has an empty tenant id")
		}
		if _, ok := p.Profiles[name]; !ok {
			return fmt.Errorf("policy: tenant %q maps to %q, which is not defined under profiles", tenant, name)
		}
	}
	for _, name := range c.ProfileNames() {
		if _, err := c.ProfileConfig(name); err != nil {
			return err
		}
	}
	return nil
}

// ProfileConfig returns the effective configuration for a profile: a deep copy of the base with the
// profile's overlay applied. The empty name returns the base itself. The base is never modified.
func (c *Config) ProfileConfig(name string) (*Config, error) {
	if name == "" {
		return c, nil
	}
	node, ok := c.Policy.Profiles[name]
	if !ok {
		return nil, fmt.Errorf("policy: unknown profile %q", name)
	}
	cp := *c
	// A deep copy of the sections an overlay can touch, so a profile never edits the base's slices.
	raw, err := yaml.Marshal(overlaySections{&c.PromptInjection, &c.MetadataValidation, &c.OutputValidation, &c.UserNotice})
	if err != nil {
		return nil, fmt.Errorf("policy: copy base: %w", err)
	}
	dst := overlaySections{&cp.PromptInjection, &cp.MetadataValidation, &cp.OutputValidation, &cp.UserNotice}
	if err := yaml.Unmarshal(raw, &dst); err != nil {
		return nil, fmt.Errorf("policy: copy base: %w", err)
	}
	// The profile's own keys, decoded strictly so a typo or a global key is an error, not a silent no-op.
	body, err := yaml.Marshal(&node)
	if err != nil {
		return nil, fmt.Errorf("policy: profile %q: %w", name, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(body))
	dec.KnownFields(true)
	if err := dec.Decode(&dst); err != nil && err.Error() != "EOF" {
		return nil, fmt.Errorf("policy: profile %q: %w (a profile may set only prompt_injection, metadata_validation, output_validation, user_notice)", name, err)
	}
	cp.Policy = PolicyConfig{} // an effective profile config does not nest policies
	return &cp, nil
}
