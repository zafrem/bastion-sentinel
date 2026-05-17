package metadata

import (
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/zafrem/bastion-sentinel/config"
	"github.com/zafrem/bastion-sentinel/types"
)

var reservedIdentifiers = map[string]bool{
	"system": true,
	"admin":  true,
	"root":   true,
}

// Validator checks incoming metadata for structural correctness and business rule compliance.
type Validator struct {
	cfg      config.MetadataValidationConfig
	patterns map[string]*regexp.Regexp
}

func New(cfg config.MetadataValidationConfig) (*Validator, error) {
	v := &Validator{
		cfg:      cfg,
		patterns: make(map[string]*regexp.Regexp),
	}
	for field, rule := range cfg.FieldRules {
		if rule.Pattern == "" {
			continue
		}
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, fmt.Errorf("field %s: invalid pattern %q: %w", field, rule.Pattern, err)
		}
		v.patterns[field] = re
	}
	return v, nil
}

func (v *Validator) Validate(metadata map[string]string, query string) types.MetadataCheckResult {
	// required field presence check — fail fast
	var missing []string
	for _, field := range v.cfg.RequiredFields {
		if _, ok := metadata[field]; !ok {
			missing = append(missing, field)
		}
	}
	if len(missing) > 0 {
		return types.MetadataCheckResult{
			Status:        types.StatusBlocked,
			MissingFields: missing,
		}
	}

	var errs []string

	// field format rules
	for field, rule := range v.cfg.FieldRules {
		val, ok := metadata[field]
		if !ok {
			continue
		}

		if re, ok := v.patterns[field]; ok && !re.MatchString(val) {
			errs = append(errs, fmt.Sprintf("%s: invalid format (must match %s)", field, rule.Pattern))
		}
		if rule.MinLength > 0 && len(val) < rule.MinLength {
			errs = append(errs, fmt.Sprintf("%s: too short (min %d chars)", field, rule.MinLength))
		}
		if rule.MaxLength > 0 && len(val) > rule.MaxLength {
			errs = append(errs, fmt.Sprintf("%s: too long (max %d chars)", field, rule.MaxLength))
		}

		switch rule.Format {
		case "uuid":
			if _, err := uuid.Parse(val); err != nil {
				errs = append(errs, fmt.Sprintf("%s: must be a valid UUID v4", field))
			}
		case "rfc3339":
			if _, err := time.Parse(time.RFC3339, val); err != nil {
				errs = append(errs, fmt.Sprintf("%s: must be a valid RFC3339 timestamp", field))
			}
		}
	}

	// business rules
	errs = append(errs, v.checkBusinessRules(metadata)...)

	// payload size limits
	if utf8.RuneCountInString(query) > 10000 {
		errs = append(errs, "query: exceeds maximum length of 10000 characters")
	}
	if metadataByteSize(metadata) > 4096 {
		errs = append(errs, "metadata: total payload exceeds 4KB limit")
	}

	status := types.StatusPassed
	if len(errs) > 0 {
		status = types.StatusBlocked
	}
	return types.MetadataCheckResult{
		Status:       status,
		FormatErrors: errs,
	}
}

func (v *Validator) checkBusinessRules(metadata map[string]string) []string {
	var errs []string

	for _, rule := range v.cfg.BusinessRules {
		if !rule.Enabled {
			continue
		}
		switch rule.Name {
		case "timestamp_bounds":
			if ts, ok := metadata["timestamp"]; ok {
				t, err := time.Parse(time.RFC3339, ts)
				if err == nil {
					diff := time.Since(t)
					if diff > time.Hour || diff < -time.Hour {
						errs = append(errs, "timestamp: outside allowed window (±1 hour from current time)")
					}
				}
			}
		case "reserved_identifiers":
			for _, field := range []string{"tenant_id", "user_id"} {
				if val, ok := metadata[field]; ok {
					if reservedIdentifiers[strings.ToLower(val)] {
						errs = append(errs, fmt.Sprintf("%s: reserved identifier not allowed", field))
					}
				}
			}
		}
	}
	return errs
}

func metadataByteSize(metadata map[string]string) int {
	total := 0
	for k, v := range metadata {
		total += len(k) + len(v)
	}
	return total
}
