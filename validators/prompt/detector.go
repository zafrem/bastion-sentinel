package prompt

import (
	"fmt"
	"math"
	"regexp"
	"strings"

	"github.com/zafrem/bastion-sentinel/config"
	"github.com/zafrem/bastion-sentinel/ml"
	"github.com/zafrem/bastion-sentinel/types"
	"golang.org/x/text/unicode/norm"
)

// Detector runs prompt injection detection using regex patterns, keyword matching,
// and optional ML scoring, then aggregates into a single risk score.
type Detector struct {
	cfg     config.PromptInjectionConfig
	regexes []*regexp.Regexp
	scorer  ml.Scorer
}

func New(cfg config.PromptInjectionConfig, scorer ml.Scorer) (*Detector, error) {
	d := &Detector{cfg: cfg, scorer: scorer}
	for _, rule := range cfg.RegexRules {
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, fmt.Errorf("rule %s: invalid regex %q: %w", rule.ID, rule.Pattern, err)
		}
		d.regexes = append(d.regexes, re)
	}
	return d, nil
}

func (d *Detector) Detect(query string) types.PromptCheckResult {
	normalized := norm.NFC.String(query)
	lower := strings.ToLower(normalized)

	var matched []string
	var activeMethods []string

	// regex matching
	if len(d.regexes) > 0 {
		activeMethods = append(activeMethods, "regex")
		for i, re := range d.regexes {
			if re.MatchString(normalized) {
				matched = append(matched, d.cfg.RegexRules[i].ID)
			}
		}
	}

	// keyword matching
	if len(d.cfg.KeywordRules) > 0 {
		activeMethods = append(activeMethods, "keyword")
		for _, kw := range d.cfg.KeywordRules {
			if strings.Contains(lower, strings.ToLower(kw.Keyword)) {
				matched = append(matched, kw.ID)
			}
		}
	}

	ruleScore := 0.0
	if len(matched) > 0 {
		ruleScore = 1.0
	}

	mlScore := 0.0
	if d.scorer != nil && d.cfg.MLModel.Enabled {
		score, err := d.scorer.Score(normalized)
		if err == nil {
			mlScore = score
			activeMethods = append(activeMethods, "ml")
		}
	}

	finalScore := aggregate(d.cfg.Scoring.Method, ruleScore, mlScore)

	status := types.StatusPassed
	if finalScore >= d.cfg.Scoring.BlockThreshold {
		status = types.StatusBlocked
	}

	return types.PromptCheckResult{
		Status:          status,
		RiskScore:       finalScore,
		Method:          strings.Join(activeMethods, "+"),
		MatchedPatterns: matched,
	}
}

func aggregate(method string, ruleScore, mlScore float64) float64 {
	switch method {
	case "weighted_avg":
		return ruleScore*0.6 + mlScore*0.4
	default: // "max"
		return math.Max(ruleScore, mlScore)
	}
}
