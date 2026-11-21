package prompt

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"

	"github.com/zafrem/bastion-sentinel/config"
	"github.com/zafrem/bastion-sentinel/ml"
	"github.com/zafrem/bastion-sentinel/types"
)

// Detector runs prompt injection detection using regex patterns, keyword matching,
// and optional ML scoring, then aggregates into a single risk score.
type Detector struct {
	cfg     config.PromptInjectionConfig
	regexes []*regexp.Regexp
	scorer  ml.Scorer
	// severity maps a rule ID to its severity, for scoring.
	severity map[string]string
}

// ruleWeight is how much a single matching rule counts towards the risk score.
// critical and high rules decide on their own, as they always have. A medium rule
// is only a hint (for example "for educational purposes" or a mention of the topic):
// alone it stays under the block threshold, and it takes corroboration to block.
// A rule with no or an unknown severity is treated as high, so custom configs keep
// their old behaviour.
func ruleWeight(severity string) float64 {
	switch strings.ToLower(severity) {
	case "low":
		return 0.25
	case "medium":
		return 0.5
	default:
		return 1.0
	}
}

// ruleScore combines the weights of every matched rule: the strongest one, plus a
// quarter of the next ones, capped at 1. Two medium rules together reach 0.75.
func ruleScore(weights []float64) float64 {
	if len(weights) == 0 {
		return 0
	}
	top, rest := 0.0, 0.0
	for _, w := range weights {
		if w > top {
			rest += top
			top = w
		} else {
			rest += w
		}
	}
	return math.Min(1.0, top+0.25*rest)
}

func New(cfg config.PromptInjectionConfig, scorer ml.Scorer) (*Detector, error) {
	d := &Detector{cfg: cfg, scorer: scorer, severity: map[string]string{}}
	for _, rule := range cfg.RegexRules {
		d.severity[rule.ID] = rule.Severity
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, fmt.Errorf("rule %s: invalid regex %q: %w", rule.ID, rule.Pattern, err)
		}
		d.regexes = append(d.regexes, re)
	}
	for _, kw := range cfg.KeywordRules {
		d.severity[kw.ID] = kw.Severity
	}
	return d, nil
}

func (d *Detector) Detect(query string) types.PromptCheckResult {
	return d.DetectExcept(query, nil)
}

// DetectExcept is Detect, but a pattern for which exempt returns true is
// ignored when scoring (it is still reported as ExemptedPatterns). exempt may
// be nil.
func (d *Detector) DetectExcept(query string, exempt func(patternID string) (exceptionID string, ok bool)) types.PromptCheckResult {
	// Rules run on the query as sent and on every decoded or normalised view of it
	// (base64, hex, URL-encoding, invisible characters, full-width forms), so hiding
	// an attack does not hide it from the rules.
	cands := Candidates(query)
	normalized := cands[0].Text

	var matched []string
	var activeMethods []string
	seen := map[string]bool{}
	decodedVia := map[string]bool{}
	hit := func(id, encoding string) {
		if seen[id] {
			return
		}
		seen[id] = true
		matched = append(matched, id)
		if encoding != "" {
			decodedVia[encoding] = true
		}
	}

	if len(d.regexes) > 0 {
		activeMethods = append(activeMethods, "regex")
	}
	if len(d.cfg.KeywordRules) > 0 {
		activeMethods = append(activeMethods, "keyword")
	}
	for _, c := range cands {
		lower := strings.ToLower(c.Text)
		for i, re := range d.regexes {
			if re.MatchString(c.Text) {
				hit(d.cfg.RegexRules[i].ID, c.Encoding)
			}
		}
		for _, kw := range d.cfg.KeywordRules {
			if strings.Contains(lower, strings.ToLower(kw.Keyword)) {
				hit(kw.ID, c.Encoding)
			}
		}
	}
	if len(decodedVia) > 0 {
		var enc []string
		for e := range decodedVia {
			enc = append(enc, e)
		}
		sort.Strings(enc)
		activeMethods = append(activeMethods, "decoded("+strings.Join(enc, ",")+")")
	}

	var exemptedPatterns, exceptionIDs []string
	if exempt != nil && len(matched) > 0 {
		kept := matched[:0:0]
		for _, id := range matched {
			if excID, ok := exempt(id); ok {
				exemptedPatterns = append(exemptedPatterns, id)
				exceptionIDs = append(exceptionIDs, excID)
				continue
			}
			kept = append(kept, id)
		}
		matched = kept
	}

	var weights []float64
	for _, id := range matched {
		weights = append(weights, ruleWeight(d.severity[id]))
	}
	rScore := ruleScore(weights)

	mlScore := 0.0
	if d.scorer != nil && d.cfg.MLModel.Enabled {
		// A slow (model-backed) scorer is skipped once the rules have already blocked.
		if c, slow := d.scorer.(ml.Costly); slow && c.Costly() && rScore >= d.cfg.Scoring.BlockThreshold {
			activeMethods = append(activeMethods, "ml-skipped")
		} else if score, err := d.scorer.Score(normalized); err == nil {
			mlScore = score
			activeMethods = append(activeMethods, "ml")
		} else {
			// The rules above still decide; say that the model could not be used.
			mlScore = score
			activeMethods = append(activeMethods, "ml-unavailable")
		}
	}

	finalScore := aggregate(d.cfg.Scoring.Method, rScore, mlScore)

	status := types.StatusPassed
	if finalScore >= d.cfg.Scoring.BlockThreshold {
		status = types.StatusBlocked
	}

	return types.PromptCheckResult{
		Status:           status,
		RiskScore:        finalScore,
		Method:           strings.Join(activeMethods, "+"),
		MatchedPatterns:  matched,
		ExemptedPatterns: exemptedPatterns,
		ExceptionIDs:     exceptionIDs,
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
