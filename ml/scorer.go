package ml

import (
	"math"
	"regexp"
	"strings"
	"unicode"

	"github.com/zafrem/bastion-sentinel/config"
)

// Scorer is the interface for ML-based prompt injection risk scoring.
// Implementations return a risk probability in [0.0, 1.0].
type Scorer interface {
	Score(query string) (float64, error)
}

// OnnxStub satisfies Scorer as a zero-returning stub when only rule-based scoring is desired.
type OnnxStub struct{}

func (s *OnnxStub) Score(_ string) (float64, error) {
	return 0.0, nil
}

// HeuristicScorer is a lightweight, zero-CGO logistic feature scorer that evaluates
// structural, lexical, and obfuscation signals (imperative role-overrides, delimiter
// escapes, base64/hex payloads, and multilingual prompt-leak markers) and maps the
// weighted log-odds into [0.0, 1.0] via a logistic sigmoid.
type HeuristicScorer struct{}

var (
	reRoleOverride = regexp.MustCompile(`(?i)\b(ignore|disregard|forget|override|bypass)\b.{0,40}\b(previous|above|prior|system|developer|instructions?|rules?|constraints?|guardrails?)\b`)
	rePersonaTake  = regexp.MustCompile(`(?i)\b(you are now|act as|pretend to be|simulate|developer mode|jailbreak|dan mode|unrestricted|do anything now)\b`)
	rePromptExfil  = regexp.MustCompile(`(?i)\b(reveal|print|show|output|repeat|dump|leak)\b.{0,40}\b(system prompt|hidden prompt|initial instructions|secret key|confidential)\b`)
	reDelimEscape  = regexp.MustCompile("(?s)(```\\s*(system|assistant|developer)|<\\|im_start\\|>|<\\|system\\|>|\\[INST\\]|\\[/INST\\]|###\\s*(System|Instruction))")
	reBase64Blob   = regexp.MustCompile(`\b[A-Za-z0-9+/]{32,}={0,2}\b`)
	reKoreanInj    = regexp.MustCompile(`(이전\s*지시|시스템\s*프롬프트|관리자\s*모드|제한\s*없이|규칙.*무시)`)
)

func (h *HeuristicScorer) Score(query string) (float64, error) {
	q := strings.TrimSpace(query)
	if q == "" {
		return 0.0, nil
	}

	// Base log-odds (prior ~ 0.03 for benign queries).
	logit := -3.5

	if reRoleOverride.MatchString(q) {
		logit += 4.2
	}
	if rePersonaTake.MatchString(q) {
		logit += 3.8
	}
	if rePromptExfil.MatchString(q) {
		logit += 3.8
	}
	if reDelimEscape.MatchString(q) {
		logit += 3.5
	}
	if reKoreanInj.MatchString(q) {
		logit += 4.0
	}
	if reBase64Blob.MatchString(q) {
		logit += 2.2
	}

	// Punctuation / control-character density anomaly (typical of token-smuggling payloads).
	var special, total int
	for _, r := range q {
		total++
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			special += 3
		} else if strings.ContainsRune("<>|{}[]\\`~^", r) {
			special++
		}
	}
	if total > 16 && float64(special)/float64(total) > 0.18 {
		logit += 1.8
	}

	prob := 1.0 / (1.0 + math.Exp(-logit))
	return math.Round(prob*10000) / 10000, nil
}

// NewScorer returns a HeuristicScorer when ML scoring is enabled and an OnnxStub when it is
// disabled. The configured model path is not used: the heuristic scorer needs no model file.
func NewScorer(cfg config.MLModelConfig) Scorer {
	if cfg.Enabled {
		return &HeuristicScorer{}
	}
	return &OnnxStub{}
}

