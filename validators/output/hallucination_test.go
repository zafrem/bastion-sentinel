package output_test

import (
	"testing"

	"github.com/zafrem/bastion-sentinel/config"
	"github.com/zafrem/bastion-sentinel/validators/output"
)

func defaultHallucinationDetector() *output.HallucinationDetector {
	return output.NewHallucinationDetector(config.Default().OutputValidation.Hallucination)
}

func TestHallucination_NoClaims(t *testing.T) {
	d := defaultHallucinationDetector()
	result := d.Check("This product is great.", []string{"product is great"})
	if result.Status != "PASSED" {
		t.Errorf("expected PASSED for claim-free response, got %s", result.Status)
	}
	if result.GroundingScore != 1.0 {
		t.Errorf("expected score 1.0, got %f", result.GroundingScore)
	}
}

func TestHallucination_NoSources(t *testing.T) {
	d := defaultHallucinationDetector()
	result := d.Check("Revenue was $1,000,000 last year.", nil)
	if result.Status != "PASSED" {
		t.Errorf("expected PASSED with no sources (skip grounding), got %s", result.Status)
	}
}

func TestHallucination_AllGrounded(t *testing.T) {
	d := defaultHallucinationDetector()
	sources := []string{"Q3 revenue was $5,000,000. Date: 2026-01-15."}
	result := d.Check("Revenue was $5,000,000. Date: 2026-01-15.", sources)
	if result.Status != "PASSED" {
		t.Errorf("expected PASSED when all claims grounded, got %s", result.Status)
	}
	if result.GroundingScore < 0.9 {
		t.Errorf("expected high grounding score, got %f", result.GroundingScore)
	}
}

func TestHallucination_Ungrounded(t *testing.T) {
	d := defaultHallucinationDetector()
	sources := []string{"The product exists in the catalog."}
	result := d.Check("The product costs $9,999.", sources)
	if len(result.UngroundedClaims) == 0 {
		t.Error("expected ungrounded claims for fabricated price")
	}
}

func TestHallucination_SuspiciousScore(t *testing.T) {
	cfg := config.HallucinationConfig{
		Enabled:            true,
		GroundingThreshold: 0.9,
		LowScoreThreshold:  0.3,
	}
	d := output.NewHallucinationDetector(cfg)
	// Provide sources that ground some but not all claims
	sources := []string{"Revenue was $5,000,000"}
	result := d.Check("Revenue was $5,000,000. Total was $9,999. Growth: 42%.", sources)
	if result.Status == "PASSED" {
		t.Error("expected SUSPICIOUS or FAILED for partially ungrounded response")
	}
}

func TestHallucination_Method(t *testing.T) {
	d := defaultHallucinationDetector()
	result := d.Check("No claims here.", []string{"context"})
	if result.Method != "heuristic" {
		t.Errorf("expected method 'heuristic', got %q", result.Method)
	}
}
