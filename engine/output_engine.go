package engine

import (
	"time"

	"github.com/zafrem/bastion-sentinel/config"
	"github.com/zafrem/bastion-sentinel/types"
	"github.com/zafrem/bastion-sentinel/validators/output"
)

// OutputEngine orchestrates all Sentinel-OUT validators (PII re-emergence,
// hallucination, content filter, permission boundary, format).
type OutputEngine struct {
	pii        *output.PIIDetector
	halluc     *output.HallucinationDetector
	content    *output.ContentFilter
	permission *output.PermissionChecker
	format     *output.FormatValidator
	cfg        config.OutputValidationConfig
}

// NewOutputEngine builds an OutputEngine from the supplied configuration.
// Returns an error if any compiled regex pattern is invalid.
func NewOutputEngine(cfg *config.Config) (*OutputEngine, error) {
	pii, err := output.NewPIIDetector(cfg.OutputValidation.PIIReemergence)
	if err != nil {
		return nil, err
	}
	content, err := output.NewContentFilter(cfg.OutputValidation.ContentFilter)
	if err != nil {
		return nil, err
	}
	return &OutputEngine{
		pii:        pii,
		halluc:     output.NewHallucinationDetector(cfg.OutputValidation.Hallucination),
		content:    content,
		permission: output.NewPermissionChecker(cfg.OutputValidation.PermissionCheck),
		format:     output.NewFormatValidator(cfg.OutputValidation.Format),
		cfg:        cfg.OutputValidation,
	}, nil
}

// Validate runs all enabled checks against the LLM response in req and returns
// a sanitized (or blocked) OutputValidateResponse.
func (e *OutputEngine) Validate(req types.OutputValidateRequest) types.OutputValidateResponse {
	start := time.Now()

	opts := normaliseOptions(req.Options)

	// ── Format check (always runs; reject immediately on failure) ──────────────
	formatResult := e.format.Check(req.LLMResponse)
	if formatResult.Status == "FAILED" {
		return types.OutputValidateResponse{
			RequestID: req.RequestID,
			Status:    types.OutputStatusBlocked,
			ValidatedResponse: "Response rejected: format validation failed.",
			Checks:           types.OutputValidationResults{FormatCheck: formatResult},
			ProcessingTimeMs: msElapsed(start),
		}
	}

	// ── PII re-emergence ───────────────────────────────────────────────────────
	var piiResult types.PIICheckResult
	if e.cfg.PIIReemergence.Enabled && opts.CheckPIIReemergence {
		piiResult = e.pii.Check(req.LLMResponse)
	} else {
		piiResult = types.PIICheckResult{Status: "SKIPPED"}
	}

	// ── Hallucination ──────────────────────────────────────────────────────────
	var hallucResult types.HallucinationCheckResult
	if e.cfg.Hallucination.Enabled && opts.CheckHallucination {
		hallucResult = e.halluc.Check(req.LLMResponse, req.Retrieval.SourceDocuments)
	} else {
		hallucResult = types.HallucinationCheckResult{Status: "SKIPPED"}
	}

	// ── Content filter ─────────────────────────────────────────────────────────
	var contentResult types.ContentCheckResult
	if e.cfg.ContentFilter.Enabled && opts.CheckContent {
		contentResult = e.content.Check(req.LLMResponse)
	} else {
		contentResult = types.ContentCheckResult{Status: "SKIPPED"}
	}

	// ── Permission boundary ────────────────────────────────────────────────────
	var permResult types.PermissionCheckResult
	if e.cfg.PermissionCheck.Enabled && opts.CheckPermission {
		permResult = e.permission.Check(req.LLMResponse, req.User)
	} else {
		permResult = types.PermissionCheckResult{Status: "SKIPPED"}
	}

	// ── Aggregate results ──────────────────────────────────────────────────────
	validatedResponse := req.LLMResponse
	var allMods []types.Modification
	finalStatus := types.OutputStatusPassed

	// Content block takes priority; WARNING is surfaced as-is.
	if contentResult.Status == "BLOCKED" {
		finalStatus = types.OutputStatusBlocked
		validatedResponse = "This response has been blocked due to content policy violations."
	} else if contentResult.Status == "WARNING" {
		finalStatus = types.OutputStatusWarning
	}

	// Permission violation: block in strict mode, sanitize otherwise.
	if permResult.BoundaryViolated && finalStatus != types.OutputStatusBlocked {
		if opts.StrictMode {
			finalStatus = types.OutputStatusBlocked
			validatedResponse = "This information requires additional permissions to view."
		} else {
			finalStatus = types.OutputStatusSanitized
		}
	}

	// PII: sanitize (or block in strict+critical mode).
	if piiResult.Status == "VIOLATIONS_DETECTED" && finalStatus != types.OutputStatusBlocked {
		sanitized, mods := e.pii.Sanitize(req.LLMResponse, piiResult.Incidents)
		if opts.StrictMode && e.cfg.PIIReemergence.BlockOnCritical && output.HasCritical(piiResult.Incidents) {
			finalStatus = types.OutputStatusBlocked
			validatedResponse = "This response contained sensitive information and has been blocked."
		} else {
			finalStatus = types.OutputStatusSanitized
			validatedResponse = sanitized
			allMods = append(allMods, mods...)
		}
	}

	// Hallucination: add disclaimer or block.
	if hallucResult.Status == "SUSPICIOUS" || hallucResult.Status == "FAILED" {
		if hallucResult.Status == "FAILED" && e.cfg.Hallucination.BlockOnLowScore &&
			finalStatus == types.OutputStatusPassed {
			finalStatus = types.OutputStatusBlocked
			validatedResponse = "This response could not be verified against the provided context."
		} else if e.cfg.Hallucination.AddDisclaimer && finalStatus == types.OutputStatusPassed {
			disclaimer := "\n\n[Note: Some claims in this response could not be fully verified against the provided sources.]"
			validatedResponse += disclaimer
			finalStatus = types.OutputStatusWarning
			allMods = append(allMods, types.Modification{
				Type:        "disclaimer_added",
				Replacement: disclaimer,
			})
		}
	}

	return types.OutputValidateResponse{
		RequestID:         req.RequestID,
		Status:            finalStatus,
		ValidatedResponse: validatedResponse,
		Checks: types.OutputValidationResults{
			PIICheck:           piiResult,
			HallucinationCheck: hallucResult,
			ContentCheck:       contentResult,
			PermissionCheck:    permResult,
			FormatCheck:        formatResult,
		},
		Modifications:    allMods,
		ProcessingTimeMs: msElapsed(start),
	}
}

// normaliseOptions converts a zero-value Options (all false) into "run everything".
func normaliseOptions(opts types.OutputValidationOptions) types.OutputValidationOptions {
	if !opts.CheckPIIReemergence && !opts.CheckHallucination &&
		!opts.CheckContent && !opts.CheckPermission {
		opts.CheckPIIReemergence = true
		opts.CheckHallucination = true
		opts.CheckContent = true
		opts.CheckPermission = true
	}
	return opts
}

func msElapsed(start time.Time) float64 {
	return float64(time.Since(start).Microseconds()) / 1000.0
}
