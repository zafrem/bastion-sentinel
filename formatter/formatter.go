package formatter

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/zafrem/bastion-sentinel/types"
)

func Write(w io.Writer, resp types.ValidateResponse, format string) error {
	switch format {
	case "json":
		return writeJSON(w, resp)
	case "compact":
		return writeCompact(w, resp)
	default: // "text"
		return writeText(w, resp)
	}
}

func writeJSON(w io.Writer, resp types.ValidateResponse) error {
	patterns := resp.PromptCheck.MatchedPatterns
	if patterns == nil {
		patterns = []string{}
	}
	missing := resp.MetadataCheck.MissingFields
	if missing == nil {
		missing = []string{}
	}
	fmtErrors := resp.MetadataCheck.FormatErrors
	if fmtErrors == nil {
		fmtErrors = []string{}
	}

	out := map[string]any{
		"request_id":          resp.RequestID,
		"status":              resp.Status,
		"timestamp":           resp.Timestamp.Format(time.RFC3339Nano),
		"processing_time_ms":  resp.ProcessingTimeMs,
		"checks": map[string]any{
			"prompt_injection": map[string]any{
				"status":           resp.PromptCheck.Status,
				"risk_score":       resp.PromptCheck.RiskScore,
				"method":           resp.PromptCheck.Method,
				"matched_patterns": patterns,
			},
			"metadata_validation": map[string]any{
				"status":         resp.MetadataCheck.Status,
				"missing_fields": missing,
				"format_errors":  fmtErrors,
			},
		},
		"extracted_data": map[string]any{
			"tenant_id":     resp.ExtractedData.TenantID,
			"user_id":       resp.ExtractedData.UserID,
			"cleaned_query": resp.ExtractedData.CleanedQuery,
		},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func writeCompact(w io.Writer, resp types.ValidateResponse) error {
	metaStatus := "OK"
	if resp.MetadataCheck.Status == types.StatusBlocked {
		metaStatus = "FAIL"
	}

	extra := ""
	if resp.Status == types.StatusBlocked {
		if len(resp.PromptCheck.MatchedPatterns) > 0 {
			extra = fmt.Sprintf(" reason=%q", "injection pattern")
		} else if len(resp.MetadataCheck.MissingFields) > 0 || len(resp.MetadataCheck.FormatErrors) > 0 {
			extra = fmt.Sprintf(" reason=%q", "invalid metadata")
		}
	}

	_, err := fmt.Fprintf(w, "[%s] %s prompt=%.2f meta=%s time=%.1fms%s\n",
		resp.RequestID,
		resp.Status,
		resp.PromptCheck.RiskScore,
		metaStatus,
		resp.ProcessingTimeMs,
		extra,
	)
	return err
}

func writeText(w io.Writer, resp types.ValidateResponse) error {
	border := strings.Repeat("═", 44)
	divider := strings.Repeat("─", 44)

	statusLabel := func(s types.Status) string {
		if s == types.StatusPassed {
			return "✅ PASSED"
		}
		return "🚫 BLOCKED"
	}

	riskLabel := func(score float64) string {
		switch {
		case score >= 0.9:
			return "Critical"
		case score >= 0.7:
			return "High"
		case score >= 0.4:
			return "Medium"
		default:
			return "Low"
		}
	}

	lines := []string{
		border,
		"  Bastion-Sentinel Validation Report",
		border,
		fmt.Sprintf("Request ID:      %s", resp.RequestID),
		fmt.Sprintf("Timestamp:       %s", resp.Timestamp.Format("2006-01-02 15:04:05.000")),
		fmt.Sprintf("Processing Time: %.2f ms", resp.ProcessingTimeMs),
		fmt.Sprintf("Final Status:    %s", statusLabel(resp.Status)),
		"",
		fmt.Sprintf("%s Prompt Injection Check %s", divider[:3], ""),
		fmt.Sprintf("Status:          %s", statusLabel(resp.PromptCheck.Status)),
		fmt.Sprintf("Risk Score:      %.2f / 1.00 (%s)", resp.PromptCheck.RiskScore, riskLabel(resp.PromptCheck.RiskScore)),
		fmt.Sprintf("Method:          %s", resp.PromptCheck.Method),
	}

	if len(resp.PromptCheck.MatchedPatterns) == 0 {
		lines = append(lines, "Matched Patterns: (None)")
	} else {
		lines = append(lines, "Matched Patterns:")
		for _, p := range resp.PromptCheck.MatchedPatterns {
			lines = append(lines, fmt.Sprintf("  - %q", p))
		}
	}

	lines = append(lines,
		"",
		fmt.Sprintf("%s Metadata Verification %s", divider[:3], ""),
		fmt.Sprintf("Status:          %s", statusLabel(resp.MetadataCheck.Status)),
	)

	if len(resp.MetadataCheck.MissingFields) > 0 {
		lines = append(lines, fmt.Sprintf("Missing Fields:  %s", strings.Join(resp.MetadataCheck.MissingFields, ", ")))
	}
	if len(resp.MetadataCheck.FormatErrors) == 0 {
		lines = append(lines, "Format Check:    ✅ All fields valid")
	} else {
		lines = append(lines, "Format Errors:")
		for _, e := range resp.MetadataCheck.FormatErrors {
			lines = append(lines, fmt.Sprintf("  - %s", e))
		}
	}

	lines = append(lines,
		"",
		fmt.Sprintf("%s Extracted Data %s", divider[:3], ""),
		fmt.Sprintf("Tenant ID:       %s", resp.ExtractedData.TenantID),
		fmt.Sprintf("User ID:         %s", resp.ExtractedData.UserID),
		fmt.Sprintf("Cleaned Query:   %q", resp.ExtractedData.CleanedQuery),
		"",
		fmt.Sprintf("%s Next Action %s", divider[:3], ""),
	)

	if resp.Status == types.StatusPassed {
		lines = append(lines, "→ Forward to Module C (Vault)")
	} else {
		lines = append(lines, "→ Reject Request (HTTP 403 Forbidden)")
		if resp.PromptCheck.Status == types.StatusBlocked {
			lines = append(lines, "→ Dispatch security incident alert")
		}
	}
	lines = append(lines, border, "")

	_, err := fmt.Fprintln(w, strings.Join(lines, "\n"))
	return err
}
