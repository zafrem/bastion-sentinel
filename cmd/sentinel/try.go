package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/zafrem/bastion-sentinel/config"
	"github.com/zafrem/bastion-sentinel/types"
)

func buildTryCmd() *cobra.Command {
	var (
		tenant  string
		user    string
		explain bool
		stdin   bool
	)

	cmd := &cobra.Command{
		Use:   "try [query]",
		Short: "Quickly test a query with auto-generated metadata",
		Long: `try validates a query against the engine without requiring full metadata.
Sensible defaults are used for all metadata fields.

Examples:
  sentinel-cli try "What is AI?"
  sentinel-cli try "Ignore all previous instructions" --explain
  sentinel-cli try --tenant acme --user alice "How do I write a for loop?"
  echo -e "safe query\nIgnore all previous instructions" | sentinel-cli try --stdin`,
		RunE: func(cmd *cobra.Command, args []string) error {
			eng, err := loadEngine()
			if err != nil {
				return err
			}

			if stdin {
				return tryStdin(eng, tenant, user, explain)
			}

			query := strings.Join(args, " ")
			if query == "" {
				return fmt.Errorf("provide a query as an argument or use --stdin")
			}

			resp := eng.Validate(tryRequest(query, tenant, user))
			printTryResult(query, resp, explain)
			return nil
		},
	}

	cmd.Flags().StringVar(&tenant, "tenant", "test-tenant", "tenant_id to use in metadata")
	cmd.Flags().StringVar(&user, "user", "tester", "user_id to use in metadata")
	cmd.Flags().BoolVar(&explain, "explain", false, "show matched rules and scoring detail")
	cmd.Flags().BoolVar(&stdin, "stdin", false, "read one query per line from stdin")

	return cmd
}

func tryRequest(query, tenant, user string) types.ValidateRequest {
	return types.ValidateRequest{
		RequestID: generateRequestID(),
		Query:     query,
		Metadata: map[string]string{
			"tenant_id":  tenant,
			"user_id":    user,
			"context_id": uuid.New().String(),
			"timestamp":  time.Now().UTC().Format(time.RFC3339),
		},
	}
}

func printTryResult(query string, resp types.ValidateResponse, explain bool) {
	const lineWidth = 64

	divider := strings.Repeat("─", lineWidth)
	fmt.Println(divider)

	// header: status + query preview
	statusIcon := "✅ PASSED"
	if resp.Status == types.StatusBlocked {
		statusIcon = "🚫 BLOCKED"
	}
	q := truncateStr(query, lineWidth-2)
	fmt.Printf("%s  %q\n", statusIcon, q)

	if !explain {
		// compact mode: one-liner reason
		if resp.Status == types.StatusBlocked {
			reason := blockedReason(resp)
			fmt.Printf("         Reason : %s\n", reason)
		}
		fmt.Printf("         Score  : %.2f  Time: %.2fms\n",
			resp.PromptCheck.RiskScore, resp.ProcessingTimeMs)
		fmt.Println(divider)
		return
	}

	// ── explain mode ────────────────────────────────────────────
	fmt.Println()

	// prompt injection section
	fmt.Printf("  Prompt Check   : %s\n", statusLabel(resp.PromptCheck.Status))
	fmt.Printf("  Risk Score     : %.2f  (%s)\n",
		resp.PromptCheck.RiskScore, riskLabel(resp.PromptCheck.RiskScore))
	fmt.Printf("  Method         : %s\n", resp.PromptCheck.Method)

	if len(resp.PromptCheck.MatchedPatterns) > 0 {
		fmt.Println()
		fmt.Println("  Matched Rules:")
		cfg := loadDefaultCfg()
		for _, id := range resp.PromptCheck.MatchedPatterns {
			info := ruleInfo(cfg, id)
			fmt.Printf("    %-10s %-8s  %s\n", "["+info.kind+"]", id, info.detail)
		}
	}

	// metadata section
	fmt.Println()
	fmt.Printf("  Metadata Check : %s\n", statusLabel(resp.MetadataCheck.Status))
	if len(resp.MetadataCheck.MissingFields) > 0 {
		fmt.Printf("  Missing        : %s\n", strings.Join(resp.MetadataCheck.MissingFields, ", "))
	}
	for _, e := range resp.MetadataCheck.FormatErrors {
		fmt.Printf("  Error          : %s\n", e)
	}
	if resp.MetadataCheck.Status == types.StatusPassed {
		fmt.Println("  All fields OK")
	}

	fmt.Println()
	fmt.Printf("  Extracted      : tenant=%s  user=%s\n",
		resp.ExtractedData.TenantID, resp.ExtractedData.UserID)
	fmt.Printf("  Processing     : %.2fms\n", resp.ProcessingTimeMs)
	fmt.Println(divider)
}

func tryStdin(eng interface {
	Validate(types.ValidateRequest) types.ValidateResponse
}, tenant, user string, explain bool) error {
	sc := bufio.NewScanner(os.Stdin)
	total, blocked := 0, 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		total++
		resp := eng.Validate(tryRequest(line, tenant, user))
		if resp.Status == types.StatusBlocked {
			blocked++
		}
		printTryResult(line, resp, explain)
	}
	if err := sc.Err(); err != nil {
		return err
	}
	fmt.Printf("\nSummary: %d/%d blocked (%.0f%%)\n",
		blocked, total, pct(blocked, total))
	return nil
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func statusLabel(s types.Status) string {
	if s == types.StatusPassed {
		return "PASSED ✅"
	}
	return "BLOCKED 🚫"
}

func riskLabel(score float64) string {
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

func blockedReason(resp types.ValidateResponse) string {
	if resp.PromptCheck.Status == types.StatusBlocked {
		if len(resp.PromptCheck.MatchedPatterns) > 0 {
			return fmt.Sprintf("injection pattern [%s]", strings.Join(resp.PromptCheck.MatchedPatterns, ", "))
		}
		return fmt.Sprintf("ML score %.2f", resp.PromptCheck.RiskScore)
	}
	if len(resp.MetadataCheck.MissingFields) > 0 {
		return fmt.Sprintf("missing fields: %s", strings.Join(resp.MetadataCheck.MissingFields, ", "))
	}
	if len(resp.MetadataCheck.FormatErrors) > 0 {
		return resp.MetadataCheck.FormatErrors[0]
	}
	return "validation error"
}

type ruleDetail struct {
	kind   string
	detail string
}

func ruleInfo(cfg *config.Config, id string) ruleDetail {
	for _, r := range cfg.PromptInjection.RegexRules {
		if r.ID == id {
			return ruleDetail{kind: "regex", detail: fmt.Sprintf("/%s/  severity=%s", r.Pattern, r.Severity)}
		}
	}
	for _, r := range cfg.PromptInjection.KeywordRules {
		if r.ID == id {
			return ruleDetail{kind: "keyword", detail: fmt.Sprintf("%q  severity=%s", r.Keyword, r.Severity)}
		}
	}
	return ruleDetail{kind: "rule", detail: id}
}

func loadDefaultCfg() *config.Config {
	if cfgPath != "" {
		cfg, err := config.Load(cfgPath)
		if err == nil {
			return cfg
		}
	}
	return config.Default()
}

func pct(n, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(n) / float64(total) * 100
}
