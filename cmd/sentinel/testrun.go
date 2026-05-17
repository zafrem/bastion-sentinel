package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/zafrem/bastion-sentinel/engine"
	"github.com/zafrem/bastion-sentinel/types"
)

type fixtureRecord struct {
	RequestID   string            `json:"request_id"`
	Description string            `json:"description"`
	Query       string            `json:"query"`
	Metadata    map[string]string `json:"metadata"`
	Expected    string            `json:"expected"`
}

func buildTestrunCmd() *cobra.Command {
	var (
		fixtureFile string
		fixtureDir  string
		verbose     bool
		stopOnFail  bool
	)

	cmd := &cobra.Command{
		Use:   "testrun",
		Short: "Run JSONL fixture suites against the validation engine",
		Long: `testrun loads one or more JSONL fixture files and validates each record
against the engine, comparing the actual status to the expected field.

Timestamps set to "NOW" are substituted with the current UTC time at run time.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			eng, err := loadEngine()
			if err != nil {
				return err
			}

			var files []string
			if fixtureDir != "" {
				entries, err := os.ReadDir(fixtureDir)
				if err != nil {
					return fmt.Errorf("read dir %q: %w", fixtureDir, err)
				}
				for _, e := range entries {
					if !e.IsDir() && strings.HasSuffix(e.Name(), ".jsonl") {
						files = append(files, filepath.Join(fixtureDir, e.Name()))
					}
				}
			}
			if fixtureFile != "" {
				files = append(files, fixtureFile)
			}
			if len(files) == 0 {
				return fmt.Errorf("no fixture files found — use --fixture or --dir")
			}

			totalPass, totalFail := 0, 0
			for _, f := range files {
				p, fail, err := runFixtureFile(eng, f, verbose, stopOnFail)
				if err != nil {
					return err
				}
				totalPass += p
				totalFail += fail
				if stopOnFail && fail > 0 {
					break
				}
			}

			fmt.Printf("══════════════════════════════════════════════════════════════\n")
			if totalFail == 0 {
				fmt.Printf("Overall: %d passed  ✅ All tests passed!\n", totalPass)
			} else {
				fmt.Printf("Overall: %d passed, %d failed ❌\n", totalPass, totalFail)
				return fmt.Errorf("%d test(s) failed", totalFail)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&fixtureFile, "fixture", "", "path to a single JSONL fixture file")
	cmd.Flags().StringVar(&fixtureDir, "dir", "", "directory containing JSONL fixture files")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "print all results, not just failures")
	cmd.Flags().BoolVar(&stopOnFail, "stop-on-fail", false, "stop after first failure")

	return cmd
}

func runFixtureFile(eng *engine.Engine, path string, verbose, stopOnFail bool) (passed, failed int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	now := time.Now().UTC().Format(time.RFC3339)
	name := filepath.Base(path)

	sc := bufio.NewScanner(f)
	// 2 MB buffer — handles lines with 10000+ character queries
	sc.Buffer(make([]byte, 64*1024), 2*1024*1024)

	var records []fixtureRecord
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		line = strings.ReplaceAll(line, `"NOW"`, fmt.Sprintf(`"%s"`, now))
		var rec fixtureRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return 0, 0, fmt.Errorf("%s: parse error: %w", name, err)
		}
		records = append(records, rec)
	}
	if err := sc.Err(); err != nil {
		return 0, 0, fmt.Errorf("%s: read error: %w", name, err)
	}

	fmt.Printf("────────────────────────────────────────────────────────────\n")
	fmt.Printf("Suite: %s (%d cases)\n", name, len(records))
	fmt.Printf("────────────────────────────────────────────────────────────\n")

	var totalMs float64
	for _, rec := range records {
		req := types.ValidateRequest{
			RequestID: rec.RequestID,
			Query:     rec.Query,
			Metadata:  rec.Metadata,
		}
		resp := eng.Validate(req)
		totalMs += resp.ProcessingTimeMs

		got := string(resp.Status)
		ok := got == rec.Expected

		if ok {
			passed++
			if verbose {
				fmt.Printf("  ✅ PASS  [%-6s] %-48s (%.2fms)\n",
					rec.RequestID, truncateStr(rec.Description, 48), resp.ProcessingTimeMs)
			}
		} else {
			failed++
			fmt.Printf("  ❌ FAIL  [%-6s] %-48s (expected=%s got=%s, %.2fms)\n",
				rec.RequestID, truncateStr(rec.Description, 48),
				rec.Expected, got, resp.ProcessingTimeMs)
			if stopOnFail {
				break
			}
		}
	}

	shown := passed + failed
	avgMs := 0.0
	if shown > 0 {
		avgMs = totalMs / float64(shown)
	}
	pct := 0.0
	if len(records) > 0 {
		pct = float64(passed) / float64(len(records)) * 100
	}
	fmt.Printf("────────────────────────────────────────────────────────────\n")
	fmt.Printf("Results: %d/%d passed (%.1f%%)  avg=%.2fms\n\n",
		passed, len(records), pct, avgMs)

	return passed, failed, nil
}

func truncateStr(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max-3]) + "..."
}
