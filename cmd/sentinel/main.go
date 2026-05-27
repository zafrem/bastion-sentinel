package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/zafrem/bastion-sentinel/cache"
	"github.com/zafrem/bastion-sentinel/config"
	"github.com/zafrem/bastion-sentinel/engine"
	"github.com/zafrem/bastion-sentinel/formatter"
	"github.com/zafrem/bastion-sentinel/server"
	"github.com/zafrem/bastion-sentinel/types"
)

var (
	cfgPath      string
	outputFormat string
	strictMode   bool
	timeoutMs    int
)

func main() {
	root := &cobra.Command{
		Use:   "sentinel-cli",
		Short: "Bastion-Sentinel — AI input gateway security validation",
	}

	root.PersistentFlags().StringVar(&cfgPath, "config", "", "path to config file (default: built-in)")
	root.PersistentFlags().StringVar(&outputFormat, "output-format", "text", "output format: text, json, compact")
	root.PersistentFlags().BoolVar(&strictMode, "strict-mode", false, "treat warnings as blocking errors")
	root.PersistentFlags().IntVar(&timeoutMs, "timeout", 0, "maximum processing time in milliseconds (0 = no limit)")

	root.AddCommand(
		buildValidateCmd(),
		buildValidateOutputCmd(),
		buildInteractiveCmd(),
		buildConfigCmd(),
		buildServerCmd(),
		buildTestrunCmd(),
		buildTryCmd(),
	)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func loadConfig() (*config.Config, error) {
	if cfgPath != "" {
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return nil, fmt.Errorf("load config: %w", err)
		}
		return cfg, nil
	}
	return config.Default(), nil
}

func loadEngine() (*engine.Engine, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	return engine.New(cfg)
}

// ─── validate command ────────────────────────────────────────────────────────

func buildValidateCmd() *cobra.Command {
	var (
		query      string
		metaJSON   string
		inputFile  string
		outputFile string
		parallel   int
	)

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate a query and metadata for prompt injection and schema compliance",
		RunE: func(cmd *cobra.Command, args []string) error {
			eng, err := loadEngine()
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			var outFile *os.File
			if outputFile != "" {
				f, err := os.Create(outputFile)
				if err != nil {
					return fmt.Errorf("open output file: %w", err)
				}
				defer f.Close()
				outFile = f
			} else {
				outFile = os.Stdout
			}

			// batch mode
			if inputFile != "" {
				return runBatch(eng, inputFile, outFile, parallel)
			}

			// interactive stdin mode when --query is omitted
			if query == "" {
				query, metaJSON, err = promptInteractiveInput()
				if err != nil {
					return err
				}
			}

			meta, err := parseMetadata(metaJSON)
			if err != nil {
				return fmt.Errorf("parse metadata: %w", err)
			}

			req := types.ValidateRequest{
				RequestID: generateRequestID(),
				Query:     query,
				Metadata:  meta,
				Options: types.ValidateOptions{
					StrictMode:   strictMode,
					TimeoutMs:    timeoutMs,
					OutputFormat: outputFormat,
				},
			}

			resp := eng.Validate(req)
			return formatter.Write(out, resp, outputFormat)
		},
	}

	cmd.Flags().StringVar(&query, "query", "", "query string to validate")
	cmd.Flags().StringVar(&metaJSON, "metadata", "", "metadata as JSON string")
	cmd.Flags().StringVar(&inputFile, "input-file", "", "JSONL input file for batch validation")
	cmd.Flags().StringVar(&outputFile, "output-file", "", "file to write results to")
	cmd.Flags().IntVar(&parallel, "parallel", 4, "number of parallel workers for batch mode")

	return cmd
}

func promptInteractiveInput() (query, metaJSON string, err error) {
	sc := bufio.NewScanner(os.Stdin)

	fmt.Print("Query: ")
	if sc.Scan() {
		query = strings.TrimSpace(sc.Text())
	}
	fmt.Print("Metadata (JSON): ")
	if sc.Scan() {
		metaJSON = strings.TrimSpace(sc.Text())
	}
	if err = sc.Err(); err != nil {
		return "", "", err
	}
	return query, metaJSON, nil
}

func parseMetadata(raw string) (map[string]string, error) {
	if raw == "" {
		return map[string]string{}, nil
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, err
	}
	return m, nil
}

// ─── batch processing ────────────────────────────────────────────────────────

type batchInput struct {
	RequestID string            `json:"request_id"`
	Query     string            `json:"query"`
	Metadata  map[string]string `json:"metadata"`
}

func runBatch(eng *engine.Engine, inputPath string, out *os.File, workers int) error {
	f, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("open input file: %w", err)
	}
	defer f.Close()

	// Pre-count total lines for the progress bar.
	total, err := countLines(f)
	if err != nil {
		return err
	}
	if _, err := f.Seek(0, 0); err != nil {
		return err
	}

	type work struct {
		line string
		idx  int
	}
	type result struct {
		resp types.ValidateResponse
		idx  int
		err  error
	}

	jobs := make(chan work, workers*2)
	results := make(chan result, workers*2)

	var completed sync.WaitGroup
	var doneCount int64
	var totalMs float64
	var statsMu sync.Mutex

	for i := 0; i < workers; i++ {
		completed.Add(1)
		go func() {
			defer completed.Done()
			for w := range jobs {
				var inp batchInput
				if err := json.Unmarshal([]byte(w.line), &inp); err != nil {
					results <- result{idx: w.idx, err: err}
					statsMu.Lock()
					doneCount++
					statsMu.Unlock()
					continue
				}
				if inp.RequestID == "" {
					inp.RequestID = fmt.Sprintf("batch-%d", w.idx)
				}
				resp := eng.Validate(types.ValidateRequest{
					RequestID: inp.RequestID,
					Query:     inp.Query,
					Metadata:  inp.Metadata,
				})
				results <- result{resp: resp, idx: w.idx}
				statsMu.Lock()
				doneCount++
				totalMs += resp.ProcessingTimeMs
				statsMu.Unlock()
			}
		}()
	}

	// Collect results.
	collected := make(map[int]result)
	var collectWg sync.WaitGroup
	collectWg.Add(1)
	go func() {
		defer collectWg.Done()
		for r := range results {
			collected[r.idx] = r
		}
	}()

	// Progress bar ticker — only when writing to a file (not stdout).
	progressDone := make(chan struct{})
	if out != os.Stdout && total > 0 {
		go func() {
			defer close(progressDone)
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					statsMu.Lock()
					n := doneCount
					ms := totalMs
					statsMu.Unlock()
					printProgress(n, int64(total), ms)
				case <-func() chan struct{} {
					ch := make(chan struct{})
					go func() {
						completed.Wait()
						close(ch)
					}()
					return ch
				}():
					printProgress(int64(total), int64(total), totalMs)
					fmt.Fprintln(os.Stderr)
					return
				}
			}
		}()
	} else {
		close(progressDone)
	}

	sc := bufio.NewScanner(f)
	idx := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		jobs <- work{line: line, idx: idx}
		idx++
	}
	close(jobs)
	completed.Wait()
	close(results)
	collectWg.Wait()
	<-progressDone

	if err := sc.Err(); err != nil {
		return err
	}

	passed, blocked := 0, 0
	var writeErr error

	for i := 0; i < idx; i++ {
		r := collected[i]
		if r.err != nil {
			fmt.Fprintf(os.Stderr, "line %d: parse error: %v\n", i+1, r.err)
			continue
		}
		if r.resp.Status == types.StatusPassed {
			passed++
		} else {
			blocked++
		}
		if writeErr == nil {
			if out != os.Stdout {
				data, _ := json.Marshal(jsonResponse(r.resp))
				writeErr = writeJSONL(out, data)
			} else {
				writeErr = formatter.Write(out, r.resp, outputFormat)
			}
		}
	}

	statsMu.Lock()
	avgMs := 0.0
	if idx > 0 {
		avgMs = totalMs / float64(idx)
	}
	statsMu.Unlock()

	fmt.Fprintf(os.Stderr, "✅ Total: %d  ✅ Passed: %d  🚫 Blocked: %d  ⏱ Avg: %.2fms\n",
		idx, passed, blocked, avgMs)
	if out != os.Stdout {
		fmt.Fprintf(os.Stderr, "📊 Results saved to %s\n", out.Name())
	}
	return writeErr
}

// countLines returns the number of non-empty lines in an open file.
func countLines(f *os.File) (int, error) {
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			n++
		}
	}
	return n, sc.Err()
}

// printProgress renders an in-place progress bar to stderr.
func printProgress(done, total int64, totalMs float64) {
	if total == 0 {
		return
	}
	pct := float64(done) / float64(total)
	barWidth := 20
	filled := int(pct * float64(barWidth))
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	avgMs := 0.0
	if done > 0 {
		avgMs = totalMs / float64(done)
	}
	fmt.Fprintf(os.Stderr, "\rProcessing: %s %3.0f%% (%d/%d) | %.2fms avg",
		bar, pct*100, done, total, avgMs)
}

func writeJSONL(w *os.File, data []byte) error {
	_, err := fmt.Fprintf(w, "%s\n", data)
	return err
}

func jsonResponse(resp types.ValidateResponse) map[string]any {
	return map[string]any{
		"request_id":         resp.RequestID,
		"status":             resp.Status,
		"processing_time_ms": resp.ProcessingTimeMs,
		"prompt_risk_score":  resp.PromptCheck.RiskScore,
		"matched_patterns":   resp.PromptCheck.MatchedPatterns,
		"metadata_errors":    resp.MetadataCheck.FormatErrors,
	}
}

// ─── validate-output command ─────────────────────────────────────────────────

func buildValidateOutputCmd() *cobra.Command {
	var (
		llmResponse string
		inputFile   string
		tenantID    string
		userID      string
	)

	cmd := &cobra.Command{
		Use:   "validate-output",
		Short: "Validate an LLM response for PII, hallucination, and content policy",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			outEng, err := engine.NewOutputEngine(cfg)
			if err != nil {
				return fmt.Errorf("init output engine: %w", err)
			}

			text := llmResponse
			if inputFile != "" {
				data, err := os.ReadFile(inputFile)
				if err != nil {
					return fmt.Errorf("read input file: %w", err)
				}
				text = strings.TrimSpace(string(data))
			}
			if text == "" {
				return fmt.Errorf("provide --llm-response or --file")
			}

			resp := outEng.Validate(types.OutputValidateRequest{
				RequestID:   generateRequestID(),
				LLMResponse: text,
				User: types.UserContext{
					TenantID:    tenantID,
					UserID:      userID,
					AccessLevel: "full",
				},
			})

			switch outputFormat {
			case "json":
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(resp)
			default:
				fmt.Fprintf(cmd.OutOrStdout(), "Status:           %s\n", resp.Status)
				fmt.Fprintf(cmd.OutOrStdout(), "Processing time:  %.2fms\n", resp.ProcessingTimeMs)
				fmt.Fprintf(cmd.OutOrStdout(), "PII redactions:   %d\n", resp.Checks.PIICheck.RedactionsApplied)
				fmt.Fprintf(cmd.OutOrStdout(), "Grounding score:  %.3f\n", resp.Checks.HallucinationCheck.GroundingScore)
				if resp.Status != types.OutputStatusPassed {
					fmt.Fprintf(cmd.OutOrStdout(), "Validated output:\n%s\n", resp.ValidatedResponse)
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&llmResponse, "llm-response", "", "LLM response text to validate")
	cmd.Flags().StringVar(&inputFile, "file", "", "File containing the LLM response")
	cmd.Flags().StringVar(&tenantID, "tenant-id", "default", "Tenant ID")
	cmd.Flags().StringVar(&userID, "user-id", "cli-user", "User ID")
	return cmd
}

// ─── interactive (REPL) command ──────────────────────────────────────────────

func buildInteractiveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "interactive",
		Short: "Launch an interactive REPL session",
		RunE: func(cmd *cobra.Command, args []string) error {
			eng, err := loadEngine()
			if err != nil {
				return err
			}

			fmt.Println("Welcome to Bastion-Sentinel REPL v1.0")
			fmt.Println("Commands: validate, validate-quick <query>, stats, config, exit, help")

			var total, passed, blocked int
			var totalMs float64
			sc := bufio.NewScanner(os.Stdin)

			for {
				fmt.Print("\nsentinel> ")
				if !sc.Scan() {
					break
				}
				line := strings.TrimSpace(sc.Text())
				if line == "" {
					continue
				}

				parts := strings.SplitN(line, " ", 2)
				command := parts[0]

				switch command {
				case "exit", "quit":
					fmt.Println("Goodbye!")
					return nil

				case "help":
					fmt.Println("  validate              — interactive prompt validation")
					fmt.Println("  validate-quick <q>    — quick single-line validation")
					fmt.Println("  stats                 — show session statistics")
					fmt.Println("  config                — show current config summary")
					fmt.Println("  exit                  — quit")

				case "validate":
					fmt.Print("Query: ")
					if !sc.Scan() {
						return nil
					}
					query := strings.TrimSpace(sc.Text())
					fmt.Print("Tenant ID: ")
					if !sc.Scan() {
						return nil
					}
					tenantID := strings.TrimSpace(sc.Text())
					fmt.Print("User ID: ")
					if !sc.Scan() {
						return nil
					}
					userID := strings.TrimSpace(sc.Text())

					req := quickRequest(eng, query, tenantID, userID)
					resp := eng.Validate(req)
					total++
					totalMs += resp.ProcessingTimeMs
					if resp.Status == types.StatusPassed {
						passed++
						fmt.Printf("✅ PASSED (%.1fms)\n", resp.ProcessingTimeMs)
					} else {
						blocked++
						reason := injectionReason(resp)
						fmt.Printf("🚫 BLOCKED (%.1fms) — %s\n", resp.ProcessingTimeMs, reason)
					}

				case "validate-quick":
					if len(parts) < 2 {
						fmt.Println("usage: validate-quick <query>")
						continue
					}
					req := quickRequest(eng, parts[1], "repl", "repl-user")
					resp := eng.Validate(req)
					total++
					totalMs += resp.ProcessingTimeMs
					if resp.Status == types.StatusPassed {
						passed++
						fmt.Printf("✅ PASSED (%.1fms)\n", resp.ProcessingTimeMs)
					} else {
						blocked++
						fmt.Printf("🚫 BLOCKED (%.1fms) — %s\n", resp.ProcessingTimeMs, injectionReason(resp))
					}

				case "stats":
					avgMs := 0.0
					if total > 0 {
						avgMs = totalMs / float64(total)
					}
					blockPct := 0.0
					if total > 0 {
						blockPct = float64(blocked) / float64(total) * 100
					}
					fmt.Printf("Total requests: %d\nPassed: %d (%.0f%%)\nBlocked: %d (%.0f%%)\nAvg latency: %.1fms\n",
						total, passed, 100-blockPct, blocked, blockPct, avgMs)

				case "config":
					fmt.Printf("Config source: %s\n", configSource())
					fmt.Printf("Block threshold: %.1f\n", config.Default().PromptInjection.Scoring.BlockThreshold)

				default:
					fmt.Printf("Unknown command: %q — type 'help' for available commands\n", command)
				}
			}
			return sc.Err()
		},
	}
}

func quickRequest(eng *engine.Engine, query, tenantID, userID string) types.ValidateRequest {
	return types.ValidateRequest{
		RequestID: generateRequestID(),
		Query:     query,
		Metadata: map[string]string{
			"tenant_id":  tenantID,
			"user_id":    userID,
			"context_id": "00000000-0000-4000-8000-000000000000",
			"timestamp":  time.Now().UTC().Format(time.RFC3339),
		},
	}
}

func injectionReason(resp types.ValidateResponse) string {
	if resp.PromptCheck.Status == types.StatusBlocked {
		if len(resp.PromptCheck.MatchedPatterns) > 0 {
			return "Pattern match"
		}
		return "ML score"
	}
	if len(resp.MetadataCheck.MissingFields) > 0 {
		return fmt.Sprintf("Missing fields: %s", strings.Join(resp.MetadataCheck.MissingFields, ", "))
	}
	if len(resp.MetadataCheck.FormatErrors) > 0 {
		return resp.MetadataCheck.FormatErrors[0]
	}
	return "Validation error"
}

func configSource() string {
	if cfgPath != "" {
		return cfgPath
	}
	return "(built-in defaults)"
}

// ─── config command ──────────────────────────────────────────────────────────

func buildConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage Sentinel configuration",
	}

	cmd.AddCommand(
		&cobra.Command{
			Use:   "show",
			Short: "Display the active configuration",
			RunE: func(cmd *cobra.Command, args []string) error {
				var cfg *config.Config
				var err error
				if cfgPath != "" {
					cfg, err = config.Load(cfgPath)
					if err != nil {
						return err
					}
				} else {
					cfg = config.Default()
				}
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(cfg)
			},
		},
		&cobra.Command{
			Use:   "validate <file>",
			Short: "Validate a configuration file",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				if err := config.Validate(args[0]); err != nil {
					return fmt.Errorf("invalid config: %w", err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "✅ Config %q is valid\n", args[0])
				return nil
			},
		},
		&cobra.Command{
			Use:   "reload",
			Short: "Signal a running server to reload its configuration (stub)",
			Run: func(cmd *cobra.Command, args []string) {
				fmt.Fprintln(cmd.OutOrStdout(), "Config reload: send SIGHUP to the running sentinel-cli server process.")
			},
		},
	)

	return cmd
}

// ─── server command ──────────────────────────────────────────────────────────

func buildServerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Start the Sentinel REST + gRPC validation servers",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			eng, err := engine.New(cfg)
			if err != nil {
				return fmt.Errorf("init engine: %w", err)
			}

			c, err := cache.New(cfg.Cache)
			if err != nil {
				return fmt.Errorf("init cache: %w", err)
			}
			defer c.Close()

			ttl, _ := time.ParseDuration(cfg.Cache.TTL)
			if ttl == 0 {
				ttl = 5 * time.Minute
			}
			val := cache.NewCached(eng, c, ttl)

			log := server.NewLogger(cfg.Logging, cfg.Version)
			notifier := server.NewNotifier(cfg.Notifications, log)

			restSrv, err := server.NewREST(cfg, val, c, cfgPath, log, notifier)
			if err != nil {
				return fmt.Errorf("init REST server: %w", err)
			}
			grpcSrv := server.NewGRPC(cfg, val, c, cfgPath, log, notifier)

			stop := make(chan os.Signal, 1)
			sighup := make(chan os.Signal, 1)
			signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
			signal.Notify(sighup, syscall.SIGHUP)
			errc := make(chan error, 2)

			// REST
			go func() {
				fmt.Fprintf(cmd.OutOrStdout(),
					"REST  listening on %s\n"+
						"  POST /v1/validate  POST /v1/validate/batch\n"+
						"  GET  /v1/health    GET  /v1/config  GET /v1/metrics\n"+
						"  POST /v1/config/reload\n"+
						"  GET  /health/live  GET  /health/ready\n",
					restSrv.Addr(),
				)
				if err := restSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					errc <- fmt.Errorf("REST: %w", err)
				}
			}()

			// gRPC
			go func() {
				fmt.Fprintf(cmd.OutOrStdout(),
					"gRPC  listening on %s\n"+
						"  Validate  ValidateBatch  Health\n"+
						"Press Ctrl+C to stop.\n",
					grpcSrv.Addr(),
				)
				if err := grpcSrv.ListenAndServe(); err != nil {
					errc <- fmt.Errorf("gRPC: %w", err)
				}
			}()

			// SIGHUP: hot-reload config + engine
			go func() {
				for range sighup {
					log.Info("SIGHUP received, reloading config", "path", cfgPath)
					if cfgPath == "" {
						log.Warn("no config file specified; SIGHUP reload is a no-op")
						continue
					}
					newCfg, err := config.Load(cfgPath)
					if err != nil {
						log.Error("config reload failed", "err", err)
						continue
					}
					newEng, err := engine.New(newCfg)
					if err != nil {
						log.Error("engine rebuild failed", "err", err)
						continue
					}
					restSrv.Reload(newCfg, newEng)
					grpcSrv.Reload(newCfg, newEng)
					log.Info("config reloaded successfully")
				}
			}()

			select {
			case <-stop:
			case err := <-errc:
				return err
			}

			timeout, err := time.ParseDuration(cfg.Features.ShutdownTimeout)
			if err != nil {
				timeout = 30 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			fmt.Fprintln(cmd.OutOrStdout(), "\nShutting down gracefully...")
			grpcSrv.Shutdown()
			return restSrv.Shutdown(ctx)
		},
	}
	return cmd
}

// ─── helpers ─────────────────────────────────────────────────────────────────

var requestCounter int64

func generateRequestID() string {
	requestCounter++
	return fmt.Sprintf("req-%d-%d", time.Now().UnixNano(), requestCounter)
}
