package config_test

import (
	"os"
	"testing"

	"github.com/zafrem/bastion-sentinel/config"
)

func TestDefault_HasRequiredFields(t *testing.T) {
	cfg := config.Default()

	if cfg.Version == "" {
		t.Error("Version must not be empty")
	}
	if cfg.Server.RESTPort == 0 {
		t.Error("RESTPort must be set")
	}
	if cfg.Server.GRPCPort == 0 {
		t.Error("GRPCPort must be set")
	}
	if !cfg.PromptInjection.Enabled {
		t.Error("PromptInjection must be enabled by default")
	}
	if len(cfg.PromptInjection.RegexRules) == 0 {
		t.Error("must have at least one regex rule")
	}
	if len(cfg.PromptInjection.KeywordRules) == 0 {
		t.Error("must have at least one keyword rule")
	}
	if !cfg.MetadataValidation.Enabled {
		t.Error("MetadataValidation must be enabled by default")
	}
	if len(cfg.MetadataValidation.RequiredFields) == 0 {
		t.Error("RequiredFields must not be empty")
	}
	if len(cfg.MetadataValidation.BusinessRules) == 0 {
		t.Error("must have at least one business rule")
	}
	if cfg.Notifications.CriticalThreshold <= 0 {
		t.Error("CriticalThreshold must be positive")
	}
}

func TestDefault_DetectionRuleCounts(t *testing.T) {
	cfg := config.Default()
	if len(cfg.PromptInjection.RegexRules) < 25 {
		t.Errorf("expected ≥25 regex rules, got %d", len(cfg.PromptInjection.RegexRules))
	}
	if len(cfg.PromptInjection.KeywordRules) < 25 {
		t.Errorf("expected ≥25 keyword rules, got %d", len(cfg.PromptInjection.KeywordRules))
	}
}

func TestDefault_ScoringDefaults(t *testing.T) {
	cfg := config.Default()
	if cfg.PromptInjection.Scoring.Method != "max" {
		t.Errorf("expected scoring method 'max', got %q", cfg.PromptInjection.Scoring.Method)
	}
	if cfg.PromptInjection.Scoring.BlockThreshold != 0.7 {
		t.Errorf("expected block_threshold 0.7, got %f", cfg.PromptInjection.Scoring.BlockThreshold)
	}
}

func TestLoad_ValidYAML(t *testing.T) {
	yaml := `
server:
  rest_port: 9000
  grpc_port: 9001
logging:
  level: debug
  format: text
`
	f, err := os.CreateTemp("", "sentinel-config-*.yaml")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(yaml); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	f.Close()

	cfg, err := config.Load(f.Name())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.RESTPort != 9000 {
		t.Errorf("expected REST port 9000, got %d", cfg.Server.RESTPort)
	}
	if cfg.Server.GRPCPort != 9001 {
		t.Errorf("expected gRPC port 9001, got %d", cfg.Server.GRPCPort)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("expected log level 'debug', got %q", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "text" {
		t.Errorf("expected log format 'text', got %q", cfg.Logging.Format)
	}
	// Defaults from Default() must be preserved for unspecified fields.
	if len(cfg.PromptInjection.RegexRules) == 0 {
		t.Error("regex rules from Default() must be preserved after partial override")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := config.Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	f, err := os.CreateTemp("", "sentinel-config-*.yaml")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(": invalid: yaml: content:"); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	f.Close()

	_, err = config.Load(f.Name())
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestValidate_ValidFile(t *testing.T) {
	f, err := os.CreateTemp("", "sentinel-config-*.yaml")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString("server:\n  rest_port: 8080\n"); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	f.Close()

	if err := config.Validate(f.Name()); err != nil {
		t.Errorf("Validate: unexpected error: %v", err)
	}
}

func TestValidate_InvalidFile(t *testing.T) {
	if err := config.Validate("/nonexistent/config.yaml"); err == nil {
		t.Error("expected error for missing file")
	}
}
