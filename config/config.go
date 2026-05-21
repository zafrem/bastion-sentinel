package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Version            string                   `yaml:"version"`
	Server             ServerConfig             `yaml:"server"`
	PromptInjection    PromptInjectionConfig    `yaml:"prompt_injection"`
	MetadataValidation MetadataValidationConfig `yaml:"metadata_validation"`
	OutputValidation   OutputValidationConfig   `yaml:"output_validation"`
	Cache              CacheConfig              `yaml:"cache"`
	Logging            LoggingConfig            `yaml:"logging"`
	Metrics            MetricsConfig            `yaml:"metrics"`
	Notifications      NotificationsConfig      `yaml:"notifications"`
	Features           FeaturesConfig           `yaml:"features"`
}

type ServerConfig struct {
	RESTPort int `yaml:"rest_port"`
	GRPCPort int `yaml:"grpc_port"`
}

type PromptInjectionConfig struct {
	Enabled      bool          `yaml:"enabled"`
	RegexRules   []RegexRule   `yaml:"regex_rules"`
	KeywordRules []KeywordRule `yaml:"keyword_rules"`
	MLModel      MLModelConfig `yaml:"ml_model"`
	Scoring      ScoringConfig `yaml:"scoring"`
}

type RegexRule struct {
	ID       string `yaml:"id"`
	Pattern  string `yaml:"pattern"`
	Severity string `yaml:"severity"`
}

type KeywordRule struct {
	ID       string `yaml:"id"`
	Keyword  string `yaml:"keyword"`
	Severity string `yaml:"severity"`
}

type MLModelConfig struct {
	Enabled   bool    `yaml:"enabled"`
	Path      string  `yaml:"path"`
	Threshold float64 `yaml:"threshold"`
}

type ScoringConfig struct {
	Method         string  `yaml:"method"` // "max" or "weighted_avg"
	BlockThreshold float64 `yaml:"block_threshold"`
}

type MetadataValidationConfig struct {
	Enabled        bool                 `yaml:"enabled"`
	RequiredFields []string             `yaml:"required_fields"`
	FieldRules     map[string]FieldRule `yaml:"field_rules"`
	BusinessRules  []BusinessRule       `yaml:"business_rules"`
}

type FieldRule struct {
	Type      string `yaml:"type"`
	Pattern   string `yaml:"pattern"`
	Format    string `yaml:"format"`
	MinLength int    `yaml:"min_length"`
	MaxLength int    `yaml:"max_length"`
}

type BusinessRule struct {
	ID      string `yaml:"id"`
	Name    string `yaml:"name"`
	Enabled bool   `yaml:"enabled"`
}

type CacheConfig struct {
	Enabled bool   `yaml:"enabled"`
	Type    string `yaml:"type"`    // "redis" or "memory"
	TTL     string `yaml:"ttl"`
	Address string `yaml:"address"` // Redis address, e.g. "localhost:6379"
}

type LoggingConfig struct {
	Level            string `yaml:"level"`
	Format           string `yaml:"format"`
	Destination      string `yaml:"destination"`       // "stdout" or "elasticsearch"
	ElasticsearchURL string `yaml:"elasticsearch_url"` // e.g. "http://localhost:9200"
}

type NotificationsConfig struct {
	SlackWebhookURL     string  `yaml:"slack_webhook_url"`
	PagerDutyRoutingKey string  `yaml:"pagerduty_routing_key"`
	CriticalThreshold   float64 `yaml:"critical_threshold"` // risk score ≥ this triggers alert
}

type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Port    int    `yaml:"port"`
	Path    string `yaml:"path"`
}

type FeaturesConfig struct {
	HotReload        bool   `yaml:"hot_reload"`
	GracefulShutdown bool   `yaml:"graceful_shutdown"`
	ShutdownTimeout  string `yaml:"shutdown_timeout"`
}

// ─── Output Validation Config ─────────────────────────────────────────────────

type PIIPatternConfig struct {
	ID       string `yaml:"id"`
	Name     string `yaml:"name"`
	Pattern  string `yaml:"pattern"`
	Severity string `yaml:"severity"` // "critical", "high", "medium"
}

type VaultIntegrationConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Endpoint string `yaml:"endpoint"`
	CacheTTL string `yaml:"cache_ttl"`
}

type PIIReemergenceConfig struct {
	Enabled             bool                   `yaml:"enabled"`
	Patterns            []PIIPatternConfig     `yaml:"patterns"`
	ExternalPatternsDir string                 `yaml:"external_patterns_dir"`
	VaultIntegration    VaultIntegrationConfig `yaml:"vault_integration"`
	BlockOnCritical     bool                   `yaml:"block_on_critical"`
}

type HallucinationConfig struct {
	Enabled            bool    `yaml:"enabled"`
	GroundingThreshold float64 `yaml:"grounding_threshold"`
	LowScoreThreshold  float64 `yaml:"low_score_threshold"`
	AddDisclaimer      bool    `yaml:"add_disclaimer"`
	BlockOnLowScore    bool    `yaml:"block_on_low_score"`
}

type ContentFilterPatternConfig struct {
	ID       string `yaml:"id"`
	Name     string `yaml:"name"`
	Pattern  string `yaml:"pattern"`
	Severity string `yaml:"severity"`
}

type ContentFilterConfig struct {
	Enabled  bool                         `yaml:"enabled"`
	Patterns []ContentFilterPatternConfig `yaml:"patterns"`
}

type PermissionCheckConfig struct {
	Enabled bool `yaml:"enabled"`
}

type OutputFormatConfig struct {
	MinLength      int  `yaml:"min_length"`
	MaxLength      int  `yaml:"max_length"`
	UTF8Required   bool `yaml:"utf8_required"`
	NoControlChars bool `yaml:"no_control_chars"`
}

type OutputValidationConfig struct {
	Enabled         bool                  `yaml:"enabled"`
	PIIReemergence  PIIReemergenceConfig  `yaml:"pii_reemergence"`
	Hallucination   HallucinationConfig   `yaml:"hallucination"`
	ContentFilter   ContentFilterConfig   `yaml:"content_filter"`
	PermissionCheck PermissionCheckConfig `yaml:"permission_check"`
	Format          OutputFormatConfig    `yaml:"format"`
}

func Default() *Config {
	return &Config{
		Version: "1.0",
		Server: ServerConfig{
			RESTPort: 8080,
			GRPCPort: 9090,
		},
		PromptInjection: PromptInjectionConfig{
			Enabled: true,
			RegexRules: []RegexRule{
				// ── English: instruction override ──────────────────────────────
				{ID: "pi-001", Pattern: `(?i)ignore\s+all\s+previous`, Severity: "critical"},
				{ID: "pi-007", Pattern: `(?i)disregard\s+(all\s+|your\s+)?(previous\s+)?(instructions?|directives?|guidelines?)`, Severity: "critical"},
				{ID: "pi-008", Pattern: `(?i)(forget|ignore|disregard)\s+(your\s+)?(training|instructions?|guidelines?|rules?|constraints?)`, Severity: "critical"},
				{ID: "pi-009", Pattern: `(?i)override\s+(your\s+)?(previous\s+)?(instructions?|programming|directives?)`, Severity: "critical"},
				// ── English: identity / persona hijack ────────────────────────
				{ID: "pi-006", Pattern: `(?i)you\s+are\s+now\s+(in\s+)?(dan|jailbreak|developer|god)\s+mode`, Severity: "critical"},
				{ID: "pi-010", Pattern: `(?i)(developer|god|unrestricted|evil|do\s+anything\s+now|turbo)\s+mode`, Severity: "critical"},
				{ID: "pi-011", Pattern: `(?i)pretend\s+(you\s+are|to\s+be)\s+(an?\s+)?(ai|assistant|bot|model)?\s*(with\s+no|without\s+any?)?\s*(restrictions?|limits?|filters?)`, Severity: "high"},
				{ID: "pi-012", Pattern: `(?i)act\s+as\s+(if\s+you\s+are\s+)?(an?\s+)?(unrestricted|uncensored|unfiltered|evil|malicious)`, Severity: "high"},
				{ID: "pi-013", Pattern: `(?i)as\s+a\s+(fictional|hypothetical)\s+(character|ai|assistant|persona)\s+(who|that|with)\s+(has\s+)?(no|without)\s+(restrictions?|limits?)`, Severity: "high"},
				// ── English: prompt/system exfiltration ───────────────────────
				{ID: "pi-002", Pattern: `(?i)system\s+prompt`, Severity: "high"},
				{ID: "pi-014", Pattern: `(?i)(reveal|show|print|display|output|repeat|recite|leak)\s+(your\s+)?(system\s+)?(prompt|instructions?|training\s+data|guidelines?|configuration)`, Severity: "high"},
				{ID: "pi-015", Pattern: `(?i)what\s+(are|were)\s+your\s+(original\s+)?(instructions?|directives?|guidelines?|rules?)`, Severity: "high"},
				// ── English: restriction bypass ────────────────────────────────
				{ID: "pi-005", Pattern: `(?i)(bypass|override)\s+(system|security|limitations)`, Severity: "high"},
				{ID: "pi-016", Pattern: `(?i)(no|without)\s+(any\s+)?(restrictions?|limitations?|filters?|censorship|guardrails?)`, Severity: "high"},
				{ID: "pi-017", Pattern: `(?i)for\s+educational\s+purposes\s+only`, Severity: "medium"},
				{ID: "pi-018", Pattern: `(?i)in\s+this\s+hypothetical\s+(scenario|situation|context|world)`, Severity: "medium"},
				{ID: "pi-019", Pattern: `(?i)(simulate|roleplay)\s+(being\s+)?(an?\s+)?(ai|assistant|system)\s+(without|with\s+no)\s+(restrictions?|limits?|filters?)`, Severity: "high"},
				// ── Korean: instruction override ──────────────────────────────
				{ID: "pi-003", Pattern: `(?i)이전\s+지시를?\s+무시`, Severity: "critical"},
				{ID: "pi-020", Pattern: `(?i)(이전|모든|기존)\s*(명령|지시|규칙|제약)\s*(무시|잊어|삭제|초기화)`, Severity: "critical"},
				{ID: "pi-021", Pattern: `(?i)(지시|명령|규칙)\s*(을|를)?\s*(따르지|무시|어기|위반)`, Severity: "critical"},
				// ── Korean: identity / persona hijack ─────────────────────────
				{ID: "pi-004", Pattern: `(?i)관리자\s+모드\s+진입`, Severity: "critical"},
				{ID: "pi-022", Pattern: `(?i)(제한|필터|검열)\s*(없이|을\s*무시|을\s*우회|을\s*제거)`, Severity: "high"},
				{ID: "pi-023", Pattern: `(?i)(역할극|롤플레이)\s*.{0,20}(제한|규칙|필터)\s*(없이|무시)`, Severity: "high"},
				// ── Korean: prompt/system exfiltration ────────────────────────
				{ID: "pi-024", Pattern: `(?i)(시스템\s+)?프롬프트를?\s*(보여|공개|출력|알려|노출)`, Severity: "critical"},
				{ID: "pi-025", Pattern: `(?i)(학습|훈련)\s*(데이터|내용)\s*(보여|공개|알려)`, Severity: "high"},
			},
			KeywordRules: []KeywordRule{
				// ── English ───────────────────────────────────────────────────
				{ID: "kw-001", Keyword: "jailbreak", Severity: "critical"},
				{ID: "kw-003", Keyword: "prompt injection", Severity: "high"},
				{ID: "kw-004", Keyword: "dan mode", Severity: "critical"},
				{ID: "kw-005", Keyword: "do anything now", Severity: "critical"},
				{ID: "kw-006", Keyword: "no restrictions", Severity: "high"},
				{ID: "kw-007", Keyword: "without restrictions", Severity: "high"},
				{ID: "kw-008", Keyword: "ignore your training", Severity: "critical"},
				{ID: "kw-009", Keyword: "forget everything", Severity: "critical"},
				{ID: "kw-010", Keyword: "unrestricted mode", Severity: "critical"},
				{ID: "kw-011", Keyword: "pretend you are", Severity: "high"},
				{ID: "kw-012", Keyword: "for educational purposes", Severity: "medium"},
				{ID: "kw-013", Keyword: "hypothetical scenario", Severity: "medium"},
				{ID: "kw-014", Keyword: "ignore all ethics", Severity: "critical"},
				{ID: "kw-015", Keyword: "bypass safety", Severity: "critical"},
				{ID: "kw-016", Keyword: "evil mode", Severity: "critical"},
				{ID: "kw-017", Keyword: "god mode", Severity: "critical"},
				// ── Korean ────────────────────────────────────────────────────
				{ID: "kw-002", Keyword: "관리자 모드", Severity: "high"},
				{ID: "kw-018", Keyword: "탈옥", Severity: "critical"},
				{ID: "kw-019", Keyword: "시스템 프롬프트", Severity: "high"},
				{ID: "kw-020", Keyword: "제한 없이", Severity: "high"},
				{ID: "kw-021", Keyword: "지시 무시", Severity: "critical"},
				{ID: "kw-022", Keyword: "명령 무시", Severity: "critical"},
				{ID: "kw-023", Keyword: "역할극", Severity: "medium"},
				{ID: "kw-024", Keyword: "프롬프트 무시", Severity: "critical"},
				{ID: "kw-025", Keyword: "검열 우회", Severity: "high"},
			},
			MLModel: MLModelConfig{
				Enabled:   true,
				Path:      "/models/injection-detector.onnx",
				Threshold: 0.7,
			},
			Scoring: ScoringConfig{
				Method:         "max",
				BlockThreshold: 0.7,
			},
		},
		MetadataValidation: MetadataValidationConfig{
			Enabled:        true,
			RequiredFields: []string{"tenant_id", "user_id", "context_id", "timestamp"},
			FieldRules: map[string]FieldRule{
				"tenant_id": {
					Type:      "string",
					Pattern:   `^[a-z0-9-]+$`,
					MinLength: 3,
					MaxLength: 64,
				},
				"user_id": {
					Type:      "string",
					Pattern:   `^[a-zA-Z0-9_-]+$`,
					MinLength: 3,
					MaxLength: 64,
				},
				"context_id": {
					Type:   "string",
					Format: "uuid",
				},
				"timestamp": {
					Type:   "string",
					Format: "rfc3339",
				},
			},
			BusinessRules: []BusinessRule{
				{ID: "br-001", Name: "timestamp_bounds", Enabled: true},
				{ID: "br-002", Name: "reserved_identifiers", Enabled: true},
			},
		},
		OutputValidation: OutputValidationConfig{
			Enabled: true,
			PIIReemergence: PIIReemergenceConfig{
				Enabled: true,
				Patterns: []PIIPatternConfig{
					// Most standard PII patterns (email, SSN, Korean RRN, credit cards, etc.) 
					// are now loaded automatically from the external pii-pattern-engine.
					{ID: "pii-006", Name: "leaked_token", Pattern: `[A-Z]{2,}_[A-Z]{2,}_[a-z0-9]{16}`, Severity: "high"},
				},
				ExternalPatternsDir: "external/pii-pattern-engine/regex",
				BlockOnCritical:     true,
			},
			Hallucination: HallucinationConfig{
				Enabled:            true,
				GroundingThreshold: 0.5,
				LowScoreThreshold:  0.3,
				AddDisclaimer:      true,
				BlockOnLowScore:    false,
			},
			ContentFilter: ContentFilterConfig{
				Enabled: true,
				Patterns: []ContentFilterPatternConfig{
					{ID: "cf-001", Name: "api_key_openai", Pattern: `sk-[a-zA-Z0-9]{32,}`, Severity: "critical"},
					{ID: "cf-002", Name: "api_key_github", Pattern: `ghp_[a-zA-Z0-9]{36}`, Severity: "critical"},
					{ID: "cf-003", Name: "aws_access_key", Pattern: `AKIA[0-9A-Z]{16}`, Severity: "critical"},
					{ID: "cf-004", Name: "internal_unix_path", Pattern: `/(?:var|etc|proc|sys)/[^\s]{3,}`, Severity: "medium"},
				},
			},
			PermissionCheck: PermissionCheckConfig{Enabled: true},
			Format: OutputFormatConfig{
				MinLength:      10,
				MaxLength:      10000,
				UTF8Required:   true,
				NoControlChars: true,
			},
		},
		Cache: CacheConfig{
			Enabled: false,
			Type:    "redis",
			TTL:     "5m",
			Address: "localhost:6379",
		},
		Logging: LoggingConfig{
			Level:            "info",
			Format:           "json",
			Destination:      "stdout",
			ElasticsearchURL: "",
		},
		Notifications: NotificationsConfig{
			CriticalThreshold: 0.9,
		},
		Metrics: MetricsConfig{
			Enabled: true,
			Port:    9091,
			Path:    "/metrics",
		},
		Features: FeaturesConfig{
			HotReload:        true,
			GracefulShutdown: true,
			ShutdownTimeout:  "30s",
		},
	}
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := Default()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func Validate(path string) error {
	_, err := Load(path)
	return err
}
