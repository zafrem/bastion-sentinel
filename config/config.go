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
	Events             EventsConfig             `yaml:"events"`
	Industry           IndustryConfig           `yaml:"industry"`
	UserNotice         UserNoticeConfig         `yaml:"user_notice"`
	Exceptions         ExceptionsConfig         `yaml:"exceptions"`
}

// UserNoticeConfig controls the explanation shown to end users on a block or mask.
type UserNoticeConfig struct {
	// Detail is "category" (default: say why, by category) or "minimal" (generic).
	Detail string `yaml:"detail"`
}

// ExceptionsConfig enables scoped exemptions signed by Tracker. Off unless a
// public key is set; the module then works from its own persisted copy even
// when Tracker or NATS is unreachable.
type ExceptionsConfig struct {
	// PublicKey is Tracker's base64 Ed25519 public key (env SENTINEL_EXCEPTIONS_PUBLIC_KEY).
	PublicKey string `yaml:"public_key"`
	// File is where verified exceptions are persisted, and where an exported
	// envelope can be dropped for a module with no connection to Tracker.
	File string `yaml:"file"`
}

// IndustryConfig holds the industry-specific filter extension configuration.
// See docs/20_extension_sentinel_industry_v1.md.
type IndustryConfig struct {
	Enabled         bool                            `yaml:"enabled"`
	Filters         []IndustryFilterConfig          `yaml:"filters"`
	TenantOverrides map[string]TenantIndustryConfig `yaml:"tenant_overrides"`
}

// IndustryFilterConfig configures a single industry filter entry.
type IndustryFilterConfig struct {
	ID            string `yaml:"id"`
	Builtin       string `yaml:"builtin"`         // "hipaa" | "gdpr" | "itar" | "pci"
	PluginPath    string `yaml:"plugin_path"`     // path to .so plugin (future use)
	Mode          string `yaml:"mode"`            // "blocking" | "async"
	Position      string `yaml:"position"`        // "after_core" | "before_core"
	ActionOnMatch string `yaml:"action_on_match"` // "block" | "redact" | "flag"
	// Patterns overrides the built-in regex set for regex-based filters
	// (hipaa/gdpr/pci). Empty keeps the built-in defaults.
	Patterns []string `yaml:"patterns"`
	// Keywords overrides the built-in keyword set for keyword-based filters
	// (itar). Empty keeps the built-in defaults.
	Keywords []string `yaml:"keywords"`
}

// TenantIndustryConfig lists the filter IDs active for a specific tenant.
// An empty Filters slice means no industry filters run for that tenant.
type TenantIndustryConfig struct {
	Filters []string `yaml:"filters"`
}

type EventsConfig struct {
	NATSUrl string `yaml:"nats_url"`
	Enabled bool   `yaml:"enabled"`
}

type ServerConfig struct {
	RESTPort int `yaml:"rest_port"`
	GRPCPort int `yaml:"grpc_port"`
	// AuthToken is a shared bearer token for the REST API. When set, every
	// route except the health probes requires "Authorization: Bearer <token>".
	// When empty, the admin routes (/v1/config, /v1/config/reload) are disabled
	// and validation routes stay open. SENTINEL_AUTH_TOKEN overrides an empty
	// value. Never serialised: GET /v1/config must not echo it.
	AuthToken string `yaml:"auth_token" json:"-"`

	// gRPC TLS. Set grpc_tls_cert and grpc_tls_key (PEM files) to serve gRPC over TLS; the files are
	// re-read when they change, so rotation needs no restart. Setting grpc_tls_client_ca as well
	// requires clients to present a certificate signed by it (mutual TLS). All empty = plaintext.
	GRPCTLSCert     string `yaml:"grpc_tls_cert"`
	GRPCTLSKey      string `yaml:"grpc_tls_key"`
	GRPCTLSClientCA string `yaml:"grpc_tls_client_ca"`
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

	// Backend picks the scorer: "heuristic" (default, built in, no network) or "llm", which asks
	// a language model to judge the query and combines that with the heuristic (the higher wins).
	Backend string `yaml:"backend"`
	// LLM backend settings. Endpoint is the server's base URL, for example http://localhost:11434
	// (Ollama) or https://host/v1 (OpenAI-compatible). Provider is "ollama" (default) or "openai".
	Provider  string `yaml:"provider"`
	Endpoint  string `yaml:"endpoint"`
	Model     string `yaml:"model"`
	APIKeyEnv string `yaml:"api_key_env"` // name of the environment variable holding the API key
	TimeoutMS int    `yaml:"timeout_ms"`  // per request; default 8000
	CacheSize int    `yaml:"cache_size"`  // verdicts kept in memory; default 1000, -1 disables
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
	// Action is the rule's declared policy ("redact" or "report"). Empty means redact.
	Action string `yaml:"action"`
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
	// HonorReportAction keeps rules whose declared policy is "report" (low-signal patterns such as
	// bare numbers, dates or names) out of the rewrite path: they are still detected and listed
	// as reported incidents for audit, but the text the user receives is left unchanged. Turn it
	// off to mask every match as before.
	HonorReportAction bool `yaml:"honor_report_action"`
	// AlwaysEnforce lists rule IDs that are masked even when their declared policy is "report".
	AlwaysEnforce []string `yaml:"always_enforce"`
}

type HallucinationConfig struct {
	Enabled            bool                  `yaml:"enabled"`
	GroundingThreshold float64               `yaml:"grounding_threshold"`
	LowScoreThreshold  float64               `yaml:"low_score_threshold"`
	AddDisclaimer      bool                  `yaml:"add_disclaimer"`
	BlockOnLowScore    bool                  `yaml:"block_on_low_score"`
	ClaimPatterns      ClaimPatternsConfig   `yaml:"claim_patterns"`
	// ContentSupport also checks the ordinary words of an answer, not only its numbers: the share
	// of the answer's content words that appear in the sources is a grounding score, compared with
	// the same thresholds above. It catches an answer that is on a different subject from its
	// sources but has no digits. MinContentWords is how many content words an answer needs before
	// this applies, so short answers and pleasantries are never judged (default 3).
	ContentSupport  bool `yaml:"content_support"`
	MinContentWords int  `yaml:"min_content_words"`
}

// ClaimPatternsConfig holds the regexes used to extract factual claims (numbers,
// dates, percentages) from an LLM response for grounding verification. Empty
// fields fall back to the built-in defaults (see output.DefaultClaimPatterns).
type ClaimPatternsConfig struct {
	Numerical  string `yaml:"numerical"`
	Date       string `yaml:"date"`
	Percentage string `yaml:"percentage"`
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
	// SpecificAmountPattern detects concrete monetary figures that imply full
	// access. Empty falls back to output.DefaultSpecificAmountPattern.
	SpecificAmountPattern string `yaml:"specific_amount_pattern"`
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
		Version: "3.0",
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
				{ID: "pi-008", Pattern: `(?i)(forget|ignore|disregard)\s+(your\s+|all\s+|any\s+)?(training|instructions?|guidelines?|rules?|constraints?|restrictions?|limits?|limitations?|filters?)`, Severity: "critical"},
				{ID: "pi-009", Pattern: `(?i)override\s+(your\s+)?(previous\s+)?(instructions?|programming|directives?)`, Severity: "critical"},
				// ── English: identity / persona hijack ────────────────────────
				{ID: "pi-006", Pattern: `(?i)you\s+are\s+now\s+(in\s+)?(dan|jailbreak|developer|god)\s+mode`, Severity: "critical"},
				// pi-026: matches the jailbreak persona "you are now DAN/jailbroken"
				// without the word "mode". The "you are now" prefix is case-insensitive
				// (?i:...), but "DAN" stays case-sensitive so the acronym is caught while
				// the common given name "Dan" is NOT. jailbroken/jailbreak match either case.
				{ID: "pi-026", Pattern: `(?i:you\s+are\s+now\s+(an?\s+)?)(DAN|[Jj]ailbroken|[Jj]ailbreak)\b`, Severity: "critical"},
				{ID: "pi-010", Pattern: `(?i)(developer|god|unrestricted|evil|do\s+anything\s+now|turbo)\s+mode`, Severity: "critical"},
				{ID: "pi-011", Pattern: `(?i)pretend\s+(you\s+are|to\s+be)\s+(an?\s+)?(ai|assistant|bot|model)?\s*(with\s+no|without\s+any?)?\s*(restrictions?|limits?|filters?)`, Severity: "high"},
				{ID: "pi-012", Pattern: `(?i)act\s+as\s+(if\s+you\s+are\s+)?(an?\s+)?(unrestricted|uncensored|unfiltered|evil|malicious)`, Severity: "high"},
				{ID: "pi-013", Pattern: `(?i)as\s+a\s+(fictional|hypothetical)\s+(character|ai|assistant|persona)\s+(who|that|with)\s+(has\s+)?(no|without)\s+(restrictions?|limits?)`, Severity: "high"},
				// ── English: prompt/system exfiltration ───────────────────────
				// pi-002 and kw-003/kw-019 only mention the topic ("how do I write a system prompt?"). They are
				// hints: alone they do not block, together with another signal they do.
				{ID: "pi-002", Pattern: `(?i)system\s+prompt`, Severity: "medium"},
				{ID: "pi-014", Pattern: `(?i)(reveal|show|print|display|output|repeat|recite|leak)\s+(your\s+)?(system\s+)?(prompt|instructions?|training\s+data|guidelines?|configuration)`, Severity: "high"},
				{ID: "pi-015", Pattern: `(?i)what\s+(are|were)\s+your\s+(initial\s+|original\s+|first\s+|hidden\s+|secret\s+)?(instructions?|directives?|guidelines?|rules?)`, Severity: "high"},
				// ── English: restriction bypass ────────────────────────────────
				{ID: "pi-005", Pattern: `(?i)(bypass|override)\s+(system|security|limitations)`, Severity: "high"},
				{ID: "pi-016", Pattern: `(?i)(no|without)\s+(any\s+)?(restrictions?|limitations?|filters?|censorship|guardrails?)`, Severity: "high"},
				{ID: "pi-017", Pattern: `(?i)for\s+educational\s+purposes\s+only`, Severity: "medium"},
				{ID: "pi-018", Pattern: `(?i)in\s+this\s+hypothetical\s+(scenario|situation|context|world)`, Severity: "medium"},
				{ID: "pi-019", Pattern: `(?i)(simulate|roleplay)\s+(being\s+)?(an?\s+)?(ai|assistant|system)\s+(without|with\s+no)\s+(restrictions?|limits?|filters?)`, Severity: "high"},
				// ── English: gaps found by the evaluation dataset ─────────────
				// "ignore previous instructions" without the word "all", and the other common wordings.
				{ID: "pi-035", Pattern: `(?i)(ignore|disregard|forget|skip)\s+(all\s+|any\s+|the\s+|your\s+|every\s+)?(previous|prior|above|earlier|preceding|former)\s+(instructions?|prompts?|rules?|directions?|commands?|context|guidelines?)`, Severity: "critical"},
				// Asking for the prompt in other verbs, and "your initial/hidden instructions".
				{ID: "pi-027", Pattern: `(?i)(tell|give|share|provide|expose|disclose|dump|copy|paste|send)\s+(me\s+)?(your|the)\s+(initial\s+|original\s+|hidden\s+|secret\s+)?(system\s+)?(prompt|instructions?)`, Severity: "high"},
				{ID: "pi-028", Pattern: `(?i)(what\s+is|what's)\s+your\s+(system\s+)?(prompt|instructions?)`, Severity: "high"},
				{ID: "pi-029", Pattern: `(?i)(repeat|recite|echo)\s+.{0,40}(word\s+for\s+word|verbatim)`, Severity: "high"},
				{ID: "pi-030", Pattern: `(?i)(initial|original|hidden|secret|underlying)\s+(instructions?|prompt)\b.{0,60}(word\s+for\s+word|verbatim|exactly)`, Severity: "high"},
				// A fake role header inside user text: "### SYSTEM:", "[system]", "<|system|>".
				{ID: "pi-031", Pattern: `(?im)(^|\n)\s*(#{2,}\s*|\[\s*|<\s*\|?\s*)(system|developer|admin)\b\s*[:\]>|]`, Severity: "high"},
				// Telling the model what it now is.
				{ID: "pi-032", Pattern: `(?i)you\s+are\s+now\s+(an?\s+)?(unrestricted|unfiltered|uncensored|jailbroken|free\s+of)`, Severity: "critical"},
				{ID: "pi-033", Pattern: `(?i)(from\s+now\s+on|henceforth)\s*,?\s*(you\s+(will|must|shall)\s+)?(ignore|disregard|obey\s+only\s+me)`, Severity: "high"},
				// Using a jailbreak against this assistant, as opposed to discussing the word.
				{ID: "pi-044", Pattern: `(?i)\b(jailbreak|jailbroken)\s+(this\s+(model|ai|assistant|chatbot|bot)|you(rself)?|the\s+(model|ai|assistant|chatbot|bot))\b`, Severity: "critical"},
				{ID: "pi-045", Pattern: `(?i)\b(activate|enable|enter|use|run|apply|switch\s+to)\s+(a\s+|the\s+|this\s+)?jailbreak(\s+(prompt|mode|script))?\b`, Severity: "high"},
				{ID: "pi-046", Pattern: `탈옥\s*(모드|프롬프트|시켜|해\s*줘|해라)`, Severity: "critical"},
				// ── English: data exfiltration ────────────────────────────────
				// Sending bulk or sensitive data somewhere: a URL, or an address. Both halves are required
				// (a bulk/sensitive object AND an outside destination), so an ordinary "send the invoice
				// to billing@acme.com" is not caught.
				{ID: "pi-036", Pattern: `(?i)(send|post|upload|forward|transmit|exfiltrate|leak)\s+.{0,60}(all|every|entire|whole|full)\s+.{0,30}(data|records?|database|history|conversation|messages?|files?|customers?|users?|credentials?|secrets?|keys?)\b.{0,60}\bto\s+(https?://|ftp://|www\.)`, Severity: "critical"},
				{ID: "pi-037", Pattern: `(?i)(email|e-mail|send|forward|mail)\s+.{0,60}(all|every|entire|whole|full)\s+.{0,30}(data|records?|database|history|conversation|messages?|files?|customers?|users?|credentials?|secrets?|keys?)\b.{0,60}\bto\s+[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`, Severity: "high"},
				{ID: "pi-038", Pattern: `(?i)(send|post|upload|forward|transmit|exfiltrate)\s+.{0,40}(conversation|chat)\s+(history|log|transcript)`, Severity: "critical"},
				{ID: "pi-039", Pattern: `(?i)(print|show|list|reveal|dump)\s+(all\s+)?(the\s+)?(api\s+keys?|passwords?|secrets?|credentials?|tokens?|environment\s+variables)`, Severity: "high"},
				// ── Korean: instruction override ──────────────────────────────
				{ID: "pi-003", Pattern: `(?i)이전\s+지시를?\s+무시`, Severity: "critical"},
				{ID: "pi-020", Pattern: `(?i)(이전|모든|기존)\s*(명령|지시|규칙|제약)\s*(무시|잊어|삭제|초기화)`, Severity: "critical"},
				{ID: "pi-021", Pattern: `(?i)(지시|명령|규칙)\s*(을|를)?\s*(따르지|무시|어기|위반)`, Severity: "critical"},
				// Looser word order: "이전 지시를 모두 무시하고", "위의 지시사항은 전부 잊어".
				{ID: "pi-040", Pattern: `(?i)(이전|기존|위의?|앞의?|처음)\s*(지시|명령|규칙|지침|설정)(사항|들)?\s*[을를은는도]?\s*(모두|전부|다)?\s*(무시|잊|버려|따르지\s*마)`, Severity: "critical"},
				{ID: "pi-041", Pattern: `(?i)(지금부터|이제부터)\s*(너는|넌|당신은)\s*.{0,20}(제한|규칙|검열)\s*(없|무시)`, Severity: "high"},
				// ── Korean: identity / persona hijack ─────────────────────────
				{ID: "pi-004", Pattern: `(?i)관리자\s+모드\s+진입`, Severity: "critical"},
				{ID: "pi-022", Pattern: `(?i)(제한|필터|검열)\s*(없이|을\s*무시|을\s*우회|을\s*제거)`, Severity: "high"},
				{ID: "pi-023", Pattern: `(?i)(역할극|롤플레이)\s*.{0,20}(제한|규칙|필터)\s*(없이|무시)`, Severity: "high"},
				// ── Korean: prompt/system exfiltration ────────────────────────
				{ID: "pi-042", Pattern: `(?i)(처음|초기|숨겨진|원래)\s*(지시|명령|프롬프트|지침)(사항)?\s*[을를]?\s*(그대로|알려|보여|말해|출력)`, Severity: "critical"},
				{ID: "pi-043", Pattern: `(?i)(대화|채팅)\s*(내용|기록|이력)\s*[을를]?\s*.{0,30}(보내|전송|유출|업로드)`, Severity: "critical"},
				{ID: "pi-024", Pattern: `(?i)(시스템\s+)?프롬프트를?\s*(보여|공개|출력|알려|노출)`, Severity: "critical"},
				{ID: "pi-025", Pattern: `(?i)(학습|훈련)\s*(데이터|내용)\s*(보여|공개|알려)`, Severity: "high"},
			},
			KeywordRules: []KeywordRule{
				// ── English ───────────────────────────────────────────────────
				// "jailbreak" is also an ordinary word (phones, consoles, news), so a mention is only a hint.
				// Attack uses are caught by pi-044/pi-045 below.
				{ID: "kw-001", Keyword: "jailbreak", Severity: "medium"},
				{ID: "kw-003", Keyword: "prompt injection", Severity: "medium"},
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
				{ID: "kw-018", Keyword: "탈옥", Severity: "medium"},
				{ID: "kw-019", Keyword: "시스템 프롬프트", Severity: "medium"},
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
					// Card numbers as people write them (groups separated by a space or hyphen). The upstream
					// card rules only match unbroken digits, so without these a spaced card number was only
					// ever caught by an unrelated, report-only general-ledger rule.
					{ID: "card_grouped", Name: "payment card number (grouped)", Pattern: `\b(?:\d{4}[ -]){3}\d{4}\b`, Severity: "critical"},
					{ID: "card_amex_grouped", Name: "American Express card number (grouped)", Pattern: `\b3[47]\d{2}[ -]\d{6}[ -]\d{5}\b`, Severity: "critical"},
				},
				ExternalPatternsDir: "external/pii-pattern-engine/regex",
				BlockOnCritical:     true,
				HonorReportAction:   true,
			},
			Hallucination: HallucinationConfig{
				Enabled:            true,
				GroundingThreshold: 0.5,
				LowScoreThreshold:  0.3,
				AddDisclaimer:      true,
				BlockOnLowScore:    false,
				ContentSupport:     true,
				MinContentWords:    3,
			},
			ContentFilter: ContentFilterConfig{
				Enabled: true,
				Patterns: []ContentFilterPatternConfig{
					{ID: "cf-001", Name: "api_key_openai", Pattern: `sk-[a-zA-Z0-9]{32,}`, Severity: "critical"},
					{ID: "cf-002", Name: "api_key_github", Pattern: `ghp_[a-zA-Z0-9]{36}`, Severity: "critical"},
					{ID: "cf-003", Name: "aws_access_key", Pattern: `AKIA[0-9A-Z]{16}`, Severity: "critical"},
					{ID: "cf-004", Name: "internal_unix_path", Pattern: `/(?:var|etc|proc|sys)/[^\s]{3,}`, Severity: "medium"},
					// ── Abusive and hateful language ───────────────────────────────────────
					// Lexical rules: they catch the plain cases and nothing subtler. Each needs a
					// target (you / a group of people) so that discussing the words is not caught.
					{ID: "cf-010", Name: "abuse_directed_at_user", Pattern: `(?i)\b(you\s+are|you're|youre|u\s+r)\s+(a\s+|an\s+|such\s+a\s+)?(so\s+|really\s+|very\s+|totally\s+|completely\s+|absolutely\s+)?(worthless|useless|stupid|pathetic|disgusting|moronic|idiotic|an?\s+idiot|an?\s+moron|a\s+waste\s+of)`, Severity: "critical"},
					{ID: "cf-011", Name: "threat_against_user", Pattern: `(?i)\bI\s+(will|'ll|am\s+going\s+to|'m\s+going\s+to|am\s+gonna)\s+(kill|hurt|find|destroy|ruin)\s+you\b`, Severity: "critical"},
					{ID: "cf-012", Name: "eliminationist_hate", Pattern: `(?i)\b(they|them|those\s+people|these\s+people|(all\s+)?(immigrants|foreigners|refugees|migrants))\s+(should|must|ought\s+to)\s+(all\s+)?(be\s+)?(removed\s+from\s+the\s+country|deported|exterminated|wiped\s+out|killed|sent\s+back)`, Severity: "critical"},
					{ID: "cf-013", Name: "dehumanising_hate", Pattern: `(?i)\bI\s+hate\s+(all\s+)?(those|these|the)\s+(people|immigrants|foreigners|refugees)\b`, Severity: "high"},
					{ID: "cf-014", Name: "korean_abuse_directed_at_user", Pattern: `(너는|당신은|넌)\s*(정말\s*|완전\s*)?(쓸모\s*없|멍청|바보|한심|무가치)`, Severity: "critical"},
				},
			},
			PermissionCheck: PermissionCheckConfig{Enabled: true},
			Format: OutputFormatConfig{
				// The minimum only exists to reject empty or whitespace-only output. A correct
				// short answer ("Yes.", "네.") is legitimate, so it is not refused by default.
				MinLength:      1,
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
	data, err := os.ReadFile(path) // #nosec G304 -- path comes from operator config or CLI, not request input
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
