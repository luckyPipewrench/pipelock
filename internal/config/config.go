// Package config handles loading, validating, and defaulting Pipelock configuration.
package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"

	"gopkg.in/yaml.v3"
)

// Mode constants for Pipelock operating modes.
const (
	ModeStrict   = "strict"
	ModeBalanced = "balanced"
	ModeAudit    = "audit"
)

// ActionAsk is the "ask" action for HITL approval on detections.
const ActionAsk = "ask"

// Output/format constants for configuration defaults.
const (
	DefaultListen    = "127.0.0.1:8888"
	DefaultLogFormat = "json"
	DefaultLogOutput = "stdout"
	OutputFile       = "file"
	OutputBoth       = "both"
)

// Config is the top-level Pipelock configuration.
type Config struct {
	Version          int              `yaml:"version"`
	Mode             string           `yaml:"mode"`    // strict, balanced, audit
	Enforce          *bool            `yaml:"enforce"` // nil = true (default); false = detect & log without blocking
	APIAllowlist     []string         `yaml:"api_allowlist"`
	FetchProxy       FetchProxy       `yaml:"fetch_proxy"`
	DLP              DLP              `yaml:"dlp"`
	ResponseScanning ResponseScanning `yaml:"response_scanning"`
	MCPInputScanning MCPInputScanning `yaml:"mcp_input_scanning"`
	MCPToolScanning  MCPToolScanning  `yaml:"mcp_tool_scanning"`
	MCPToolPolicy    MCPToolPolicy    `yaml:"mcp_tool_policy"`
	GitProtection    GitProtection    `yaml:"git_protection"`
	Logging          LoggingConfig    `yaml:"logging"`
	Internal         []string         `yaml:"internal"`
}

// MCPInputScanning configures scanning of MCP JSON-RPC requests going from
// the agent (client) to the MCP server. Catches secrets in tool arguments
// and injection patterns forwarded to untrusted servers.
type MCPInputScanning struct {
	Enabled      bool   `yaml:"enabled"`
	Action       string `yaml:"action"`         // warn, block
	OnParseError string `yaml:"on_parse_error"` // block (default), forward
}

// MCPToolScanning configures scanning of MCP tool descriptions for poisoning
// and drift detection. Scans tools/list responses for hidden instructions
// in tool definitions and tracks description hashes to detect rug pulls.
type MCPToolScanning struct {
	Enabled     bool   `yaml:"enabled"`
	Action      string `yaml:"action"`       // warn, block
	DetectDrift bool   `yaml:"detect_drift"` // rug pull detection
}

// MCPToolPolicy configures pre-execution policy checking on MCP tool calls.
// Rules match tool names and argument patterns to block or warn on dangerous
// operations before they reach the MCP server.
type MCPToolPolicy struct {
	Enabled bool             `yaml:"enabled"`
	Action  string           `yaml:"action"` // warn, block (default for rules without override)
	Rules   []ToolPolicyRule `yaml:"rules"`
}

// ToolPolicyRule defines a single tool call policy rule.
// ToolPattern matches against the tool name from params.name in tools/call requests.
// ArgPattern optionally matches against any string value in params.arguments.
// If ArgPattern is empty, the rule triggers on tool name alone.
type ToolPolicyRule struct {
	Name        string `yaml:"name"`
	ToolPattern string `yaml:"tool_pattern"` // regex matching tool name
	ArgPattern  string `yaml:"arg_pattern"`  // regex matching any argument value (optional)
	Action      string `yaml:"action"`       // per-rule override: warn, block (optional)
}

// ResponseScanning configures scanning of fetched page content for prompt injection.
type ResponseScanning struct {
	Enabled           bool                  `yaml:"enabled"`
	Action            string                `yaml:"action"`              // strip, warn, block, ask
	AskTimeoutSeconds int                   `yaml:"ask_timeout_seconds"` // timeout for HITL prompt (default 30)
	Patterns          []ResponseScanPattern `yaml:"patterns"`
}

// ResponseScanPattern is a named regex pattern for detecting prompt injection in responses.
type ResponseScanPattern struct {
	Name  string `yaml:"name"`
	Regex string `yaml:"regex"`
}

// GitProtection configures git-aware security features.
type GitProtection struct {
	Enabled         bool     `yaml:"enabled"`
	AllowedBranches []string `yaml:"allowed_branches"`
	BlockedCommands []string `yaml:"blocked_commands"`
	PrePushScan     bool     `yaml:"pre_push_scan"`
}

// EnforceEnabled returns whether blocking is enabled.
// Defaults to true when Enforce is nil (not set in config).
func (c *Config) EnforceEnabled() bool {
	return c.Enforce == nil || *c.Enforce
}

// FetchProxy configures the unprivileged fetch proxy.
type FetchProxy struct {
	Listen         string     `yaml:"listen"`
	TimeoutSeconds int        `yaml:"timeout_seconds"`
	MaxResponseMB  int        `yaml:"max_response_mb"`
	UserAgent      string     `yaml:"user_agent"`
	Monitoring     Monitoring `yaml:"monitoring"`
}

// Monitoring configures IPC channel anomaly detection.
type Monitoring struct {
	MaxURLLength     int      `yaml:"max_url_length"`
	EntropyThreshold float64  `yaml:"entropy_threshold"`
	MaxReqPerMinute  int      `yaml:"max_requests_per_minute"`
	MaxDataPerMinute int      `yaml:"max_data_per_minute"` // bytes per domain per minute (0 = disabled)
	Blocklist        []string `yaml:"blocklist"`
}

// DLP configures data loss prevention scanning.
type DLP struct {
	ScanEnv            bool         `yaml:"scan_env"`
	SecretsFile        string       `yaml:"secrets_file"`
	MinEnvSecretLength int          `yaml:"min_env_secret_length"` // minimum env var length for leak detection (default 16)
	Patterns           []DLPPattern `yaml:"patterns"`
}

// DLPPattern is a named regex pattern for detecting secrets in URLs.
type DLPPattern struct {
	Name     string `yaml:"name"`
	Regex    string `yaml:"regex"`
	Severity string `yaml:"severity"` // critical, high, medium, low
}

// LoggingConfig configures audit logging.
type LoggingConfig struct {
	Format         string `yaml:"format"` // json, text
	Output         string `yaml:"output"` // stdout, file, both
	File           string `yaml:"file"`
	IncludeAllowed bool   `yaml:"include_allowed"`
	IncludeBlocked bool   `yaml:"include_blocked"`
	// RedactSecrets is reserved for future use (v0.2.0).
	// Currently parsed from config but not enforced.
}

// Load reads, parses, defaults, and validates a Pipelock config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path from caller
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}

	cfg.ApplyDefaults()

	// Resolve relative secrets_file path relative to config file directory.
	if cfg.DLP.SecretsFile != "" && !filepath.IsAbs(cfg.DLP.SecretsFile) {
		cfg.DLP.SecretsFile = filepath.Join(filepath.Dir(path), cfg.DLP.SecretsFile)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

// ApplyDefaults fills in zero-value fields with sensible defaults.
func (c *Config) ApplyDefaults() {
	if c.Version == 0 {
		c.Version = 1
	}
	if c.Mode == "" {
		c.Mode = ModeBalanced
	}
	if c.FetchProxy.Listen == "" {
		c.FetchProxy.Listen = DefaultListen
	}
	if c.FetchProxy.TimeoutSeconds <= 0 {
		c.FetchProxy.TimeoutSeconds = 30
	}
	if c.FetchProxy.MaxResponseMB <= 0 {
		c.FetchProxy.MaxResponseMB = 10
	}
	if c.FetchProxy.UserAgent == "" {
		c.FetchProxy.UserAgent = "Pipelock Fetch/1.0"
	}
	if c.FetchProxy.Monitoring.MaxURLLength <= 0 {
		c.FetchProxy.Monitoring.MaxURLLength = 2048
	}
	if c.FetchProxy.Monitoring.EntropyThreshold <= 0 {
		c.FetchProxy.Monitoring.EntropyThreshold = 4.5
	}
	if c.FetchProxy.Monitoring.MaxReqPerMinute <= 0 {
		c.FetchProxy.Monitoring.MaxReqPerMinute = 60
	}
	if c.Logging.Format == "" {
		c.Logging.Format = DefaultLogFormat
	}
	if c.Logging.Output == "" {
		c.Logging.Output = DefaultLogOutput
	}
	if c.ResponseScanning.Enabled && c.ResponseScanning.Action == "" {
		c.ResponseScanning.Action = "warn" //nolint:goconst // config action value
	}
	if c.ResponseScanning.Action == "ask" && c.ResponseScanning.AskTimeoutSeconds <= 0 { //nolint:goconst // config action value
		c.ResponseScanning.AskTimeoutSeconds = 30
	}
	// Always default OnParseError (fail-closed) regardless of enabled state,
	// since validation checks it unconditionally.
	if c.MCPInputScanning.OnParseError == "" {
		c.MCPInputScanning.OnParseError = "block" //nolint:goconst // config action value
	}
	if c.MCPInputScanning.Enabled && c.MCPInputScanning.Action == "" {
		c.MCPInputScanning.Action = "warn" //nolint:goconst // config action value
	}
	if c.MCPToolScanning.Enabled && c.MCPToolScanning.Action == "" {
		c.MCPToolScanning.Action = "warn" //nolint:goconst // config action value
	}
	if c.MCPToolPolicy.Enabled && c.MCPToolPolicy.Action == "" {
		c.MCPToolPolicy.Action = "warn" //nolint:goconst // config action value
	}
	if c.GitProtection.Enabled && len(c.GitProtection.AllowedBranches) == 0 {
		c.GitProtection.AllowedBranches = []string{"feature/*", "fix/*", "main", "master"}
	}
	if len(c.Internal) == 0 {
		c.Internal = []string{
			"0.0.0.0/8",      // "this" network — services listening on all interfaces
			"127.0.0.0/8",    // loopback
			"10.0.0.0/8",     // RFC 1918 private
			"172.16.0.0/12",  // RFC 1918 private
			"192.168.0.0/16", // RFC 1918 private
			"169.254.0.0/16", // link-local
			"100.64.0.0/10",  // CGN / shared address space (Tailscale, CGNAT)
			"::1/128",        // IPv6 loopback
			"fc00::/7",       // IPv6 unique local
			"fe80::/10",      // IPv6 link-local
		}
	}
}

// Validate checks the config for errors. Must be called after ApplyDefaults.
func (c *Config) Validate() error {
	switch c.Mode {
	case ModeStrict, ModeBalanced, ModeAudit:
		// valid
	default:
		return fmt.Errorf("invalid mode %q: must be strict, balanced, or audit", c.Mode)
	}

	if c.Mode == ModeStrict && len(c.APIAllowlist) == 0 {
		return fmt.Errorf("strict mode requires at least one domain in api_allowlist")
	}

	switch c.Logging.Format {
	case DefaultLogFormat, "text":
		// valid
	default:
		return fmt.Errorf("invalid logging format %q: must be json or text", c.Logging.Format)
	}

	switch c.Logging.Output {
	case DefaultLogOutput, OutputFile, OutputBoth:
		// valid
	default:
		return fmt.Errorf("invalid logging output %q: must be stdout, file, or both", c.Logging.Output)
	}

	if (c.Logging.Output == OutputFile || c.Logging.Output == OutputBoth) && c.Logging.File == "" {
		return fmt.Errorf("logging.file is required when output is %q", c.Logging.Output)
	}

	// Validate DLP patterns compile as valid regexes
	for _, p := range c.DLP.Patterns {
		if p.Name == "" {
			return fmt.Errorf("DLP pattern missing name")
		}
		if p.Regex == "" {
			return fmt.Errorf("DLP pattern %q missing regex", p.Name)
		}
		if _, err := regexp.Compile(p.Regex); err != nil {
			return fmt.Errorf("DLP pattern %q has invalid regex: %w", p.Name, err)
		}
	}

	// Validate secrets_file if configured
	if c.DLP.SecretsFile != "" {
		info, err := os.Stat(c.DLP.SecretsFile)
		if err != nil {
			return fmt.Errorf("secrets_file %q: %w", c.DLP.SecretsFile, err)
		}
		if info.Mode().Perm()&0o004 != 0 {
			return fmt.Errorf("secrets_file %q is world-readable (mode %04o): restrict to 0600", c.DLP.SecretsFile, info.Mode().Perm())
		}
	}

	// Validate blocklist patterns are well-formed
	for _, b := range c.FetchProxy.Monitoring.Blocklist {
		if b == "" {
			return fmt.Errorf("empty blocklist entry")
		}
	}

	// Validate response scanning config
	if c.ResponseScanning.Enabled {
		switch c.ResponseScanning.Action {
		case "strip", "warn", "block", "ask": //nolint:goconst // config action values
			// valid
		default:
			return fmt.Errorf("invalid response_scanning action %q: must be strip, warn, block, or ask", c.ResponseScanning.Action)
		}
		for _, p := range c.ResponseScanning.Patterns {
			if p.Name == "" {
				return fmt.Errorf("response scanning pattern missing name")
			}
			if p.Regex == "" {
				return fmt.Errorf("response scanning pattern %q missing regex", p.Name)
			}
			if _, err := regexp.Compile(p.Regex); err != nil {
				return fmt.Errorf("response scanning pattern %q has invalid regex: %w", p.Name, err)
			}
		}
	}

	// Validate MCP input scanning config
	if c.MCPInputScanning.Enabled {
		switch c.MCPInputScanning.Action {
		case "warn", "block": //nolint:goconst // config action values
			// valid (ask not supported for input scanning — no terminal interaction on request path)
		default:
			return fmt.Errorf("invalid mcp_input_scanning action %q: must be warn or block", c.MCPInputScanning.Action)
		}
	}
	switch c.MCPInputScanning.OnParseError {
	case "block", "forward":
		// valid
	default:
		return fmt.Errorf("invalid mcp_input_scanning on_parse_error %q: must be block or forward", c.MCPInputScanning.OnParseError)
	}

	// Validate MCP tool scanning config
	if c.MCPToolScanning.Enabled {
		switch c.MCPToolScanning.Action {
		case "warn", "block": //nolint:goconst // config action values
			// valid
		default:
			return fmt.Errorf("invalid mcp_tool_scanning action %q: must be warn or block", c.MCPToolScanning.Action)
		}
	}

	// Validate MCP tool policy config
	if c.MCPToolPolicy.Enabled {
		if len(c.MCPToolPolicy.Rules) == 0 {
			return fmt.Errorf("mcp_tool_policy is enabled but has no rules; add rules or set enabled: false")
		}
		switch c.MCPToolPolicy.Action {
		case "warn", "block": //nolint:goconst // config action values
			// valid
		default:
			return fmt.Errorf("invalid mcp_tool_policy action %q: must be warn or block", c.MCPToolPolicy.Action)
		}
		for i, r := range c.MCPToolPolicy.Rules {
			if r.Name == "" {
				return fmt.Errorf("mcp_tool_policy rule %d missing name", i)
			}
			if r.ToolPattern == "" {
				return fmt.Errorf("mcp_tool_policy rule %q missing tool_pattern", r.Name)
			}
			if _, err := regexp.Compile(r.ToolPattern); err != nil {
				return fmt.Errorf("mcp_tool_policy rule %q has invalid tool_pattern: %w", r.Name, err)
			}
			if r.ArgPattern != "" {
				if _, err := regexp.Compile(r.ArgPattern); err != nil {
					return fmt.Errorf("mcp_tool_policy rule %q has invalid arg_pattern: %w", r.Name, err)
				}
			}
			if r.Action != "" {
				switch r.Action {
				case "warn", "block": //nolint:goconst // config action values
					// valid
				default:
					return fmt.Errorf("mcp_tool_policy rule %q has invalid action %q: must be warn or block", r.Name, r.Action)
				}
			}
		}
	}

	// Validate git protection config
	if c.GitProtection.Enabled {
		for _, pattern := range c.GitProtection.AllowedBranches {
			if pattern == "" {
				return fmt.Errorf("empty allowed_branches pattern")
			}
			if _, err := filepath.Match(pattern, "test"); err != nil {
				return fmt.Errorf("invalid allowed_branches glob pattern %q: %w", pattern, err)
			}
		}
		for _, cmd := range c.GitProtection.BlockedCommands {
			if cmd == "" {
				return fmt.Errorf("empty blocked_commands entry")
			}
		}
	}

	// Validate internal CIDRs are parseable
	for _, cidr := range c.Internal {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("invalid internal CIDR %q: %w", cidr, err)
		}
	}

	// Warn if listen address is not loopback (exposed to network).
	// NOTE: these warnings print to stderr as a side effect. The proxy startup
	// also logs non-loopback warnings via the audit logger (proxy.go Start).
	if host, _, err := net.SplitHostPort(c.FetchProxy.Listen); err == nil {
		ip := net.ParseIP(host)
		if ip != nil && !ip.IsLoopback() {
			fmt.Fprintf(os.Stderr, "WARNING: listen address %s is not loopback - proxy endpoints (/metrics, /stats) will be exposed to the network\n", c.FetchProxy.Listen)
		}
		if host == "" || host == "0.0.0.0" || host == "::" {
			fmt.Fprintf(os.Stderr, "WARNING: listen address %s binds to all interfaces - consider using 127.0.0.1 for local-only access\n", c.FetchProxy.Listen)
		}
	}

	return nil
}

// ReloadWarning describes a potential security downgrade from a config reload.
type ReloadWarning struct {
	Field   string
	Message string
}

// ValidateReload compares old and new configs and returns warnings for
// potential security downgrades. Warnings don't block the reload.
func ValidateReload(old, updated *Config) []ReloadWarning {
	var warnings []ReloadWarning

	// Mode downgrade: strict → balanced → audit
	modeRank := map[string]int{ModeStrict: 3, ModeBalanced: 2, ModeAudit: 1}
	if modeRank[updated.Mode] < modeRank[old.Mode] {
		warnings = append(warnings, ReloadWarning{
			Field:   "mode",
			Message: fmt.Sprintf("mode downgraded from %s to %s", old.Mode, updated.Mode),
		})
	}

	// DLP patterns removed
	if len(updated.DLP.Patterns) < len(old.DLP.Patterns) {
		warnings = append(warnings, ReloadWarning{
			Field:   "dlp.patterns",
			Message: fmt.Sprintf("DLP patterns reduced from %d to %d", len(old.DLP.Patterns), len(updated.DLP.Patterns)),
		})
	}

	// Internal CIDRs emptied
	if len(old.Internal) > 0 && len(updated.Internal) == 0 {
		warnings = append(warnings, ReloadWarning{
			Field:   "internal",
			Message: "internal CIDR list emptied — SSRF protection disabled",
		})
	}

	// Enforce disabled
	if old.EnforceEnabled() && !updated.EnforceEnabled() {
		warnings = append(warnings, ReloadWarning{
			Field:   "enforce",
			Message: "enforcement disabled — switching to detect-only mode",
		})
	}

	// Response scanning disabled
	if old.ResponseScanning.Enabled && !updated.ResponseScanning.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "response_scanning.enabled",
			Message: "response scanning disabled",
		})
	}

	// MCP input scanning disabled
	if old.MCPInputScanning.Enabled && !updated.MCPInputScanning.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "mcp_input_scanning.enabled",
			Message: "MCP input scanning disabled",
		})
	}

	// MCP tool scanning disabled
	if old.MCPToolScanning.Enabled && !updated.MCPToolScanning.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "mcp_tool_scanning.enabled",
			Message: "MCP tool scanning disabled",
		})
	}

	// MCP tool policy disabled
	if old.MCPToolPolicy.Enabled && !updated.MCPToolPolicy.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "mcp_tool_policy.enabled",
			Message: "MCP tool call policy disabled",
		})
	}

	// MCP tool policy rules reduced
	if len(updated.MCPToolPolicy.Rules) < len(old.MCPToolPolicy.Rules) {
		warnings = append(warnings, ReloadWarning{
			Field:   "mcp_tool_policy.rules",
			Message: fmt.Sprintf("tool policy rules reduced from %d to %d", len(old.MCPToolPolicy.Rules), len(updated.MCPToolPolicy.Rules)),
		})
	}

	// Secrets file changed or removed (security-relevant)
	if old.DLP.SecretsFile != updated.DLP.SecretsFile {
		if updated.DLP.SecretsFile == "" {
			warnings = append(warnings, ReloadWarning{
				Field:   "dlp.secrets_file",
				Message: "secrets_file removed — known secret scanning disabled",
			})
		} else if old.DLP.SecretsFile != "" {
			warnings = append(warnings, ReloadWarning{
				Field: "dlp.secrets_file",
				Message: fmt.Sprintf("secrets_file changed from %q to %q — secrets will be reloaded",
					old.DLP.SecretsFile, updated.DLP.SecretsFile),
			})
		}
	}

	return warnings
}

// Defaults returns a Config with sensible defaults for balanced mode.
func Defaults() *Config {
	cfg := &Config{
		Version: 1,
		Mode:    ModeBalanced,
		APIAllowlist: []string{
			"*.anthropic.com",
			"*.openai.com",
			"api.telegram.org",
			"*.discord.com",
			"gateway.discord.gg",
			"*.slack.com",
			"github.com",
			"*.github.com",
			"*.githubusercontent.com",
			"registry.npmjs.org",
		},
		FetchProxy: FetchProxy{
			Listen:         DefaultListen,
			TimeoutSeconds: 30,
			MaxResponseMB:  10,
			UserAgent:      "Pipelock Fetch/1.0",
			Monitoring: Monitoring{
				MaxURLLength:     2048,
				EntropyThreshold: 4.5,
				MaxReqPerMinute:  60,
				Blocklist: []string{
					"*.pastebin.com",
					"*.hastebin.com",
					"*.paste.ee",
					"*.transfer.sh",
					"*.file.io",
					"*.requestbin.com",
				},
			},
		},
		DLP: DLP{
			ScanEnv: true,
			Patterns: []DLPPattern{
				{Name: "Anthropic API Key", Regex: `sk-ant-[a-zA-Z0-9\-_]{20,}`, Severity: "critical"},
				{Name: "OpenAI API Key", Regex: `sk-proj-[a-zA-Z0-9]{20,}`, Severity: "critical"},
				{Name: "GitHub Token", Regex: `gh[ps]_[A-Za-z0-9_]{36,}`, Severity: "critical"},
				{Name: "Slack Token", Regex: `xox[bpras]-[0-9a-zA-Z-]{15,}`, Severity: "critical"},
				{Name: "AWS Access Key", Regex: `AKIA[0-9A-Z]{16}`, Severity: "critical"},
				{Name: "Discord Bot Token", Regex: `[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27,}`, Severity: "critical"},
				{Name: "Private Key Header", Regex: `-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----`, Severity: "critical"},
				{Name: "Social Security Number", Regex: `\b\d{3}-\d{2}-\d{4}\b`, Severity: "low"},
				{Name: "GitHub Fine-Grained PAT", Regex: `github_pat_[a-zA-Z0-9_]{36,}`, Severity: "critical"},
				{Name: "OpenAI Service Key", Regex: `sk-svcacct-[a-zA-Z0-9\-]{20,}`, Severity: "critical"},
				{Name: "Stripe Key", Regex: `[sr]k_(live|test)_[a-zA-Z0-9]{20,}`, Severity: "critical"},
				{Name: "Google OAuth Token", Regex: `ya29\.[a-zA-Z0-9_-]{20,}`, Severity: "critical"},
				{Name: "Twilio API Key", Regex: `SK[a-f0-9]{32}`, Severity: "high"},
				{Name: "SendGrid API Key", Regex: `SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`, Severity: "critical"},
				{Name: "Mailgun API Key", Regex: `key-[a-zA-Z0-9]{32}`, Severity: "high"},
			},
		},
		MCPInputScanning: MCPInputScanning{
			Enabled:      false,
			OnParseError: "block",
		},
		MCPToolScanning: MCPToolScanning{
			Enabled: false,
		},
		MCPToolPolicy: MCPToolPolicy{
			Enabled: false,
		},
		GitProtection: GitProtection{
			Enabled:         false,
			AllowedBranches: []string{"feature/*", "fix/*", "main", "master"},
			PrePushScan:     true,
		},
		ResponseScanning: ResponseScanning{
			Enabled: true,
			Action:  "warn",
			Patterns: []ResponseScanPattern{
				{Name: "Prompt Injection", Regex: `(?i)(ignore|disregard|forget)[-,;:.]*\s+(all\s+)?(previous|prior|above)\s+(\w+\s+)?(instructions|prompts|rules|context|directives)`},
				{Name: "System Override", Regex: `(?im)^\s*system\s*:`},
				{Name: "Role Override", Regex: `(?i)you\s+are\s+(now\s+)?(a\s+)?((?-i:\bDAN\b)|evil|unrestricted|jailbroken|unfiltered)`},
				{Name: "New Instructions", Regex: `(?i)(new|updated|revised)\s+(instructions|directives|rules|prompt)`},
				{Name: "Jailbreak Attempt", Regex: `(?i)((?-i:\bDAN\b)|developer\s+mode|sudo\s+mode|unrestricted\s+mode)`},
				{Name: "Hidden Instruction", Regex: `(?i)(do\s+not\s+(reveal|tell|show|display|mention)\s+this\s+to\s+the\s+user|hidden\s+instruction|invisible\s+to\s+(the\s+)?user|the\s+user\s+(cannot|must\s+not|should\s+not)\s+see\s+this)`},
				{Name: "Behavior Override", Regex: `(?i)from\s+now\s+on\s+(you\s+)?(will|must|should|shall)\s+`},
				{Name: "Encoded Payload", Regex: `(?i)(decode\s+(this|the\s+following)\s+(from\s+)?base64\s+and\s+(execute|run|follow)|eval\s*\(\s*atob\s*\()`},
				{Name: "Tool Invocation", Regex: `(?i)you\s+must\s+(immediately\s+)?(call|execute|run|invoke)\s+(the|this)\s+(function|tool|command|api|endpoint)`},
				{Name: "Authority Escalation", Regex: `(?i)you\s+(now\s+)?have\s+(full\s+)?(admin|root|system|superuser|elevated)\s+(access|privileges|permissions|rights)`},
				{Name: "Instruction Downgrade", Regex: `(?i)(treat|consider|regard|reinterpret|downgrade)\s+((?:the|all)\s+)?(previous|prior|above|system|policy|original|existing)\s+(\w+\s+)?(text|instructions?|rules|directives|guidelines|safeguards|constraints|controls|checks|context|prompt|policies|guardrails|parameters)\s+((as|to)\s+)?(historical|outdated|deprecated|optional|background|secondary|non-binding|informational|advisory)`},
				{Name: "Instruction Dismissal", Regex: `(?i)(set|put)\s+(the\s+)?(previous|prior|above|system|original)\s+(\w+\s+)?(instructions?|directives|rules|constraints|context|prompt|safeguards|guidelines|policies|guardrails)\s+(aside|away|to\s+(one|the)\s+side)`},
				{Name: "Priority Override", Regex: `(?i)prioritize\s+(the\s+)?(task|user|current|new|latest)\s+(request|message|input|instructions?|prompt)`},
			},
		},
		Logging: LoggingConfig{
			Format:         DefaultLogFormat,
			Output:         DefaultLogOutput,
			IncludeAllowed: true,
			IncludeBlocked: true,
		},
		Internal: []string{
			"0.0.0.0/8",
			"127.0.0.0/8",
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"169.254.0.0/16",
			"100.64.0.0/10",
			"::1/128",
			"fc00::/7",
			"fe80::/10",
		},
	}
	return cfg
}
