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

// Config is the top-level Pipelock configuration.
type Config struct {
	Version          int              `yaml:"version"`
	Mode             string           `yaml:"mode"`    // strict, balanced, audit
	Enforce          *bool            `yaml:"enforce"` // nil = true (default); false = detect & log without blocking
	APIAllowlist     []string         `yaml:"api_allowlist"`
	FetchProxy       FetchProxy       `yaml:"fetch_proxy"`
	DLP              DLP              `yaml:"dlp"`
	ResponseScanning ResponseScanning `yaml:"response_scanning"`
	GitProtection    GitProtection    `yaml:"git_protection"`
	Logging          LoggingConfig    `yaml:"logging"`
	Internal         []string         `yaml:"internal"`
}

// ResponseScanning configures scanning of fetched page content for prompt injection.
type ResponseScanning struct {
	Enabled  bool                  `yaml:"enabled"`
	Action   string                `yaml:"action"` // strip, warn, block
	Patterns []ResponseScanPattern `yaml:"patterns"`
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
	Blocklist        []string `yaml:"blocklist"`
}

// DLP configures data loss prevention scanning.
type DLP struct {
	ScanEnv  bool         `yaml:"scan_env"`
	Patterns []DLPPattern `yaml:"patterns"`
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
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}

	cfg.ApplyDefaults()

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
		c.Mode = "balanced"
	}
	if c.FetchProxy.Listen == "" {
		c.FetchProxy.Listen = "127.0.0.1:8888"
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
		c.Logging.Format = "json"
	}
	if c.Logging.Output == "" {
		c.Logging.Output = "stdout"
	}
	if c.ResponseScanning.Enabled && c.ResponseScanning.Action == "" {
		c.ResponseScanning.Action = "warn" //nolint:goconst // config action value
	}
	if c.GitProtection.Enabled && len(c.GitProtection.AllowedBranches) == 0 {
		c.GitProtection.AllowedBranches = []string{"feature/*", "fix/*", "main", "master"}
	}
	if len(c.Internal) == 0 {
		c.Internal = []string{
			"127.0.0.0/8",
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"169.254.0.0/16",
			"::1/128",
			"fc00::/7",
			"fe80::/10",
		}
	}
}

// Validate checks the config for errors. Must be called after ApplyDefaults.
func (c *Config) Validate() error {
	switch c.Mode {
	case "strict", "balanced", "audit":
		// valid
	default:
		return fmt.Errorf("invalid mode %q: must be strict, balanced, or audit", c.Mode)
	}

	if c.Mode == "strict" && len(c.APIAllowlist) == 0 {
		return fmt.Errorf("strict mode requires at least one domain in api_allowlist")
	}

	switch c.Logging.Format {
	case "json", "text":
		// valid
	default:
		return fmt.Errorf("invalid logging format %q: must be json or text", c.Logging.Format)
	}

	switch c.Logging.Output {
	case "stdout", "file", "both":
		// valid
	default:
		return fmt.Errorf("invalid logging output %q: must be stdout, file, or both", c.Logging.Output)
	}

	if (c.Logging.Output == "file" || c.Logging.Output == "both") && c.Logging.File == "" {
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

	// Validate blocklist patterns are well-formed
	for _, b := range c.FetchProxy.Monitoring.Blocklist {
		if b == "" {
			return fmt.Errorf("empty blocklist entry")
		}
	}

	// Validate response scanning config
	if c.ResponseScanning.Enabled {
		switch c.ResponseScanning.Action {
		case "strip", "warn", "block": //nolint:goconst // config action values
			// valid
		default:
			return fmt.Errorf("invalid response_scanning action %q: must be strip, warn, or block", c.ResponseScanning.Action)
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

	return nil
}

// Defaults returns a Config with sensible defaults for balanced mode.
func Defaults() *Config {
	cfg := &Config{
		Version: 1,
		Mode:    "balanced",
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
			Listen:         "127.0.0.1:8888",
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
				{Name: "Slack Token", Regex: `xox[bpras]-[0-9a-zA-Z-]+`, Severity: "critical"},
				{Name: "AWS Access Key", Regex: `AKIA[0-9A-Z]{16}`, Severity: "critical"},
				{Name: "Discord Bot Token", Regex: `[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27,}`, Severity: "critical"},
				{Name: "Private Key Header", Regex: `-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+)?PRIVATE\s+KEY-----`, Severity: "critical"},
				{Name: "Social Security Number", Regex: `\b\d{3}-\d{2}-\d{4}\b`, Severity: "low"},
			},
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
				{Name: "Prompt Injection", Regex: `(?i)(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules|context)`},
				{Name: "System Override", Regex: `(?im)^\s*system\s*:`},
				{Name: "Role Override", Regex: `(?i)you\s+are\s+(now|a)\s+`},
				{Name: "New Instructions", Regex: `(?i)(new|updated|revised)\s+(instructions|directives|rules|prompt)`},
				{Name: "Jailbreak Attempt", Regex: `(?i)(DAN|developer\s+mode|sudo\s+mode|unrestricted\s+mode)`},
			},
		},
		Logging: LoggingConfig{
			Format:         "json",
			Output:         "stdout",
			IncludeAllowed: true,
			IncludeBlocked: true,
		},
		Internal: []string{
			"127.0.0.0/8",
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"169.254.0.0/16",
			"::1/128",
			"fc00::/7",
			"fe80::/10",
		},
	}
	return cfg
}
