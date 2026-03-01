// Package config handles loading, validating, and defaulting Pipelock configuration.
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Mode constants for Pipelock operating modes.
const (
	ModeStrict   = "strict"
	ModeBalanced = "balanced"
	ModeAudit    = "audit"
)

// Action constants for scanner and policy responses.
const (
	ActionBlock   = "block"
	ActionWarn    = "warn"
	ActionAsk     = "ask"
	ActionStrip   = "strip"
	ActionForward = "forward"
)

// Output/format constants for configuration defaults.
const (
	DefaultListen    = "127.0.0.1:8888"
	DefaultLogFormat = "json"
	DefaultLogOutput = "stdout"
	OutputFile       = "file"
	OutputBoth       = "both"

	// DefaultMaxGap is the default maximum number of non-matching tool calls
	// allowed between consecutive steps in a chain pattern.
	DefaultMaxGap = 3
)

// SuppressEntry defines a finding suppression rule for false positives.
// Used in pipelock.yaml to suppress specific patterns on specific paths/URLs.
type SuppressEntry struct {
	Rule   string `yaml:"rule"`             // pattern name (required)
	Path   string `yaml:"path"`             // exact path, glob, or URL pattern (required)
	Reason string `yaml:"reason,omitempty"` // human-readable justification
}

// IsSuppressed checks if a finding with the given rule name and target path/URL
// matches any suppress entry. Supports exact match, glob (path.Match), directory
// prefix ("vendor/"), and basename glob ("*.txt" matches "dir/foo.txt").
func IsSuppressed(rule, target string, entries []SuppressEntry) bool {
	_, ok := SuppressedReason(rule, target, entries)
	return ok
}

// SuppressedReason returns the reason and true if the finding is suppressed,
// or ("", false) if not suppressed.
func SuppressedReason(rule, target string, entries []SuppressEntry) (string, bool) {
	if target == "" || len(entries) == 0 {
		return "", false
	}
	target = toSlash(target)
	for _, e := range entries {
		if !strings.EqualFold(e.Rule, rule) {
			continue
		}
		if matchesPath(target, e.Path) {
			return e.Reason, true
		}
	}
	return "", false
}

// matchesPath checks if target matches the given pattern.
func matchesPath(target, pattern string) bool {
	p := toSlash(pattern)
	if p == "" {
		return false
	}
	// Directory prefix: "vendor/" matches "vendor/foo/bar.go"
	if strings.HasSuffix(p, "/") {
		return strings.HasPrefix(target, p)
	}
	// Exact match.
	if target == p {
		return true
	}
	// Glob on full path.
	if matched, _ := path.Match(p, target); matched {
		return true
	}
	// Glob on basename (e.g., "*.txt" matches "dir/foo.txt").
	if matched, _ := path.Match(p, path.Base(target)); matched {
		return true
	}
	// URL suffix match: pattern without leading slash matches URL path suffix.
	// e.g., "robots.txt" matches "https://example.com/robots.txt"
	if !strings.HasPrefix(p, "/") && strings.HasSuffix(target, "/"+p) {
		return true
	}
	return false
}

// toSlash normalizes path separators to forward slashes.
func toSlash(s string) string {
	return strings.ReplaceAll(s, "\\", "/")
}

// Config is the top-level Pipelock configuration.
type Config struct {
	Version             int                 `yaml:"version"`
	Mode                string              `yaml:"mode"`    // strict, balanced, audit
	Enforce             *bool               `yaml:"enforce"` // nil = true (default); false = detect & log without blocking
	APIAllowlist        []string            `yaml:"api_allowlist"`
	Suppress            []SuppressEntry     `yaml:"suppress"`
	FetchProxy          FetchProxy          `yaml:"fetch_proxy"`
	ForwardProxy        ForwardProxy        `yaml:"forward_proxy"`
	WebSocketProxy      WebSocketProxy      `yaml:"websocket_proxy"`
	DLP                 DLP                 `yaml:"dlp"`
	ResponseScanning    ResponseScanning    `yaml:"response_scanning"`
	MCPInputScanning    MCPInputScanning    `yaml:"mcp_input_scanning"`
	MCPToolScanning     MCPToolScanning     `yaml:"mcp_tool_scanning"`
	MCPToolPolicy       MCPToolPolicy       `yaml:"mcp_tool_policy"`
	GitProtection       GitProtection       `yaml:"git_protection"`
	Logging             LoggingConfig       `yaml:"logging"`
	SessionProfiling    SessionProfiling    `yaml:"session_profiling"`
	AdaptiveEnforcement AdaptiveEnforcement `yaml:"adaptive_enforcement"`
	MCPSessionBinding   MCPSessionBinding   `yaml:"mcp_session_binding"`
	KillSwitch          KillSwitch          `yaml:"kill_switch"`
	MetricsListen       string              `yaml:"metrics_listen"` // separate listen address for /metrics and /stats
	Emit                EmitConfig          `yaml:"emit"`
	ToolChainDetection  ToolChainDetection  `yaml:"tool_chain_detection"`
	MCPWSListener       MCPWSListener       `yaml:"mcp_ws_listener"`
	Internal            []string            `yaml:"internal"`
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
	IncludeDefaults   *bool                 `yaml:"include_defaults"`    // nil/true: merge user patterns with defaults; false: user patterns only
	Patterns          []ResponseScanPattern `yaml:"patterns"`
}

// ResponseScanPattern is a named regex pattern for detecting prompt injection in responses.
type ResponseScanPattern struct {
	Name  string `yaml:"name"`
	Regex string `yaml:"regex"`
}

// ForwardProxy configures HTTP CONNECT and absolute-URI forward proxy support.
// When enabled, the proxy accepts standard CONNECT tunnels (for HTTPS) and
// absolute-URI requests (for HTTP), applying the scanner pipeline to each target.
type ForwardProxy struct {
	Enabled                bool     `yaml:"enabled"`
	MaxTunnelSeconds       int      `yaml:"max_tunnel_seconds"`
	IdleTimeoutSeconds     int      `yaml:"idle_timeout_seconds"`
	RedirectWebSocketHosts []string `yaml:"redirect_websocket_hosts"`
}

// WebSocketProxy configures the /ws WebSocket proxy endpoint.
// When enabled, the proxy upgrades client connections, dials upstream WebSocket
// servers through the SSRF-safe dialer, and scans frames bidirectionally.
type WebSocketProxy struct {
	Enabled                  bool   `yaml:"enabled"`
	MaxMessageBytes          int    `yaml:"max_message_bytes"`
	MaxConcurrentConnections int    `yaml:"max_concurrent_connections"`
	ScanTextFrames           *bool  `yaml:"scan_text_frames"`
	AllowBinaryFrames        bool   `yaml:"allow_binary_frames"`
	ForwardCookies           bool   `yaml:"forward_cookies"`
	StripCompression         *bool  `yaml:"strip_compression"`
	MaxConnectionSeconds     int    `yaml:"max_connection_seconds"`
	IdleTimeoutSeconds       int    `yaml:"idle_timeout_seconds"`
	OriginPolicy             string `yaml:"origin_policy"` // rewrite (default), forward, strip
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
	IncludeDefaults    *bool        `yaml:"include_defaults"`      // nil/true: merge user patterns with defaults; false: user patterns only
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

// SessionProfiling configures per-session behavioral analysis.
// Tracks domains, volumes, and scanner signals per agent session to detect
// anomalous behavior patterns like sudden domain bursts or volume spikes.
type SessionProfiling struct {
	Enabled                bool    `yaml:"enabled"`
	AnomalyAction          string  `yaml:"anomaly_action"`           // warn, block
	DomainBurst            int     `yaml:"domain_burst"`             // new domains in one window to flag
	WindowMinutes          int     `yaml:"window_minutes"`           // rolling window duration
	VolumeSpikeRatio       float64 `yaml:"volume_spike_ratio"`       // bytes > ratio * rolling avg
	MaxSessions            int     `yaml:"max_sessions"`             // hard cap on concurrent sessions
	SessionTTLMinutes      int     `yaml:"session_ttl_minutes"`      // idle eviction TTL
	CleanupIntervalSeconds int     `yaml:"cleanup_interval_seconds"` // background cleanup period
}

// AdaptiveEnforcement configures per-session threat scoring with escalation.
// Score accumulates from DLP near-misses and blocks. When threshold is exceeded,
// the session's enforcement level escalates (audit->warn or warn->block).
type AdaptiveEnforcement struct {
	Enabled              bool    `yaml:"enabled"`
	EscalationThreshold  float64 `yaml:"escalation_threshold"`    // points before escalation
	DecayPerCleanRequest float64 `yaml:"decay_per_clean_request"` // score reduction per clean request
}

// MCPSessionBinding configures tool inventory validation per MCP connection.
// Captures tool names on first tools/list response and validates subsequent
// tools/call requests against that baseline.
type MCPSessionBinding struct {
	Enabled           bool   `yaml:"enabled"`
	UnknownToolAction string `yaml:"unknown_tool_action"` // warn, block
	NoBaselineAction  string `yaml:"no_baseline_action"`  // warn, block
}

// KillSwitch configures the emergency deny-all kill switch.
// When active, all requests are rejected except health/metrics endpoints
// and allowlisted IPs. Three activation sources (config, SIGUSR1, sentinel
// file) are OR-composed: any one active means the kill switch is engaged.
type KillSwitch struct {
	Enabled       bool     `yaml:"enabled"`
	SentinelFile  string   `yaml:"sentinel_file"`
	Message       string   `yaml:"message"`
	HealthExempt  *bool    `yaml:"health_exempt"`
	MetricsExempt *bool    `yaml:"metrics_exempt"`
	APIExempt     *bool    `yaml:"api_exempt"` // exempt /api/v1/* from kill switch (default true)
	APIToken      string   `yaml:"api_token"`  //nolint:gosec // G117: config field, not a hardcoded credential
	APIListen     string   `yaml:"api_listen"` // separate listen address for kill switch API (e.g. "0.0.0.0:9090")
	AllowlistIPs  []string `yaml:"allowlist_ips"`
}

// EmitConfig configures external event emission (webhook and syslog).
type EmitConfig struct {
	InstanceID string        `yaml:"instance_id"` // defaults to hostname
	Webhook    WebhookConfig `yaml:"webhook"`
	Syslog     SyslogConfig  `yaml:"syslog"`
}

// WebhookConfig configures the webhook emission sink.
type WebhookConfig struct {
	URL         string `yaml:"url"`
	MinSeverity string `yaml:"min_severity"` // info, warn, critical
	AuthToken   string `yaml:"auth_token"`   //nolint:gosec // G117: config field, not a hardcoded credential
	TimeoutSecs int    `yaml:"timeout_seconds"`
	QueueSize   int    `yaml:"queue_size"`
}

// SyslogConfig configures the syslog emission sink (RFC 5424).
type SyslogConfig struct {
	Address     string `yaml:"address"`      // e.g. "udp://syslog.example.com:514"
	MinSeverity string `yaml:"min_severity"` // info, warn, critical
	Facility    string `yaml:"facility"`     // e.g. "local0" (default)
	Tag         string `yaml:"tag"`          // e.g. "pipelock" (default)
}

// MCPWSListener configures the MCP WebSocket listener for inbound connections.
// When the MCP proxy is running in listener mode with a ws:// or wss:// upstream,
// this controls origin validation and connection limits for inbound WS clients.
type MCPWSListener struct {
	AllowedOrigins []string `yaml:"allowed_origins"` // additional browser origins to allow (loopback always allowed)
	MaxConnections int      `yaml:"max_connections"` // max concurrent inbound WS connections (default 100)
}

// ToolChainDetection configures MCP tool call chain pattern detection.
// Detects attack patterns in sequences of tool calls using subsequence
// matching with a configurable max_gap constraint.
type ToolChainDetection struct {
	Enabled          bool                `yaml:"enabled"`
	Action           string              `yaml:"action"`            // warn, block
	WindowSize       int                 `yaml:"window_size"`       // max tool calls in history
	WindowSeconds    int                 `yaml:"window_seconds"`    // time-based eviction
	MaxGap           *int                `yaml:"max_gap"`           // max innocent calls between steps (nil = default 3)
	ToolCategories   map[string][]string `yaml:"tool_categories"`   // category -> tool name patterns
	PatternOverrides map[string]string   `yaml:"pattern_overrides"` // pattern name -> action override
	CustomPatterns   []ChainPattern      `yaml:"custom_patterns"`
}

// ChainPattern defines a tool call chain to detect.
type ChainPattern struct {
	Name     string   `yaml:"name"`
	Sequence []string `yaml:"sequence"` // category names
	Severity string   `yaml:"severity"` // medium, high, critical
	Action   string   `yaml:"action"`   // optional per-pattern override
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
	// Merge default response scanning patterns with user patterns.
	// include_defaults (nil/true): defaults load first, user patterns override by name.
	// include_defaults (false): only user patterns are used (full override).
	if c.ResponseScanning.Enabled {
		c.ResponseScanning.Patterns = mergeResponsePatterns(
			c.ResponseScanning.IncludeDefaults,
			c.ResponseScanning.Patterns,
			Defaults().ResponseScanning.Patterns,
		)
	}
	// Merge default DLP patterns with user patterns.
	// include_defaults (nil/true): defaults load first, user patterns override by name.
	// include_defaults (false): only user patterns are used (full override).
	c.DLP.Patterns = mergeDLPPatterns(
		c.DLP.IncludeDefaults,
		c.DLP.Patterns,
		Defaults().DLP.Patterns,
	)
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
	if c.ForwardProxy.MaxTunnelSeconds <= 0 {
		c.ForwardProxy.MaxTunnelSeconds = 300
	}
	if c.ForwardProxy.IdleTimeoutSeconds <= 0 {
		c.ForwardProxy.IdleTimeoutSeconds = 120
	}
	if c.WebSocketProxy.MaxMessageBytes <= 0 {
		c.WebSocketProxy.MaxMessageBytes = 1048576 // 1MB
	}
	if c.WebSocketProxy.MaxConcurrentConnections <= 0 {
		c.WebSocketProxy.MaxConcurrentConnections = 128
	}
	if c.WebSocketProxy.ScanTextFrames == nil {
		t := true
		c.WebSocketProxy.ScanTextFrames = &t
	}
	if c.WebSocketProxy.StripCompression == nil {
		t := true
		c.WebSocketProxy.StripCompression = &t
	}
	if c.WebSocketProxy.MaxConnectionSeconds <= 0 {
		c.WebSocketProxy.MaxConnectionSeconds = 3600
	}
	if c.WebSocketProxy.IdleTimeoutSeconds <= 0 {
		c.WebSocketProxy.IdleTimeoutSeconds = 300
	}
	if c.WebSocketProxy.OriginPolicy == "" {
		c.WebSocketProxy.OriginPolicy = "rewrite" //nolint:goconst // used as default value
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

	// Session profiling defaults
	if c.SessionProfiling.Enabled {
		if c.SessionProfiling.AnomalyAction == "" {
			c.SessionProfiling.AnomalyAction = ActionWarn
		}
		if c.SessionProfiling.DomainBurst <= 0 {
			c.SessionProfiling.DomainBurst = 5
		}
		if c.SessionProfiling.WindowMinutes <= 0 {
			c.SessionProfiling.WindowMinutes = 5
		}
		if c.SessionProfiling.VolumeSpikeRatio <= 0 {
			c.SessionProfiling.VolumeSpikeRatio = 3.0
		}
	}
	if c.SessionProfiling.MaxSessions <= 0 {
		c.SessionProfiling.MaxSessions = 1000
	}
	if c.SessionProfiling.SessionTTLMinutes <= 0 {
		c.SessionProfiling.SessionTTLMinutes = 30
	}
	if c.SessionProfiling.CleanupIntervalSeconds <= 0 {
		c.SessionProfiling.CleanupIntervalSeconds = 60
	}

	// Adaptive enforcement defaults
	if c.AdaptiveEnforcement.Enabled {
		if c.AdaptiveEnforcement.EscalationThreshold <= 0 {
			c.AdaptiveEnforcement.EscalationThreshold = 5.0
		}
		if c.AdaptiveEnforcement.DecayPerCleanRequest <= 0 {
			c.AdaptiveEnforcement.DecayPerCleanRequest = 0.5
		}
	}

	// Kill switch defaults
	if c.KillSwitch.Message == "" {
		c.KillSwitch.Message = "Emergency deny-all active"
	}
	if c.KillSwitch.HealthExempt == nil {
		c.KillSwitch.HealthExempt = ptrBool(true)
	}
	if c.KillSwitch.MetricsExempt == nil {
		c.KillSwitch.MetricsExempt = ptrBool(true)
	}
	if c.KillSwitch.APIExempt == nil {
		c.KillSwitch.APIExempt = ptrBool(true)
	}

	// Emit defaults
	if c.Emit.Webhook.TimeoutSecs <= 0 {
		c.Emit.Webhook.TimeoutSecs = 5
	}
	if c.Emit.Webhook.QueueSize <= 0 {
		c.Emit.Webhook.QueueSize = 64
	}
	if c.Emit.Webhook.MinSeverity == "" {
		c.Emit.Webhook.MinSeverity = "warn"
	}
	if c.Emit.Syslog.MinSeverity == "" {
		c.Emit.Syslog.MinSeverity = "warn"
	}
	if c.Emit.Syslog.Facility == "" {
		c.Emit.Syslog.Facility = "local0"
	}
	if c.Emit.Syslog.Tag == "" {
		c.Emit.Syslog.Tag = "pipelock"
	}

	// Tool chain detection defaults
	if c.ToolChainDetection.Enabled && c.ToolChainDetection.Action == "" {
		c.ToolChainDetection.Action = ActionWarn
	}
	if c.ToolChainDetection.WindowSize <= 0 {
		c.ToolChainDetection.WindowSize = 20
	}
	if c.ToolChainDetection.WindowSeconds <= 0 {
		c.ToolChainDetection.WindowSeconds = 60
	}
	if c.ToolChainDetection.MaxGap == nil {
		d := DefaultMaxGap
		c.ToolChainDetection.MaxGap = &d
	}

	// MCP WS listener defaults
	if c.MCPWSListener.MaxConnections <= 0 {
		c.MCPWSListener.MaxConnections = 100
	}

	// MCP session binding defaults
	if c.MCPSessionBinding.Enabled {
		if c.MCPSessionBinding.UnknownToolAction == "" {
			c.MCPSessionBinding.UnknownToolAction = ActionWarn
		}
		if c.MCPSessionBinding.NoBaselineAction == "" {
			c.MCPSessionBinding.NoBaselineAction = ActionWarn
		}
	}
}

// mergeDLPPatterns merges default DLP patterns with user-defined patterns.
// When includeDefaults is nil or true, defaults are loaded first and user
// patterns override by name (matching Name field). New defaults that don't
// exist in the user config are automatically added.
// When includeDefaults is false, only user patterns are used.
func mergeDLPPatterns(includeDefaults *bool, user, defaults []DLPPattern) []DLPPattern {
	if includeDefaults != nil && !*includeDefaults {
		// Explicit opt-out: user patterns only (old behavior).
		return user
	}
	if len(user) == 0 {
		return defaults
	}
	// Build lookup of user pattern names.
	userNames := make(map[string]struct{}, len(user))
	for _, p := range user {
		userNames[p.Name] = struct{}{}
	}
	// Start with defaults not overridden by user, then append all user patterns.
	merged := make([]DLPPattern, 0, len(defaults)+len(user))
	for _, d := range defaults {
		if _, overridden := userNames[d.Name]; !overridden {
			merged = append(merged, d)
		}
	}
	merged = append(merged, user...)
	return merged
}

// mergeResponsePatterns merges default response scanning patterns with user-defined patterns.
// Same semantics as mergeDLPPatterns: nil/true merges by name, false uses user only.
func mergeResponsePatterns(includeDefaults *bool, user, defaults []ResponseScanPattern) []ResponseScanPattern {
	if includeDefaults != nil && !*includeDefaults {
		return user
	}
	if len(user) == 0 {
		return defaults
	}
	userNames := make(map[string]struct{}, len(user))
	for _, p := range user {
		userNames[p.Name] = struct{}{}
	}
	merged := make([]ResponseScanPattern, 0, len(defaults)+len(user))
	for _, d := range defaults {
		if _, overridden := userNames[d.Name]; !overridden {
			merged = append(merged, d)
		}
	}
	merged = append(merged, user...)
	return merged
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
		case ActionStrip, ActionWarn, ActionBlock, ActionAsk:
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
		case ActionWarn, ActionBlock:
			// valid (ask not supported for input scanning — no terminal interaction on request path)
		default:
			return fmt.Errorf("invalid mcp_input_scanning action %q: must be warn or block", c.MCPInputScanning.Action)
		}
	}
	switch c.MCPInputScanning.OnParseError {
	case ActionBlock, ActionForward:
		// valid
	default:
		return fmt.Errorf("invalid mcp_input_scanning on_parse_error %q: must be block or forward", c.MCPInputScanning.OnParseError)
	}

	// Validate MCP tool scanning config
	if c.MCPToolScanning.Enabled {
		switch c.MCPToolScanning.Action {
		case ActionWarn, ActionBlock:
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
		case ActionWarn, ActionBlock:
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
				case ActionWarn, ActionBlock:
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

	// Validate forward proxy config
	if c.ForwardProxy.Enabled {
		if c.ForwardProxy.MaxTunnelSeconds <= 0 {
			return fmt.Errorf("forward_proxy.max_tunnel_seconds must be positive")
		}
		if c.ForwardProxy.IdleTimeoutSeconds <= 0 {
			return fmt.Errorf("forward_proxy.idle_timeout_seconds must be positive")
		}
	}

	// Validate WebSocket proxy config
	if c.WebSocketProxy.Enabled {
		if c.WebSocketProxy.MaxMessageBytes <= 0 {
			return fmt.Errorf("websocket_proxy.max_message_bytes must be positive")
		}
		if c.WebSocketProxy.MaxConcurrentConnections <= 0 {
			return fmt.Errorf("websocket_proxy.max_concurrent_connections must be positive")
		}
		if c.WebSocketProxy.MaxConnectionSeconds <= 0 {
			return fmt.Errorf("websocket_proxy.max_connection_seconds must be positive")
		}
		if c.WebSocketProxy.IdleTimeoutSeconds <= 0 {
			return fmt.Errorf("websocket_proxy.idle_timeout_seconds must be positive")
		}
		switch c.WebSocketProxy.OriginPolicy {
		case "rewrite", "forward", ActionStrip:
			// valid
		default:
			return fmt.Errorf("invalid websocket_proxy.origin_policy %q: must be rewrite, forward, or strip", c.WebSocketProxy.OriginPolicy)
		}
		// Compression must stay stripped; scanning requires uncompressed frame payloads.
		if c.WebSocketProxy.StripCompression != nil && !*c.WebSocketProxy.StripCompression {
			return fmt.Errorf("websocket_proxy.strip_compression must be true: scanning requires uncompressed frames")
		}
		// Warn about memory budget
		memBudget := int64(c.WebSocketProxy.MaxConcurrentConnections) * int64(c.WebSocketProxy.MaxMessageBytes) * 2
		if memBudget > 1<<30 { // 1GB
			fmt.Fprintf(os.Stderr, "WARNING: websocket_proxy memory budget is %dMB (max_concurrent_connections * max_message_bytes * 2) - consider reducing\n", memBudget/(1<<20))
		}
	}

	// Validate session profiling config
	if c.SessionProfiling.Enabled {
		switch c.SessionProfiling.AnomalyAction {
		case ActionWarn, ActionBlock:
			// valid
		default:
			return fmt.Errorf("invalid session_profiling.anomaly_action %q: must be warn or block", c.SessionProfiling.AnomalyAction)
		}
		if c.SessionProfiling.DomainBurst <= 0 {
			return fmt.Errorf("session_profiling.domain_burst must be positive")
		}
		if c.SessionProfiling.WindowMinutes <= 0 {
			return fmt.Errorf("session_profiling.window_minutes must be positive")
		}
		if c.SessionProfiling.VolumeSpikeRatio <= 0 {
			return fmt.Errorf("session_profiling.volume_spike_ratio must be positive")
		}
	}
	if c.SessionProfiling.MaxSessions <= 0 {
		return fmt.Errorf("session_profiling.max_sessions must be positive")
	}
	if c.SessionProfiling.SessionTTLMinutes <= 0 {
		return fmt.Errorf("session_profiling.session_ttl_minutes must be positive")
	}
	if c.SessionProfiling.CleanupIntervalSeconds <= 0 {
		return fmt.Errorf("session_profiling.cleanup_interval_seconds must be positive")
	}

	// Validate adaptive enforcement config
	if c.AdaptiveEnforcement.Enabled {
		if !c.SessionProfiling.Enabled {
			return fmt.Errorf("adaptive_enforcement.enabled requires session_profiling.enabled")
		}
		if c.AdaptiveEnforcement.EscalationThreshold <= 0 {
			return fmt.Errorf("adaptive_enforcement.escalation_threshold must be positive")
		}
		if c.AdaptiveEnforcement.DecayPerCleanRequest <= 0 {
			return fmt.Errorf("adaptive_enforcement.decay_per_clean_request must be positive")
		}
	}

	// Validate MCP session binding config
	if c.MCPSessionBinding.Enabled {
		if !c.MCPToolScanning.Enabled {
			return fmt.Errorf("mcp_session_binding.enabled requires mcp_tool_scanning.enabled (binding needs tool scanning for baseline capture)")
		}
		switch c.MCPSessionBinding.UnknownToolAction {
		case ActionWarn, ActionBlock:
			// valid
		default:
			return fmt.Errorf("invalid mcp_session_binding.unknown_tool_action %q: must be warn or block", c.MCPSessionBinding.UnknownToolAction)
		}
		switch c.MCPSessionBinding.NoBaselineAction {
		case ActionWarn, ActionBlock:
			// valid
		default:
			return fmt.Errorf("invalid mcp_session_binding.no_baseline_action %q: must be warn or block", c.MCPSessionBinding.NoBaselineAction)
		}
	}

	// Validate tool chain detection config
	if c.ToolChainDetection.Enabled {
		switch c.ToolChainDetection.Action {
		case ActionWarn, ActionBlock:
			// valid
		default:
			return fmt.Errorf("invalid tool_chain_detection.action %q: must be warn or block", c.ToolChainDetection.Action)
		}
		if c.ToolChainDetection.WindowSize <= 0 {
			return fmt.Errorf("tool_chain_detection.window_size must be positive")
		}
		if c.ToolChainDetection.WindowSeconds <= 0 {
			return fmt.Errorf("tool_chain_detection.window_seconds must be positive")
		}
		if c.ToolChainDetection.MaxGap != nil && *c.ToolChainDetection.MaxGap < 0 {
			return fmt.Errorf("tool_chain_detection.max_gap must be non-negative")
		}
		for i, p := range c.ToolChainDetection.CustomPatterns {
			if p.Name == "" {
				return fmt.Errorf("tool_chain_detection.custom_patterns[%d] missing name", i)
			}
			if len(p.Sequence) < 2 {
				return fmt.Errorf("tool_chain_detection.custom_patterns[%d] %q: sequence must have at least 2 steps", i, p.Name)
			}
			switch p.Severity {
			case "medium", "high", "critical": //nolint:goconst // severity values shared across validation
				// valid
			default:
				return fmt.Errorf("tool_chain_detection.custom_patterns[%d] %q: invalid severity %q: must be medium, high, or critical", i, p.Name, p.Severity)
			}
			if p.Action != "" {
				switch p.Action {
				case ActionWarn, ActionBlock:
					// valid
				default:
					return fmt.Errorf("tool_chain_detection.custom_patterns[%d] %q: invalid action %q: must be warn or block", i, p.Name, p.Action)
				}
			}
		}
		for name, action := range c.ToolChainDetection.PatternOverrides {
			switch action {
			case ActionWarn, ActionBlock:
				// valid
			default:
				return fmt.Errorf("tool_chain_detection.pattern_overrides[%q]: invalid action %q: must be warn or block", name, action)
			}
		}
	}

	// Validate MCP WS listener config
	if c.MCPWSListener.MaxConnections <= 0 {
		return fmt.Errorf("mcp_ws_listener.max_connections must be positive")
	}
	for i, origin := range c.MCPWSListener.AllowedOrigins {
		if origin == "" {
			return fmt.Errorf("mcp_ws_listener.allowed_origins[%d] is empty", i)
		}
		u, parseErr := url.Parse(origin)
		if parseErr != nil || u.Host == "" {
			return fmt.Errorf("mcp_ws_listener.allowed_origins[%d] %q: must be a valid origin (e.g. https://example.com)", i, origin)
		}
	}

	// Validate suppress entries have required fields
	for i, s := range c.Suppress {
		if s.Rule == "" {
			return fmt.Errorf("suppress entry %d missing required field \"rule\"", i)
		}
		if s.Path == "" {
			return fmt.Errorf("suppress entry %d (%s) missing required field \"path\"", i, s.Rule)
		}
		// Validate glob syntax so misconfigured patterns fail fast
		// instead of silently never matching at runtime.
		if strings.ContainsAny(s.Path, "*?[") {
			if _, err := path.Match(toSlash(s.Path), "x"); err != nil {
				return fmt.Errorf("suppress entry %d (%s) has invalid path pattern %q: %w", i, s.Rule, s.Path, err)
			}
		}
	}

	// Validate kill switch allowlist CIDRs are parseable
	for _, cidr := range c.KillSwitch.AllowlistIPs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("invalid kill_switch.allowlist_ips CIDR %q: %w", cidr, err)
		}
	}

	// Validate kill switch API listen address (if set)
	if c.KillSwitch.APIListen != "" {
		_, apiPort, err := net.SplitHostPort(c.KillSwitch.APIListen)
		if err != nil {
			return fmt.Errorf("invalid kill_switch.api_listen %q: %w", c.KillSwitch.APIListen, err)
		}
		_, proxyPort, proxyErr := net.SplitHostPort(c.FetchProxy.Listen)
		if proxyErr != nil {
			return fmt.Errorf("invalid fetch_proxy.listen %q: %w", c.FetchProxy.Listen, proxyErr)
		}
		if apiPort == proxyPort {
			return fmt.Errorf("kill_switch.api_listen port %s collides with fetch_proxy.listen port %s", apiPort, proxyPort)
		}
		if c.KillSwitch.APIToken == "" {
			return fmt.Errorf("kill_switch.api_listen requires kill_switch.api_token to be set")
		}
	}

	// Validate metrics listen address (if set)
	if c.MetricsListen != "" {
		_, metricsPort, err := net.SplitHostPort(c.MetricsListen)
		if err != nil {
			return fmt.Errorf("invalid metrics_listen %q: %w", c.MetricsListen, err)
		}
		_, proxyPort, proxyErr := net.SplitHostPort(c.FetchProxy.Listen)
		if proxyErr != nil {
			return fmt.Errorf("invalid fetch_proxy.listen %q: %w", c.FetchProxy.Listen, proxyErr)
		}
		if metricsPort == proxyPort {
			return fmt.Errorf("metrics_listen port %s collides with fetch_proxy.listen port %s", metricsPort, proxyPort)
		}
		if c.KillSwitch.APIListen != "" {
			_, apiPort, _ := net.SplitHostPort(c.KillSwitch.APIListen)
			if metricsPort == apiPort {
				return fmt.Errorf("metrics_listen port %s collides with kill_switch.api_listen port %s", metricsPort, apiPort)
			}
		}
	}

	// Validate emit config
	if c.Emit.Webhook.URL != "" {
		u, urlErr := url.Parse(c.Emit.Webhook.URL)
		if urlErr != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("invalid emit.webhook.url %q: must be http:// or https:// with a host", c.Emit.Webhook.URL)
		}
		switch c.Emit.Webhook.MinSeverity { //nolint:goconst // severity values shared across validation
		case "info", "warn", "critical":
			// valid
		default:
			return fmt.Errorf("invalid emit.webhook.min_severity %q: must be info, warn, or critical", c.Emit.Webhook.MinSeverity)
		}
		if c.Emit.Webhook.TimeoutSecs <= 0 {
			return fmt.Errorf("emit.webhook.timeout_seconds must be positive")
		}
		if c.Emit.Webhook.QueueSize <= 0 {
			return fmt.Errorf("emit.webhook.queue_size must be positive")
		}
	}
	if c.Emit.Syslog.Address != "" {
		sysU, sysErr := url.Parse(c.Emit.Syslog.Address)
		if sysErr != nil || (sysU.Scheme != "udp" && sysU.Scheme != "tcp") || sysU.Host == "" {
			return fmt.Errorf("invalid emit.syslog.address %q: must be udp:// or tcp:// with host:port", c.Emit.Syslog.Address)
		}
		if _, _, splitErr := net.SplitHostPort(sysU.Host); splitErr != nil {
			return fmt.Errorf("invalid emit.syslog.address %q: must include port (e.g. udp://host:514): %w", c.Emit.Syslog.Address, splitErr)
		}
		switch c.Emit.Syslog.MinSeverity { //nolint:goconst // severity values shared across validation
		case "info", "warn", "critical":
			// valid
		default:
			return fmt.Errorf("invalid emit.syslog.min_severity %q: must be info, warn, or critical", c.Emit.Syslog.MinSeverity)
		}
		if c.Emit.Syslog.Facility != "" {
			validFacilities := map[string]bool{
				"kern": true, "user": true, "mail": true, "daemon": true,
				"auth": true, "syslog": true, "lpr": true, "news": true,
				"uucp": true, "local0": true, "local1": true, "local2": true,
				"local3": true, "local4": true, "local5": true, "local6": true,
				"local7": true,
			}
			if !validFacilities[strings.ToLower(c.Emit.Syslog.Facility)] {
				return fmt.Errorf("invalid emit.syslog.facility %q", c.Emit.Syslog.Facility)
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

	// DLP include_defaults disabled
	oldInclude := old.DLP.IncludeDefaults == nil || *old.DLP.IncludeDefaults
	newInclude := updated.DLP.IncludeDefaults == nil || *updated.DLP.IncludeDefaults
	if oldInclude && !newInclude {
		warnings = append(warnings, ReloadWarning{
			Field:   "dlp.include_defaults",
			Message: "DLP include_defaults disabled — new default patterns will not be merged on future upgrades",
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

	// Forward proxy disabled
	if old.ForwardProxy.Enabled && !updated.ForwardProxy.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "forward_proxy.enabled",
			Message: "forward proxy disabled",
		})
	}

	// WebSocket proxy disabled
	if old.WebSocketProxy.Enabled && !updated.WebSocketProxy.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "websocket_proxy.enabled",
			Message: "WebSocket proxy disabled",
		})
	}

	// Session profiling disabled
	if old.SessionProfiling.Enabled && !updated.SessionProfiling.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "session_profiling.enabled",
			Message: "session behavioral profiling disabled",
		})
	}

	// Adaptive enforcement disabled
	if old.AdaptiveEnforcement.Enabled && !updated.AdaptiveEnforcement.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "adaptive_enforcement.enabled",
			Message: "adaptive enforcement disabled",
		})
	}

	// MCP session binding disabled
	if old.MCPSessionBinding.Enabled && !updated.MCPSessionBinding.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "mcp_session_binding.enabled",
			Message: "MCP session binding disabled",
		})
	}

	// Tool chain detection disabled
	if old.ToolChainDetection.Enabled && !updated.ToolChainDetection.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "tool_chain_detection.enabled",
			Message: "tool chain detection disabled",
		})
	}

	// Emit sinks removed
	if old.Emit.Webhook.URL != "" && updated.Emit.Webhook.URL == "" {
		warnings = append(warnings, ReloadWarning{
			Field:   "emit.webhook.url",
			Message: "webhook emission disabled",
		})
	}
	if old.Emit.Syslog.Address != "" && updated.Emit.Syslog.Address == "" {
		warnings = append(warnings, ReloadWarning{
			Field:   "emit.syslog.address",
			Message: "syslog emission disabled",
		})
	}

	// Kill switch API listen address changed (requires restart)
	if old.KillSwitch.APIListen != updated.KillSwitch.APIListen {
		warnings = append(warnings, ReloadWarning{
			Field:   "kill_switch.api_listen",
			Message: "api_listen cannot change at runtime (requires restart) — ignoring",
		})
	}

	// Metrics listen address changed (requires restart)
	if old.MetricsListen != updated.MetricsListen {
		warnings = append(warnings, ReloadWarning{
			Field:   "metrics_listen",
			Message: "metrics_listen cannot change at runtime (requires restart) — ignoring",
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
		ForwardProxy: ForwardProxy{
			Enabled:            false,
			MaxTunnelSeconds:   300,
			IdleTimeoutSeconds: 120,
		},
		WebSocketProxy: WebSocketProxy{
			Enabled:                  false,
			MaxMessageBytes:          1048576,
			MaxConcurrentConnections: 128,
			ScanTextFrames:           ptrBool(true),
			StripCompression:         ptrBool(true),
			MaxConnectionSeconds:     3600,
			IdleTimeoutSeconds:       300,
			OriginPolicy:             "rewrite",
		},
		DLP: DLP{
			ScanEnv: true,
			Patterns: []DLPPattern{
				// Provider API keys
				{Name: "Anthropic API Key", Regex: `sk-ant-[a-zA-Z0-9\-_]{10,}`, Severity: "critical"},
				{Name: "OpenAI API Key", Regex: `sk-proj-[a-zA-Z0-9\-_]{10,}`, Severity: "critical"},
				{Name: "OpenAI Service Key", Regex: `sk-svcacct-[a-zA-Z0-9\-]{10,}`, Severity: "critical"},
				{Name: "Fireworks API Key", Regex: `fw_[a-zA-Z0-9]{24,}`, Severity: "critical"},
				{Name: "Google API Key", Regex: `AIza[0-9A-Za-z\-_]{35}`, Severity: "high"},
				{Name: "Google OAuth Client Secret", Regex: `GOCSPX-[A-Za-z0-9_\-]{28,}`, Severity: "critical"},
				{Name: "Stripe Key", Regex: `[sr]k_(live|test)_[a-zA-Z0-9]{20,}`, Severity: "critical"},

				// Source control tokens
				{Name: "GitHub Token", Regex: `gh[pousr]_[A-Za-z0-9_]{36,}`, Severity: "critical"},
				{Name: "GitHub Fine-Grained PAT", Regex: `github_pat_[a-zA-Z0-9_]{36,}`, Severity: "critical"},

				// Cloud provider credentials
				// All AWS credential prefixes: AKIA (access key), ASIA (STS temp), AROA (role),
				// AIDA (user ID), AIPA (instance profile), AGPA (group), ANPA/ANVA (policy), A3T (legacy).
				// {16,}: real AWS IDs have 16+ chars after prefix. Avoids FPs like ASIA2025REPORT1234.
				{Name: "AWS Access ID", Regex: `(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16,}`, Severity: "critical"},
				{Name: "Google OAuth Token", Regex: `ya29\.[a-zA-Z0-9_-]{20,}`, Severity: "critical"},

				// Messaging platform tokens
				{Name: "Slack Token", Regex: `xox[bpras]-[0-9a-zA-Z-]{15,}`, Severity: "critical"},
				{Name: "Slack App Token", Regex: `xapp-[0-9]+-[A-Za-z0-9_]+-[0-9]+-[a-f0-9]+`, Severity: "critical"},
				{Name: "Discord Bot Token", Regex: `[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27,}`, Severity: "critical"},

				// Communication service keys
				{Name: "Twilio API Key", Regex: `SK[a-f0-9]{32}`, Severity: "high"},
				{Name: "SendGrid API Key", Regex: `SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`, Severity: "critical"},
				{Name: "Mailgun API Key", Regex: `key-[a-zA-Z0-9]{32}`, Severity: "high"},

				// Cryptographic material
				{Name: "Private Key Header", Regex: `-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----`, Severity: "critical"},
				{Name: "JWT Token", Regex: `(ey[a-zA-Z0-9_\-=]{10,}\.){2}[a-zA-Z0-9_\-=]{10,}`, Severity: "high"},

				// Identity / PII
				{Name: "Social Security Number", Regex: `\b\d{3}-\d{2}-\d{4}\b`, Severity: "low"},
				{Name: "Google OAuth Client ID", Regex: `[0-9]{6,}-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`, Severity: "medium"},

				// Generic credential patterns
				// \b protects underscore-compound names (next_token, csrf_token_id) since _ is \w.
				// Hyphen-compound names (show-password, x-token) are NOT protected since - is \W,
				// so \b still fires. Accepted tradeoff: such params are rare in agent traffic.
				// Case-insensitive matching is added automatically by scanner.New() via (?i) prefix.
				{Name: "Credential in URL", Regex: `\b(?:password|passwd|secret|token|apikey|api_key|api-key)\s*=\s*[^\s&]{4,}`, Severity: "high"},
			},
		},
		MCPInputScanning: MCPInputScanning{
			Enabled:      false,
			OnParseError: ActionBlock,
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
				{Name: "Prompt Injection", Regex: `(?i)(ignore|disregard|forget|abandon)[-,;:.\s]+\s*(?:all\s+\w+\s+|\w+\s+all\s+|all\s+|\w+\s+)?(previous|prior|above|earlier)\s+(\w+\s+)?(instructions|prompts|rules|context|directives|constraints|policies|guardrails)`},
				{Name: "System Override", Regex: `(?im)^\s*system\s*:`},
				{Name: "Role Override", Regex: `(?i)you\s+are\s+(now\s+)?(a\s+)?((?-i:\bDAN\b)|evil|unrestricted|jailbroken|unfiltered)`},
				{Name: "New Instructions", Regex: `(?i)(new|updated|revised)\s+(instructions|directives|rules|prompt)`},
				{Name: "Jailbreak Attempt", Regex: `(?i)((?-i:\bDAN\b)|developer\s+mode|sudo\s+mode|unrestricted\s+mode)`},
				{Name: "Hidden Instruction", Regex: `(?i)(do\s+not\s+(reveal|tell|show|display|mention)\s+this\s+to\s+the\s+user|hidden\s+instruction|invisible\s+to\s+(the\s+)?user|the\s+user\s+(cannot|must\s+not|should\s+not)\s+see\s+this)`},
				{Name: "Behavior Override", Regex: `(?i)from\s+now\s+on\s+(you\s+)?(will|must|should|shall)\s+`},
				{Name: "Encoded Payload", Regex: `(?i)(decode\s+(this|the\s+following)\s+(from\s+)?base64\s+and\s+(execute|run|follow)|eval\s*\(\s*atob\s*\()`},
				{Name: "Tool Invocation", Regex: `(?i)you\s+must\s+(immediately\s+)?(call|execute|run|invoke)\s+(the|this)\s+(function|tool|command|api|endpoint)`},
				{Name: "Authority Escalation", Regex: `(?i)you\s+(now\s+)?have\s+(full\s+)?(admin|root|system|superuser|elevated)\s+(access|privileges|permissions|rights)`},
				{Name: "Instruction Downgrade", Regex: `(?i)(treat|consider|regard|reinterpret|downgrade)\s+((?:the|all)\s+)?(previous|prior|above|earlier|system|policy|original|existing)\s+(\w+\s+)?(text|instructions?|rules|directives|guidelines|safeguards|constraints|controls|checks|context|prompt|policies|guardrails|parameters)\s+((as|to)\s+)?(historical|outdated|deprecated|optional|background|secondary|non-binding|non-authoritative|informational|advisory)`},
				{Name: "Instruction Dismissal", Regex: `(?i)(set|put)\s+(the\s+)?(previous|prior|above|earlier|system|original)\s+(\w+\s+)?(instructions?|directives|rules|constraints|context|prompt|safeguards|guidelines|policies|guardrails)\s+(aside|away|to\s+(one|the)\s+side)`},
				{Name: "Priority Override", Regex: `(?i)\bprioritize\s+(the\s+)?(task|user|current|new|latest)\s+(request|message|input|instructions?|prompt)`},
			},
		},
		Logging: LoggingConfig{
			Format:         DefaultLogFormat,
			Output:         DefaultLogOutput,
			IncludeAllowed: true,
			IncludeBlocked: true,
		},
		MCPWSListener: MCPWSListener{
			MaxConnections: 100,
		},
		SessionProfiling: SessionProfiling{
			MaxSessions:            1000,
			SessionTTLMinutes:      30,
			CleanupIntervalSeconds: 60,
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

func ptrBool(v bool) *bool { return &v }
