// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package config handles loading, validating, and defaulting Pipelock configuration.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Mode constants for Pipelock operating modes.
const (
	ModeStrict   = "strict"
	ModeBalanced = "balanced"
	ModeAudit    = "audit"
)

// Hook variables set by enterprise builds. Nil in OSS mode.
// These live in config (not edition) to avoid import cycles.
var (
	// ValidateAgentsFunc validates agent profiles in config.
	ValidateAgentsFunc func(cfg *Config) error

	// EnforceLicenseGateFunc verifies license and disables agents if invalid.
	EnforceLicenseGateFunc func(c *Config)

	// MergeAgentProfileFunc merges agent profile overrides into base config.
	MergeAgentProfileFunc func(base *Config, profile *AgentProfile) (*Config, error)
)

// Action constants for scanner and policy responses.
const (
	ActionBlock   = "block"
	ActionWarn    = "warn"
	ActionAsk     = "ask"
	ActionStrip   = "strip"
	ActionForward = "forward"
	ActionAllow   = "allow"
)

// Severity constants for chain detection and emit thresholds.
const (
	SeverityInfo     = "info"
	SeverityWarn     = "warn"
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
)

// Origin policy constants for WebSocket proxy.
const (
	OriginPolicyRewrite = "rewrite"
)

// Header mode constants for request body scanning.
const (
	HeaderModeSensitive = "sensitive" // scan only explicitly listed headers
	HeaderModeAll       = "all"       // scan all headers except ignore list
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

	// HashDefaults is returned by Config.Hash() when no config file was loaded.
	HashDefaults = "defaults"

	// DefaultCertTTL is the default TLS interception leaf certificate TTL.
	DefaultCertTTL = "24h"

	// EnvLicenseKey is the environment variable for license token override.
	// Takes highest priority over license_file and license_key config fields.
	EnvLicenseKey = "PIPELOCK_LICENSE_KEY"
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
	Version               int                     `yaml:"version"`
	Mode                  string                  `yaml:"mode"`           // strict, balanced, audit
	Enforce               *bool                   `yaml:"enforce"`        // nil = true (default); false = detect & log without blocking
	ExplainBlocks         *bool                   `yaml:"explain_blocks"` // nil = false (default); true = include hints in block responses
	APIAllowlist          []string                `yaml:"api_allowlist"`
	Suppress              []SuppressEntry         `yaml:"suppress"`
	FetchProxy            FetchProxy              `yaml:"fetch_proxy"`
	ForwardProxy          ForwardProxy            `yaml:"forward_proxy"`
	WebSocketProxy        WebSocketProxy          `yaml:"websocket_proxy"`
	DLP                   DLP                     `yaml:"dlp"`
	ResponseScanning      ResponseScanning        `yaml:"response_scanning"`
	MCPInputScanning      MCPInputScanning        `yaml:"mcp_input_scanning"`
	MCPToolScanning       MCPToolScanning         `yaml:"mcp_tool_scanning"`
	MCPToolPolicy         MCPToolPolicy           `yaml:"mcp_tool_policy"`
	GitProtection         GitProtection           `yaml:"git_protection"`
	Logging               LoggingConfig           `yaml:"logging"`
	SessionProfiling      SessionProfiling        `yaml:"session_profiling"`
	AdaptiveEnforcement   AdaptiveEnforcement     `yaml:"adaptive_enforcement"`
	MCPSessionBinding     MCPSessionBinding       `yaml:"mcp_session_binding"`
	RequestBodyScanning   RequestBodyScanning     `yaml:"request_body_scanning"`
	KillSwitch            KillSwitch              `yaml:"kill_switch"`
	Sentry                SentryConfig            `yaml:"sentry"`
	MetricsListen         string                  `yaml:"metrics_listen"` // separate listen address for /metrics and /stats
	Emit                  EmitConfig              `yaml:"emit"`
	ToolChainDetection    ToolChainDetection      `yaml:"tool_chain_detection"`
	MCPWSListener         MCPWSListener           `yaml:"mcp_ws_listener"`
	TLSInterception       TLSInterception         `yaml:"tls_interception"`
	CrossRequestDetection CrossRequestDetection   `yaml:"cross_request_detection"`
	ScanAPI               ScanAPI                 `yaml:"scan_api"`
	AddressProtection     AddressProtection       `yaml:"address_protection"`
	Agents                map[string]AgentProfile `yaml:"agents,omitempty"`
	LicenseKey            string                  `yaml:"license_key,omitempty"`        // signed license token (from pipelock license issue)
	LicenseFile           string                  `yaml:"license_file,omitempty"`       // path to file containing the license token (read at startup)
	LicensePublicKey      string                  `yaml:"license_public_key,omitempty"` // hex-encoded Ed25519 public key for license verification (dev builds only)
	Internal              []string                `yaml:"internal"`

	// LicenseExpiresAt is the Unix timestamp of the license expiry, populated
	// by EnforceLicenseGate(). Zero means perpetual. Used for runtime expiry
	// enforcement so agents are disabled even without a config reload.
	LicenseExpiresAt int64 `yaml:"-"`

	// rawBytes stores the original config file bytes for deterministic hashing.
	// Not serialized to YAML. Set by Load(), nil for Defaults().
	rawBytes []byte `yaml:"-"`
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
	SNIVerification        *bool    `yaml:"sni_verification"`
	RedirectWebSocketHosts []string `yaml:"redirect_websocket_hosts"`
}

// SNIVerificationEnabled returns whether SNI verification is active.
// Defaults to true when not explicitly set.
func (f ForwardProxy) SNIVerificationEnabled() bool {
	if f.SNIVerification == nil {
		return true
	}
	return *f.SNIVerification
}

// TLSInterception configures CONNECT tunnel decryption for body/header scanning.
type TLSInterception struct {
	Enabled            bool     `yaml:"enabled"`
	CACertPath         string   `yaml:"ca_cert"`
	CAKeyPath          string   `yaml:"ca_key"`
	PassthroughDomains []string `yaml:"passthrough_domains"`
	CertTTL            string   `yaml:"cert_ttl"`
	CertCacheSize      int      `yaml:"cert_cache_size"`
	MaxResponseBytes   int64    `yaml:"max_response_bytes"`
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

// ExplainBlocksEnabled returns whether block responses include hints.
// Defaults to false when ExplainBlocks is nil (opt-in only).
// Enabling this exposes scanner names and config field names in responses,
// which is useful for debugging but constitutes information disclosure.
func (c *Config) ExplainBlocksEnabled() bool {
	return c.ExplainBlocks != nil && *c.ExplainBlocks
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
	MaxURLLength               int      `yaml:"max_url_length"`
	EntropyThreshold           float64  `yaml:"entropy_threshold"`
	MaxReqPerMinute            int      `yaml:"max_requests_per_minute"`
	MaxDataPerMinute           int      `yaml:"max_data_per_minute"` // bytes per domain per minute (0 = disabled)
	Blocklist                  []string `yaml:"blocklist"`
	SubdomainEntropyExclusions []string `yaml:"subdomain_entropy_exclusions"` // domains excluded from subdomain entropy checks (exact or *.example.com wildcard)
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
	Name          string   `yaml:"name"`
	Regex         string   `yaml:"regex"`
	Severity      string   `yaml:"severity"`       // critical, high, medium, low
	ExemptDomains []string `yaml:"exempt_domains"` // domains where this pattern is not enforced
}

// AddressProtection configures crypto address poisoning detection.
// This is destination verification, not secret detection — separate from DLP.
// Detects lookalike blockchain addresses compared against a user-supplied
// allowlist of known-good destinations.
type AddressProtection struct {
	Enabled          bool             `yaml:"enabled"`
	Action           string           `yaml:"action"`            // block or warn (for poisoning/lookalike findings)
	UnknownAction    string           `yaml:"unknown_action"`    // allow, warn, or block (for valid addresses not in allowlist)
	AllowedAddresses []string         `yaml:"allowed_addresses"` // global baseline allowlist (free tier)
	Chains           AddressChains    `yaml:"chains"`
	Similarity       SimilarityConfig `yaml:"similarity"`
}

// AddressChains toggles which blockchain address formats to detect.
// nil = use chain-specific default (ETH/BTC/BNB: true, SOL: false).
type AddressChains struct {
	ETH *bool `yaml:"eth"` // nil = true when feature enabled
	BTC *bool `yaml:"btc"` // nil = true when feature enabled
	SOL *bool `yaml:"sol"` // nil = false (disabled by default, high FP risk from base58 regex)
	BNB *bool `yaml:"bnb"` // nil = true when feature enabled
}

// SimilarityConfig controls the prefix/suffix comparison for address poisoning detection.
// Compared on chain-specific CompareKey (payload), not the full address string.
type SimilarityConfig struct {
	PrefixLength int `yaml:"prefix_length"` // default 4
	SuffixLength int `yaml:"suffix_length"` // default 4
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

// RequestBodyScanning configures DLP scanning of request bodies and headers
// on the forward proxy path. Catches secrets exfiltrated via POST bodies or
// smuggled in Authorization/Cookie headers. CONNECT tunnels are out of scope
// (TLS-encrypted, can't scan without MITM).
type RequestBodyScanning struct {
	Enabled          bool     `yaml:"enabled"`
	Action           string   `yaml:"action"`            // warn, block (no strip for bodies)
	MaxBodyBytes     int      `yaml:"max_body_bytes"`    // fail-closed above this limit
	ScanHeaders      bool     `yaml:"scan_headers"`      // scan request headers for DLP
	HeaderMode       string   `yaml:"header_mode"`       // "sensitive" (listed headers) or "all" (everything except ignore list)
	SensitiveHeaders []string `yaml:"sensitive_headers"` // headers to scan in sensitive mode
	IgnoreHeaders    []string `yaml:"ignore_headers"`    // headers to skip in all mode
}

// CrossRequestDetection configures cross-request exfiltration detection.
// Tracks cumulative entropy and reassembles outbound fragments per session
// to catch secrets split across multiple requests.
type CrossRequestDetection struct {
	Enabled            bool                      `yaml:"enabled"`
	Action             string                    `yaml:"action"` // block, warn (applies to fragment DLP match)
	EntropyBudget      CrossRequestEntropyBudget `yaml:"entropy_budget"`
	FragmentReassembly CrossRequestFragments     `yaml:"fragment_reassembly"`
}

// CrossRequestEntropyBudget configures per-session entropy tracking.
type CrossRequestEntropyBudget struct {
	Enabled       bool    `yaml:"enabled"`
	BitsPerWindow float64 `yaml:"bits_per_window"` // total Shannon entropy bits before signaling
	WindowMinutes int     `yaml:"window_minutes"`  // sliding window duration
	Action        string  `yaml:"action"`          // warn, block (entropy alone is medium-confidence)
}

// CrossRequestFragments configures outbound payload fragment reassembly.
type CrossRequestFragments struct {
	Enabled        bool `yaml:"enabled"`
	MaxBufferBytes int  `yaml:"max_buffer_bytes"` // per-session rolling buffer cap
	WindowMinutes  int  `yaml:"window_minutes"`   // fragment retention window (independent of entropy budget)
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

// SentryConfig configures Sentry error reporting with secret redaction.
// All error data is scrubbed through DLP patterns before leaving the process.
type SentryConfig struct {
	Enabled     *bool    `yaml:"enabled"`     // nil = true (default enabled)
	DSN         string   `yaml:"dsn"`         // Sentry DSN; also reads SENTRY_DSN env
	Environment string   `yaml:"environment"` // e.g. "production" (default)
	SampleRate  *float64 `yaml:"sample_rate"` // nil = 1.0; 0.0-1.0
	Debug       bool     `yaml:"debug"`       // SDK debug mode
}

// IsEnabled returns true if Sentry is enabled (nil defaults to true).
func (s *SentryConfig) IsEnabled() bool {
	return s.Enabled == nil || *s.Enabled
}

// EffectiveSampleRate returns the configured sample rate (nil defaults to 1.0).
func (s *SentryConfig) EffectiveSampleRate() float64 {
	if s.SampleRate == nil {
		return 1.0
	}
	return *s.SampleRate
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

// AgentProfile defines per-agent policy overrides. Fields that are set
// override the base config; fields left at zero value inherit from base.
type AgentProfile struct {
	Listeners        []string          `yaml:"listeners,omitempty"`
	SourceCIDRs      []string          `yaml:"source_cidrs,omitempty"`
	Mode             string            `yaml:"mode,omitempty"`
	Enforce          *bool             `yaml:"enforce,omitempty"`
	APIAllowlist     []string          `yaml:"api_allowlist,omitempty"`
	DLP              *AgentDLP         `yaml:"dlp,omitempty"`
	RateLimit        *AgentRateLimit   `yaml:"rate_limit,omitempty"`
	SessionProfiling *AgentSessionProf `yaml:"session_profiling,omitempty"`
	MCPToolPolicy    *MCPToolPolicy    `yaml:"mcp_tool_policy,omitempty"`
	Budget           BudgetConfig      `yaml:"budget,omitempty"`
	AllowedAddresses []string          `yaml:"allowed_addresses,omitempty"` // per-agent crypto address allowlist (enterprise, additive with global)
}

// AgentDLP controls DLP pattern merging for agent profiles.
type AgentDLP struct {
	IncludeDefaults *bool        `yaml:"include_defaults,omitempty"` // nil/true: append to base; false: replace
	Patterns        []DLPPattern `yaml:"patterns,omitempty"`
}

// AgentRateLimit overrides rate limit settings per agent.
type AgentRateLimit struct {
	MaxRequestsPerMinute int `yaml:"max_requests_per_minute,omitempty"`
	MaxDataPerMinute     int `yaml:"max_data_per_minute,omitempty"`
}

// AgentSessionProf overrides per-agent session profiling thresholds.
// Global-only fields (max_sessions, session_ttl_minutes, cleanup_interval_seconds)
// are NOT included; validation rejects them in agent profiles.
type AgentSessionProf struct {
	DomainBurst      int     `yaml:"domain_burst,omitempty"`
	AnomalyAction    string  `yaml:"anomaly_action,omitempty"`
	VolumeSpikeRatio float64 `yaml:"volume_spike_ratio,omitempty"`
}

// BudgetConfig defines per-agent request budgets. Zero values mean unlimited.
type BudgetConfig struct {
	MaxRequestsPerSession      int `yaml:"max_requests_per_session,omitempty"`
	MaxBytesPerSession         int `yaml:"max_bytes_per_session,omitempty"`
	MaxUniqueDomainsPerSession int `yaml:"max_unique_domains_per_session,omitempty"`
	WindowMinutes              int `yaml:"window_minutes,omitempty"`
}

// ScanAPI configures the evaluation-plane HTTP listener.
// Disabled by default (Listen: ""). When enabled, serves POST /api/v1/scan
// on a dedicated port with independent timeouts and connection limits.
type ScanAPI struct {
	Listen          string             `yaml:"listen"`
	Auth            ScanAPIAuth        `yaml:"auth"`
	RateLimit       ScanAPIRateLimit   `yaml:"rate_limit"`
	MaxBodyBytes    int64              `yaml:"max_body_bytes"`
	FieldLimits     ScanAPIFieldLimits `yaml:"field_limits"`
	Timeouts        ScanAPITimeouts    `yaml:"timeouts"`
	ConnectionLimit int                `yaml:"connection_limit"`
	Kinds           ScanAPIKinds       `yaml:"kinds"`
}

// ScanAPIAuth holds bearer token credentials for the Scan API.
type ScanAPIAuth struct {
	BearerTokens []string `yaml:"bearer_tokens"` //nolint:gosec // G117: config field, not a hardcoded credential
}

// ScanAPIRateLimit configures per-client request rate limiting for the Scan API.
type ScanAPIRateLimit struct {
	RequestsPerMinute int `yaml:"requests_per_minute"`
	Burst             int `yaml:"burst"`
}

// ScanAPIFieldLimits caps the byte length of individual input fields in scan requests.
type ScanAPIFieldLimits struct {
	URL       int `yaml:"url"`
	Text      int `yaml:"text"`
	Content   int `yaml:"content"`
	Arguments int `yaml:"arguments"`
}

// ScanAPITimeouts controls per-request timing for the Scan API listener.
type ScanAPITimeouts struct {
	Read  string `yaml:"read"`
	Write string `yaml:"write"`
	Scan  string `yaml:"scan"`
}

// ScanAPIKinds selects which scan kinds are enabled on the Scan API.
// All kinds are enabled by default; set a field to false to disable it.
type ScanAPIKinds struct {
	URL             bool `yaml:"url"`
	DLP             bool `yaml:"dlp"`
	PromptInjection bool `yaml:"prompt_injection"`
	ToolCall        bool `yaml:"tool_call"`
}

// Load reads, parses, defaults, and validates a Pipelock config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}

	cfg.rawBytes = data

	// Detect omitted security booleans via raw YAML introspection and
	// default them to true (fail-closed). Must run before ApplyDefaults().
	applySecurityDefaults(data, cfg)

	cfg.ApplyDefaults()

	// Resolve license key from multiple sources. Priority:
	// 1. PIPELOCK_LICENSE_KEY env var (containers, CI)
	// 2. license_file config field (file path, read at startup)
	// 3. license_key config field (inline YAML, lowest priority)
	if err := cfg.resolveLicenseKey(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("license key: %w", err)
	}

	// Soft-gate premium features: disable agents section if no license key.
	if EnforceLicenseGateFunc != nil {
		EnforceLicenseGateFunc(cfg)
	}

	// Resolve relative secrets_file path relative to config file directory.
	if cfg.DLP.SecretsFile != "" && !filepath.IsAbs(cfg.DLP.SecretsFile) {
		cfg.DLP.SecretsFile = filepath.Join(filepath.Dir(path), cfg.DLP.SecretsFile)
	}

	// Resolve relative CA cert/key paths relative to config file directory.
	// This ensures TLS interception works under systemd (CWD=/), containers,
	// and when --config points to a non-local path.
	configDir := filepath.Dir(path)
	if cfg.TLSInterception.CACertPath != "" && !filepath.IsAbs(cfg.TLSInterception.CACertPath) {
		cfg.TLSInterception.CACertPath = filepath.Join(configDir, cfg.TLSInterception.CACertPath)
	}
	if cfg.TLSInterception.CAKeyPath != "" && !filepath.IsAbs(cfg.TLSInterception.CAKeyPath) {
		cfg.TLSInterception.CAKeyPath = filepath.Join(configDir, cfg.TLSInterception.CAKeyPath)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

// resolveLicenseKey populates LicenseKey from the highest-priority source:
// env var > license_file > inline license_key. The configDir is used to
// resolve relative license_file paths.
func (c *Config) resolveLicenseKey(configDir string) error {
	// 1. Env var takes highest priority. Trim before checking so that a
	// whitespace-only value (e.g. trailing newline) falls through to
	// lower-priority sources instead of winning with an empty token.
	if envKey := strings.TrimSpace(os.Getenv(EnvLicenseKey)); envKey != "" {
		c.LicenseKey = envKey
		return nil
	}

	// 2. File path: read token from the file.
	if c.LicenseFile != "" {
		p := c.LicenseFile
		if !filepath.IsAbs(p) {
			p = filepath.Join(configDir, p)
		}
		p = filepath.Clean(p)
		// Reject non-regular files (FIFOs, devices) that could hang
		// startup, and oversized files since tokens are ~200 bytes.
		const maxLicenseFileBytes int64 = 16 * 1024
		info, err := os.Stat(p)
		if err != nil {
			return fmt.Errorf("stat license_file %s: %w", c.LicenseFile, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("license_file %s must be a regular file", c.LicenseFile)
		}
		// Reject group-write/execute and all other access. Group-read
		// (0o040) is allowed for k8s Secret volumes where fsGroup adds
		// group-read automatically.
		if info.Mode().Perm()&0o037 != 0 {
			return fmt.Errorf("license_file %s is too permissive (mode %04o): restrict to 0600 or 0640",
				c.LicenseFile, info.Mode().Perm())
		}
		if info.Size() > maxLicenseFileBytes {
			return fmt.Errorf("license_file %s exceeds %d bytes", c.LicenseFile, maxLicenseFileBytes)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("reading license_file %s: %w", c.LicenseFile, err)
		}
		token := strings.TrimSpace(string(data))
		if token == "" {
			return fmt.Errorf("license_file %s is empty", c.LicenseFile)
		}
		c.LicenseKey = token
		return nil
	}

	// 3. Inline license_key from YAML stays as-is (already parsed).
	return nil
}

// Hash returns the SHA256 hex digest of the raw config file bytes.
// Returns "defaults" if the config was created via Defaults() (no file).
func (c *Config) Hash() string {
	if c.rawBytes == nil {
		return HashDefaults
	}
	h := sha256.Sum256(c.rawBytes)
	return hex.EncodeToString(h[:])
}

// applySecurityDefaults sets security-sensitive booleans to true when they are
// omitted or null in the config YAML. YAML unmarshal into a plain bool cannot
// distinguish "field omitted" (should default to true, fail-closed) from "field
// explicitly set to false" (user intent). We unmarshal into a raw map to detect
// which fields are actually present with a non-nil value, then default the rest.
func applySecurityDefaults(rawYAML []byte, cfg *Config) {
	var raw map[string]interface{}
	if err := yaml.Unmarshal(rawYAML, &raw); err != nil {
		// Primary unmarshal already succeeded; treat parse errors as "all omitted"
		// so we fail closed with all security defaults enabled.
		cfg.DLP.ScanEnv = true
		cfg.ResponseScanning.Enabled = true
		cfg.RequestBodyScanning.Enabled = true
		cfg.RequestBodyScanning.ScanHeaders = true
		cfg.GitProtection.PrePushScan = true
		cfg.Logging.IncludeAllowed = true
		cfg.Logging.IncludeBlocked = true
		cfg.ScanAPI.Kinds.URL = true
		cfg.ScanAPI.Kinds.DLP = true
		cfg.ScanAPI.Kinds.PromptInjection = true
		cfg.ScanAPI.Kinds.ToolCall = true
		return
	}

	setBoolDefault := func(section map[string]interface{}, key string, target *bool) {
		if section == nil {
			*target = true
			return
		}
		val, present := section[key]
		if !present || val == nil { // omitted or YAML null/blank: fail closed
			*target = true
		}
	}

	dlp, _ := raw["dlp"].(map[string]interface{})
	setBoolDefault(dlp, "scan_env", &cfg.DLP.ScanEnv)

	resp, _ := raw["response_scanning"].(map[string]interface{})
	setBoolDefault(resp, "enabled", &cfg.ResponseScanning.Enabled)

	reqBody, _ := raw["request_body_scanning"].(map[string]interface{})
	setBoolDefault(reqBody, "enabled", &cfg.RequestBodyScanning.Enabled)
	setBoolDefault(reqBody, "scan_headers", &cfg.RequestBodyScanning.ScanHeaders)

	git, _ := raw["git_protection"].(map[string]interface{})
	setBoolDefault(git, "pre_push_scan", &cfg.GitProtection.PrePushScan)

	logging, _ := raw["logging"].(map[string]interface{})
	setBoolDefault(logging, "include_allowed", &cfg.Logging.IncludeAllowed)
	setBoolDefault(logging, "include_blocked", &cfg.Logging.IncludeBlocked)

	// Scan API kind enable flags default to true (all kinds enabled).
	scanAPI, _ := raw["scan_api"].(map[string]interface{})
	var kinds map[string]interface{}
	if scanAPI != nil {
		kinds, _ = scanAPI["kinds"].(map[string]interface{})
	}
	setBoolDefault(kinds, "url", &cfg.ScanAPI.Kinds.URL)
	setBoolDefault(kinds, "dlp", &cfg.ScanAPI.Kinds.DLP)
	setBoolDefault(kinds, "prompt_injection", &cfg.ScanAPI.Kinds.PromptInjection)
	setBoolDefault(kinds, "tool_call", &cfg.ScanAPI.Kinds.ToolCall)
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
		c.ResponseScanning.Action = ActionWarn
	}
	if c.ResponseScanning.Action == ActionAsk && c.ResponseScanning.AskTimeoutSeconds <= 0 {
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
		c.MCPInputScanning.OnParseError = ActionBlock
	}
	if c.MCPInputScanning.Enabled && c.MCPInputScanning.Action == "" {
		c.MCPInputScanning.Action = ActionWarn
	}
	if c.MCPToolScanning.Enabled && c.MCPToolScanning.Action == "" {
		c.MCPToolScanning.Action = ActionWarn
	}
	if c.MCPToolPolicy.Enabled && c.MCPToolPolicy.Action == "" {
		c.MCPToolPolicy.Action = ActionWarn
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
		c.WebSocketProxy.OriginPolicy = OriginPolicyRewrite
	}
	if c.GitProtection.Enabled && len(c.GitProtection.AllowedBranches) == 0 {
		c.GitProtection.AllowedBranches = []string{"feature/*", "fix/*", "main", "master"}
	}
	if c.Internal == nil {
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
			"224.0.0.0/4",    // IPv4 multicast
			"ff00::/8",       // IPv6 multicast
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
		c.Emit.Webhook.MinSeverity = SeverityWarn
	}
	if c.Emit.Syslog.MinSeverity == "" {
		c.Emit.Syslog.MinSeverity = SeverityWarn
	}
	if c.Emit.Syslog.Facility == "" {
		c.Emit.Syslog.Facility = "local0"
	}
	if c.Emit.Syslog.Tag == "" {
		c.Emit.Syslog.Tag = "pipelock"
	}

	// Sentry defaults (nil sample_rate = 1.0, handled by EffectiveSampleRate())
	if c.Sentry.Environment == "" {
		c.Sentry.Environment = "production"
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

	// TLS interception defaults
	if c.TLSInterception.CertTTL == "" {
		c.TLSInterception.CertTTL = DefaultCertTTL
	}
	if c.TLSInterception.CertCacheSize <= 0 {
		c.TLSInterception.CertCacheSize = 10000
	}
	if c.TLSInterception.MaxResponseBytes <= 0 {
		c.TLSInterception.MaxResponseBytes = 5 * 1024 * 1024 // 5MB
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

	// Request body scanning defaults
	if c.RequestBodyScanning.Enabled {
		if c.RequestBodyScanning.Action == "" {
			c.RequestBodyScanning.Action = ActionWarn
		}
		if c.RequestBodyScanning.MaxBodyBytes == 0 {
			c.RequestBodyScanning.MaxBodyBytes = 5 * 1024 * 1024 // 5MB default
		}
		// Note: ScanHeaders defaults to false (Go bool zero value). YAML must
		// explicitly set scan_headers: true to enable header scanning. This is a
		// known limitation of Go's YAML bool unmarshaling (can't distinguish
		// "omitted" from "explicitly false").
		if c.RequestBodyScanning.HeaderMode == "" {
			c.RequestBodyScanning.HeaderMode = HeaderModeSensitive
		}
		if len(c.RequestBodyScanning.SensitiveHeaders) == 0 {
			c.RequestBodyScanning.SensitiveHeaders = []string{
				"Authorization",
				"Cookie",
				"X-Api-Key",
				"X-Token",
				"Proxy-Authorization",
				"X-Goog-Api-Key",
			}
		}
		if len(c.RequestBodyScanning.IgnoreHeaders) == 0 {
			c.RequestBodyScanning.IgnoreHeaders = []string{
				"Connection", "Keep-Alive", "Proxy-Authenticate",
				"Te", "Trailer", "Transfer-Encoding", "Upgrade",
				"Host", "Content-Length", "Content-Type",
				"Accept", "Accept-Encoding", "User-Agent",
			}
		}
	}

	// Scan API defaults (applied regardless of Listen, so a partial config gets sane values)
	if c.ScanAPI.RateLimit.RequestsPerMinute <= 0 {
		c.ScanAPI.RateLimit.RequestsPerMinute = 600
	}
	if c.ScanAPI.RateLimit.Burst <= 0 {
		c.ScanAPI.RateLimit.Burst = 50
	}
	if c.ScanAPI.MaxBodyBytes == 0 {
		c.ScanAPI.MaxBodyBytes = 1 << 20 // 1MB
	}
	if c.ScanAPI.FieldLimits.URL <= 0 {
		c.ScanAPI.FieldLimits.URL = 8192
	}
	if c.ScanAPI.FieldLimits.Text <= 0 {
		c.ScanAPI.FieldLimits.Text = 512 * 1024 // 512KB
	}
	if c.ScanAPI.FieldLimits.Content <= 0 {
		c.ScanAPI.FieldLimits.Content = 512 * 1024 // 512KB
	}
	if c.ScanAPI.FieldLimits.Arguments <= 0 {
		c.ScanAPI.FieldLimits.Arguments = 512 * 1024 // 512KB
	}
	if c.ScanAPI.Timeouts.Read == "" {
		c.ScanAPI.Timeouts.Read = "2s"
	}
	if c.ScanAPI.Timeouts.Write == "" {
		c.ScanAPI.Timeouts.Write = "2s"
	}
	if c.ScanAPI.Timeouts.Scan == "" {
		c.ScanAPI.Timeouts.Scan = "5s"
	}
	if c.ScanAPI.ConnectionLimit == 0 {
		c.ScanAPI.ConnectionLimit = 100
	}

	// Cross-request detection defaults
	if c.CrossRequestDetection.Enabled {
		if c.CrossRequestDetection.Action == "" {
			c.CrossRequestDetection.Action = ActionBlock
		}
		if c.CrossRequestDetection.EntropyBudget.Enabled {
			if c.CrossRequestDetection.EntropyBudget.BitsPerWindow <= 0 {
				c.CrossRequestDetection.EntropyBudget.BitsPerWindow = 4096 // generous for legitimate traffic
			}
			if c.CrossRequestDetection.EntropyBudget.WindowMinutes <= 0 {
				c.CrossRequestDetection.EntropyBudget.WindowMinutes = 5
			}
			if c.CrossRequestDetection.EntropyBudget.Action == "" {
				c.CrossRequestDetection.EntropyBudget.Action = ActionWarn
			}
		}
		if c.CrossRequestDetection.FragmentReassembly.Enabled {
			if c.CrossRequestDetection.FragmentReassembly.MaxBufferBytes <= 0 {
				c.CrossRequestDetection.FragmentReassembly.MaxBufferBytes = 65536 // 64KB per session
			}
			if c.CrossRequestDetection.FragmentReassembly.WindowMinutes <= 0 {
				c.CrossRequestDetection.FragmentReassembly.WindowMinutes = 5
			}
		}
	}

	// Address protection defaults
	if c.AddressProtection.Enabled {
		if c.AddressProtection.Action == "" {
			c.AddressProtection.Action = ActionBlock
		}
		if c.AddressProtection.UnknownAction == "" {
			c.AddressProtection.UnknownAction = ActionAllow
		}
		if c.AddressProtection.Similarity.PrefixLength <= 0 {
			c.AddressProtection.Similarity.PrefixLength = 4
		}
		if c.AddressProtection.Similarity.SuffixLength <= 0 {
			c.AddressProtection.Similarity.SuffixLength = 4
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
		for j, raw := range p.ExemptDomains {
			d := strings.TrimSuffix(strings.TrimSpace(strings.ToLower(raw)), ".")
			if d == "" {
				return fmt.Errorf("DLP pattern %q exempt_domains[%d] is empty", p.Name, j)
			}
			if strings.Contains(d, "://") || strings.Contains(d, "/") || strings.Contains(d, ":") {
				return fmt.Errorf("DLP pattern %q exempt_domains[%d] %q: use a hostname pattern, not a URL or host:port", p.Name, j, raw)
			}
			if strings.HasPrefix(d, "*.") {
				// Wildcard must target a concrete domain (*.com is too broad).
				if strings.Count(d[2:], ".") < 1 {
					return fmt.Errorf("DLP pattern %q exempt_domains[%d] %q: wildcard must target a concrete domain like *.example.com", p.Name, j, raw)
				}
			} else if strings.ContainsAny(d, "*?[]") {
				return fmt.Errorf("DLP pattern %q exempt_domains[%d] %q: only exact hosts and *.example.com wildcards are supported", p.Name, j, raw)
			}
			p.ExemptDomains[j] = d
		}
	}

	// Validate secrets_file if configured
	if c.DLP.SecretsFile != "" {
		info, err := os.Stat(c.DLP.SecretsFile)
		if err != nil {
			return fmt.Errorf("secrets_file %q: %w", c.DLP.SecretsFile, err)
		}
		// Reject group-write/execute and all other access. Group-read
		// allowed for k8s Secret volume compatibility.
		if info.Mode().Perm()&0o037 != 0 {
			return fmt.Errorf("secrets_file %q has unsafe permissions (mode %04o): restrict to 0600 or 0640", c.DLP.SecretsFile, info.Mode().Perm())
		}
	}

	// Validate blocklist patterns are well-formed
	for _, b := range c.FetchProxy.Monitoring.Blocklist {
		if b == "" {
			return fmt.Errorf("empty blocklist entry")
		}
	}

	// Validate subdomain entropy exclusions are well-formed hostname patterns.
	// Accepted formats: exact hostnames ("runpod.net") and wildcard prefixes
	// ("*.runpod.net"). Reject URLs, host:port, and over-broad patterns.
	for i, raw := range c.FetchProxy.Monitoring.SubdomainEntropyExclusions {
		d := strings.TrimSpace(strings.ToLower(raw))
		if d == "" {
			return fmt.Errorf("subdomain_entropy_exclusions[%d] is empty", i)
		}
		if strings.Contains(d, "://") || strings.Contains(d, "/") || strings.Contains(d, ":") {
			return fmt.Errorf("subdomain_entropy_exclusions[%d] %q: use a hostname pattern, not a URL or host:port", i, raw)
		}
		if strings.HasPrefix(d, "*.") {
			// Wildcard must target a concrete domain (*.com is too broad)
			if strings.Count(d[2:], ".") < 1 {
				return fmt.Errorf("subdomain_entropy_exclusions[%d] %q: wildcard must target a concrete domain like *.example.com", i, raw)
			}
		} else if strings.ContainsAny(d, "*?[]") {
			return fmt.Errorf("subdomain_entropy_exclusions[%d] %q: only exact hosts and *.example.com wildcards are supported", i, raw)
		}
		// Normalize: store lowercase, trimmed, trailing-dot-stripped version
		c.FetchProxy.Monitoring.SubdomainEntropyExclusions[i] = strings.TrimSuffix(d, ".")
	}

	// Validate global rate limits are non-negative
	if c.FetchProxy.Monitoring.MaxReqPerMinute < 0 {
		return fmt.Errorf("fetch_proxy.monitoring.max_requests_per_minute must be >= 0")
	}
	if c.FetchProxy.Monitoring.MaxDataPerMinute < 0 {
		return fmt.Errorf("fetch_proxy.monitoring.max_data_per_minute must be >= 0")
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
		case OriginPolicyRewrite, "forward", ActionStrip:
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

	// Validate request body scanning config
	if c.RequestBodyScanning.Enabled {
		switch c.RequestBodyScanning.Action {
		case ActionWarn, ActionBlock:
			// valid
		default:
			return fmt.Errorf("invalid request_body_scanning.action %q: must be warn or block", c.RequestBodyScanning.Action)
		}
		if c.RequestBodyScanning.MaxBodyBytes <= 0 {
			return fmt.Errorf("request_body_scanning.max_body_bytes must be positive")
		}
		switch c.RequestBodyScanning.HeaderMode {
		case HeaderModeSensitive, HeaderModeAll:
			// valid
		default:
			return fmt.Errorf("invalid request_body_scanning.header_mode %q: must be sensitive or all", c.RequestBodyScanning.HeaderMode)
		}
	}

	// Validate cross-request detection config
	if c.CrossRequestDetection.Enabled {
		if !c.CrossRequestDetection.EntropyBudget.Enabled && !c.CrossRequestDetection.FragmentReassembly.Enabled {
			return fmt.Errorf("cross_request_detection.enabled is true but both entropy_budget and fragment_reassembly are disabled (silent no-op)")
		}
		switch c.CrossRequestDetection.Action {
		case ActionBlock, ActionWarn:
			// valid
		default:
			return fmt.Errorf("invalid cross_request_detection.action %q: must be block or warn", c.CrossRequestDetection.Action)
		}
		if c.CrossRequestDetection.EntropyBudget.Enabled {
			switch c.CrossRequestDetection.EntropyBudget.Action {
			case ActionBlock, ActionWarn:
				// valid
			default:
				return fmt.Errorf("invalid cross_request_detection.entropy_budget.action %q: must be block or warn", c.CrossRequestDetection.EntropyBudget.Action)
			}
			if c.CrossRequestDetection.EntropyBudget.BitsPerWindow <= 0 {
				return fmt.Errorf("cross_request_detection.entropy_budget.bits_per_window must be > 0")
			}
			if c.CrossRequestDetection.EntropyBudget.WindowMinutes <= 0 {
				return fmt.Errorf("cross_request_detection.entropy_budget.window_minutes must be > 0")
			}
		}
		if c.CrossRequestDetection.FragmentReassembly.Enabled {
			if c.CrossRequestDetection.FragmentReassembly.MaxBufferBytes <= 0 {
				return fmt.Errorf("cross_request_detection.fragment_reassembly.max_buffer_bytes must be > 0")
			}
			if c.CrossRequestDetection.FragmentReassembly.WindowMinutes <= 0 {
				return fmt.Errorf("cross_request_detection.fragment_reassembly.window_minutes must be > 0")
			}
		}
	}

	// Validate TLS interception config
	if c.TLSInterception.Enabled {
		ttl, err := time.ParseDuration(c.TLSInterception.CertTTL)
		if err != nil {
			return fmt.Errorf("tls_interception.cert_ttl: %w", err)
		}
		if ttl <= 0 {
			return errors.New("tls_interception.cert_ttl must be positive")
		}
		if c.TLSInterception.CertCacheSize <= 0 {
			return errors.New("tls_interception.cert_cache_size must be > 0")
		}
		if c.TLSInterception.MaxResponseBytes <= 0 {
			return errors.New("tls_interception.max_response_bytes must be > 0")
		}
		certPath, keyPath, resolveErr := c.ResolveCAPath()
		if resolveErr != nil {
			return fmt.Errorf("tls_interception: %w", resolveErr)
		}
		if _, err := os.Stat(certPath); err != nil {
			return fmt.Errorf("CA cert not found at %s (run 'pipelock tls init'): %w", certPath, err)
		}
		keyInfo, err := os.Stat(keyPath)
		if err != nil {
			return fmt.Errorf("CA key not found at %s (run 'pipelock tls init'): %w", keyPath, err)
		}
		// Reject world-readable, any writable, or any executable bits. Allow
		// group-read (0o040) because Kubernetes fsGroup sets it on secret volumes.
		if keyInfo.Mode().Perm()&0o137 != 0 {
			return fmt.Errorf("CA key %s is too permissive (mode %04o): restrict to 0600 or 0640", keyPath, keyInfo.Mode().Perm())
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
			case SeverityMedium, SeverityHigh, SeverityCritical:
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
		switch c.Emit.Webhook.MinSeverity {
		case SeverityInfo, SeverityWarn, SeverityCritical:
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
		switch c.Emit.Syslog.MinSeverity {
		case SeverityInfo, SeverityWarn, SeverityCritical:
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

	// Validate address protection config
	if c.AddressProtection.Enabled {
		switch c.AddressProtection.Action {
		case ActionBlock, ActionWarn:
			// valid
		default:
			return fmt.Errorf("invalid address_protection.action %q: must be block or warn", c.AddressProtection.Action)
		}
		switch c.AddressProtection.UnknownAction {
		case ActionAllow, ActionWarn, ActionBlock:
			// valid
		default:
			return fmt.Errorf("invalid address_protection.unknown_action %q: must be allow, warn, or block", c.AddressProtection.UnknownAction)
		}
		if c.AddressProtection.Similarity.PrefixLength <= 0 {
			return fmt.Errorf("address_protection.similarity.prefix_length must be positive")
		}
		if c.AddressProtection.Similarity.SuffixLength <= 0 {
			return fmt.Errorf("address_protection.similarity.suffix_length must be positive")
		}
		// Require at least one chain enabled. All chains disabled means the
		// feature is a silent no-op, which is a config error when enabled: true.
		eth := c.AddressProtection.Chains.ETH == nil || *c.AddressProtection.Chains.ETH
		btc := c.AddressProtection.Chains.BTC == nil || *c.AddressProtection.Chains.BTC
		sol := c.AddressProtection.Chains.SOL != nil && *c.AddressProtection.Chains.SOL
		bnb := c.AddressProtection.Chains.BNB == nil || *c.AddressProtection.Chains.BNB
		if !eth && !btc && !sol && !bnb {
			return fmt.Errorf("address_protection.enabled is true but all chains are disabled (silent no-op)")
		}
	}

	// Validate Sentry config
	sr := c.Sentry.EffectiveSampleRate()
	if math.IsNaN(sr) {
		return fmt.Errorf("invalid sentry.sample_rate: NaN not allowed")
	}
	if sr < 0 || sr > 1 {
		return fmt.Errorf("invalid sentry.sample_rate %f: must be between 0.0 and 1.0", sr)
	}

	// Validate internal CIDRs are parseable
	for _, cidr := range c.Internal {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("invalid internal CIDR %q: %w", cidr, err)
		}
	}

	// Validate agent profiles (enterprise hook; nil in OSS).
	if ValidateAgentsFunc != nil {
		if err := ValidateAgentsFunc(c); err != nil {
			return err
		}
	}

	// Validate scan API config
	if c.ScanAPI.Listen != "" {
		if len(c.ScanAPI.Auth.BearerTokens) == 0 {
			return fmt.Errorf("scan_api.auth.bearer_tokens required when scan_api.listen is set")
		}
		for i, tok := range c.ScanAPI.Auth.BearerTokens {
			if strings.TrimSpace(tok) == "" {
				return fmt.Errorf("scan_api.auth.bearer_tokens[%d] must be non-empty", i)
			}
		}
		// Validate timeouts: must parse as valid durations and be positive.
		// Zero or negative timeouts would disable deadlines or expire instantly.
		validatePositiveDuration := func(name, value string) error {
			if value == "" {
				return nil
			}
			d, err := time.ParseDuration(value)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			if d <= 0 {
				return fmt.Errorf("%s must be positive", name)
			}
			return nil
		}
		if err := validatePositiveDuration("scan_api.timeouts.scan", c.ScanAPI.Timeouts.Scan); err != nil {
			return err
		}
		if err := validatePositiveDuration("scan_api.timeouts.read", c.ScanAPI.Timeouts.Read); err != nil {
			return err
		}
		if err := validatePositiveDuration("scan_api.timeouts.write", c.ScanAPI.Timeouts.Write); err != nil {
			return err
		}
		if c.ScanAPI.ConnectionLimit < 0 {
			return fmt.Errorf("scan_api.connection_limit must be >= 0")
		}
		if c.ScanAPI.MaxBodyBytes < 0 {
			return fmt.Errorf("scan_api.max_body_bytes must be >= 0")
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

// ResolveCAPath returns resolved CA cert and key paths.
// Empty config values resolve to ~/.pipelock/ca.pem and ~/.pipelock/ca-key.pem.
// Returns an error if $HOME cannot be determined and paths are not set explicitly.
func (c *Config) ResolveCAPath() (certPath, keyPath string, err error) {
	certPath = c.TLSInterception.CACertPath
	keyPath = c.TLSInterception.CAKeyPath
	if certPath == "" || keyPath == "" {
		home, homeErr := os.UserHomeDir()
		if homeErr != nil {
			return "", "", fmt.Errorf("resolve CA path: %w (set ca_cert and ca_key explicitly)", homeErr)
		}
		dir := filepath.Join(home, ".pipelock")
		if certPath == "" {
			certPath = filepath.Join(dir, "ca.pem")
		}
		if keyPath == "" {
			keyPath = filepath.Join(dir, "ca-key.pem")
		}
	}
	return certPath, keyPath, nil
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

	// TLS interception disabled
	if old.TLSInterception.Enabled && !updated.TLSInterception.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "tls_interception.enabled",
			Message: "TLS interception disabled — CONNECT tunnel body/header scanning lost",
		})
	}

	// TLS passthrough domains changed (scanning coverage may be reduced).
	// Uses set-diff semantics: warns when new domains are added that weren't
	// in the old list, even if the total count stays the same or shrinks.
	if old.TLSInterception.Enabled && updated.TLSInterception.Enabled {
		added := passthroughDomainsAdded(old.TLSInterception.PassthroughDomains, updated.TLSInterception.PassthroughDomains)
		if len(added) > 0 {
			warnings = append(warnings, ReloadWarning{
				Field:   "tls_interception.passthrough_domains",
				Message: fmt.Sprintf("passthrough domains added: %s — these CONNECT tunnels now bypass body scanning", strings.Join(added, ", ")),
			})
		}
	}

	// Subdomain entropy exclusions expanded (reduces detection coverage)
	if added := passthroughDomainsAdded(
		old.FetchProxy.Monitoring.SubdomainEntropyExclusions,
		updated.FetchProxy.Monitoring.SubdomainEntropyExclusions,
	); len(added) > 0 {
		warnings = append(warnings, ReloadWarning{
			Field:   "fetch_proxy.monitoring.subdomain_entropy_exclusions",
			Message: fmt.Sprintf("subdomain entropy exclusions added: %s — entropy detection coverage reduced", strings.Join(added, ", ")),
		})
	}

	// Request body scanning disabled
	if old.RequestBodyScanning.Enabled && !updated.RequestBodyScanning.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "request_body_scanning.enabled",
			Message: "request body scanning disabled",
		})
	}

	// Tool chain detection disabled
	if old.ToolChainDetection.Enabled && !updated.ToolChainDetection.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "tool_chain_detection.enabled",
			Message: "tool chain detection disabled",
		})
	}

	// Cross-request detection disabled
	if old.CrossRequestDetection.Enabled && !updated.CrossRequestDetection.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "cross_request_detection.enabled",
			Message: "cross-request exfiltration detection disabled",
		})
	}
	// Per-detector warnings only matter when the parent stays enabled.
	// If the parent is being disabled, the parent warning above covers it.
	if old.CrossRequestDetection.Enabled &&
		updated.CrossRequestDetection.Enabled &&
		old.CrossRequestDetection.EntropyBudget.Enabled &&
		!updated.CrossRequestDetection.EntropyBudget.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "cross_request_detection.entropy_budget.enabled",
			Message: "cross-request entropy budget detection disabled",
		})
	}
	if old.CrossRequestDetection.Enabled &&
		updated.CrossRequestDetection.Enabled &&
		old.CrossRequestDetection.FragmentReassembly.Enabled &&
		!updated.CrossRequestDetection.FragmentReassembly.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "cross_request_detection.fragment_reassembly.enabled",
			Message: "cross-request fragment reassembly disabled",
		})
	}

	// Address protection disabled
	if old.AddressProtection.Enabled && !updated.AddressProtection.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "address_protection.enabled",
			Message: "address protection disabled",
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

	// Sentry DSN changed (requires restart — scrubber is built once at init)
	if old.Sentry.DSN != updated.Sentry.DSN {
		warnings = append(warnings, ReloadWarning{Field: "sentry.dsn", Message: "Sentry DSN changes require restart"})
	}

	// Sentry scrubber uses DLP patterns, env secrets, and file secrets from
	// init time. Warn on ANY change that would affect scrubbing coverage.
	if dlpPatternsChanged(old.DLP.Patterns, updated.DLP.Patterns) {
		warnings = append(warnings, ReloadWarning{
			Field:   "sentry",
			Message: "DLP patterns changed; Sentry scrubber uses init-time patterns until restart",
		})
	}
	if old.DLP.ScanEnv != updated.DLP.ScanEnv {
		warnings = append(warnings, ReloadWarning{
			Field:   "sentry",
			Message: "dlp.scan_env changed; Sentry scrubber uses init-time env secrets until restart",
		})
	}
	if old.DLP.SecretsFile != updated.DLP.SecretsFile {
		warnings = append(warnings, ReloadWarning{
			Field:   "sentry",
			Message: "dlp.secrets_file changed; Sentry scrubber uses init-time file secrets until restart",
		})
	}

	return warnings
}

// dlpPatternsChanged returns true if the DLP pattern set differs in ways that
// affect the Sentry scrubber (count, name, or regex content). exempt_domains
// changes are intentionally excluded — the scrubber compiles regexes only and
// does not use destination-domain exemptions.
func dlpPatternsChanged(old, updated []DLPPattern) bool {
	if len(old) != len(updated) {
		return true
	}
	for i := range old {
		if old[i].Regex != updated[i].Regex {
			return true
		}
		if old[i].Name != updated[i].Name {
			return true
		}
	}
	return false
}

// passthroughDomainsAdded returns domains present in updated but not in old.
func passthroughDomainsAdded(old, updated []string) []string {
	oldSet := make(map[string]struct{}, len(old))
	for _, d := range old {
		oldSet[strings.ToLower(d)] = struct{}{}
	}
	var added []string
	for _, d := range updated {
		if _, exists := oldSet[strings.ToLower(d)]; !exists {
			added = append(added, d)
		}
	}
	return added
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
				SubdomainEntropyExclusions: []string{},
			},
		},
		ForwardProxy: ForwardProxy{
			Enabled:            false,
			MaxTunnelSeconds:   300,
			IdleTimeoutSeconds: 120,
			SNIVerification:    ptrBool(true),
		},
		WebSocketProxy: WebSocketProxy{
			Enabled:                  false,
			MaxMessageBytes:          1048576,
			MaxConcurrentConnections: 128,
			ScanTextFrames:           ptrBool(true),
			StripCompression:         ptrBool(true),
			MaxConnectionSeconds:     3600,
			IdleTimeoutSeconds:       300,
			OriginPolicy:             OriginPolicyRewrite,
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
				// Stripe webhook signing secrets: "whsec_" prefix.
				{Name: "Stripe Webhook Secret", Regex: `whsec_[a-zA-Z0-9_\-]{20,}`, Severity: "critical"},

				// Source control tokens
				{Name: "GitHub Token", Regex: `gh[pousr]_[A-Za-z0-9_]{36,}`, Severity: "critical"},
				{Name: "GitHub Fine-Grained PAT", Regex: `github_pat_[a-zA-Z0-9_]{36,}`, Severity: "critical"},
				// GitLab personal access tokens: "glpat-" prefix, 20+ chars.
				{Name: "GitLab PAT", Regex: `glpat-[a-zA-Z0-9\-_]{20,}`, Severity: "critical"},

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

				// Observability / monitoring
				// New Relic user API keys: "NRAK-" prefix, 27+ uppercase alphanumeric.
				{Name: "New Relic API Key", Regex: `NRAK-[A-Z0-9]{27,}`, Severity: "critical"},

				// AI/ML provider keys
				{Name: "Hugging Face Token", Regex: `hf_[A-Za-z0-9]{20,}`, Severity: "critical"},
				{Name: "Databricks Token", Regex: `dapi[a-z0-9]{30,}`, Severity: "critical"},
				{Name: "Replicate API Token", Regex: `r8_[A-Za-z0-9]{20,}`, Severity: "critical"},
				{Name: "Together AI Key", Regex: `tok_[a-z0-9]{40,}`, Severity: "critical"},
				// Pinecone API keys: "pcsk_" prefix followed by alphanumeric.
				{Name: "Pinecone API Key", Regex: `pcsk_[a-zA-Z0-9]{36,}`, Severity: "critical"},
				// Groq inference API keys: "gsk_" prefix, 48+ alphanumeric chars.
				{Name: "Groq API Key", Regex: `gsk_[a-zA-Z0-9]{48,}`, Severity: "critical"},
				// xAI (Grok) API keys: "xai-" prefix, 80+ chars including hyphens.
				{Name: "xAI API Key", Regex: `xai-[a-zA-Z0-9\-_]{80,}`, Severity: "critical"},

				// Infrastructure and platform tokens
				// DigitalOcean personal access tokens: 64 hex chars after prefix.
				{Name: "DigitalOcean Token", Regex: `dop_v1_[a-f0-9]{64}`, Severity: "critical"},
				{Name: "HashiCorp Vault Token", Regex: `hvs\.[a-zA-Z0-9]{23,}`, Severity: "critical"},
				{Name: "Vercel Token", Regex: `(?:vercel|vc[piark])_[a-zA-Z0-9]{24,}`, Severity: "critical"},
				{Name: "Supabase Service Key", Regex: `sb_secret_[a-zA-Z0-9_-]{20,}`, Severity: "critical"},

				// Package registry tokens
				{Name: "npm Token", Regex: `npm_[A-Za-z0-9]{36,}`, Severity: "critical"},
				{Name: "PyPI Token", Regex: `pypi-[A-Za-z0-9_-]{16,}`, Severity: "critical"},

				// Developer platform tokens
				{Name: "Linear API Key", Regex: `lin_api_[a-zA-Z0-9]{40,}`, Severity: "high"},
				{Name: "Notion API Key", Regex: `ntn_[a-zA-Z0-9]{40,}`, Severity: "high"},
				{Name: "Sentry Auth Token", Regex: `sntrys_[a-zA-Z0-9]{40,}`, Severity: "high"},

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
		TLSInterception: TLSInterception{
			Enabled:          false,
			CertTTL:          DefaultCertTTL,
			CertCacheSize:    10000,
			MaxResponseBytes: 5 * 1024 * 1024, // 5MB
		},
		RequestBodyScanning: RequestBodyScanning{
			Enabled:      true,
			Action:       ActionWarn,
			MaxBodyBytes: 5 * 1024 * 1024, // 5MB
			ScanHeaders:  true,
			HeaderMode:   HeaderModeSensitive,
			SensitiveHeaders: []string{
				"Authorization",
				"Cookie",
				"X-Api-Key",
				"X-Token",
				"Proxy-Authorization",
				"X-Goog-Api-Key",
			},
		},
		Internal: []string{
			"0.0.0.0/8",
			"127.0.0.0/8",
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"169.254.0.0/16",
			"100.64.0.0/10",
			"224.0.0.0/4", // IPv4 multicast
			"::1/128",
			"fc00::/7",
			"fe80::/10",
			"ff00::/8", // IPv6 multicast
		},
		ScanAPI: ScanAPI{
			Listen: "", // disabled by default
			RateLimit: ScanAPIRateLimit{
				RequestsPerMinute: 600,
				Burst:             50,
			},
			MaxBodyBytes: 1 << 20, // 1MB
			FieldLimits: ScanAPIFieldLimits{
				URL:       8192,
				Text:      512 * 1024, // 512KB
				Content:   512 * 1024, // 512KB
				Arguments: 512 * 1024, // 512KB
			},
			Timeouts: ScanAPITimeouts{
				Read:  "2s",
				Write: "2s",
				Scan:  "5s",
			},
			ConnectionLimit: 100,
			Kinds: ScanAPIKinds{
				URL:             true,
				DLP:             true,
				PromptInjection: true,
				ToolCall:        true,
			},
		},
	}
	return cfg
}

func ptrBool(v bool) *bool { return &v }
