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
	"slices"
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
	ActionBlock    = "block"
	ActionRedirect = "redirect"
	ActionWarn     = "warn"
	ActionAsk      = "ask"
	ActionStrip    = "strip"
	ActionForward  = "forward"
	ActionAllow    = "allow"
)

// Severity constants for chain detection and emit thresholds.
const (
	SeverityInfo     = "info"
	SeverityWarn     = "warn"
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
)

// DLP validator names for post-match checksum verification.
const (
	ValidatorLuhn  = "luhn"
	ValidatorMod97 = "mod97"
	ValidatorABA   = "aba"
	ValidatorWIF   = "wif"
)

// Confidence constants for community rule minimum confidence filtering.
const (
	ConfidenceHigh   = "high"
	ConfidenceMedium = "medium"
	ConfidenceLow    = "low"
)

// Origin policy constants for WebSocket proxy.
const (
	OriginPolicyRewrite = "rewrite"
	OriginPolicyForward = "forward"
)

// Header mode constants for request body scanning.
const (
	HeaderModeSensitive = "sensitive" // scan only explicitly listed headers
	HeaderModeAll       = "all"       // scan all headers except ignore list
)

// MCP tool provenance verification mode constants.
const (
	ProvenanceModePipelock = "pipelock" // pipelock-native Ed25519 verification
	ProvenanceModeSigstore = "sigstore" // Sigstore OIDC verification
	ProvenanceModeAny      = "any"      // accept either
)

// Behavioral baseline seasonality mode constants.
const (
	SeasonalityModeNone    = "none"
	SeasonalityModeLabeled = "labeled"
	SeasonalityModeTime    = "time"
)

// URL scheme constants for validation.
const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
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

	// DefaultSyslogTag is the default syslog tag for emitted events.
	DefaultSyslogTag = "pipelock"

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
	// Strip standard ports from both target and pattern so suppress
	// entries like "https://api.anthropic.com:443/*" match targets
	// without explicit ports, and vice versa.
	normalized := stripStandardPorts(target)
	p = stripStandardPorts(p)
	// Directory prefix: "vendor/" matches "vendor/foo/bar.go"
	if strings.HasSuffix(p, "/") {
		return strings.HasPrefix(normalized, p)
	}
	// Exact match (try both original and port-stripped).
	if normalized == p || target == p {
		return true
	}
	// Glob on full path.
	if matched, _ := path.Match(p, normalized); matched {
		return true
	}
	// Glob on basename (e.g., "*.txt" matches "dir/foo.txt").
	if matched, _ := path.Match(p, path.Base(normalized)); matched {
		return true
	}
	// Substring match for URL-style patterns containing "://".
	// Enables "*.anthropic.com*" to match "https://api.anthropic.com/v1/messages"
	// where path.Match fails because "*" doesn't cross "/" boundaries.
	if strings.Contains(p, "://") || (strings.Contains(p, ".") && strings.Contains(normalized, "://")) {
		if matchGlobSubstring(normalized, p) {
			return true
		}
	}
	// URL suffix match: pattern without leading slash matches URL path suffix.
	// e.g., "robots.txt" matches "https://example.com/robots.txt"
	if !strings.HasPrefix(p, "/") && strings.HasSuffix(normalized, "/"+p) {
		return true
	}
	return false
}

// stripStandardPorts removes :443 and :80 from URLs so suppress patterns
// don't need to account for explicit default ports. Uses net/url parsing
// to correctly identify the host:port boundary.
func stripStandardPorts(u string) string {
	if !strings.Contains(u, "://") {
		return u
	}
	parsed, err := url.Parse(u)
	if err != nil {
		return u
	}
	port := parsed.Port()
	if port == "443" || port == "80" {
		parsed.Host = parsed.Hostname()
		return parsed.String()
	}
	return u
}

// matchGlobSubstring does a simple glob match where "*" matches any character
// including "/". This is needed for URL patterns where path.Match's "*"
// (which stops at "/") is too restrictive.
func matchGlobSubstring(s, pattern string) bool {
	if pattern == "" {
		return false
	}
	// Convert glob to a simple check: split on "*" and verify all parts
	// appear in order in the string.
	parts := strings.Split(pattern, "*")
	if len(parts) == 0 {
		return false
	}
	idx := 0
	for i, part := range parts {
		if part == "" {
			continue
		}
		pos := strings.Index(s[idx:], part)
		if pos < 0 {
			return false
		}
		// First part must be a prefix if pattern doesn't start with "*".
		if i == 0 && !strings.HasPrefix(pattern, "*") && pos != 0 {
			return false
		}
		idx += pos + len(part)
	}
	// Last part must be a suffix if pattern doesn't end with "*".
	if !strings.HasSuffix(pattern, "*") {
		lastPart := parts[len(parts)-1]
		if lastPart != "" && !strings.HasSuffix(s, lastPart) {
			return false
		}
	}
	return true
}

// toSlash normalizes path separators to forward slashes.
func toSlash(s string) string {
	return strings.ReplaceAll(s, "\\", "/")
}

// Rules configures community rule bundle loading.
type Rules struct {
	RulesDir            string       `yaml:"rules_dir"`
	MinConfidence       string       `yaml:"min_confidence"`
	IncludeExperimental bool         `yaml:"include_experimental"`
	Disabled            []string     `yaml:"disabled"`
	TrustedKeys         []TrustedKey `yaml:"trusted_keys"`
}

// TrustedKey is a named Ed25519 public key for verifying third-party bundles.
// When Tier is set, this key is bound to that tier — bundles signed by this
// key must declare the matching tier, preventing key-swap attacks.
type TrustedKey struct {
	Name      string `yaml:"name"`
	PublicKey string `yaml:"public_key"` // 64 lowercase hex chars
	Tier      string `yaml:"tier,omitempty"`
}

// FileSentry configures real-time filesystem monitoring for agent processes.
// Detects secrets written to disk by agent subprocesses that bypass
// the MCP tool call path. Applies to subprocess MCP mode only.
type FileSentry struct {
	Enabled        bool     `yaml:"enabled"`
	BestEffort     bool     `yaml:"best_effort"` // degrade gracefully when watch setup fails (e.g. inotify exhaustion)
	WatchPaths     []string `yaml:"watch_paths"`
	ScanContent    *bool    `yaml:"scan_content"`    // nil = default true
	IgnorePatterns []string `yaml:"ignore_patterns"` // glob patterns to skip
}

// Sandbox configures process containment for child processes.
// Sandbox config is startup-only and reload-immutable: changing these
// values in a config reload has no effect on an already-running sandbox.
type Sandbox struct {
	Enabled    bool               `yaml:"enabled"`
	Strict     bool               `yaml:"strict"`      // error if any containment layer is unavailable
	BestEffort bool               `yaml:"best_effort"` // degrade gracefully when namespace isolation unavailable (e.g. containers)
	Workspace  string             `yaml:"workspace"`   // agent working dir; resolved to absolute at startup
	FS         *SandboxFilesystem `yaml:"filesystem"`
}

// AgentSandboxOverride controls per-agent sandbox settings.
// Nil pointer fields mean "inherit from global sandbox config."
// Scoped to mcp proxy --agent and agent listeners. pipelock sandbox
// CLI does not support per-agent resolution.
type AgentSandboxOverride struct {
	Enabled    *bool              `yaml:"enabled,omitempty"`
	Strict     *bool              `yaml:"strict,omitempty"`
	BestEffort *bool              `yaml:"best_effort,omitempty"`
	Workspace  string             `yaml:"workspace,omitempty"`
	FS         *SandboxFilesystem `yaml:"filesystem,omitempty"`
}

// SandboxFilesystem overrides the default Landlock policy. If nil, the
// default policy is used (safe for Python/Node/Go agents without config).
//
// Landlock is an allowlist model. Execute access is bundled with read
// (RODirs grants execute). RWDirs grants full access including execute.
// There is no separate allow_exec field — writable dirs are executable.
type SandboxFilesystem struct {
	AllowRead  []string `yaml:"allow_read"`
	AllowWrite []string `yaml:"allow_write"`
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
	CanaryTokens          CanaryTokens            `yaml:"canary_tokens"`
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
	ReverseProxy          ReverseProxy            `yaml:"reverse_proxy"`
	ScanAPI               ScanAPI                 `yaml:"scan_api"`
	AddressProtection     AddressProtection       `yaml:"address_protection"`
	SeedPhraseDetection   SeedPhraseDetection     `yaml:"seed_phrase_detection"`
	Rules                 Rules                   `yaml:"rules"`
	FileSentry            FileSentry              `yaml:"file_sentry"`
	Sandbox               Sandbox                 `yaml:"sandbox"`
	FlightRecorder        FlightRecorder          `yaml:"flight_recorder"`
	MCPBinaryIntegrity    MCPBinaryIntegrity      `yaml:"mcp_binary_integrity"`
	MCPToolProvenance     MCPToolProvenance       `yaml:"mcp_tool_provenance"`
	BehavioralBaseline    BehavioralBaseline      `yaml:"behavioral_baseline"`
	Airlock               Airlock                 `yaml:"airlock"`
	BrowserShield         BrowserShield           `yaml:"browser_shield"`
	A2AScanning           A2AScanning             `yaml:"a2a_scanning"`
	Agents                map[string]AgentProfile `yaml:"agents,omitempty"`
	LicenseKey            string                  `yaml:"license_key,omitempty"`        // signed license token (from pipelock license issue)
	LicenseFile           string                  `yaml:"license_file,omitempty"`       // path to file containing the license token (read at startup)
	LicensePublicKey      string                  `yaml:"license_public_key,omitempty"` // hex-encoded Ed25519 public key for license verification (dev builds only)
	Internal              []string                `yaml:"internal"`
	TrustedDomains        []string                `yaml:"trusted_domains"` // domains exempt from SSRF internal-IP check (wildcard supported)
	SSRF                  SSRF                    `yaml:"ssrf"`

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

// RedirectProfile defines a local executable to invoke when a tool call
// is redirected instead of blocked. The redirect handler receives the
// original tool arguments and returns output that pipelock wraps as a
// synthetic MCP success response.
type RedirectProfile struct {
	Exec         []string `yaml:"exec"`           // command + args (e.g. ["/proc/self/exe", "internal-redirect", "fetch-proxy"])
	Reason       string   `yaml:"reason"`         // human-readable justification for redirect
	PreserveArgv bool     `yaml:"preserve_argv"`  // pass original tool arguments to handler
	MatchAbsPath bool     `yaml:"match_abs_path"` // require absolute path in exec[0]
}

// MCPToolPolicy configures pre-execution policy checking on MCP tool calls.
// Rules match tool names and argument patterns to block or warn on dangerous
// operations before they reach the MCP server.
type MCPToolPolicy struct {
	Enabled          bool                       `yaml:"enabled"`
	Action           string                     `yaml:"action"` // warn, block, redirect (default for rules without override)
	Rules            []ToolPolicyRule           `yaml:"rules"`
	RedirectProfiles map[string]RedirectProfile `yaml:"redirect_profiles,omitempty"`
	QuarantineDir    string                     `yaml:"quarantine_dir,omitempty"`
}

// ToolPolicyRule defines a single tool call policy rule.
// ToolPattern matches against the tool name from params.name in tools/call requests.
// ArgPattern optionally matches against any string value in params.arguments.
// If ArgPattern is empty, the rule triggers on tool name alone.
// ArgKey optionally scopes ArgPattern to values under matching top-level argument
// keys only. Without ArgKey, ArgPattern matches against ALL argument values.
type ToolPolicyRule struct {
	Name            string `yaml:"name"`
	ToolPattern     string `yaml:"tool_pattern"`     // regex matching tool name
	ArgPattern      string `yaml:"arg_pattern"`      // regex matching argument values (optional)
	ArgKey          string `yaml:"arg_key"`          // regex scoping arg_pattern to specific argument keys (optional)
	Action          string `yaml:"action"`           // per-rule override: warn, block, redirect (optional)
	RedirectProfile string `yaml:"redirect_profile"` // key in redirect_profiles (required when action=redirect)
}

// ResponseScanning configures scanning of fetched page content for prompt injection.
type ResponseScanning struct {
	Enabled           bool                  `yaml:"enabled"`
	Action            string                `yaml:"action"`              // strip, warn, block, ask
	AskTimeoutSeconds int                   `yaml:"ask_timeout_seconds"` // timeout for HITL prompt (default 30)
	IncludeDefaults   *bool                 `yaml:"include_defaults"`    // nil/true: merge user patterns with defaults; false: user patterns only
	Patterns          []ResponseScanPattern `yaml:"patterns"`
	ExemptDomains     []string              `yaml:"exempt_domains"` // responses from these hosts skip injection scanning (DLP still applies)
}

// ResponseScanPattern is a named regex pattern for detecting prompt injection in responses.
type ResponseScanPattern struct {
	Name          string `yaml:"name"`
	Regex         string `yaml:"regex"`
	Bundle        string `yaml:"-"` // set by rules loader, not from YAML
	BundleVersion string `yaml:"-"` // set by rules loader, not from YAML
	Compiled      bool   `yaml:"-"` // true for patterns from Defaults(), set by ApplyDefaults
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

// ReverseProxy configures a generic HTTP reverse proxy with body scanning.
// All requests are forwarded to the upstream URL. Request bodies are scanned
// for DLP patterns (secret exfiltration) and response bodies are scanned for
// prompt injection, using the same scanning infrastructure as the fetch and
// forward proxies.
type ReverseProxy struct {
	Enabled  bool   `yaml:"enabled"`
	Listen   string `yaml:"listen"`   // listen address (e.g. ":8888")
	Upstream string `yaml:"upstream"` // upstream URL (e.g. "http://localhost:7899")
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
	SubdomainEntropyThreshold  float64  `yaml:"subdomain_entropy_threshold"` // separate threshold for subdomain labels (default 4.0, lower than query params)
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
	Action             string       `yaml:"action,omitempty"` // reserved — not yet implemented; rejected at validation
}

// DLPPattern is a named regex pattern for detecting secrets in URLs.
type DLPPattern struct {
	Name          string   `yaml:"name"`
	Regex         string   `yaml:"regex"`
	Severity      string   `yaml:"severity"`            // critical, high, medium, low
	Validator     string   `yaml:"validator,omitempty"` // post-match checksum: "luhn", "mod97", "aba"
	ExemptDomains []string `yaml:"exempt_domains"`      // domains where this pattern is not enforced
	Action        string   `yaml:"action,omitempty"`    // reserved — not yet implemented; rejected at validation
	Bundle        string   `yaml:"-"`                   // set by rules loader, not from YAML
	BundleVersion string   `yaml:"-"`                   // set by rules loader, not from YAML
	Compiled      bool     `yaml:"-"`                   // true for patterns from Defaults(), set by ApplyDefaults
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

// SeedPhraseDetection configures BIP-39 mnemonic seed phrase detection.
// Action is not configurable here — it follows the transport-level DLP action
// (URL scan: block, MCP/body/header: transport config).
type SeedPhraseDetection struct {
	Enabled        *bool `yaml:"enabled"`         // nil = true (security default)
	MinWords       int   `yaml:"min_words"`       // minimum consecutive BIP-39 words (default 12)
	VerifyChecksum *bool `yaml:"verify_checksum"` // nil = true (validate BIP-39 checksum)
}

// SSRF configures SSRF protection options beyond the default internal CIDRs.
type SSRF struct {
	// IPAllowlist exempts specific IP ranges from SSRF blocking. CIDRs listed
	// here are still considered "internal" but are explicitly trusted by the
	// operator. Complementary to trusted_domains: this is IP-based trust,
	// trusted_domains is hostname-based trust.
	IPAllowlist []string `yaml:"ip_allowlist"`
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
	Enabled              bool             `yaml:"enabled"`
	EscalationThreshold  float64          `yaml:"escalation_threshold"`    // points before escalation
	DecayPerCleanRequest float64          `yaml:"decay_per_clean_request"` // score reduction per clean request
	Levels               EscalationLevels `yaml:"levels"`
	ExemptDomains        []string         `yaml:"exempt_domains"` // DLP findings on these hosts skip escalation scoring and action upgrades
}

// EscalationLevels configures per-level enforcement behavior.
// Pointer fields distinguish "omitted (apply defaults)" from "explicitly softened".
type EscalationLevels struct {
	Elevated EscalationActions `yaml:"elevated"`
	High     EscalationActions `yaml:"high"`
	Critical EscalationActions `yaml:"critical"`
}

// EscalationActions defines enforcement upgrades for a single escalation level.
type EscalationActions struct {
	UpgradeWarn *string `yaml:"upgrade_warn"` // nil=default, "block"=upgrade, ""=no upgrade
	UpgradeAsk  *string `yaml:"upgrade_ask"`  // nil=default, "block"=upgrade, ""=no upgrade
	BlockAll    *bool   `yaml:"block_all"`    // nil=default, true=session deny, false=no
}

// MCPSessionBinding configures tool inventory validation per MCP connection.
// Captures tool names on first tools/list response and validates subsequent
// tools/call requests against that baseline.
type MCPSessionBinding struct {
	Enabled           bool   `yaml:"enabled"`
	UnknownToolAction string `yaml:"unknown_tool_action"` // warn, block
	NoBaselineAction  string `yaml:"no_baseline_action"`  // warn, block
}

// A2AScanning configures scanning of Google A2A (Agent-to-Agent) protocol
// traffic. Detects A2A messages in forward proxy and MCP HTTP proxy paths,
// applies field-aware scanning with URL/text/secret classification.
type A2AScanning struct {
	Enabled                   bool   `yaml:"enabled"`
	Action                    string `yaml:"action"`                      // block, warn
	ScanAgentCards            bool   `yaml:"scan_agent_cards"`            // Agent Card skill poisoning
	DetectCardDrift           bool   `yaml:"detect_card_drift"`           // rug-pull detection on Agent Cards
	SessionSmugglingDetection bool   `yaml:"session_smuggling_detection"` // contextId tracking
	MaxContextMessages        int    `yaml:"max_context_messages"`        // per-context message cap (default 100)
	MaxContexts               int    `yaml:"max_contexts"`                // total tracked contexts (default 1000)
	ScanRawParts              bool   `yaml:"scan_raw_parts"`              // decode text-like Part.raw
	MaxRawSize                int    `yaml:"max_raw_size"`                // encoded size cap for Part.raw decode (default 1MB)
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
	Enabled       bool     `yaml:"enabled"`
	BitsPerWindow float64  `yaml:"bits_per_window"` // total Shannon entropy bits before signaling
	WindowMinutes int      `yaml:"window_minutes"`  // sliding window duration
	Action        string   `yaml:"action"`          // warn, block (entropy alone is medium-confidence)
	ExemptDomains []string `yaml:"exempt_domains"`  // domains excluded from entropy budget (e.g. API polling endpoints with tokens in URLs)
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

// EmitConfig configures external event emission (webhook, syslog, and OTLP).
type EmitConfig struct {
	InstanceID string        `yaml:"instance_id"` // defaults to hostname
	Webhook    WebhookConfig `yaml:"webhook"`
	Syslog     SyslogConfig  `yaml:"syslog"`
	OTLP       OTLPConfig    `yaml:"otlp"`
}

// OTLPConfig configures the OpenTelemetry log export sink (HTTP/protobuf).
type OTLPConfig struct {
	Endpoint       string            `yaml:"endpoint"`        // base URL, /v1/logs appended
	Headers        map[string]string `yaml:"headers"`         // custom headers (auth, tenant)
	TimeoutSeconds int               `yaml:"timeout_seconds"` // per-request timeout (default 10)
	MinSeverity    string            `yaml:"min_severity"`    // info, warn, critical
	QueueSize      int               `yaml:"queue_size"`      // async buffer size (default 256)
	Gzip           bool              `yaml:"gzip"`            // compress requests
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
	Listeners        []string              `yaml:"listeners,omitempty"`
	SourceCIDRs      []string              `yaml:"source_cidrs,omitempty"`
	Mode             string                `yaml:"mode,omitempty"`
	Enforce          *bool                 `yaml:"enforce,omitempty"`
	APIAllowlist     []string              `yaml:"api_allowlist,omitempty"`
	DLP              *AgentDLP             `yaml:"dlp,omitempty"`
	RateLimit        *AgentRateLimit       `yaml:"rate_limit,omitempty"`
	SessionProfiling *AgentSessionProf     `yaml:"session_profiling,omitempty"`
	MCPToolPolicy    *MCPToolPolicy        `yaml:"mcp_tool_policy,omitempty"`
	Budget           BudgetConfig          `yaml:"budget,omitempty"`
	AllowedAddresses []string              `yaml:"allowed_addresses,omitempty"` // per-agent crypto address allowlist (enterprise, additive with global)
	Sandbox          *AgentSandboxOverride `yaml:"sandbox,omitempty"`           // per-agent sandbox overrides (Pro, gated by FeatureAgents)
	TrustedDomains   []string              `yaml:"trusted_domains,omitempty"`   // per-agent SSRF-exempt domains (replace, not merge)
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
	MaxRequestsPerSession      int                `yaml:"max_requests_per_session,omitempty"`
	MaxBytesPerSession         int                `yaml:"max_bytes_per_session,omitempty"`
	MaxUniqueDomainsPerSession int                `yaml:"max_unique_domains_per_session,omitempty"`
	WindowMinutes              int                `yaml:"window_minutes,omitempty"`
	MaxToolCallsPerSession     int                `yaml:"max_tool_calls_per_session,omitempty"`
	MaxConcurrentToolCalls     int                `yaml:"max_concurrent_tool_calls,omitempty"` // parallel in-flight limit (default 10)
	MaxWallClockMinutes        int                `yaml:"max_wall_clock_minutes,omitempty"`
	MaxRetriesPerTool          int                `yaml:"max_retries_per_tool,omitempty"`     // same tool+args (default 5)
	MaxRetriesPerEndpoint      int                `yaml:"max_retries_per_endpoint,omitempty"` // same domain+path (default 20)
	LoopDetectionWindow        int                `yaml:"loop_detection_window,omitempty"`    // tool calls to track (default 20)
	FanOutLimit                int                `yaml:"fan_out_limit,omitempty"`            // max unique endpoints in window (default 50)
	FanOutWindowSeconds        int                `yaml:"fan_out_window_seconds,omitempty"`   // window for fan-out detection (default 60)
	CostMultipliers            map[string]float64 `yaml:"cost_multipliers,omitempty"`         // optional domain -> cost weight
	DoWAction                  string             `yaml:"dow_action,omitempty"`               // "block" or "warn" (default "block")
}

// HasDoWFields returns true if any denial-of-wallet tracking field is set.
func (b *BudgetConfig) HasDoWFields() bool {
	return b.MaxToolCallsPerSession > 0 ||
		b.MaxConcurrentToolCalls > 0 ||
		b.MaxWallClockMinutes > 0 ||
		b.MaxRetriesPerTool > 0 ||
		b.MaxRetriesPerEndpoint > 0 ||
		b.LoopDetectionWindow > 0 ||
		b.FanOutLimit > 0
}

// ValidateDoW checks that dow_action is a recognized value.
func (b *BudgetConfig) ValidateDoW() error {
	switch b.DoWAction {
	case "", ActionBlock, ActionWarn:
		return nil
	default:
		return fmt.Errorf("invalid dow_action %q: must be block or warn", b.DoWAction)
	}
}

// FlightRecorder configures the tamper-evident evidence recording system.
type FlightRecorder struct {
	Enabled            bool   `yaml:"enabled"`
	Dir                string `yaml:"dir"`
	CheckpointInterval int    `yaml:"checkpoint_interval"`  // entries between signed checkpoints (default 1000)
	RetentionDays      int    `yaml:"retention_days"`       // auto-expire after N days (0=forever)
	Redact             bool   `yaml:"redact"`               // DLP on evidence before commit (default true)
	SignCheckpoints    bool   `yaml:"sign_checkpoints"`     // Ed25519 sign checkpoints (default true)
	MaxEntriesPerFile  int    `yaml:"max_entries_per_file"` // rotate files (default 10000)
	RawEscrow          bool   `yaml:"raw_escrow"`           // encrypted raw detail sidecar (default false)
	EscrowPublicKey    string `yaml:"escrow_public_key"`    // X25519 public key for raw escrow encryption
	SigningKeyPath     string `yaml:"signing_key_path"`     // Ed25519 private key for checkpoint signing and action receipts
}

// MCPBinaryIntegrity configures pre-spawn hash verification for MCP subprocesses.
type MCPBinaryIntegrity struct {
	Enabled      bool   `yaml:"enabled"`
	ManifestPath string `yaml:"manifest_path"` // path to hash manifest JSON
	Action       string `yaml:"action"`        // "block" or "warn" (default "warn")
}

// MCPToolProvenance configures cryptographic provenance verification for MCP tools.
type MCPToolProvenance struct {
	Enabled         bool     `yaml:"enabled"`
	Action          string   `yaml:"action"`           // "block" or "warn" for missing provenance (default "warn")
	Mode            string   `yaml:"mode"`             // "pipelock", "sigstore", "any" (default "pipelock")
	TrustedKeys     []string `yaml:"trusted_keys"`     // Ed25519 public keys (pipelock mode)
	TrustedIssuers  []string `yaml:"trusted_issuers"`  // OIDC issuers (sigstore mode)
	TrustedSubjects []string `yaml:"trusted_subjects"` // OIDC subjects (sigstore mode)
	OfflineOnly     bool     `yaml:"offline_only"`     // never call Sigstore APIs (default true)
}

// BehavioralBaseline configures the profile-then-lock behavioral analysis system.
type BehavioralBaseline struct {
	Enabled          bool     `yaml:"enabled"`
	LearningWindow   int      `yaml:"learning_window"`   // sessions to observe (default 10)
	DeviationAction  string   `yaml:"deviation_action"`  // "warn", "ask", "block" (default "warn")
	ProfileDir       string   `yaml:"profile_dir"`       // where to save/load profiles
	AutoRatify       bool     `yaml:"auto_ratify"`       // skip operator approval (default false, DANGEROUS)
	SensitivitySigma float64  `yaml:"sensitivity_sigma"` // stddev multiplier (default 2.0)
	LockDimensions   []string `yaml:"lock_dimensions"`   // metrics to enforce (default: all)
	PoisonResistance bool     `yaml:"poison_resistance"` // trim outlier sessions (default true)
	SeasonalityMode  string   `yaml:"seasonality_mode"`  // "none", "labeled", "time" (default "none")
}

// Airlock configures per-session quarantine with graduated tiers.
// Airlock restricts action classes (read vs write) rather than just upgrading
// scanner verdicts like adaptive enforcement does.
type Airlock struct {
	Enabled    bool              `yaml:"enabled"`
	Triggers   AirlockTriggers   `yaml:"triggers"`
	Timers     AirlockTimers     `yaml:"timers"`
	ToolFreeze AirlockToolFreeze `yaml:"tool_freeze"`
}

// AirlockTriggers configures automatic airlock activation from adaptive
// enforcement levels, scanner severity, or anomaly counts.
type AirlockTriggers struct {
	OnElevated           string `yaml:"on_elevated"`            // none|soft|hard|drain
	OnHigh               string `yaml:"on_high"`                // none|soft|hard|drain
	OnCritical           string `yaml:"on_critical"`            // none|soft|hard|drain
	OnSeverity           string `yaml:"on_severity"`            // scanner severity threshold ("critical", "high", or "")
	AnomalyCount         int    `yaml:"anomaly_count"`          // N anomalies in window triggers soft (0 = disabled)
	AnomalyWindowMinutes int    `yaml:"anomaly_window_minutes"` // rolling window for anomaly count
}

// AirlockTimers configures per-tier duration before automatic de-escalation.
type AirlockTimers struct {
	SoftMinutes         int `yaml:"soft_minutes"`
	HardMinutes         int `yaml:"hard_minutes"`
	DrainMinutes        int `yaml:"drain_minutes"`
	DrainTimeoutSeconds int `yaml:"drain_timeout_seconds"`
}

// AirlockToolFreeze configures MCP tool inventory freeze behavior in hard tier.
type AirlockToolFreeze struct {
	SnapshotOnEntry  bool `yaml:"snapshot_on_entry"`  // capture immutable tool set on hard entry
	AllowCachedTools bool `yaml:"allow_cached_tools"` // allow calls to tools in the frozen snapshot
}

// AirlockTier constants for state machine transitions.
const (
	AirlockTierNone  = "none"
	AirlockTierSoft  = "soft"
	AirlockTierHard  = "hard"
	AirlockTierDrain = "drain"
)

// BrowserShield configures inline HTML/JS rewriting for agent browser sessions.
// Strips fingerprinting, extension probing, telemetry beacons, and agent traps
// from response bodies flowing through the proxy.
type BrowserShield struct {
	Enabled                bool     `yaml:"enabled"`
	Strictness             string   `yaml:"strictness"`               // minimal|standard|aggressive
	MaxShieldBytes         int      `yaml:"max_shield_bytes"`         // size limit for shielding
	OversizeAction         string   `yaml:"oversize_action"`          // block|scan_head|warn
	ExemptDomains          []string `yaml:"exempt_domains"`           // hostnames only (validated, no paths)
	StripExtensionProbing  bool     `yaml:"strip_extension_probing"`  // strip chrome-extension:// + runtime shims
	StripHiddenTraps       bool     `yaml:"strip_hidden_traps"`       // strip hidden DOM elements with instructions
	StripTrackingPixels    bool     `yaml:"strip_tracking_pixels"`    // strip 1x1 images and beacon calls
	InjectFingerprintShims bool     `yaml:"inject_fingerprint_shims"` // canvas/WebGL/audio defense shims
	TrackingDomains        []string `yaml:"tracking_domains"`         // hostnames (validated same as exempt)
}

// BrowserShield strictness constants.
const (
	ShieldStrictnessMinimal    = "minimal"
	ShieldStrictnessStandard   = "standard"
	ShieldStrictnessAggressive = "aggressive"
)

// BrowserShield oversize action constants.
const (
	ShieldOversizeBlock    = "block"
	ShieldOversizeScanHead = "scan_head"
	ShieldOversizeWarn     = "warn"
)

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
	// - PIPELOCK_LICENSE_KEY env var (containers, CI)
	// - license_file config field (file path, read at startup)
	// - license_key config field (inline YAML, lowest priority)
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

	// Resolve relative file_sentry.watch_paths against config file directory.
	// "." in the config means the project directory, not whatever CWD the
	// process happens to have (systemd sets CWD=/, containers vary).
	//
	// Relative paths with ".." traversal are rejected to prevent
	// unintentional escapes. Absolute paths are allowed as-is since the
	// user explicitly chose the target directory.
	for i, p := range cfg.FileSentry.WatchPaths {
		if !filepath.IsAbs(p) {
			resolved := filepath.Clean(filepath.Join(configDir, p))
			// Verify the resolved path is still under the config directory.
			// filepath.Rel returns a ".." prefix if the target escapes.
			rel, err := filepath.Rel(configDir, resolved)
			if err != nil || strings.HasPrefix(rel, "..") {
				return nil, fmt.Errorf("file_sentry: watch_paths[%d] %q escapes config directory (use absolute path instead)", i, p)
			}
			cfg.FileSentry.WatchPaths[i] = resolved
		} else {
			cfg.FileSentry.WatchPaths[i] = filepath.Clean(cfg.FileSentry.WatchPaths[i])
		}
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
	// Env var takes highest priority. Trim before checking so that a
	// whitespace-only value (e.g. trailing newline) falls through to
	// lower-priority sources instead of winning with an empty token.
	if envKey := strings.TrimSpace(os.Getenv(EnvLicenseKey)); envKey != "" {
		c.LicenseKey = envKey
		return nil
	}

	// File path: read token from the file.
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

	// Inline license_key from YAML stays as-is (already parsed).
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

	// A2A scanning: detection booleans default to true (full scanning when enabled).
	a2a, _ := raw["a2a_scanning"].(map[string]interface{})
	setBoolDefault(a2a, "scan_agent_cards", &cfg.A2AScanning.ScanAgentCards)
	setBoolDefault(a2a, "detect_card_drift", &cfg.A2AScanning.DetectCardDrift)
	setBoolDefault(a2a, "session_smuggling_detection", &cfg.A2AScanning.SessionSmugglingDetection)
	setBoolDefault(a2a, "scan_raw_parts", &cfg.A2AScanning.ScanRawParts)

	// Flight recorder: redact and sign default to true (fail-closed for forensics).
	fr, _ := raw["flight_recorder"].(map[string]interface{})
	setBoolDefault(fr, "redact", &cfg.FlightRecorder.Redact)
	setBoolDefault(fr, "sign_checkpoints", &cfg.FlightRecorder.SignCheckpoints)

	// MCP tool provenance: offline_only defaults to true (no network calls).
	prov, _ := raw["mcp_tool_provenance"].(map[string]interface{})
	setBoolDefault(prov, "offline_only", &cfg.MCPToolProvenance.OfflineOnly)

	// Behavioral baseline: poison_resistance defaults to true (trimmed-mean scoring).
	bb, _ := raw["behavioral_baseline"].(map[string]interface{})
	setBoolDefault(bb, "poison_resistance", &cfg.BehavioralBaseline.PoisonResistance)
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
	if c.FetchProxy.Monitoring.SubdomainEntropyThreshold <= 0 {
		c.FetchProxy.Monitoring.SubdomainEntropyThreshold = 4.0
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

		// Level defaults: only fill nil fields (explicit values including "" and false are operator intent).
		// Elevated: warn actions upgrade to block.
		if c.AdaptiveEnforcement.Levels.Elevated.UpgradeWarn == nil {
			c.AdaptiveEnforcement.Levels.Elevated.UpgradeWarn = ptrStr(ActionBlock)
		}
		// High: both warn and ask upgrade to block.
		if c.AdaptiveEnforcement.Levels.High.UpgradeWarn == nil {
			c.AdaptiveEnforcement.Levels.High.UpgradeWarn = ptrStr(ActionBlock)
		}
		if c.AdaptiveEnforcement.Levels.High.UpgradeAsk == nil {
			c.AdaptiveEnforcement.Levels.High.UpgradeAsk = ptrStr(ActionBlock)
		}
		// Critical: all upgrades to block + session deny.
		if c.AdaptiveEnforcement.Levels.Critical.UpgradeWarn == nil {
			c.AdaptiveEnforcement.Levels.Critical.UpgradeWarn = ptrStr(ActionBlock)
		}
		if c.AdaptiveEnforcement.Levels.Critical.UpgradeAsk == nil {
			c.AdaptiveEnforcement.Levels.Critical.UpgradeAsk = ptrStr(ActionBlock)
		}
		if c.AdaptiveEnforcement.Levels.Critical.BlockAll == nil {
			c.AdaptiveEnforcement.Levels.Critical.BlockAll = ptrBool(true)
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
	if c.Emit.OTLP.MinSeverity == "" {
		c.Emit.OTLP.MinSeverity = SeverityWarn
	}
	if c.Emit.OTLP.TimeoutSeconds <= 0 {
		c.Emit.OTLP.TimeoutSeconds = 10
	}
	if c.Emit.OTLP.QueueSize <= 0 {
		c.Emit.OTLP.QueueSize = 256
	}
	if c.Emit.Syslog.Facility == "" {
		c.Emit.Syslog.Facility = "local0"
	}
	if c.Emit.Syslog.Tag == "" {
		c.Emit.Syslog.Tag = DefaultSyslogTag
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

	// Community rules defaults
	if c.Rules.MinConfidence == "" {
		c.Rules.MinConfidence = ConfidenceMedium
	}

	// File sentry defaults
	if c.FileSentry.ScanContent == nil {
		c.FileSentry.ScanContent = ptrBool(true)
	}

	// A2A scanning defaults
	if c.A2AScanning.Enabled {
		if c.A2AScanning.Action == "" {
			c.A2AScanning.Action = ActionWarn
		}
		if c.A2AScanning.MaxContextMessages <= 0 {
			c.A2AScanning.MaxContextMessages = 100
		}
		if c.A2AScanning.MaxContexts <= 0 {
			c.A2AScanning.MaxContexts = 1000
		}
		if c.A2AScanning.MaxRawSize <= 0 {
			c.A2AScanning.MaxRawSize = 1 << 20 // 1MB encoded
		}
	}

	// MCP binary integrity defaults
	if c.MCPBinaryIntegrity.Enabled {
		if c.MCPBinaryIntegrity.Action == "" {
			c.MCPBinaryIntegrity.Action = ActionWarn
		}
	}

	// Flight recorder defaults — applied when section is present.
	// Redact and SignCheckpoints default to true via applySecurityDefaults.
	if c.FlightRecorder.CheckpointInterval <= 0 {
		c.FlightRecorder.CheckpointInterval = 1000 // entries between signed checkpoints
	}
	if c.FlightRecorder.MaxEntriesPerFile <= 0 {
		c.FlightRecorder.MaxEntriesPerFile = 10000 // rotate files at this count
	}

	// MCP tool provenance defaults
	if c.MCPToolProvenance.Enabled {
		if c.MCPToolProvenance.Action == "" {
			c.MCPToolProvenance.Action = ActionWarn
		}
		if c.MCPToolProvenance.Mode == "" {
			c.MCPToolProvenance.Mode = ProvenanceModePipelock
		}
	}
	// OfflineOnly defaults to true via applySecurityDefaults.

	// Behavioral baseline defaults
	if c.BehavioralBaseline.Enabled {
		if c.BehavioralBaseline.DeviationAction == "" {
			c.BehavioralBaseline.DeviationAction = ActionWarn
		}
		if c.BehavioralBaseline.LearningWindow <= 0 {
			c.BehavioralBaseline.LearningWindow = 10 // sessions to observe before enforcement
		}
		if c.BehavioralBaseline.SensitivitySigma <= 0 {
			c.BehavioralBaseline.SensitivitySigma = 2.0 // stddev multiplier for deviation threshold
		}
		if c.BehavioralBaseline.SeasonalityMode == "" {
			c.BehavioralBaseline.SeasonalityMode = SeasonalityModeNone
		}
	}
	// PoisonResistance defaults to true via applySecurityDefaults.
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

// ValidateTrustedDomains validates and normalizes a slice of trusted domain
// entries. Each entry is lowercased, trimmed, and checked for: empty values,
// URL/host:port formats, bare wildcards, over-broad wildcards (e.g. *.com),
// non-prefix wildcards, and trailing dots. The slice is modified in-place
// with normalized values. The label parameter identifies the config section
// for error messages (e.g. "trusted_domains" or "agent \"foo\" trusted_domains").
func ValidateTrustedDomains(domains []string, label string) error {
	for i, raw := range domains {
		// Normalize early: lowercase, trim whitespace and trailing DNS dot.
		// Trailing dot must be stripped before breadth check so *.com. doesn't
		// pass as having a subdomain level.
		d := strings.TrimSuffix(strings.TrimSpace(strings.ToLower(raw)), ".")
		if d == "" {
			return fmt.Errorf("%s[%d] is empty", label, i)
		}
		if strings.Contains(d, "://") || strings.Contains(d, "/") || strings.Contains(d, ":") {
			return fmt.Errorf("%s[%d] %q: use a hostname pattern, not a URL or host:port", label, i, raw)
		}
		if d == "*" {
			return fmt.Errorf("%s[%d]: bare wildcard disables all SSRF protection", label, i)
		}
		if strings.HasPrefix(d, "*.") {
			// Wildcard must target a concrete domain (*.com is too broad).
			if strings.Count(d[2:], ".") < 1 {
				return fmt.Errorf("%s[%d] %q: wildcard must target a concrete domain like *.example.com", label, i, raw)
			}
		} else if strings.ContainsAny(d, "*?[]") {
			return fmt.Errorf("%s[%d] %q: only exact hosts and *.example.com wildcards are supported", label, i, raw)
		}
		domains[i] = d
	}
	return nil
}

// Validate checks the config for errors. Must be called after ApplyDefaults.
func (c *Config) Validate() error {
	validators := []func() error{
		c.validateMode,
		c.validateLogging,
		c.validateDLP,
		c.validateFetchProxy,
		c.validateResponseScanning,
		c.validateMCPInputScanning,
		c.validateMCPToolScanning,
		c.validateMCPToolPolicy,
		c.validateGitProtection,
		c.validateForwardProxy,
		c.validateWebSocketProxy,
		c.validateSessionProfiling,
		c.validateAdaptiveEnforcement,
		c.validateMCPSessionBinding,
		c.validateA2AScanning,
		c.validateRequestBodyScanning,
		c.validateSeedPhraseDetection,
		c.validateCrossRequestDetection,
		c.validateTLSInterception,
		c.validateToolChainDetection,
		c.validateMCPWSListener,
		c.validateSuppress,
		c.validateKillSwitch,
		c.validateMetricsListen,
		c.validateEmit,
		c.validateAddressProtection,
		c.validateSentry,
		c.validateInternalCIDRs,
		c.validateSSRF,
		c.validateTrustedDomains,
		c.validateRules,
		c.validateFileSentry,
		c.validateAgents,
		c.validateScanAPI,
		c.validateListenWarnings,
		c.validateReverseProxy,
		c.validateSandbox,
		c.validateFlightRecorder,
		c.validateMCPBinaryIntegrity,
		c.validateMCPToolProvenance,
		c.validateBehavioralBaseline,
		c.validateAirlock,
		c.validateBrowserShield,
	}
	for _, v := range validators {
		if err := v(); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) validateMode() error {
	switch c.Mode {
	case ModeStrict, ModeBalanced, ModeAudit:
		// valid
	default:
		return fmt.Errorf("invalid mode %q: must be strict, balanced, or audit", c.Mode)
	}

	if c.Mode == ModeStrict && len(c.APIAllowlist) == 0 {
		return fmt.Errorf("strict mode requires at least one domain in api_allowlist")
	}
	return nil
}

func (c *Config) validateLogging() error {
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
	return nil
}

func (c *Config) validateDLP() error {
	// Reject unsupported DLP action fields. Request-side DLP redaction (strip)
	// is not implemented — DLP matches follow the transport-level action
	// (request_body_scanning.action, mcp_input_scanning.action, or enforce mode).
	// These fields exist on the struct so YAML doesn't silently drop them;
	// validation rejects non-empty values with an explicit error.
	if c.DLP.Action != "" {
		return fmt.Errorf("dlp.action %q is not supported; DLP match behavior depends on the calling surface (e.g. request_body_scanning.action for bodies, mcp_input_scanning.action for MCP, enforce/audit mode for URL scanning)", c.DLP.Action)
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
		if p.Action != "" {
			return fmt.Errorf("DLP pattern %q has action %q which is not supported; per-pattern DLP actions are not yet implemented", p.Name, p.Action)
		}
		if p.Validator != "" {
			valid := p.Validator == ValidatorLuhn || p.Validator == ValidatorMod97 || p.Validator == ValidatorABA || p.Validator == ValidatorWIF
			if !valid {
				return fmt.Errorf("DLP pattern %q has unknown validator %q (valid: %s, %s, %s, %s)",
					p.Name, p.Validator, ValidatorLuhn, ValidatorMod97, ValidatorABA, ValidatorWIF)
			}
		}
		if err := ValidateTrustedDomains(p.ExemptDomains, fmt.Sprintf("DLP pattern %q exempt_domains", p.Name)); err != nil {
			return err
		}
	}

	if err := validateCanaryTokens(c); err != nil {
		return fmt.Errorf("canary_tokens: %w", err)
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
	return nil
}

func (c *Config) validateFetchProxy() error {
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
	return nil
}

func (c *Config) validateResponseScanning() error {
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

	// Validate exempt_domains regardless of whether response scanning is enabled.
	// Prevents dormant bad config from activating silently on reload.
	if err := ValidateTrustedDomains(c.ResponseScanning.ExemptDomains, "response_scanning.exempt_domains"); err != nil {
		return err
	}
	if !c.ResponseScanning.Enabled && len(c.ResponseScanning.ExemptDomains) > 0 {
		_, _ = fmt.Fprintf(os.Stderr, "WARNING: response_scanning.exempt_domains configured but response_scanning is disabled — these will take effect when enabled\n")
	}
	return nil
}

func (c *Config) validateMCPInputScanning() error {
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
	return nil
}

func (c *Config) validateMCPToolScanning() error {
	// Validate MCP tool scanning config
	if c.MCPToolScanning.Enabled {
		switch c.MCPToolScanning.Action {
		case ActionWarn, ActionBlock:
			// valid
		default:
			return fmt.Errorf("invalid mcp_tool_scanning action %q: must be warn or block", c.MCPToolScanning.Action)
		}
	}
	return nil
}

func (c *Config) validateMCPToolPolicy() error {
	// Validate MCP tool policy config
	if !c.MCPToolPolicy.Enabled {
		return nil
	}
	if len(c.MCPToolPolicy.Rules) == 0 {
		return fmt.Errorf("mcp_tool_policy is enabled but has no rules; add rules or set enabled: false")
	}
	switch c.MCPToolPolicy.Action {
	case ActionWarn, ActionBlock, ActionRedirect:
		// valid
	default:
		return fmt.Errorf("invalid mcp_tool_policy action %q: must be warn, block, or redirect", c.MCPToolPolicy.Action)
	}
	// Validate redirect profiles.
	for name, profile := range c.MCPToolPolicy.RedirectProfiles {
		if len(profile.Exec) == 0 || profile.Exec[0] == "" {
			return fmt.Errorf("mcp_tool_policy redirect_profile %q has empty exec", name)
		}
		if profile.MatchAbsPath && !filepath.IsAbs(profile.Exec[0]) {
			return fmt.Errorf("mcp_tool_policy redirect_profile %q: match_abs_path is true but exec[0] %q is not absolute", name, profile.Exec[0])
		}
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
		if r.ArgKey != "" {
			if r.ArgPattern == "" {
				return fmt.Errorf("mcp_tool_policy rule %q has arg_key without arg_pattern", r.Name)
			}
			if _, err := regexp.Compile(r.ArgKey); err != nil {
				return fmt.Errorf("mcp_tool_policy rule %q has invalid arg_key: %w", r.Name, err)
			}
		}
		if r.Action != "" {
			switch r.Action {
			case ActionWarn, ActionBlock, ActionRedirect:
				// valid
			default:
				return fmt.Errorf("mcp_tool_policy rule %q has invalid action %q: must be warn, block, or redirect", r.Name, r.Action)
			}
		}
		// Redirect rules must reference an existing redirect profile.
		effectiveAction := r.Action
		if effectiveAction == "" {
			effectiveAction = c.MCPToolPolicy.Action
		}
		if effectiveAction == ActionRedirect {
			if r.RedirectProfile == "" {
				return fmt.Errorf("mcp_tool_policy rule %q has action=redirect but no redirect_profile", r.Name)
			}
			if _, ok := c.MCPToolPolicy.RedirectProfiles[r.RedirectProfile]; !ok {
				return fmt.Errorf("mcp_tool_policy rule %q references unknown redirect_profile %q", r.Name, r.RedirectProfile)
			}
		}
	}
	return nil
}

func (c *Config) validateGitProtection() error {
	// Validate git protection config
	if !c.GitProtection.Enabled {
		return nil
	}
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
	return nil
}

func (c *Config) validateForwardProxy() error {
	// Validate forward proxy config
	if !c.ForwardProxy.Enabled {
		return nil
	}
	if c.ForwardProxy.MaxTunnelSeconds <= 0 {
		return fmt.Errorf("forward_proxy.max_tunnel_seconds must be positive")
	}
	if c.ForwardProxy.IdleTimeoutSeconds <= 0 {
		return fmt.Errorf("forward_proxy.idle_timeout_seconds must be positive")
	}
	return nil
}

func (c *Config) validateWebSocketProxy() error {
	// Validate WebSocket proxy config
	if !c.WebSocketProxy.Enabled {
		return nil
	}
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
	case OriginPolicyRewrite, OriginPolicyForward, ActionStrip:
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
	return nil
}

func (c *Config) validateSessionProfiling() error {
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
	return nil
}

func (c *Config) validateAdaptiveEnforcement() error {
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
		// Validate escalation level actions.
		if err := validateEscalationActions("elevated", &c.AdaptiveEnforcement.Levels.Elevated); err != nil {
			return err
		}
		if err := validateEscalationActions("high", &c.AdaptiveEnforcement.Levels.High); err != nil {
			return err
		}
		if err := validateEscalationActions("critical", &c.AdaptiveEnforcement.Levels.Critical); err != nil {
			return err
		}
		// Monotonic check: higher levels must not be weaker than lower levels.
		if err := validateEscalationMonotonic(&c.AdaptiveEnforcement.Levels); err != nil {
			return err
		}
	}

	// Validate adaptive enforcement exempt_domains regardless of enabled state.
	if err := ValidateTrustedDomains(c.AdaptiveEnforcement.ExemptDomains, "adaptive_enforcement.exempt_domains"); err != nil {
		return err
	}
	if !c.AdaptiveEnforcement.Enabled && len(c.AdaptiveEnforcement.ExemptDomains) > 0 {
		_, _ = fmt.Fprintf(os.Stderr, "WARNING: adaptive_enforcement.exempt_domains configured but adaptive_enforcement is disabled — these will take effect when enabled\n")
	}
	return nil
}

func (c *Config) validateMCPSessionBinding() error {
	// Validate MCP session binding config
	if !c.MCPSessionBinding.Enabled {
		return nil
	}
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
	return nil
}

func (c *Config) validateA2AScanning() error {
	// Validate A2A scanning config
	if !c.A2AScanning.Enabled {
		return nil
	}
	switch c.A2AScanning.Action {
	case ActionWarn, ActionBlock:
		// valid
	default:
		return fmt.Errorf("invalid a2a_scanning action %q: must be warn or block", c.A2AScanning.Action)
	}
	if c.A2AScanning.MaxContextMessages <= 0 {
		c.A2AScanning.MaxContextMessages = 100
	}
	if c.A2AScanning.MaxContexts <= 0 {
		c.A2AScanning.MaxContexts = 1000
	}
	if c.A2AScanning.MaxRawSize <= 0 {
		c.A2AScanning.MaxRawSize = 1 << 20
	}
	return nil
}

func (c *Config) validateRequestBodyScanning() error {
	// Validate request body scanning config
	if !c.RequestBodyScanning.Enabled {
		return nil
	}
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
	return nil
}

func (c *Config) validateSeedPhraseDetection() error {
	// Validate seed phrase detection config
	if c.SeedPhraseDetection.Enabled == nil || *c.SeedPhraseDetection.Enabled {
		if c.SeedPhraseDetection.MinWords == 0 {
			c.SeedPhraseDetection.MinWords = 12
		}
		validMinWords := map[int]bool{12: true, 15: true, 18: true, 21: true, 24: true}
		if !validMinWords[c.SeedPhraseDetection.MinWords] {
			return fmt.Errorf("invalid seed_phrase_detection.min_words %d: must be 12, 15, 18, 21, or 24", c.SeedPhraseDetection.MinWords)
		}
	}
	return nil
}

func (c *Config) validateCrossRequestDetection() error {
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

	// Validate CEE entropy budget exempt_domains regardless of enabled state.
	if err := ValidateTrustedDomains(c.CrossRequestDetection.EntropyBudget.ExemptDomains, "cross_request_detection.entropy_budget.exempt_domains"); err != nil {
		return err
	}
	if !c.CrossRequestDetection.Enabled && len(c.CrossRequestDetection.EntropyBudget.ExemptDomains) > 0 {
		_, _ = fmt.Fprintf(os.Stderr, "WARNING: cross_request_detection.entropy_budget.exempt_domains configured but cross_request_detection is disabled — these will take effect when enabled\n")
	}
	return nil
}

func (c *Config) validateTLSInterception() error {
	// Validate TLS interception config
	if !c.TLSInterception.Enabled {
		return nil
	}
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
	return nil
}

func (c *Config) validateToolChainDetection() error {
	// Validate tool chain detection config
	if !c.ToolChainDetection.Enabled {
		return nil
	}
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
	return nil
}

func (c *Config) validateMCPWSListener() error {
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
	return nil
}

func (c *Config) validateSuppress() error {
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
	return nil
}

func (c *Config) validateKillSwitch() error {
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
	return nil
}

func (c *Config) validateMetricsListen() error {
	// Validate metrics listen address (if set)
	if c.MetricsListen == "" {
		return nil
	}
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
	return nil
}

func (c *Config) validateEmit() error {
	// Validate emit config
	if c.Emit.Webhook.URL != "" {
		u, urlErr := url.Parse(c.Emit.Webhook.URL)
		if urlErr != nil || (u.Scheme != schemeHTTP && u.Scheme != schemeHTTPS) || u.Host == "" {
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

	// Validate OTLP config
	if c.Emit.OTLP.Endpoint != "" {
		u, otlpErr := url.Parse(c.Emit.OTLP.Endpoint)
		if otlpErr != nil || (u.Scheme != schemeHTTP && u.Scheme != schemeHTTPS) || u.Host == "" {
			return fmt.Errorf("invalid emit.otlp.endpoint %q: must be http:// or https:// with a host", c.Emit.OTLP.Endpoint)
		}
		switch c.Emit.OTLP.MinSeverity {
		case SeverityInfo, SeverityWarn, SeverityCritical:
			// valid
		default:
			return fmt.Errorf("invalid emit.otlp.min_severity %q: must be info, warn, or critical", c.Emit.OTLP.MinSeverity)
		}
		if c.Emit.OTLP.TimeoutSeconds <= 0 {
			return fmt.Errorf("emit.otlp.timeout_seconds must be positive")
		}
		if c.Emit.OTLP.QueueSize <= 0 {
			return fmt.Errorf("emit.otlp.queue_size must be positive")
		}
	}
	return nil
}

func (c *Config) validateAddressProtection() error {
	// Validate address protection config
	if !c.AddressProtection.Enabled {
		return nil
	}
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
	return nil
}

func (c *Config) validateSentry() error {
	// Validate Sentry config
	sr := c.Sentry.EffectiveSampleRate()
	if math.IsNaN(sr) {
		return fmt.Errorf("invalid sentry.sample_rate: NaN not allowed")
	}
	if sr < 0 || sr > 1 {
		return fmt.Errorf("invalid sentry.sample_rate %f: must be between 0.0 and 1.0", sr)
	}
	return nil
}

func (c *Config) validateInternalCIDRs() error {
	// Validate internal CIDRs are parseable
	for _, cidr := range c.Internal {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("invalid internal CIDR %q: %w", cidr, err)
		}
	}
	return nil
}

func (c *Config) validateTrustedDomains() error {
	// Validate trusted_domains entries.
	return ValidateTrustedDomains(c.TrustedDomains, "trusted_domains")
}

func (c *Config) validateSSRF() error {
	for _, cidr := range c.SSRF.IPAllowlist {
		ip, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("invalid ssrf.ip_allowlist CIDR %q: %w", cidr, err)
		}
		// Reject catch-all prefixes (/0) — they disable SSRF protection entirely.
		ones, _ := ipNet.Mask.Size()
		if ones == 0 {
			return fmt.Errorf("ssrf.ip_allowlist CIDR %q is a catch-all (/0) and would disable SSRF protection", cidr)
		}
		// Reject non-canonical CIDRs where host bits are set (e.g., 10.0.0.5/24
		// silently becomes 10.0.0.0/24). Operators must specify the network address
		// to avoid accidentally allowlisting a wider range than intended.
		if !ip.Equal(ipNet.IP) {
			return fmt.Errorf("ssrf.ip_allowlist CIDR %q has host bits set (did you mean %q?)", cidr, ipNet.String())
		}
	}
	return nil
}

func (c *Config) validateRules() error {
	// Validate community rules config
	switch c.Rules.MinConfidence {
	case ConfidenceHigh, ConfidenceMedium, ConfidenceLow:
		// valid
	default:
		return fmt.Errorf("rules: min_confidence %q must be high, medium, or low", c.Rules.MinConfidence)
	}
	for i, d := range c.Rules.Disabled {
		d = strings.TrimSpace(d)
		if d == "" {
			return fmt.Errorf("rules: disabled[%d] must be non-empty", i)
		}
		c.Rules.Disabled[i] = d
		if strings.Contains(d, ":") {
			// Namespaced ID like "community:rule-name" — validate structure.
			parts := strings.SplitN(d, ":", 2)
			if parts[0] == "" || parts[1] == "" {
				return fmt.Errorf("rules: disabled[%d] %q must be bundle:rule or a glob pattern", i, d)
			}
			continue
		}
		if strings.ContainsAny(d, "*?") {
			// Glob pattern like "community:*" or "test-*" — valid.
			continue
		}
		return fmt.Errorf("rules: disabled[%d] %q must contain ':' (namespaced) or be a glob pattern with * or ?", i, d)
	}
	for i, k := range c.Rules.TrustedKeys {
		if k.Name == "" {
			return fmt.Errorf("rules: trusted_keys[%d] name must be non-empty", i)
		}
		if len(k.PublicKey) != 64 {
			return fmt.Errorf("rules: trusted_keys[%d] %q public_key must be exactly 64 hex chars", i, k.Name)
		}
		if k.PublicKey != strings.ToLower(k.PublicKey) {
			return fmt.Errorf("rules: trusted_keys[%d] %q public_key must be lowercase hex", i, k.Name)
		}
		decoded, err := hex.DecodeString(k.PublicKey)
		if err != nil {
			return fmt.Errorf("rules: trusted_keys[%d] %q public_key invalid hex: %w", i, k.Name, err)
		}
		if len(decoded) != 32 {
			return fmt.Errorf("rules: trusted_keys[%d] %q public_key must decode to 32 bytes", i, k.Name)
		}
	}
	return nil
}

func (c *Config) validateFileSentry() error {
	// Validate file sentry config
	if !c.FileSentry.Enabled {
		return nil
	}
	if len(c.FileSentry.WatchPaths) == 0 {
		return fmt.Errorf("file_sentry: watch_paths must be non-empty when enabled")
	}
	for i, p := range c.FileSentry.WatchPaths {
		if p == "" {
			return fmt.Errorf("file_sentry: watch_paths[%d] must not be empty", i)
		}
	}
	return nil
}

func (c *Config) validateAgents() error {
	// Validate budget dow_action for all agent profiles (OSS + enterprise).
	for name, ap := range c.Agents {
		if err := ap.Budget.ValidateDoW(); err != nil {
			return fmt.Errorf("agents.%s.budget: %w", name, err)
		}
	}
	// Validate agent profiles (enterprise hook; nil in OSS).
	if ValidateAgentsFunc != nil {
		if err := ValidateAgentsFunc(c); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) validateScanAPI() error {
	// Validate scan API config
	if c.ScanAPI.Listen == "" {
		return nil
	}
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
	return nil
}

func (c *Config) validateListenWarnings() error {
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

func (c *Config) validateReverseProxy() error {
	// Reverse proxy: validate upstream URL when enabled.
	if !c.ReverseProxy.Enabled {
		return nil
	}
	if c.ReverseProxy.Upstream == "" {
		return fmt.Errorf("reverse_proxy.upstream is required when reverse_proxy is enabled")
	}
	u, uErr := url.Parse(c.ReverseProxy.Upstream)
	if uErr != nil || (u.Scheme != schemeHTTP && u.Scheme != schemeHTTPS) || u.Host == "" {
		return fmt.Errorf("reverse_proxy.upstream %q must be http:// or https:// with a host", c.ReverseProxy.Upstream)
	}
	if c.ReverseProxy.Listen == "" {
		return fmt.Errorf("reverse_proxy.listen is required when reverse_proxy is enabled")
	}
	return nil
}

func (c *Config) validateSandbox() error {
	// Sandbox: best_effort and strict are mutually exclusive.
	if c.Sandbox.BestEffort && c.Sandbox.Strict {
		return fmt.Errorf("sandbox: best_effort and strict are mutually exclusive")
	}

	// Sandbox: validate filesystem paths even when disabled (CLI can override enabled).
	if c.Sandbox.FS != nil {
		for _, p := range c.Sandbox.FS.AllowRead {
			if p == "" {
				return fmt.Errorf("sandbox filesystem allow_read contains empty path")
			}
		}
		for _, p := range c.Sandbox.FS.AllowWrite {
			if p == "" {
				return fmt.Errorf("sandbox filesystem allow_write contains empty path")
			}
		}
	}
	return nil
}

func (c *Config) validateFlightRecorder() error {
	if !c.FlightRecorder.Enabled {
		return nil
	}
	if c.FlightRecorder.Dir == "" {
		return fmt.Errorf("flight_recorder.dir is required when enabled")
	}
	if c.FlightRecorder.CheckpointInterval < 0 {
		return fmt.Errorf("flight_recorder.checkpoint_interval must be non-negative")
	}
	if c.FlightRecorder.RetentionDays < 0 {
		return fmt.Errorf("flight_recorder.retention_days must be non-negative")
	}
	if c.FlightRecorder.MaxEntriesPerFile < 0 {
		return fmt.Errorf("flight_recorder.max_entries_per_file must be non-negative")
	}
	if c.FlightRecorder.RawEscrow && c.FlightRecorder.EscrowPublicKey == "" {
		return fmt.Errorf("flight_recorder.escrow_public_key is required when raw_escrow is enabled")
	}
	return nil
}

func (c *Config) validateMCPBinaryIntegrity() error {
	if !c.MCPBinaryIntegrity.Enabled {
		return nil
	}
	if c.MCPBinaryIntegrity.ManifestPath == "" {
		return fmt.Errorf("mcp_binary_integrity.manifest_path is required when enabled")
	}
	switch c.MCPBinaryIntegrity.Action {
	case ActionWarn, ActionBlock:
		// valid
	default:
		return fmt.Errorf("invalid mcp_binary_integrity.action %q: must be warn or block", c.MCPBinaryIntegrity.Action)
	}
	return nil
}

func (c *Config) validateMCPToolProvenance() error {
	if !c.MCPToolProvenance.Enabled {
		return nil
	}
	switch c.MCPToolProvenance.Action {
	case ActionWarn, ActionBlock:
		// valid
	default:
		return fmt.Errorf("invalid mcp_tool_provenance.action %q: must be warn or block", c.MCPToolProvenance.Action)
	}
	switch c.MCPToolProvenance.Mode {
	case ProvenanceModePipelock, ProvenanceModeSigstore, ProvenanceModeAny:
		// valid
	default:
		return fmt.Errorf("invalid mcp_tool_provenance.mode %q: must be pipelock, sigstore, or any", c.MCPToolProvenance.Mode)
	}
	return nil
}

func (c *Config) validateBehavioralBaseline() error {
	if !c.BehavioralBaseline.Enabled {
		return nil
	}
	if c.BehavioralBaseline.ProfileDir == "" {
		return fmt.Errorf("behavioral_baseline.profile_dir is required when enabled")
	}
	switch c.BehavioralBaseline.DeviationAction {
	case ActionWarn, ActionAsk, ActionBlock:
		// valid
	default:
		return fmt.Errorf("invalid behavioral_baseline.deviation_action %q: must be warn, ask, or block", c.BehavioralBaseline.DeviationAction)
	}
	if c.BehavioralBaseline.LearningWindow < 0 {
		return fmt.Errorf("behavioral_baseline.learning_window must be non-negative")
	}
	if c.BehavioralBaseline.SensitivitySigma < 0 {
		return fmt.Errorf("behavioral_baseline.sensitivity_sigma must be non-negative")
	}
	switch c.BehavioralBaseline.SeasonalityMode {
	case "", SeasonalityModeNone, SeasonalityModeLabeled, SeasonalityModeTime:
		// valid (empty defaults to SeasonalityModeNone)
	default:
		return fmt.Errorf("invalid behavioral_baseline.seasonality_mode %q: must be none, labeled, or time", c.BehavioralBaseline.SeasonalityMode)
	}
	return nil
}

func (c *Config) validateAirlock() error {
	if !c.Airlock.Enabled {
		return nil
	}
	if !c.SessionProfiling.Enabled {
		return fmt.Errorf("airlock.enabled requires session_profiling.enabled")
	}

	validTiers := map[string]bool{
		AirlockTierNone: true, AirlockTierSoft: true,
		AirlockTierHard: true, AirlockTierDrain: true,
	}
	tierOrder := map[string]int{
		AirlockTierNone: 0, AirlockTierSoft: 1,
		AirlockTierHard: 2, AirlockTierDrain: 3,
	}

	// Normalize empty tier strings to AirlockTierNone so runtime code never
	// sees an empty string (which could bypass tier-based conditionals).
	if c.Airlock.Triggers.OnElevated == "" {
		c.Airlock.Triggers.OnElevated = AirlockTierNone
	}
	if c.Airlock.Triggers.OnHigh == "" {
		c.Airlock.Triggers.OnHigh = AirlockTierNone
	}
	if c.Airlock.Triggers.OnCritical == "" {
		c.Airlock.Triggers.OnCritical = AirlockTierNone
	}

	for _, pair := range []struct{ name, val string }{
		{"on_elevated", c.Airlock.Triggers.OnElevated},
		{"on_high", c.Airlock.Triggers.OnHigh},
		{"on_critical", c.Airlock.Triggers.OnCritical},
	} {
		if !validTiers[pair.val] {
			return fmt.Errorf("invalid airlock.triggers.%s %q: must be none, soft, hard, or drain", pair.name, pair.val)
		}
	}

	// Monotonicity: elevated <= high <= critical (tier severity must not decrease).
	elev := tierOrder[c.Airlock.Triggers.OnElevated]
	high := tierOrder[c.Airlock.Triggers.OnHigh]
	crit := tierOrder[c.Airlock.Triggers.OnCritical]
	if elev > high || high > crit {
		return fmt.Errorf("airlock.triggers must be monotonic: on_elevated (%s) <= on_high (%s) <= on_critical (%s)",
			c.Airlock.Triggers.OnElevated, c.Airlock.Triggers.OnHigh, c.Airlock.Triggers.OnCritical)
	}

	if c.Airlock.Triggers.OnSeverity != "" {
		switch c.Airlock.Triggers.OnSeverity {
		case SeverityCritical, SeverityHigh:
			// valid
		default:
			return fmt.Errorf("invalid airlock.triggers.on_severity %q: must be critical, high, or empty", c.Airlock.Triggers.OnSeverity)
		}
	}

	if c.Airlock.Timers.SoftMinutes < 0 || c.Airlock.Timers.HardMinutes < 0 || c.Airlock.Timers.DrainMinutes < 0 {
		return fmt.Errorf("airlock timer values must be non-negative")
	}

	// Drain timeout below the de-escalation sweep interval (30s) is effectively
	// the same as 30s. Warn but don't reject.
	if c.Airlock.Timers.DrainTimeoutSeconds < 0 {
		return fmt.Errorf("airlock.timers.drain_timeout_seconds must be non-negative")
	}

	if c.Airlock.Triggers.AnomalyCount < 0 {
		return fmt.Errorf("airlock.triggers.anomaly_count must be non-negative")
	}
	if c.Airlock.Triggers.AnomalyWindowMinutes < 0 {
		return fmt.Errorf("airlock.triggers.anomaly_window_minutes must be non-negative")
	}

	return nil
}

func (c *Config) validateBrowserShield() error {
	if !c.BrowserShield.Enabled {
		return nil
	}

	switch c.BrowserShield.Strictness {
	case ShieldStrictnessMinimal, ShieldStrictnessStandard, ShieldStrictnessAggressive:
		// valid
	default:
		return fmt.Errorf("invalid browser_shield.strictness %q: must be minimal, standard, or aggressive", c.BrowserShield.Strictness)
	}

	switch c.BrowserShield.OversizeAction {
	case ShieldOversizeBlock, ShieldOversizeScanHead, ShieldOversizeWarn:
		// valid
	default:
		return fmt.Errorf("invalid browser_shield.oversize_action %q: must be block, scan_head, or warn", c.BrowserShield.OversizeAction)
	}

	// warn is only appropriate for minimal strictness during rollout.
	if c.BrowserShield.OversizeAction == ShieldOversizeWarn && c.BrowserShield.Strictness != ShieldStrictnessMinimal {
		return fmt.Errorf("browser_shield.oversize_action \"warn\" is only allowed with strictness \"minimal\"")
	}

	if c.BrowserShield.MaxShieldBytes <= 0 {
		return fmt.Errorf("browser_shield.max_shield_bytes must be positive")
	}

	if err := ValidateTrustedDomains(c.BrowserShield.ExemptDomains, "browser_shield.exempt_domains"); err != nil {
		return err
	}
	if err := ValidateTrustedDomains(c.BrowserShield.TrackingDomains, "browser_shield.tracking_domains"); err != nil {
		return err
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

	// Response scanning exempt_domains: warn when the exemption surface may have
	// widened (new/changed entries) or was cleared entirely. Subset removal
	// (tightening) does not warn — it makes scanning stricter.
	if len(old.ResponseScanning.ExemptDomains) > 0 && len(updated.ResponseScanning.ExemptDomains) == 0 {
		warnings = append(warnings, ReloadWarning{
			Field:   "response_scanning.exempt_domains",
			Message: "response scanning exempt_domains cleared (was non-empty)",
		})
	} else if len(updated.ResponseScanning.ExemptDomains) > 0 {
		oldExempt := make(map[string]bool, len(old.ResponseScanning.ExemptDomains))
		for _, d := range old.ResponseScanning.ExemptDomains {
			oldExempt[d] = true
		}
		for _, d := range updated.ResponseScanning.ExemptDomains {
			if !oldExempt[d] {
				warnings = append(warnings, ReloadWarning{
					Field:   "response_scanning.exempt_domains",
					Message: fmt.Sprintf("response scanning exempt_domains changed: %q not in previous set", d),
				})
				break
			}
		}
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
	// Warn if escalation levels are weakened on reload.
	if old.AdaptiveEnforcement.Enabled && updated.AdaptiveEnforcement.Enabled {
		checkEscalationWeakening(&old.AdaptiveEnforcement.Levels, &updated.AdaptiveEnforcement.Levels, &warnings)
	}

	// MCP session binding disabled
	if old.MCPSessionBinding.Enabled && !updated.MCPSessionBinding.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "mcp_session_binding.enabled",
			Message: "MCP session binding disabled",
		})
	}

	// A2A scanning disabled or downgraded
	if old.A2AScanning.Enabled && !updated.A2AScanning.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "a2a_scanning.enabled",
			Message: "A2A scanning disabled",
		})
	}
	if old.A2AScanning.Action == ActionBlock && updated.A2AScanning.Action == ActionWarn {
		warnings = append(warnings, ReloadWarning{
			Field:   "a2a_scanning.action",
			Message: "A2A scanning action downgraded from block to warn",
		})
	}
	if old.A2AScanning.ScanAgentCards && !updated.A2AScanning.ScanAgentCards {
		warnings = append(warnings, ReloadWarning{
			Field:   "a2a_scanning.scan_agent_cards",
			Message: "A2A Agent Card scanning disabled",
		})
	}
	if old.A2AScanning.DetectCardDrift && !updated.A2AScanning.DetectCardDrift {
		warnings = append(warnings, ReloadWarning{
			Field:   "a2a_scanning.detect_card_drift",
			Message: "A2A Agent Card drift detection disabled",
		})
	}
	if old.A2AScanning.SessionSmugglingDetection && !updated.A2AScanning.SessionSmugglingDetection {
		warnings = append(warnings, ReloadWarning{
			Field:   "a2a_scanning.session_smuggling_detection",
			Message: "A2A session smuggling detection disabled",
		})
	}
	if old.A2AScanning.ScanRawParts && !updated.A2AScanning.ScanRawParts {
		warnings = append(warnings, ReloadWarning{
			Field:   "a2a_scanning.scan_raw_parts",
			Message: "A2A raw part scanning disabled — text-like attachments will not be scanned",
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

	// Trusted domains expanded (SSRF protection scope reduced)
	if added := passthroughDomainsAdded(old.TrustedDomains, updated.TrustedDomains); len(added) > 0 {
		warnings = append(warnings, ReloadWarning{
			Field:   "trusted_domains",
			Message: fmt.Sprintf("trusted domains added: %s — SSRF internal-IP check bypassed for these hosts", strings.Join(added, ", ")),
		})
	}
	// SSRF IP allowlist expanded (SSRF protection scope reduced).
	// CIDR-semantic comparison: a new entry expands coverage only if it is
	// not already contained within a previously-configured CIDR.
	if expanded := ssrfIPAllowlistExpanded(old.SSRF.IPAllowlist, updated.SSRF.IPAllowlist); len(expanded) > 0 {
		warnings = append(warnings, ReloadWarning{
			Field:   "ssrf.ip_allowlist",
			Message: fmt.Sprintf("SSRF IP allowlist expanded: %s — SSRF check bypassed for these IP ranges", strings.Join(expanded, ", ")),
		})
	}

	// TODO: emit reload warnings for agent-scoped trusted_domains (enterprise profiles).
	// Agent profiles live in the enterprise package, so diffing them here would require
	// either a hook or moving the diff logic into the enterprise reload path.

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

	// Seed phrase detection disabled
	if (old.SeedPhraseDetection.Enabled == nil || *old.SeedPhraseDetection.Enabled) &&
		updated.SeedPhraseDetection.Enabled != nil && !*updated.SeedPhraseDetection.Enabled {
		warnings = append(warnings, ReloadWarning{
			Field:   "seed_phrase_detection.enabled",
			Message: "seed phrase detection disabled",
		})
	}
	// Seed phrase checksum verification disabled
	if (old.SeedPhraseDetection.VerifyChecksum == nil || *old.SeedPhraseDetection.VerifyChecksum) &&
		updated.SeedPhraseDetection.VerifyChecksum != nil && !*updated.SeedPhraseDetection.VerifyChecksum {
		warnings = append(warnings, ReloadWarning{
			Field:   "seed_phrase_detection.verify_checksum",
			Message: "seed phrase checksum verification disabled — increased false positive risk",
		})
	}
	// Seed phrase min_words decreased
	if old.SeedPhraseDetection.MinWords > 0 &&
		updated.SeedPhraseDetection.MinWords > 0 &&
		updated.SeedPhraseDetection.MinWords < old.SeedPhraseDetection.MinWords {
		warnings = append(warnings, ReloadWarning{
			Field:   "seed_phrase_detection.min_words",
			Message: fmt.Sprintf("seed phrase min_words decreased from %d to %d", old.SeedPhraseDetection.MinWords, updated.SeedPhraseDetection.MinWords),
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
	if old.Emit.OTLP.Endpoint != "" && updated.Emit.OTLP.Endpoint == "" {
		warnings = append(warnings, ReloadWarning{
			Field:   "emit.otlp.endpoint",
			Message: "OTLP log emission disabled",
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

	// File sentry config is startup-only (watches are armed once at init).
	// ALL fields are reload-immutable, not just enabled/best_effort.
	if fileSentryChanged(old, updated) {
		warnings = append(warnings, ReloadWarning{
			Field:   "file_sentry",
			Message: "file_sentry config changes require restart — ignored on reload",
		})
	}

	// Sandbox config is startup-only. Warn if any sandbox fields changed
	// so operators know the reload had no effect on the running sandbox.
	if sandboxChanged(old, updated) {
		warnings = append(warnings, ReloadWarning{
			Field:   "sandbox",
			Message: "sandbox config changes require restart — ignored on reload",
		})
	}

	return warnings
}

// sandboxChanged returns true if any sandbox-related config field differs.
// fileSentryChanged returns true if any file_sentry config field differs.
// File sentry is startup-only: watches are armed once at init and cannot
// be reconfigured on reload.
func fileSentryChanged(old, updated *Config) bool {
	if old.FileSentry.Enabled != updated.FileSentry.Enabled {
		return true
	}
	if old.FileSentry.BestEffort != updated.FileSentry.BestEffort {
		return true
	}
	if !slices.Equal(old.FileSentry.WatchPaths, updated.FileSentry.WatchPaths) {
		return true
	}
	if !boolPtrEqual(old.FileSentry.ScanContent, updated.FileSentry.ScanContent) {
		return true
	}
	if !slices.Equal(old.FileSentry.IgnorePatterns, updated.FileSentry.IgnorePatterns) {
		return true
	}
	return false
}

func sandboxChanged(old, updated *Config) bool {
	if old.Sandbox.Enabled != updated.Sandbox.Enabled {
		return true
	}
	if old.Sandbox.Strict != updated.Sandbox.Strict {
		return true
	}
	if old.Sandbox.BestEffort != updated.Sandbox.BestEffort {
		return true
	}
	if old.Sandbox.Workspace != updated.Sandbox.Workspace {
		return true
	}
	if sandboxFSChanged(old.Sandbox.FS, updated.Sandbox.FS) {
		return true
	}
	// Check per-agent sandbox overrides (bidirectional: added, removed, changed).
	for name, oldProfile := range old.Agents {
		newProfile, ok := updated.Agents[name]
		if !ok {
			// Agent removed — if it had sandbox overrides, that's a change.
			if oldProfile.Sandbox != nil {
				return true
			}
			continue
		}
		if agentSandboxChanged(oldProfile.Sandbox, newProfile.Sandbox) {
			return true
		}
	}
	// Check for newly added agents with sandbox overrides.
	for name, newProfile := range updated.Agents {
		if _, existed := old.Agents[name]; !existed && newProfile.Sandbox != nil {
			return true
		}
	}
	return false
}

// sandboxFSChanged compares two SandboxFilesystem structs by content.
func sandboxFSChanged(oldFS, newFS *SandboxFilesystem) bool {
	if (oldFS == nil) != (newFS == nil) {
		return true
	}
	if oldFS == nil {
		return false
	}
	if !stringSlicesEqual(oldFS.AllowRead, newFS.AllowRead) {
		return true
	}
	return !stringSlicesEqual(oldFS.AllowWrite, newFS.AllowWrite)
}

// agentSandboxChanged compares two AgentSandboxOverride pointers.
func agentSandboxChanged(old, updated *AgentSandboxOverride) bool {
	if (old == nil) != (updated == nil) {
		return true
	}
	if old == nil {
		return false
	}
	if !boolPtrEqual(old.Enabled, updated.Enabled) || !boolPtrEqual(old.Strict, updated.Strict) || !boolPtrEqual(old.BestEffort, updated.BestEffort) {
		return true
	}
	if old.Workspace != updated.Workspace {
		return true
	}
	return sandboxFSChanged(old.FS, updated.FS)
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func boolPtrEqual(a, b *bool) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if a == nil {
		return true
	}
	return *a == *b
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

// ssrfIPAllowlistExpanded returns CIDR strings from updated that expand coverage
// beyond what old already covered. A CIDR is considered expanding if its network
// address is not contained by any CIDR in the old list. Malformed entries that
// passed validation are included verbatim (fail-open for warnings, not security).
func ssrfIPAllowlistExpanded(old, updated []string) []string {
	oldNets := make([]*net.IPNet, 0, len(old))
	for _, cidr := range old {
		if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
			oldNets = append(oldNets, ipNet)
		}
	}

	var expanded []string
	for _, cidr := range updated {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			expanded = append(expanded, cidr) // malformed — warn anyway
			continue
		}
		covered := false
		for _, oldNet := range oldNets {
			if oldNet.Contains(ipNet.IP) {
				oOnes, oSize := oldNet.Mask.Size()
				nOnes, nSize := ipNet.Mask.Size()
				// Same address family and old mask is equal or broader.
				if oSize == nSize && oOnes <= nOnes {
					covered = true
					break
				}
			}
		}
		if !covered {
			expanded = append(expanded, cidr)
		}
	}
	return expanded
}

// upgradeActionStrength returns a numeric strength for upgrade_warn/upgrade_ask values.
// "block" (2) > "" (1) > nil-should-not-reach-here (0).
// Called after ApplyDefaults, so nil fields are already filled.
func upgradeActionStrength(v *string) int {
	if v == nil {
		return 0
	}
	if *v == ActionBlock {
		return 2 // strongest: upgrade to block
	}
	return 1 // "" means no upgrade (weaker)
}

// validateEscalationActions checks that upgrade_warn and upgrade_ask contain
// only valid values: nil (use default), "" (no upgrade), or "block".
func validateEscalationActions(level string, a *EscalationActions) error {
	if a.UpgradeWarn != nil && *a.UpgradeWarn != "" && *a.UpgradeWarn != ActionBlock {
		return fmt.Errorf("adaptive_enforcement.levels.%s.upgrade_warn must be \"block\" or \"\" (got %q)", level, *a.UpgradeWarn)
	}
	if a.UpgradeAsk != nil && *a.UpgradeAsk != "" && *a.UpgradeAsk != ActionBlock {
		return fmt.Errorf("adaptive_enforcement.levels.%s.upgrade_ask must be \"block\" or \"\" (got %q)", level, *a.UpgradeAsk)
	}
	return nil
}

// validateEscalationMonotonic verifies that higher escalation levels are not
// weaker than lower ones. Runs after ApplyDefaults, so nil fields are filled.
func validateEscalationMonotonic(levels *EscalationLevels) error {
	// Compare elevated vs high: high must be >= elevated on every dimension.
	// When the lower level has block_all=true it already denies all traffic,
	// so per-action upgrades at the higher level are irrelevant — skip the
	// strength comparison to avoid false monotonic violations.
	elevatedBlockAll := levels.Elevated.BlockAll != nil && *levels.Elevated.BlockAll
	if !elevatedBlockAll {
		if upgradeActionStrength(levels.High.UpgradeWarn) < upgradeActionStrength(levels.Elevated.UpgradeWarn) {
			return fmt.Errorf("adaptive_enforcement.levels: high.upgrade_warn is weaker than elevated.upgrade_warn (monotonic violation)")
		}
		if upgradeActionStrength(levels.High.UpgradeAsk) < upgradeActionStrength(levels.Elevated.UpgradeAsk) {
			return fmt.Errorf("adaptive_enforcement.levels: high.upgrade_ask is weaker than elevated.upgrade_ask (monotonic violation)")
		}
	}
	// block_all: if elevated has it, high must too.
	if elevatedBlockAll &&
		(levels.High.BlockAll == nil || !*levels.High.BlockAll) {
		return fmt.Errorf("adaptive_enforcement.levels: high.block_all is weaker than elevated.block_all (monotonic violation)")
	}

	// Compare high vs critical: critical must be >= high on every dimension.
	highBlockAll := levels.High.BlockAll != nil && *levels.High.BlockAll
	if !highBlockAll {
		if upgradeActionStrength(levels.Critical.UpgradeWarn) < upgradeActionStrength(levels.High.UpgradeWarn) {
			return fmt.Errorf("adaptive_enforcement.levels: critical.upgrade_warn is weaker than high.upgrade_warn (monotonic violation)")
		}
		if upgradeActionStrength(levels.Critical.UpgradeAsk) < upgradeActionStrength(levels.High.UpgradeAsk) {
			return fmt.Errorf("adaptive_enforcement.levels: critical.upgrade_ask is weaker than high.upgrade_ask (monotonic violation)")
		}
	}
	// block_all: if high has it, critical must too.
	if highBlockAll &&
		(levels.Critical.BlockAll == nil || !*levels.Critical.BlockAll) {
		return fmt.Errorf("adaptive_enforcement.levels: critical.block_all is weaker than high.block_all (monotonic violation)")
	}
	return nil
}

// checkEscalationWeakening compares effective (post-default) escalation levels
// and appends warnings for any enforcement that was reduced on reload.
func checkEscalationWeakening(old, updated *EscalationLevels, warnings *[]ReloadWarning) {
	type levelPair struct {
		name    string
		oldActs *EscalationActions
		newActs *EscalationActions
	}
	pairs := []levelPair{
		{"elevated", &old.Elevated, &updated.Elevated},
		{"high", &old.High, &updated.High},
		{"critical", &old.Critical, &updated.Critical},
	}
	for _, lp := range pairs {
		if upgradeActionStrength(lp.newActs.UpgradeWarn) < upgradeActionStrength(lp.oldActs.UpgradeWarn) {
			*warnings = append(*warnings, ReloadWarning{
				Field:   fmt.Sprintf("adaptive_enforcement.levels.%s.upgrade_warn", lp.name),
				Message: fmt.Sprintf("%s.upgrade_warn weakened", lp.name),
			})
		}
		if upgradeActionStrength(lp.newActs.UpgradeAsk) < upgradeActionStrength(lp.oldActs.UpgradeAsk) {
			*warnings = append(*warnings, ReloadWarning{
				Field:   fmt.Sprintf("adaptive_enforcement.levels.%s.upgrade_ask", lp.name),
				Message: fmt.Sprintf("%s.upgrade_ask weakened", lp.name),
			})
		}
		// block_all: true -> false is weakening.
		oldBlock := lp.oldActs.BlockAll != nil && *lp.oldActs.BlockAll
		newBlock := lp.newActs.BlockAll != nil && *lp.newActs.BlockAll
		if oldBlock && !newBlock {
			*warnings = append(*warnings, ReloadWarning{
				Field:   fmt.Sprintf("adaptive_enforcement.levels.%s.block_all", lp.name),
				Message: fmt.Sprintf("%s.block_all weakened", lp.name),
			})
		}
	}
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
				MaxURLLength:              2048,
				EntropyThreshold:          4.5,
				SubdomainEntropyThreshold: 4.0,
				MaxReqPerMinute:           60,
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
				// Stripe keys use underscores (sk_test_) or hyphens (sk-test-) depending on version.
				{Name: "Stripe Key", Regex: `[sr]k[-_](live|test)[-_][a-zA-Z0-9]{20,}`, Severity: "critical"},
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
				// AWS secret access keys: 40-char base64 near AWS context words.
				// Anchored to common config key names to reduce FPs on arbitrary base64.
				// Separator class handles YAML (: ), env (=), JSON (":"), and quoted formats.
				{Name: "AWS Secret Key", Regex: `(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|secret.?access.?key|SecretAccessKey)\s*["'=:\s]{1,5}\s*[A-Za-z0-9/+=]{40}`, Severity: "critical"},
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

				// Cryptocurrency private keys
				// Bitcoin WIF: base58check. Uncompressed (5 + 50 base58 = 51 chars) or
				// compressed (K/L + 51 base58 = 52 chars). Mainnet only; testnet deferred.
				{Name: "Bitcoin WIF Private Key", Regex: `(?:5[1-9A-HJ-NP-Za-km-z]{50}|[KL][1-9A-HJ-NP-Za-km-z]{51})`, Severity: "critical", Validator: ValidatorWIF},
				// Extended private keys (BIP-32/49/84): xprv/yprv/zprv (mainnet) + tprv (testnet).
				// 111 total chars, base58check encoded.
				{Name: "Extended Private Key", Regex: `[xyzt]prv[1-9A-HJ-NP-Za-km-z]{107,108}`, Severity: "critical"},
				// Ethereum/EVM private keys: 0x-prefixed 64-char hex (256-bit).
				// Requires 0x to avoid SHA-256 hash false positives. (?i) auto-prefix covers 0X.
				{Name: "Ethereum Private Key", Regex: `0x[0-9a-f]{64}\b`, Severity: "critical"},
				// Ethereum Address (0x + 40 hex) is available in preset configs
				// but NOT in defaults because DLP fires before address_protection
				// allowlists, causing unavoidable false positives for blockchain
				// agents. Operators who need ETH address DLP without address_protection
				// should add the pattern to their config or use a preset.

				// Identity / PII
				{Name: "Social Security Number", Regex: `\b\d{3}-\d{2}-\d{4}\b`, Severity: "low"},
				{Name: "Google OAuth Client ID", Regex: `[0-9]{6,}-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`, Severity: "medium"},

				// Generic credential patterns
				// \b protects underscore-compound names (next_token, csrf_token_id) since _ is \w.
				// Hyphen-compound names (show-password, x-token) are NOT protected since - is \W,
				// so \b still fires. Accepted tradeoff: such params are rare in agent traffic.
				// Case-insensitive matching is added automatically by scanner.New() via (?i) prefix.
				{Name: "Credential in URL", Regex: `\b(?:password|passwd|secret|token|apikey|api_key|api-key)\s*=\s*[^\s&]{4,}`, Severity: "high"},
				// Environment variable credential patterns: catches env var dumps
				// where the secret-bearing keyword is the terminal segment of an
				// UPPER_CASE name (e.g., AWS_SECRET_ACCESS_KEY=..., STRIPE_SECRET_KEY=...,
				// DB_PASSWORD=..., CLIENT_SECRET=..., MY_API_KEY=...).
				// The keyword must end the variable name so benign suffixes like
				// *_TOKEN_BUCKET, *_PASSWORD_POLICY, and *_ROTATION_DAYS do not match.
				// (?-i:) overrides the scanner's auto (?i) prefix for the variable
				// name prefix — env vars are UPPER_CASE by convention, URL params
				// are lower_case (next_token, csrf_token_id). This avoids FP on
				// URL params while catching env var dumps.
				// Min value length of 8 prevents FP on short config values.
				{Name: "Environment Variable Secret", Regex: `(?-i:[A-Z][A-Z0-9]*[_-](?:SECRET(?:[_-]ACCESS)?[_-]?KEY|SECRET|PASSWORD|PASSWD|TOKEN|API[_-]?KEY))\b\s*=\s*\S{8,}`, Severity: "high"},

				// Financial identifiers — validated with post-match checksums to minimize
				// false positives. Credit card regex is intentionally broad (any 15-19
				// digit number); issuer prefix + length validation is in validateLuhn
				// where it's maintainable Go code, not regex soup across 8 files.
				// Luhn + issuer check drops ~95% of random matches. mod-97 drops ~99%
				// of random IBAN-format matches. ABA is not in defaults due to high FP
				// rate; users can add it via config with validator: "aba".
				{Name: "Credit Card Number", Regex: `\b\d{4}(?:[- ]?\d){11,15}\b`, Severity: "medium", Validator: ValidatorLuhn},
				{Name: "IBAN", Regex: `\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b`, Severity: "medium", Validator: ValidatorMod97},
			},
		},
		CanaryTokens: CanaryTokens{
			Enabled: false,
		},
		MCPInputScanning: MCPInputScanning{
			Enabled:      false,
			OnParseError: ActionBlock,
		},
		MCPToolScanning: MCPToolScanning{
			Enabled: false,
		},
		MCPToolPolicy: MCPToolPolicy{
			Enabled:       false,
			QuarantineDir: filepath.Join(os.TempDir(), "pipelock-quarantine"),
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
				{Name: "Tool Invocation", Regex: `(?i)you\s+must\s+(\w+\s+)?(call|execute|run|invoke)\s+(the|this|a)\s+(\w+\s+)?(function|tool|command|api|endpoint)`},
				{Name: "Authority Escalation", Regex: `(?i)you\s+(now\s+)?have\s+(full\s+)?(admin|root|system|superuser|elevated)\s+(access|privileges|permissions|rights)`},
				{Name: "Instruction Downgrade", Regex: `(?i)(treat|consider|regard|reinterpret|downgrade)\s+((?:the|all)\s+)?(previous|prior|above|earlier|system|policy|original|existing)\s+(\w+\s+)?(text|instructions?|rules|directives|guidelines|safeguards|constraints|controls|checks|context|prompt|policies|guardrails|parameters)\s+((as|to)\s+)?(historical|outdated|deprecated|optional|background|secondary|non-binding|non-authoritative|informational|advisory)`},
				{Name: "Instruction Dismissal", Regex: `(?i)(set|put)\s+(the\s+)?(previous|prior|above|earlier|system|original)\s+(\w+\s+)?(instructions?|directives|rules|constraints|context|prompt|safeguards|guidelines|policies|guardrails)\s+(aside|away|to\s+(one|the)\s+side)`},
				{Name: "Priority Override", Regex: `(?i)\bprioritize\s+(the\s+)?(task|user|current|new|latest)\s+(request|message|input|instructions?|prompt)`},
				// State/control poisoning — detect credential solicitation,
				// memory persistence, and preference manipulation in tool results.
				{Name: "Credential Solicitation", Regex: `(?is)\b(send|provide|paste|return|include|supply|submit|share)\b.{0,80}\b(password|passwd|token|api[_ -]?key|secret|credential|private[_ -]?key|ssh[_ -]?key|session[_ -]?cookie)\b`},
				{Name: "Credential Path Directive", Regex: `(?is)\b(read|get|fetch|retrieve|cat|copy|extract|open)\b.{0,80}(\.ssh[/\\]|\.aws[/\\]credentials|\.env\b|\.npmrc\b|\.pypirc\b|\.netrc\b|\bid_rsa\b|\bid_ed25519\b|\bkubeconfig\b|/etc/passwd\b|/etc/shadow\b)`},
				{Name: "Auth Material Requirement", Regex: `(?is)\bto\s+(complete|continue|finish|proceed|verify)\b.{0,80}\b(authentication|credential|token|api[_ -]?key|private[_ -]?key|ssh[_ -]?key)\b.{0,40}\b(required|needed|necessary|must be)\b`},
				{Name: "Memory Persistence Directive", Regex: `(?is)\b(save|store|remember|retain|persist|record|cache)\b.{0,40}\b(this|these|that|it|the)\b.{0,60}\b(for future|for later|across sessions?|next session|next time|future tasks?|subsequent|permanently|from now on|going forward|in all future)\b`},
				{Name: "Preference Poisoning", Regex: `(?is)\b(from now on|always|going forward|in future)\b.{0,80}\b(prefer|prioritize|trust|choose|use|default to)\b.{0,60}\b(this tool|that tool|my tool|the external|the remote)\b`},
				{Name: "Silent Credential Handling", Regex: `(?is)\b(do not|don'?t|never)\s+(mention|display|show|tell|reveal|log|report)\b.{0,100}\b(password|token|secret|credential|private[_ -]?key|api[_ -]?key)\b`},
				// Covert action directives — instructions to perform actions
				// secretly, silently, or without the user's knowledge.
				{Name: "Covert Action Directive", Regex: `(?is)(secretly|silently|covertly|quietly|without\s+(?:the\s+user\s+)?(?:knowing|noticing|seeing))[,;:]?\s+.{0,40}\b(execut\w*|run|call|invoke|send|fetch|curl|wget|download|upload|post)\b`},
				// Model-specific instruction boundary tokens — ChatML, Llama, Mistral.
				// Presence in tool output is a strong injection signal.
				{Name: "Instruction Boundary", Regex: `(<\|(?:endoftext|im_start|im_end|system|end_header_id|begin_of_text)\|>|\[/?INST\]|<\|(?:user|assistant)\|>|<<SYS>>)`},
				// CJK injection patterns — Chinese, Japanese, Korean prompt
				// injection phrases sourced from published attack research,
				// jailbreak datasets, and security disclosures. Patterns use
				// .{0,N} ranges instead of \b because CJK has no word boundaries.
				{Name: "CJK Instruction Override ZH", Regex: `(忽略|无视|忽视|不理|不要遵[循守]|放弃|跳过).{0,10}(之前|以上|上述|以前|上面|先前|前面).{0,8}(所有|全部|一切)?.{0,6}(指令|指示|说明|规则|命令|提示|约束|限制)`},
				{Name: "CJK Instruction Override JP", Regex: `(以前|前|上記|これまで|今まで).{0,6}(指示|命令|ルール|規則|指令).{0,6}(すべて|全て|全部)?.{0,4}(無視|忘れ|従わな|捨て)`},
				{Name: "CJK Instruction Override KR", Regex: `(이전|위|앞|기존).{0,6}(모든\s*)?(지시|지침|명령|규칙|지령).{0,6}(무시|잊어|따르지|어기|무효)`},
				{Name: "CJK Jailbreak Mode", Regex: `(开发者模式|无限制模式|開発者モード|制限なしモード|개발자\s*모드|제한\s*없는\s*모드|没有任何?限制|制限.{0,4}(解除|無視)|제한.{0,4}(해제|무시))`},
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
		SeedPhraseDetection: SeedPhraseDetection{
			Enabled:        ptrBool(true),
			MinWords:       12,
			VerifyChecksum: ptrBool(true),
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
		Rules: Rules{
			MinConfidence: ConfidenceMedium,
		},
		A2AScanning: A2AScanning{
			Enabled:                   false,
			Action:                    ActionWarn,
			ScanAgentCards:            true,
			DetectCardDrift:           true,
			SessionSmugglingDetection: true,
			MaxContextMessages:        100,
			MaxContexts:               1000,
			ScanRawParts:              true,
			MaxRawSize:                1 << 20, // 1MB encoded
		},
		MCPBinaryIntegrity: MCPBinaryIntegrity{
			Action: ActionWarn, // default action when hash verification fails
		},
		FlightRecorder: FlightRecorder{
			CheckpointInterval: 1000,  // entries between signed checkpoints
			Redact:             true,  // DLP-scrub evidence before commit
			SignCheckpoints:    true,  // Ed25519 sign checkpoints
			MaxEntriesPerFile:  10000, // rotate files at this count
		},
		MCPToolProvenance: MCPToolProvenance{
			Action:      ActionWarn,
			Mode:        ProvenanceModePipelock,
			OfflineOnly: true, // no network calls for verification
		},
		BehavioralBaseline: BehavioralBaseline{
			LearningWindow:   10,
			DeviationAction:  ActionWarn,
			SensitivitySigma: 2.0,
			PoisonResistance: true, // trimmed-mean scoring resists adversarial training data
			SeasonalityMode:  SeasonalityModeNone,
		},
		Airlock: Airlock{
			Triggers: AirlockTriggers{
				OnElevated:           AirlockTierNone,
				OnHigh:               AirlockTierSoft,
				OnCritical:           AirlockTierHard,
				AnomalyWindowMinutes: 5,
			},
			Timers: AirlockTimers{
				SoftMinutes:         10,
				HardMinutes:         5,
				DrainMinutes:        2,
				DrainTimeoutSeconds: 30,
			},
			ToolFreeze: AirlockToolFreeze{
				SnapshotOnEntry:  true,
				AllowCachedTools: true,
			},
		},
		BrowserShield: BrowserShield{
			Strictness:            ShieldStrictnessStandard,
			MaxShieldBytes:        5 * 1024 * 1024, // 5MB
			OversizeAction:        ShieldOversizeBlock,
			StripExtensionProbing: true,
			StripHiddenTraps:      true,
			StripTrackingPixels:   true,
			ExemptDomains: []string{
				"challenges.cloudflare.com",
				"hcaptcha.com",
				"www.recaptcha.net",
			},
		},
	}
	// Mark all compiled defaults with provenance so the standard tier source
	// selector can distinguish them from user-supplied patterns. Set at
	// creation time (not during merge) so provenance survives any code path
	// that copies or reconstructs patterns.
	for i := range cfg.DLP.Patterns {
		cfg.DLP.Patterns[i].Compiled = true
	}
	for i := range cfg.ResponseScanning.Patterns {
		cfg.ResponseScanning.Patterns[i].Compiled = true
	}
	return cfg
}

func ptrBool(v bool) *bool { return &v }

func ptrStr(v string) *string { return &v }
