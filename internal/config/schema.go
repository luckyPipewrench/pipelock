// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package config handles loading, validating, and defaulting Pipelock configuration.
package config

import (
	"time"

	"github.com/luckyPipewrench/pipelock/internal/redact"
)

// Mode constants for Pipelock operating modes.
const (
	ModeStrict     = "strict"
	ModeBalanced   = "balanced"
	ModeAudit      = "audit"
	ModePermissive = "permissive"
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
	// ActionRedact replaces the matched value with a typed placeholder
	// (e.g. "<pl:ipv4:1>"). Irreversible: pipelock holds no mapping.
	// See the redaction-v1 design spec in ops for the semantic model.
	ActionRedact = "redact"
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
	Version                  int                     `yaml:"version"`
	Mode                     string                  `yaml:"mode"`           // strict, balanced, audit
	Enforce                  *bool                   `yaml:"enforce"`        // nil = true (default); false = detect & log without blocking
	ExplainBlocks            *bool                   `yaml:"explain_blocks"` // nil = false (default); true = include hints in block responses
	APIAllowlist             []string                `yaml:"api_allowlist"`
	Suppress                 []SuppressEntry         `yaml:"suppress"`
	FetchProxy               FetchProxy              `yaml:"fetch_proxy"`
	ForwardProxy             ForwardProxy            `yaml:"forward_proxy"`
	WebSocketProxy           WebSocketProxy          `yaml:"websocket_proxy"`
	DLP                      DLP                     `yaml:"dlp"`
	CanaryTokens             CanaryTokens            `yaml:"canary_tokens"`
	ResponseScanning         ResponseScanning        `yaml:"response_scanning"`
	MCPInputScanning         MCPInputScanning        `yaml:"mcp_input_scanning"`
	MCPToolScanning          MCPToolScanning         `yaml:"mcp_tool_scanning"`
	MCPToolPolicy            MCPToolPolicy           `yaml:"mcp_tool_policy"`
	GitProtection            GitProtection           `yaml:"git_protection"`
	Logging                  LoggingConfig           `yaml:"logging"`
	SessionProfiling         SessionProfiling        `yaml:"session_profiling"`
	AdaptiveEnforcement      AdaptiveEnforcement     `yaml:"adaptive_enforcement"`
	MCPSessionBinding        MCPSessionBinding       `yaml:"mcp_session_binding"`
	RequestBodyScanning      RequestBodyScanning     `yaml:"request_body_scanning"`
	KillSwitch               KillSwitch              `yaml:"kill_switch"`
	Sentry                   SentryConfig            `yaml:"sentry"`
	MetricsListen            string                  `yaml:"metrics_listen"` // separate listen address for /metrics and /stats
	Emit                     EmitConfig              `yaml:"emit"`
	ToolChainDetection       ToolChainDetection      `yaml:"tool_chain_detection"`
	MCPWSListener            MCPWSListener           `yaml:"mcp_ws_listener"`
	TLSInterception          TLSInterception         `yaml:"tls_interception"`
	CrossRequestDetection    CrossRequestDetection   `yaml:"cross_request_detection"`
	ReverseProxy             ReverseProxy            `yaml:"reverse_proxy"`
	ScanAPI                  ScanAPI                 `yaml:"scan_api"`
	AddressProtection        AddressProtection       `yaml:"address_protection"`
	SeedPhraseDetection      SeedPhraseDetection     `yaml:"seed_phrase_detection"`
	Rules                    Rules                   `yaml:"rules"`
	FileSentry               FileSentry              `yaml:"file_sentry"`
	Sandbox                  Sandbox                 `yaml:"sandbox"`
	FlightRecorder           FlightRecorder          `yaml:"flight_recorder"`
	MCPBinaryIntegrity       MCPBinaryIntegrity      `yaml:"mcp_binary_integrity"`
	MCPToolProvenance        MCPToolProvenance       `yaml:"mcp_tool_provenance"`
	BehavioralBaseline       BehavioralBaseline      `yaml:"behavioral_baseline"`
	Airlock                  Airlock                 `yaml:"airlock"`
	BrowserShield            BrowserShield           `yaml:"browser_shield"`
	MediaPolicy              MediaPolicy             `yaml:"media_policy"`
	A2AScanning              A2AScanning             `yaml:"a2a_scanning"`
	Taint                    TaintConfig             `yaml:"taint"`
	MediationEnvelope        MediationEnvelope       `yaml:"mediation_envelope"`
	Redaction                redact.Config           `yaml:"redaction"`
	Learn                    Learn                   `yaml:"learn"`
	Agents                   map[string]AgentProfile `yaml:"agents,omitempty"`
	DefaultAgentIdentity     string                  `yaml:"default_agent_identity,omitempty"`      // operator-configured agent name used when no stronger identity source resolves the caller
	BindDefaultAgentIdentity bool                    `yaml:"bind_default_agent_identity,omitempty"` // when true, ignore self-declared header/query identities and bind requests to default_agent_identity
	LicenseKey               string                  `yaml:"license_key,omitempty"`                 // signed license token (from pipelock license issue)
	LicenseFile              string                  `yaml:"license_file,omitempty"`                // path to file containing the license token (read at startup)
	LicensePublicKey         string                  `yaml:"license_public_key,omitempty"`          // hex-encoded Ed25519 public key for license verification (dev builds only)
	Internal                 []string                `yaml:"internal"`
	TrustedDomains           []string                `yaml:"trusted_domains"` // domains exempt from SSRF internal-IP check (wildcard supported)
	SSRF                     SSRF                    `yaml:"ssrf"`

	// LicenseExpiresAt is the Unix timestamp of the license expiry, populated
	// by EnforceLicenseGate(). Zero means perpetual. Used for runtime expiry
	// enforcement so agents are disabled even without a config reload.
	LicenseExpiresAt int64 `yaml:"-"`

	// rawBytes stores the original config file bytes for deterministic hashing.
	// Not serialized to YAML. Set by Load(), nil for Defaults().
	rawBytes []byte `yaml:"-"`

	// canonicalHashCache memoises CanonicalPolicyHash() so repeated calls
	// on the same *Config value do not re-walk and re-marshal the struct.
	// Unexported — json.Marshal skips it, yaml does not see it, and test
	// helpers that build fresh Config values always start with a nil
	// pointer (lazy-initialised on first hash read). The field is a
	// pointer rather than an embedded atomic.Value so that struct copies
	// (e.g., Config.Clone's `clone := *c`) duplicate the pointer only —
	// atomic.Value forbids copying after first use, and every caller that
	// wants a fresh cache explicitly reassigns the pointer. Config
	// instances are treated as immutable after Load(); any mutation after
	// a hash has been computed will return a stale value.
	canonicalHashCache *canonicalHashCacheHolder `yaml:"-"`
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
	SSEStreaming      GenericSSEScanning    `yaml:"sse_streaming"`  // generic text/event-stream inline scanning (LLM SSE)
}

// GenericSSEScanning configures inline body scanning of non-A2A
// text/event-stream responses (OpenAI chat completions, Anthropic
// messages, Kilo Gateway, generic LLM SSE). When disabled the proxy
// still streams events with per-read flushing so streaming UX is never
// silently downgraded to a buffered path.
type GenericSSEScanning struct {
	Enabled       bool   `yaml:"enabled"`
	Action        string `yaml:"action"`          // warn, block (mirrors a2a_scanning.action)
	MaxEventBytes int    `yaml:"max_event_bytes"` // per-event ceiling, default 65536
}

// ResponseScanPattern is a named regex pattern for detecting prompt injection in responses.
type ResponseScanPattern struct {
	Name          string `yaml:"name"`
	Regex         string `yaml:"regex"`
	Bundle        string `yaml:"-"` // set by rules loader, not from YAML
	BundleVersion string `yaml:"-"` // set by rules loader, not from YAML
	Compiled      bool   `yaml:"-"` // true for patterns created in Defaults()
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
	Compiled      bool     `yaml:"-"`                   // true for patterns created in Defaults()
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
	APIToken      string   `yaml:"api_token"`
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
	AuthToken   string `yaml:"auth_token"`
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

// MediationEnvelope configures sideband metadata on proxied requests.
// When enabled, pipelock injects a Pipelock-Mediation header (HTTP) or
// _meta["com.pipelock/mediation"] (MCP) carrying action type, verdict,
// actor identity, and receipt correlation ID. When Sign is also true,
// pipelock attaches an RFC 9421 HTTP Message Signature over a per-
// request component list, identified by the pipelock1 dictionary label
// so the pipelock signature coexists with any upstream sig1 / web-bot
// signature already on the request.
type MediationEnvelope struct {
	Enabled bool `yaml:"enabled"`

	// Sign enables RFC 9421 HTTP Message Signatures on outbound mediated
	// requests. HTTP only — MCP stdio cannot be signed in band.
	// Default false; explicit opt-in. When true, SigningKeyPath is
	// required and must load as an Ed25519 private key at startup and
	// on every hot reload. Reload failures abort the reload rather
	// than silently downgrading to unsigned.
	Sign bool `yaml:"sign"`

	// SigningKeyPath is the filesystem path to an Ed25519 private key
	// in the format accepted by signing.LoadPrivateKeyFile (the same
	// format used by receipt signing and flight recorder checkpoints).
	// The key is loaded fresh on every reload to support file rotation.
	// Capability separation: this path MUST live in pipelock's own
	// privilege domain; the agent must not have read access.
	SigningKeyPath string `yaml:"signing_key_path"`

	// KeyID is the opaque identifier emitted as the Signature-Input
	// keyid parameter. Verifiers use it to look up the corresponding
	// public key. Defaults to "pipelock-mediation-v1" when sign is
	// true and this field is empty.
	KeyID string `yaml:"key_id"`

	// SignedComponents declares the maximal RFC 9421 component list
	// that pipelock will sign. Supported values are "@method",
	// "@target-uri", "@authority", "content-digest", and
	// "pipelock-mediation". At request time the signer builds a
	// dynamic subset: content-digest is dropped on body-less requests,
	// and pipelock-mediation is skipped when the header is absent.
	// Defaults to ["@method", "@target-uri", "content-digest",
	// "pipelock-mediation"] when sign is true and this slice is empty.
	SignedComponents []string `yaml:"signed_components"`

	// CreatedSkewSeconds is the tolerance (in seconds) applied to the
	// created parameter on inbound verification. Not used on the
	// outbound signing path today but stored here so the config surface
	// is stable when inbound verify lands in a follow-up. Defaults to
	// 60 when sign is true and this field is zero.
	CreatedSkewSeconds int `yaml:"created_skew_seconds"`

	// MaxBodyBytes caps the amount of request body the signer will
	// buffer to compute Content-Digest when no upstream scanner has
	// already buffered it. Defaults to 1 MiB when sign is true and
	// this field is zero. Requests exceeding the cap are signed
	// without content-digest (the component is dropped from the
	// declared list for that request) rather than failing.
	MaxBodyBytes int `yaml:"max_body_bytes"`
}

// TaintConfig configures exposure-based policy escalation for sessions that
// recently observed untrusted content.
type TaintConfig struct {
	Enabled            bool                 `yaml:"enabled"`
	AllowlistedDomains []string             `yaml:"allowlisted_domains"`
	ProtectedPaths     []string             `yaml:"protected_paths"`
	ElevatedPaths      []string             `yaml:"elevated_paths"`
	TrustOverrides     []TaintTrustOverride `yaml:"trust_overrides"`
	Policy             string               `yaml:"policy"`         // strict, balanced, permissive
	RecentSources      int                  `yaml:"recent_sources"` // bounded recent source history
}

// TaintTrustOverride grants a narrow, expiring trust exemption.
type TaintTrustOverride struct {
	Scope       string    `yaml:"scope"`
	SourceMatch string    `yaml:"source_match"`
	ActionMatch string    `yaml:"action_match"`
	ExpiresAt   time.Time `yaml:"expires_at"`
	GrantedBy   string    `yaml:"granted_by"`
	Reason      string    `yaml:"reason"`
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

// DefaultMaxImageBytes is the default cap on inbound image response size.
// Images larger than this are rejected before any parsing so decompression
// bombs cannot allocate unbounded memory. Matches the BrowserShield
// MaxShieldBytes default for consistency across response size limits.
const DefaultMaxImageBytes int64 = 5 * 1024 * 1024 // 5 MiB

// MediaPolicy configures transport-level handling of media responses
// (image/audio/video Content-Type). Pipelock is not a multimodal inspector:
// it cannot catch instructions embedded in pixels, audio frames, or video.
// Instead this section reduces exposure by stripping unused media types,
// enforcing size limits (decompression bomb defense), surgically removing
// metadata from allowed image types, and emitting exposure events so
// downstream taint / approval systems can react to rich media reaching an
// agent before a sensitive action.
//
// Boolean fields use *bool with nil-means-security-default semantics: omitting
// a field from YAML must produce the protective default, not the zero value.
// Validate 6 states per boolean per the hard rule: omitted, YAML null/blank,
// explicit false, explicit true, reload with change, reload without change.
type MediaPolicy struct {
	// Enabled is the master switch for media policy enforcement. nil = true
	// (default enabled). When false, media responses pass through unchanged
	// and no exposure events are emitted.
	Enabled *bool `yaml:"enabled,omitempty"`

	// StripImages rejects all image/* Content-Type responses when true.
	// nil = false (default: allow images, strip metadata). Set true for
	// strict-mode agents that should never receive any image content.
	StripImages *bool `yaml:"strip_images,omitempty"`

	// StripAudio rejects all audio/* Content-Type responses when true.
	// nil = true (default: reject). Agents rarely need audio, and audio
	// is a plausible prompt-injection carrier through ASR transcription.
	StripAudio *bool `yaml:"strip_audio,omitempty"`

	// StripVideo rejects all video/* Content-Type responses when true.
	// nil = true (default: reject). Same rationale as StripAudio plus
	// frame extraction cost.
	StripVideo *bool `yaml:"strip_video,omitempty"`

	// AllowedImageTypes limits which image media types pass when StripImages
	// is false. Empty means the default set (PNG, JPEG). SVG is
	// intentionally excluded because SVG is active content handled by the
	// browser shield pipeline, not a static image.
	AllowedImageTypes []string `yaml:"allowed_image_types,omitempty"`

	// StripImageMetadata surgically removes EXIF/XMP/IPTC/ICC metadata from
	// allowed image responses without touching pixel data. nil = true
	// (default: strip). Uses byte-level marker/chunk parsing, never decode
	// + re-encode, so the forwarded image is pixel-identical.
	StripImageMetadata *bool `yaml:"strip_image_metadata,omitempty"`

	// MaxImageBytes rejects image responses larger than this size in bytes,
	// measured at ingest before any parsing. Protects against decompression
	// bombs and excessive memory pressure. 0 means use DefaultMaxImageBytes.
	MaxImageBytes int64 `yaml:"max_image_bytes,omitempty"`

	// LogMediaExposure emits a "media_exposure" event for every allowed
	// media response. nil = true (default: log). These events feed the
	// upcoming taint/authority policy system as exposure signals.
	LogMediaExposure *bool `yaml:"log_media_exposure,omitempty"`
}

// DefaultAllowedImageTypes is the media type whitelist applied when
// MediaPolicy.AllowedImageTypes is empty. Scoped to the formats the
// metadata stripper can actually sanitize (JPEG, PNG). GIF and WebP are
// intentionally excluded by default because internal/media.StripMetadata
// does not yet parse their chunk formats — admitting them here would
// pass through any embedded metadata (XMP in WebP, comment blocks in
// GIF) without stripping. Operators who accept that trade-off can add
// them explicitly via media_policy.allowed_image_types. SVG is excluded
// unconditionally: it is active content handled by the browser shield
// pipeline, not a raster image safe to forward byte-for-byte.
var DefaultAllowedImageTypes = []string{
	"image/png",
	"image/jpeg",
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
	BearerTokens []string `yaml:"bearer_tokens"`
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

// Learn governs the v2.4 learn-and-lock observation pipeline. When Enabled,
// the proxy emits classification metadata into the recorder JSONL stream so
// that pipelock learn compile (PR 2.x) can build a behavioral contract.
// All fields are reload-safe.
type Learn struct {
	Enabled    bool         `yaml:"enabled"`
	CaptureDir string       `yaml:"capture_dir"`
	Privacy    LearnPrivacy `yaml:"privacy"`
}

// LearnPrivacy controls the privacy budget on data flowing through the
// observation pipeline. The privacy enforcer (internal/contract/privacy,
// shipped in a later commit on this PR) consults these settings; PR 1.3
// only ships the schema + defaults + validation surface.
type LearnPrivacy struct {
	// SaltSource is a single string with an auto-detected resolver:
	//   "${VAR}"           -> env var lookup at runtime
	//   "file:/abs/path"   -> file contents at runtime (path validated at config-load)
	//   ""                 -> empty (fail-closed when classification needs salt)
	//   anything else      -> literal salt value (test/dev only)
	// No salt is stored in this string after Normalize; the resolver runs
	// at observation time, not config-load time.
	SaltSource string `yaml:"salt_source"`

	// PublicAllowlistDefault toggles whether the privacy enforcer ships a
	// canonical seed public-allowlist (common public APIs, well-known
	// public domains) when the operator's explicit allowlist is empty.
	// Default true. Security-sensitive boolean: 6-state default-true tests
	// required (see CLAUDE.md's security invariants section).
	PublicAllowlistDefault bool `yaml:"public_allowlist_default"`
}
