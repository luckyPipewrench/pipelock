// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
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

	"github.com/luckyPipewrench/pipelock/internal/signing"
)

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

// Warning is a non-fatal advisory surfaced during Validate. Callers render
// these to operator output (cobra's ErrOrStderr, systemd journal, etc.).
// See Config.ValidateWithWarnings for the accumulation path.
type Warning struct {
	Field   string
	Message string
}

// Validate checks the config for errors. Must be called after ApplyDefaults.
// Advisory warnings are discarded; callers that want them should use
// ValidateWithWarnings instead.
func (c *Config) Validate() error {
	_, err := c.ValidateWithWarnings()
	return err
}

// ValidateWithWarnings validates the config and returns any non-fatal
// advisory warnings alongside the first hard error. Dispatch order matches
// Validate() exactly. Warnings are returned even when err is non-nil, so
// callers can surface every advisory emitted before the failing validator.
func (c *Config) ValidateWithWarnings() ([]Warning, error) {
	var warnings []Warning
	if err := c.validateMode(); err != nil {
		return warnings, err
	}
	if err := c.validateLogging(); err != nil {
		return warnings, err
	}
	if err := c.validateDLP(); err != nil {
		return warnings, err
	}
	if err := c.validateFetchProxy(); err != nil {
		return warnings, err
	}
	if err := c.validateResponseScanning(&warnings); err != nil {
		return warnings, err
	}
	if err := c.validateMCPInputScanning(); err != nil {
		return warnings, err
	}
	if err := c.validateMCPToolScanning(); err != nil {
		return warnings, err
	}
	if err := c.validateMCPToolPolicy(); err != nil {
		return warnings, err
	}
	if err := c.validateGitProtection(); err != nil {
		return warnings, err
	}
	if err := c.validateForwardProxy(); err != nil {
		return warnings, err
	}
	if err := c.validateWebSocketProxy(&warnings); err != nil {
		return warnings, err
	}
	if err := c.validateSessionProfiling(); err != nil {
		return warnings, err
	}
	if err := c.validateAdaptiveEnforcement(&warnings); err != nil {
		return warnings, err
	}
	if err := c.validateMCPSessionBinding(); err != nil {
		return warnings, err
	}
	if err := c.validateA2AScanning(); err != nil {
		return warnings, err
	}
	if err := c.validateRequestBodyScanning(); err != nil {
		return warnings, err
	}
	if err := c.validateSeedPhraseDetection(); err != nil {
		return warnings, err
	}
	if err := c.validateCrossRequestDetection(&warnings); err != nil {
		return warnings, err
	}
	if err := c.validateTLSInterception(); err != nil {
		return warnings, err
	}
	if err := c.validateToolChainDetection(); err != nil {
		return warnings, err
	}
	if err := c.validateMCPWSListener(); err != nil {
		return warnings, err
	}
	if err := c.validateSuppress(); err != nil {
		return warnings, err
	}
	if err := c.validateKillSwitch(); err != nil {
		return warnings, err
	}
	if err := c.validateMetricsListen(); err != nil {
		return warnings, err
	}
	if err := c.validateEmit(); err != nil {
		return warnings, err
	}
	if err := c.validateAddressProtection(); err != nil {
		return warnings, err
	}
	if err := c.validateSentry(); err != nil {
		return warnings, err
	}
	if err := c.validateInternalCIDRs(); err != nil {
		return warnings, err
	}
	if err := c.validateSSRF(); err != nil {
		return warnings, err
	}
	if err := c.validateTrustedDomains(); err != nil {
		return warnings, err
	}
	if err := c.validateRules(); err != nil {
		return warnings, err
	}
	if err := c.validateFileSentry(); err != nil {
		return warnings, err
	}
	if err := c.validateAgents(); err != nil {
		return warnings, err
	}
	if err := c.validateScanAPI(); err != nil {
		return warnings, err
	}
	c.validateListenWarnings(&warnings)
	if err := c.validateReverseProxy(); err != nil {
		return warnings, err
	}
	if err := c.validateSandbox(); err != nil {
		return warnings, err
	}
	if err := c.validateFlightRecorder(); err != nil {
		return warnings, err
	}
	if err := c.validateMCPBinaryIntegrity(); err != nil {
		return warnings, err
	}
	if err := c.validateMCPToolProvenance(); err != nil {
		return warnings, err
	}
	if err := c.validateBehavioralBaseline(); err != nil {
		return warnings, err
	}
	if err := c.validateAirlock(); err != nil {
		return warnings, err
	}
	if err := c.validateBrowserShield(); err != nil {
		return warnings, err
	}
	if err := c.validateTaint(); err != nil {
		return warnings, err
	}
	if err := c.validateDefaultAgentIdentity(); err != nil {
		return warnings, err
	}
	if err := c.validateMediationEnvelope(); err != nil {
		return warnings, err
	}
	if err := c.validateMediaPolicy(); err != nil {
		return warnings, err
	}
	if err := c.validateRedaction(); err != nil {
		return warnings, err
	}
	return warnings, nil
}

// validateRedaction delegates to the redact package's own schema
// validator. The v1a startup gate that rejected enabled=true has been
// removed now that the forward, intercept, and reverse proxy paths
// invoke the redaction hook in scanRequestBody. A cross-check here
// rejects the configuration where redaction is on but the body-scanning
// path that hosts the hook is off, because that combination would
// silently disable the feature — the exact footgun class the feature
// is meant to prevent.
func (c *Config) validateRedaction() error {
	if err := c.Redaction.Validate(); err != nil {
		return fmt.Errorf("redaction: %w", err)
	}
	if c.Redaction.Enabled && !c.RequestBodyScanning.Enabled {
		return fmt.Errorf("redaction: enabled=true requires request_body_scanning.enabled=true (the redaction hook lives in the body-scan path)")
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
		return fmt.Errorf("dlp.action %q is not supported; DLP match behavior depends on the calling surface (request_body_scanning.action for HTTP bodies/headers, mcp_input_scanning.action for MCP input, enforce/audit mode for URL scanning, and response_scanning.action only for inbound prompt-injection response scanning)", c.DLP.Action)
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
			if p.Action != ActionWarn {
				return fmt.Errorf("DLP pattern %q has unsupported action %q; only %q is allowed as a per-pattern action", p.Name, p.Action, ActionWarn)
			}
			if p.Compiled {
				return fmt.Errorf("DLP pattern %q is a built-in default and cannot be set to warn mode; built-in patterns always enforce", p.Name)
			}
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

func (c *Config) validateResponseScanning(warnings *[]Warning) error {
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
		*warnings = append(*warnings, Warning{
			Field:   "response_scanning.exempt_domains",
			Message: "configured but response_scanning is disabled — these will take effect when enabled",
		})
	}

	// Generic SSE streaming sub-section. Validated regardless of the
	// parent response_scanning.enabled flag so dormant bad config can't
	// activate silently on reload.
	sse := c.ResponseScanning.SSEStreaming
	if sse.Enabled {
		switch sse.Action {
		case "", ActionBlock, ActionWarn:
			// valid (empty falls back to block downstream)
		default:
			return fmt.Errorf("invalid response_scanning.sse_streaming action %q: must be block or warn", sse.Action)
		}
		if sse.MaxEventBytes < 0 {
			return fmt.Errorf("response_scanning.sse_streaming.max_event_bytes must be >= 0 (0 means use default), got %d", sse.MaxEventBytes)
		}
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

func (c *Config) validateWebSocketProxy(warnings *[]Warning) error {
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
		*warnings = append(*warnings, Warning{
			Field:   "websocket_proxy",
			Message: fmt.Sprintf("memory budget is %dMB (max_concurrent_connections * max_message_bytes * 2) - consider reducing", memBudget/(1<<20)),
		})
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

func (c *Config) validateAdaptiveEnforcement(warnings *[]Warning) error {
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
		*warnings = append(*warnings, Warning{
			Field:   "adaptive_enforcement.exempt_domains",
			Message: "configured but adaptive_enforcement is disabled — these will take effect when enabled",
		})
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

func (c *Config) validateCrossRequestDetection(warnings *[]Warning) error {
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
		*warnings = append(*warnings, Warning{
			Field:   "cross_request_detection.entropy_budget.exempt_domains",
			Message: "configured but cross_request_detection is disabled — these will take effect when enabled",
		})
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

// validateListenWarnings emits advisories when the listen address is not
// loopback. It returns no error because the condition is advisory only —
// the proxy startup also logs non-loopback warnings via the audit logger
// (proxy.go Start); these warnings are duplicative but surface at config
// load time so operators see them during pipelock diag verify-install.
func (c *Config) validateListenWarnings(warnings *[]Warning) {
	host, _, err := net.SplitHostPort(c.FetchProxy.Listen)
	if err != nil {
		return
	}
	ip := net.ParseIP(host)
	if ip != nil && !ip.IsLoopback() {
		*warnings = append(*warnings, Warning{
			Field:   "fetch_proxy.listen",
			Message: fmt.Sprintf("listen address %s is not loopback - proxy endpoints (/metrics, /stats) will be exposed to the network", c.FetchProxy.Listen),
		})
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		*warnings = append(*warnings, Warning{
			Field:   "fetch_proxy.listen",
			Message: fmt.Sprintf("listen address %s binds to all interfaces - consider using 127.0.0.1 for local-only access", c.FetchProxy.Listen),
		})
	}
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

// Default values for the RFC 9421 envelope signer. These are used at
// load time to fill unset fields when sign: true so an operator can opt
// in with the minimum viable surface (sign: true + signing_key_path).
const (
	DefaultEnvelopeSignKeyID           = "pipelock-mediation-v1"
	DefaultEnvelopeSignCreatedSkewSecs = 60
	DefaultEnvelopeSignMaxBodyBytes    = 1 << 20 // 1 MiB
)

// DefaultEnvelopeSignedComponents returns the RFC 9421 component set
// pipelock declares when sign: true and signed_components is empty.
// Callers must not mutate the returned slice — it is returned by copy so
// each caller gets its own backing array.
func DefaultEnvelopeSignedComponents() []string {
	return []string{"@method", "@target-uri", "content-digest", "pipelock-mediation"}
}

func (c *Config) validateMediationEnvelope() error {
	me := &c.MediationEnvelope

	// Sign: true requires Enabled: true. Allowing sign without enabled
	// would silently produce signatures that no transport ever attaches
	// (the inject code paths are gated on Enabled). That is a
	// configuration error, not a runtime fallback.
	if me.Sign && !me.Enabled {
		return fmt.Errorf("mediation_envelope.sign requires mediation_envelope.enabled")
	}

	// Normalize signing-related fields unconditionally, even when
	// sign is currently off. ValidateReload compares old.MediationEnvelope
	// vs updated.MediationEnvelope for narrowing/downgrade warnings; if
	// normalization only fires on the sign-true branch, warning behavior
	// depends on whether validation had previously seen sign-true, not on
	// operator intent. Run normalization first so both sides of every
	// reload comparison are in canonical effective form.
	if err := normalizeMediationEnvelope(me); err != nil {
		return err
	}

	if !me.Sign {
		// Signing disabled — normalization is enough; skip the
		// keyfile load that's only meaningful when signing is on.
		return nil
	}

	// Require a signing key path. Fail closed: a missing key path with
	// sign: true is an explicit misconfiguration, not a soft fallback.
	if strings.TrimSpace(me.SigningKeyPath) == "" {
		return fmt.Errorf("mediation_envelope.signing_key_path is required when mediation_envelope.sign is true")
	}

	// Load the key once at validate time so the pipelock binary refuses
	// to start against an unreadable or malformed key rather than
	// spawning a signer that cannot sign. The key material itself is
	// discarded — runtime wiring re-reads the file on every reload so
	// operators can rotate without touching the config file.
	if _, err := signing.LoadPrivateKeyFile(me.SigningKeyPath); err != nil {
		return fmt.Errorf("mediation_envelope.signing_key_path %q: %w", me.SigningKeyPath, err)
	}

	return nil
}

func (c *Config) validateDefaultAgentIdentity() error {
	identity := strings.TrimSpace(c.DefaultAgentIdentity)
	if c.BindDefaultAgentIdentity && identity == "" {
		return fmt.Errorf("bind_default_agent_identity requires default_agent_identity")
	}
	if c.DefaultAgentIdentity != "" && identity != c.DefaultAgentIdentity {
		return fmt.Errorf("default_agent_identity must not contain leading or trailing whitespace")
	}
	return nil
}

func (c *Config) validateTaint() error {
	switch c.Taint.Policy {
	case "", ModeBalanced, ModeStrict, ModePermissive:
	default:
		return fmt.Errorf("invalid taint.policy %q: must be %s, %s, or %s", c.Taint.Policy, ModeStrict, ModeBalanced, ModePermissive)
	}
	if c.Taint.RecentSources < 0 {
		return fmt.Errorf("taint.recent_sources must be >= 0")
	}
	if err := ValidateTrustedDomains(c.Taint.AllowlistedDomains, "taint.allowlisted_domains"); err != nil {
		return err
	}
	if err := validatePathGlobs(c.Taint.ProtectedPaths, "taint.protected_paths"); err != nil {
		return err
	}
	if err := validatePathGlobs(c.Taint.ElevatedPaths, "taint.elevated_paths"); err != nil {
		return err
	}
	for i, override := range c.Taint.TrustOverrides {
		if override.Scope == "" {
			return fmt.Errorf("taint.trust_overrides[%d].scope is required", i)
		}
		switch override.Scope {
		case "action":
			if override.ActionMatch == "" {
				return fmt.Errorf("taint.trust_overrides[%d].action_match is required for scope=action", i)
			}
		case "source":
			if override.SourceMatch == "" {
				return fmt.Errorf("taint.trust_overrides[%d].source_match is required for scope=source", i)
			}
		default:
			return fmt.Errorf("invalid taint.trust_overrides[%d].scope %q: must be action or source", i, override.Scope)
		}
		if override.ExpiresAt.IsZero() {
			return fmt.Errorf("taint.trust_overrides[%d].expires_at is required", i)
		}
	}
	return nil
}

func validatePathGlobs(patterns []string, label string) error {
	for i, pattern := range patterns {
		if pattern == "" {
			return fmt.Errorf("%s[%d] must not be empty", label, i)
		}
		if _, err := path.Match(pattern, "probe"); err != nil {
			return fmt.Errorf("%s[%d] %q: invalid glob: %w", label, i, pattern, err)
		}
	}
	return nil
}

// validateMediaPolicy checks media_policy settings for consistency.
// Runs on every Load() and hot reload. Validation is deliberately strict on
// explicit values but permissive on unset/default (nil bool, zero int, empty
// slice) — Defaults() and the getters handle those cases so operators who
// partially configure don't hit spurious errors.
//
// Structural validation runs regardless of whether the master switch is
// enabled. "media_policy.enabled: false" cannot be a license to load
// malformed values that would apply the moment the feature is re-enabled
// on a subsequent reload.
func (c *Config) validateMediaPolicy() error {
	// MaxImageBytes: reject explicit negative values. Zero is allowed and
	// means "use DefaultMaxImageBytes" via EffectiveMaxImageBytes().
	if c.MediaPolicy.MaxImageBytes < 0 {
		return fmt.Errorf("media_policy.max_image_bytes must be non-negative (0 = default %d)", DefaultMaxImageBytes)
	}

	// AllowedImageTypes must contain only image/* media types. Empty list
	// falls through to DefaultAllowedImageTypes via the getter. SVG is
	// rejected here because it is active content, not a raster image —
	// the browser shield pipeline handles SVG separately.
	//
	// Canonicalization uses the same helper that EffectiveAllowedImageTypes
	// applies at read time, so validation and runtime matching can never
	// disagree on whether an entry like " image/png " or
	// "image/jpeg; charset=binary" is accepted.
	for _, raw := range c.MediaPolicy.AllowedImageTypes {
		canon := canonicalizeMediaTypeEntry(raw)
		if canon == "" {
			return fmt.Errorf("media_policy.allowed_image_types contains an empty or unparseable entry: %q", raw)
		}
		if !strings.HasPrefix(canon, "image/") {
			return fmt.Errorf("media_policy.allowed_image_types entry %q must be an image/* media type", raw)
		}
		// Require a concrete subtype. ImageTypeAllowed does exact string
		// matching at runtime, so wildcard or whitespace-containing
		// subtypes would pass validation but never match a real
		// response. Reject them here so the validation/matching contract
		// cannot diverge on ambiguous inputs.
		subtype := strings.TrimPrefix(canon, "image/")
		if subtype == "" || strings.ContainsAny(subtype, "*?/ ") {
			return fmt.Errorf("media_policy.allowed_image_types entry %q must name a concrete subtype (no wildcards, whitespace, or nested slashes)", raw)
		}
		if canon == "image/svg+xml" {
			return fmt.Errorf("media_policy.allowed_image_types must not include image/svg+xml: SVG is active content handled by browser_shield")
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
