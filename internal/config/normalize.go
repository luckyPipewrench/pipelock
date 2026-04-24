// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"

	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"gopkg.in/yaml.v3"
)

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
		cfg.Taint.Enabled = true
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

	// Generic SSE streaming: enabled defaults to true so LLM SSE traffic is
	// scanned out of the box. Operators must explicitly set enabled: false to
	// opt out, in which case the disabled-mode path still streams with
	// flushing rather than silently buffering.
	rs, _ := raw["response_scanning"].(map[string]interface{})
	var sse map[string]interface{}
	if rs != nil {
		sse, _ = rs["sse_streaming"].(map[string]interface{})
	}
	setBoolDefault(sse, "enabled", &cfg.ResponseScanning.SSEStreaming.Enabled)

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

	// Taint defaults to enabled when omitted, matching Defaults().
	taint, _ := raw["taint"].(map[string]interface{})
	setBoolDefault(taint, "enabled", &cfg.Taint.Enabled)
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

	// Taint policy defaults
	if c.Taint.Policy == "" {
		c.Taint.Policy = ModeBalanced
	}
	if c.Taint.RecentSources < 0 {
		c.Taint.RecentSources = 10
	}
	if c.Taint.AllowlistedDomains == nil {
		c.Taint.AllowlistedDomains = append([]string(nil), Defaults().Taint.AllowlistedDomains...)
	}
	if c.Taint.ProtectedPaths == nil {
		c.Taint.ProtectedPaths = append([]string(nil), Defaults().Taint.ProtectedPaths...)
	}
	if c.Taint.ElevatedPaths == nil {
		c.Taint.ElevatedPaths = append([]string(nil), Defaults().Taint.ElevatedPaths...)
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

// normalizeMediationEnvelope applies defaults and canonicalises
// signing-related fields regardless of whether Sign is currently on.
// Returns an error for any field whose raw value is syntactically
// invalid (negative lengths, malformed component names).
//
// Keeping this separate from the sign-gated keyfile load means two
// configs with identical effective policy but different histories
// (one that was always sign=false, one that cycled through sign=true)
// compare identically under ValidateReload.
func normalizeMediationEnvelope(me *MediationEnvelope) error {
	if me.KeyID == "" {
		me.KeyID = DefaultEnvelopeSignKeyID
	}
	if me.CreatedSkewSeconds == 0 {
		me.CreatedSkewSeconds = DefaultEnvelopeSignCreatedSkewSecs
	}
	if me.CreatedSkewSeconds < 0 {
		return fmt.Errorf("mediation_envelope.created_skew_seconds must be >= 0, got %d", me.CreatedSkewSeconds)
	}
	if me.MaxBodyBytes == 0 {
		me.MaxBodyBytes = DefaultEnvelopeSignMaxBodyBytes
	}
	if me.MaxBodyBytes < 0 {
		return fmt.Errorf("mediation_envelope.max_body_bytes must be >= 0, got %d", me.MaxBodyBytes)
	}
	if len(me.SignedComponents) == 0 {
		me.SignedComponents = DefaultEnvelopeSignedComponents()
	} else {
		normalized, err := envelope.NormalizeSignedComponents(me.SignedComponents)
		if err != nil {
			return errors.New("mediation_envelope." + err.Error())
		}
		me.SignedComponents = normalized
	}
	return nil
}
