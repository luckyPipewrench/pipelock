// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

// PreserveConductorBundleLocalRuntimeState copies follower-local runtime and
// scanner settings from oldCfg onto newCfg before a Conductor enforcement-only
// bundle is applied.
func PreserveConductorBundleLocalRuntimeState(newCfg, oldCfg *Config) {
	if oldCfg == nil || newCfg == nil {
		return
	}
	// Current Conductor bundles are enforcement-only deltas: they own fleet
	// posture fields (mode/enforce/api_allowlist) and deliberately omit the
	// follower's local scanner baseline. Preserve local runtime plumbing and
	// scanner coverage here so an omitted YAML section cannot reset a follower
	// to defaults or silently drop locally enabled enforcement. A future full
	// policy-bundle format should carry an explicit ownership/version marker
	// before this preservation is relaxed.
	newCfg.FetchProxy = oldCfg.FetchProxy
	newCfg.ForwardProxy = oldCfg.ForwardProxy
	newCfg.WebSocketProxy = oldCfg.WebSocketProxy
	newCfg.TLSInterception = oldCfg.TLSInterception
	newCfg.KillSwitch = oldCfg.KillSwitch
	newCfg.ExplainBlocks = oldCfg.ExplainBlocks
	newCfg.Logging = oldCfg.Logging
	newCfg.Emit = oldCfg.Emit
	newCfg.Sentry = oldCfg.Sentry
	newCfg.MetricsListen = oldCfg.MetricsListen
	newCfg.MCPWSListener = oldCfg.MCPWSListener
	newCfg.ReverseProxy = oldCfg.ReverseProxy
	newCfg.ScanAPI = oldCfg.ScanAPI
	newCfg.Sandbox = oldCfg.Sandbox
	newCfg.FlightRecorder = oldCfg.FlightRecorder

	if oldCfg.Agents != nil {
		newCfg.Agents = make(map[string]AgentProfile, len(oldCfg.Agents))
		for name, profile := range oldCfg.Agents {
			newCfg.Agents[name] = profile
		}
	} else {
		newCfg.Agents = nil
	}
	newCfg.LicenseKey = oldCfg.LicenseKey
	newCfg.LicenseFile = oldCfg.LicenseFile

	newCfg.Internal = append([]string(nil), oldCfg.Internal...)
	newCfg.TrustedDomains = append([]string(nil), oldCfg.TrustedDomains...)
	newCfg.SSRF = oldCfg.SSRF
	newCfg.DNS = oldCfg.DNS
	newCfg.Suppress = append([]SuppressEntry(nil), oldCfg.Suppress...)
	newCfg.DLP = oldCfg.DLP
	newCfg.CanaryTokens = oldCfg.CanaryTokens
	newCfg.ResponseScanning = oldCfg.ResponseScanning
	newCfg.MCPInputScanning = oldCfg.MCPInputScanning
	newCfg.MCPToolScanning = oldCfg.MCPToolScanning
	newCfg.MCPToolPolicy = oldCfg.MCPToolPolicy
	newCfg.Defer = oldCfg.Defer
	newCfg.GitProtection = oldCfg.GitProtection
	newCfg.RequestBodyScanning = oldCfg.RequestBodyScanning
	newCfg.RequestPolicy = oldCfg.RequestPolicy
	newCfg.SessionProfiling = oldCfg.SessionProfiling
	newCfg.AdaptiveEnforcement = oldCfg.AdaptiveEnforcement
	newCfg.MCPSessionBinding = oldCfg.MCPSessionBinding
	newCfg.A2AScanning = oldCfg.A2AScanning
	newCfg.ToolChainDetection = oldCfg.ToolChainDetection
	newCfg.CrossRequestDetection = oldCfg.CrossRequestDetection
	newCfg.AddressProtection = oldCfg.AddressProtection
	newCfg.SeedPhraseDetection = oldCfg.SeedPhraseDetection
	newCfg.Rules = oldCfg.Rules
	newCfg.FileSentry = oldCfg.FileSentry
	newCfg.MCPBinaryIntegrity = oldCfg.MCPBinaryIntegrity
	newCfg.MCPToolProvenance = oldCfg.MCPToolProvenance
	newCfg.BehavioralBaseline = oldCfg.BehavioralBaseline
	newCfg.Airlock = oldCfg.Airlock
	newCfg.BrowserShield = oldCfg.BrowserShield
	newCfg.MediaPolicy = oldCfg.MediaPolicy
	newCfg.Redaction = oldCfg.Redaction
	newCfg.Taint = oldCfg.Taint
	newCfg.MediationEnvelope = oldCfg.MediationEnvelope
	newCfg.Learn = oldCfg.Learn
	newCfg.LearnLock = oldCfg.LearnLock
	newCfg.DefaultAgentIdentity = oldCfg.DefaultAgentIdentity
	newCfg.BindDefaultAgentIdentity = oldCfg.BindDefaultAgentIdentity
}
