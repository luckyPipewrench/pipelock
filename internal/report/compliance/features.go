// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package compliance

// Framework ID constants. These are the stable identifiers emitted in
// assess output, summary.json, and the compliance grid. Tests and renderers
// match against these IDs, so they must stay in sync with the constructor
// in each framework's source file.
const (
	frameworkOWASPMCPTop10     = "owasp_mcp_top_10"
	frameworkOWASPAgenticTop10 = "owasp_agentic_top_10"
	frameworkMITREATLAS        = "mitre_atlas"
	frameworkEUAIAct           = "eu_ai_act"
	frameworkNISTAIRMF         = "nist_ai_rmf"
	frameworkHIPAASecurity     = "hipaa_security"
	frameworkSOC2TSC           = "soc2_tsc"
)

// Feature name constants. These are the canonical capability identifiers
// referenced by ControlMapping.Features. They mirror the config-section
// vocabulary (response_scanning, mcp_tool_policy, flight_recorder, ...)
// the proxy uses elsewhere, but are private here because the compliance
// package is the authoritative mapping surface — outside callers consume
// the resulting Framework / ControlMapping values, not the raw strings.
const (
	featureAdaptiveEnforcement   = "adaptive_enforcement"
	featureAddressProtection     = "address_protection"
	featureAgents                = "agents"
	featureAPIAllowlist          = "api_allowlist"
	featureAssess                = "assess"
	featureAttestation           = "attestation"
	featureAudit                 = "audit"
	featureBehavioralBaseline    = "behavioral_baseline"
	featureBrowserShield         = "browser_shield"
	featureCanaryTokens          = "canary_tokens"
	featureCrossRequestDetection = "cross_request_detection"
	featureDiscover              = "discover"
	featureDLP                   = "dlp"
	featureEmit                  = "emit"
	featureEnvLeak               = "env_leak"
	featureFlightRecorder        = "flight_recorder"
	featureForwardProxy          = "forward_proxy"
	featureHealth                = "health"
	featureHITL                  = "hitl"
	featureKillSwitch            = "kill_switch"
	featureLearnLock             = "learn_lock"
	featureLicense               = "license"
	featureMCPBinaryIntegrity    = "mcp_binary_integrity"
	featureMCPInputScanning      = "mcp_input_scanning"
	featureMCPSessionBinding     = "mcp_session_binding"
	featureMCPToolPolicy         = "mcp_tool_policy"
	featureMCPToolProvenance     = "mcp_tool_provenance"
	featureMCPToolScanning       = "mcp_tool_scanning"
	featureMediationEnvelope     = "mediation_envelope"
	featureMetrics               = "metrics"
	featureRedaction             = "redaction"
	featureRequestBodyScanning   = "request_body_scanning"
	featureResponseScanning      = "response_scanning"
	featureSandbox               = "sandbox"
	featureSeedPhraseDetection   = "seed_phrase_detection"
	featureSessionProfiling      = "session_profiling"
	featureSigning               = "signing"
	featureSimulate              = "simulate"
	featureTLSInterception       = "tls_interception"
	featureToolChainDetection    = "tool_chain_detection"
	featureToolPolicy            = "tool_policy"
)
