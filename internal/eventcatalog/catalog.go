// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package eventcatalog declares built-in event names and exported static metadata.
package eventcatalog

const (
	EventAdaptiveEscalation          = "adaptive_escalation"
	EventAdaptiveRecovery            = "adaptive_recovery"
	EventAdaptiveUpgrade             = "adaptive_upgrade"
	EventAddressProtection           = "address_protection"
	EventAgentListener               = "agent_listener"
	EventAirlockDeescalate           = "airlock_deescalate"
	EventAirlockDeny                 = "airlock_deny"
	EventAirlockEnter                = "airlock_enter"
	EventAllowed                     = "allowed"
	EventAnomaly                     = "anomaly"
	EventAuthorityVerification       = "authority_verification"
	EventBlocked                     = "blocked"
	EventBodyDLP                     = "body_dlp"
	EventBodyPromptInjection         = "body_prompt_injection"
	EventChainDetection              = "chain_detection"
	EventCommitmentKeyLifecycle      = "commitment_key_lifecycle"
	EventConfigReload                = "config_reload"
	EventContainmentMetricsDeny      = "containment_metrics_access_denied"
	EventCrossRequestDLPMatch        = "cross_request_dlp_match"
	EventCrossRequestEntropyAnomaly  = "cross_request_entropy_anomaly"
	EventCrossRequestEntropyExceeded = "cross_request_entropy_exceeded"
	EventDLPCredentialAudienceAllow  = "dlp_credential_audience_allow" // #nosec G101 -- audit event identifier, not credential material
	EventDLPIssuerCookieAllow        = "dlp_issuer_cookie_allow"
	EventDLPWarn                     = "dlp_warn"
	EventDashboardAuthFailed         = "dashboard_auth_failed"
	EventError                       = "error"
	EventFileSentryDLP               = "file_sentry_dlp"
	EventForwardHTTP                 = "forward_http"
	EventHeaderDLP                   = "header_dlp"
	EventInterceptHTTP               = "intercept_http"
	EventIssuerQueryAllow            = "entropy_issuer_query_allow"
	EventKillSwitchDeny              = "kill_switch_deny"
	EventLicenseExpiry               = "license_expiry"
	EventMCPUnknownTool              = "mcp_unknown_tool"
	EventMediaExposure               = "media_exposure"
	EventRedirect                    = "redirect"
	EventResponseScan                = "response_scan"
	EventResponseScanExempt          = "response_scan_exempt"
	EventResponseScanSuppressed      = "response_scan_suppressed"
	EventRuleBundleDegraded          = "rule_bundle_degraded"
	EventSNIMismatch                 = "sni_mismatch"
	EventSessionAdmin                = "session_admin"
	EventSessionAnomaly              = "session_anomaly"
	EventShieldRewrite               = "shield_rewrite"
	EventShutdown                    = "shutdown"
	EventStartup                     = "startup"
	EventTaintDecision               = "taint_decision"
	EventTextStego                   = "text_stego_detected"
	EventToolRedirect                = "tool_redirect"
	EventTunnelClose                 = "tunnel_close"
	EventTunnelOpen                  = "tunnel_open"
	EventWSBlocked                   = "ws_blocked"
	EventWSClose                     = "ws_close"
	EventWSOpen                      = "ws_open"
	EventWSScan                      = "ws_scan"
)

// Descriptor contains only metadata consumed by external emission. Local log
// levels and runtime severity overrides remain the caller's responsibility.
type Descriptor struct {
	Name     string
	Severity string
	Action   string
}

// Builtins returns an independent copy of the declarations. Empty severity
// preserves unknown-event fallback; empty action preserves filter fallback.
func Builtins() []Descriptor {
	return []Descriptor{
		{EventAdaptiveEscalation, "warn", "warn"},
		{EventAdaptiveRecovery, "info", "allow"},
		{EventAdaptiveUpgrade, "warn", "warn"},
		{EventAddressProtection, "warn", "warn"},
		{EventAgentListener, "info", "allow"},
		{EventAirlockDeescalate, "info", "allow"},
		{EventAirlockDeny, "warn", "block"},
		{EventAirlockEnter, "warn", "warn"},
		{EventAllowed, "info", "allow"},
		{EventAnomaly, "warn", "warn"},
		{EventAuthorityVerification, "info", "allow"},
		{EventBlocked, "warn", "block"},
		{EventBodyDLP, "warn", "warn"},
		{EventBodyPromptInjection, "warn", "warn"},
		{EventChainDetection, "", ""},
		{EventCommitmentKeyLifecycle, "", ""},
		{EventConfigReload, "info", "allow"},
		{EventContainmentMetricsDeny, "", ""},
		{EventCrossRequestDLPMatch, "", ""},
		{EventCrossRequestEntropyAnomaly, "", ""},
		{EventCrossRequestEntropyExceeded, "", ""},
		{EventDLPCredentialAudienceAllow, "", ""},
		{EventDLPIssuerCookieAllow, "", ""},
		{EventDLPWarn, "warn", "warn"},
		{EventDashboardAuthFailed, "warn", "warn"},
		{EventError, "warn", "warn"},
		{EventFileSentryDLP, "", ""},
		{EventForwardHTTP, "info", "forward"},
		{EventHeaderDLP, "warn", "warn"},
		{EventInterceptHTTP, "info", "forward"},
		{EventIssuerQueryAllow, "", ""},
		{EventKillSwitchDeny, "critical", "block"},
		{EventLicenseExpiry, "warn", "warn"},
		{EventMCPUnknownTool, "warn", "warn"},
		{EventMediaExposure, "warn", "allow"},
		{EventRedirect, "info", "redirect"},
		{EventResponseScan, "warn", "warn"},
		{EventResponseScanExempt, "warn", "warn"},
		{EventResponseScanSuppressed, "warn", "warn"},
		{EventRuleBundleDegraded, "warn", "warn"},
		{EventSNIMismatch, "warn", "block"},
		{EventSessionAdmin, "info", "allow"},
		{EventSessionAnomaly, "warn", "warn"},
		{EventShieldRewrite, "info", "allow"},
		{EventShutdown, "info", "allow"},
		{EventStartup, "info", "allow"},
		{EventTaintDecision, "warn", "warn"},
		{EventTextStego, "warn", "warn"},
		{EventToolRedirect, "info", "redirect"},
		{EventTunnelClose, "info", "allow"},
		{EventTunnelOpen, "info", "allow"},
		{EventWSBlocked, "warn", "block"},
		{EventWSClose, "info", "allow"},
		{EventWSOpen, "info", "allow"},
		{EventWSScan, "warn", "warn"},
	}
}
