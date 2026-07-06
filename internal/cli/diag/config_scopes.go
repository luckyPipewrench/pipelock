// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

// Config scope identifiers shared with consumers (for example the dashboard
// exemptions inventory). A semantic finding's Scope and a consumer's knob name
// are joined by string equality, so both the finding-producing side (this
// package) and the finding-joining side reference these constants. A scope
// rename then becomes a compile error instead of a silent join break that would
// mis-report an inert exemption as active.
//
// These live in a dedicated file so the string literals appear exactly once,
// here, and every other reference is the constant.
const (
	ConfigScopeSuppress                   = "suppress"
	ConfigScopeResponseExemptDomains      = "response_scanning.exempt_domains"
	ConfigScopeResponseMCPServers         = "response_scanning.mcp_servers"
	ConfigScopeAdaptiveExemptDomains      = "adaptive_enforcement.exempt_domains"
	ConfigScopeCrossRequestEntropyExempt  = "cross_request_detection.entropy_budget.exempt_domains"
	ConfigScopeBrowserShieldExemptDomains = "browser_shield.exempt_domains"
	ConfigScopeTLSPassthroughDomains      = "tls_interception.passthrough_domains"
	ConfigScopeRequestBodyIgnoreHeaders   = "request_body_scanning.ignore_headers"
)
