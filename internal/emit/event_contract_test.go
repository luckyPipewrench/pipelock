// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package emit

import (
	"context"
	"testing"
)

func TestBuiltinEventCompatibility(t *testing.T) {
	tests := []struct {
		name     string
		severity Severity
		mapped   bool
		action   string
	}{
		{"adaptive_escalation", SeverityWarn, true, "warn"},
		{"adaptive_recovery", SeverityInfo, true, "allow"},
		{"adaptive_upgrade", SeverityWarn, true, "warn"},
		{"address_protection", SeverityWarn, true, "warn"},
		{"agent_listener", SeverityInfo, true, "allow"},
		{"airlock_deescalate", SeverityInfo, true, "allow"},
		{"airlock_deny", SeverityWarn, true, "block"},
		{"airlock_enter", SeverityWarn, true, "warn"},
		{"allowed", SeverityInfo, true, "allow"},
		{"anomaly", SeverityWarn, true, "warn"},
		{"authority_verification", SeverityInfo, true, "allow"},
		{"blocked", SeverityWarn, true, "block"},
		{"body_dlp", SeverityWarn, true, "warn"},
		{"body_prompt_injection", SeverityWarn, true, "warn"},
		{"chain_detection", SeverityInfo, false, ""},
		{"commitment_key_lifecycle", SeverityInfo, false, ""},
		{"config_reload", SeverityInfo, true, "allow"},
		{"containment_metrics_access_denied", SeverityInfo, false, ""},
		{"cross_request_dlp_match", SeverityInfo, false, ""},
		{"cross_request_entropy_anomaly", SeverityInfo, false, ""},
		{"cross_request_entropy_exceeded", SeverityInfo, false, ""},
		{"dlp_credential_audience_allow", SeverityInfo, false, ""},
		{"dlp_issuer_cookie_allow", SeverityInfo, false, ""},
		{"dlp_warn", SeverityWarn, true, "warn"},
		{"dashboard_auth_failed", SeverityWarn, true, "warn"},
		{"error", SeverityWarn, true, "warn"},
		{"file_sentry_dlp", SeverityInfo, false, ""},
		{"forward_http", SeverityInfo, true, "forward"},
		{"header_dlp", SeverityWarn, true, "warn"},
		{"intercept_http", SeverityInfo, true, "forward"},
		{"entropy_issuer_query_allow", SeverityInfo, false, ""},
		{"kill_switch_deny", SeverityCritical, true, "block"},
		{"license_expiry", SeverityWarn, true, "warn"},
		{"mcp_unknown_tool", SeverityWarn, true, "warn"},
		{"media_exposure", SeverityWarn, true, "allow"},
		{"redirect", SeverityInfo, true, "redirect"},
		{"response_scan", SeverityWarn, true, "warn"},
		{"response_scan_exempt", SeverityWarn, true, "warn"},
		{"response_scan_suppressed", SeverityWarn, true, "warn"},
		{"rule_bundle_degraded", SeverityWarn, true, "warn"},
		{"sni_mismatch", SeverityWarn, true, "block"},
		{"session_admin", SeverityInfo, true, "allow"},
		{"session_anomaly", SeverityWarn, true, "warn"},
		{"shield_rewrite", SeverityInfo, true, "allow"},
		{"shutdown", SeverityInfo, true, "allow"},
		{"startup", SeverityInfo, true, "allow"},
		{"taint_decision", SeverityWarn, true, "warn"},
		{"text_stego_detected", SeverityWarn, true, "warn"},
		{"tool_redirect", SeverityInfo, true, "redirect"},
		{"tunnel_close", SeverityInfo, true, "allow"},
		{"tunnel_open", SeverityInfo, true, "allow"},
		{"ws_blocked", SeverityWarn, true, "block"},
		{"ws_close", SeverityInfo, true, "allow"},
		{"ws_open", SeverityInfo, true, "allow"},
		{"ws_scan", SeverityWarn, true, "warn"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			severity, mapped := EventSeverity[tt.name]
			if severity != tt.severity || mapped != tt.mapped {
				t.Errorf("severity = %v, mapped = %v; want %v, %v", severity, mapped, tt.severity, tt.mapped)
			}
			if action := eventTypeAction(tt.name); action != tt.action {
				t.Errorf("action = %q, want %q", action, tt.action)
			}
		})
	}
}

func TestEventContractUnknownAndExplicitSeverity(t *testing.T) {
	for _, name := range []string{"extension_event", "chain_detection", "file_sentry_dlp", "cross_request_dlp_match", "dlp_credential_audience_allow", "dlp_issuer_cookie_allow", "entropy_issuer_query_allow"} {
		t.Run(name, func(t *testing.T) {
			sink := &mockSink{}
			emitter := NewEmitter("test", sink)
			emitter.Emit(context.Background(), name, nil)
			emitter.EmitWithSeverity(context.Background(), SeverityCritical, name, nil)
			events := sink.getEvents()
			if len(events) != 2 || events[0].Type != name || events[0].Severity != SeverityInfo || events[1].Severity != SeverityCritical {
				t.Fatalf("fallback/explicit severity: %+v", events)
			}
			if eventTypeAction(name) != "" {
				t.Fatal("extension unexpectedly classified")
			}
			if !(Filter{Actions: []string{"block"}}).Allows(events[0]) {
				t.Fatal("unknown event excluded from block-inclusive filter")
			}
		})
	}
}
