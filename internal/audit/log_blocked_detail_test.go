// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"testing"
)

// TestLogBlockedDetail_InfrastructureErrorOmitsMITRETechnique pins the
// headline label fix from issue #440: a DNS resolver wobble blocked by the
// SSRF layer must not emit mitre_technique=T1046, because the resolver had no
// data to support a Network Service Discovery finding. The scanner label
// stays "ssrf" so existing suppression / metrics / receipts keep working;
// only the display label and the MITRE field change.
func TestLogBlockedDetail_InfrastructureErrorOmitsMITRETechnique(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name             string
		dnsKind          string
		wantDisplayLabel string
	}{
		{"dns timeout", "timeout", "dns_timeout"},
		{"dns no such host", "no_such_host", "dns_no_such_host"},
		{"dns generic resolver error", "resolver_error", "dns_resolver_error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			logger, sink := newLoggerWithEmitter(t)
			defer logger.Close()

			logger.LogBlockedDetail(
				LogContext{method: testMethodGet, url: "https://openrouter.ai", clientIP: testClientIP, requestID: "req-dns-1"},
				"ssrf",
				"DNS lookup for openrouter.ai timed out",
				BlockDetail{Class: BlockClassInfrastructureError, DNSErrorKind: tc.dnsKind},
			)
			ev, ok := sink.lastEvent()
			if !ok {
				t.Fatal("expected emitted event")
			}
			if ev.Fields["scanner"] != "ssrf" {
				t.Errorf("scanner label must stay ssrf; got %v", ev.Fields["scanner"])
			}
			if tech, present := ev.Fields["mitre_technique"]; present && tech != "" {
				t.Errorf("infrastructure_error must NOT carry mitre_technique; got %v", tech)
			}
			if got := ev.Fields["display_label"]; got != tc.wantDisplayLabel {
				t.Errorf("display_label = %v, want %s", got, tc.wantDisplayLabel)
			}
		})
	}
}

// TestLogBlockedDetail_ThreatClassKeepsMITRETechnique guards against the
// regression where the no-MITRE behavior leaks onto a real SSRF block. A
// hostname that resolves to an internal CIDR is a genuine T1046 attempt, and
// the audit stream must still tag it.
func TestLogBlockedDetail_ThreatClassKeepsMITRETechnique(t *testing.T) {
	t.Parallel()
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()

	logger.LogBlockedDetail(
		LogContext{method: testMethodGet, url: "https://internal.example", clientIP: testClientIP, requestID: "req-ssrf-1"},
		"ssrf",
		"SSRF blocked: internal.example resolves to internal IP 10.0.0.5",
		BlockDetail{Class: BlockClassThreat},
	)
	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if ev.Fields["mitre_technique"] != "T1046" {
		t.Errorf("real SSRF must still emit mitre_technique=T1046; got %v", ev.Fields["mitre_technique"])
	}
	if got, present := ev.Fields["display_label"]; present && got != "" {
		t.Errorf("threat-class block must not surface a display_label; got %v", got)
	}
}

// TestLogBlockedDetail_LegacyLogBlockedKeepsMITRE_T1046 confirms the legacy
// LogBlocked wrapper still behaves exactly as before: the zero BlockDetail
// has Class="" which maps to threat semantics, so any SSRF block emitted via
// the old signature keeps emitting T1046.
func TestLogBlockedDetail_LegacyLogBlockedKeepsMITRE_T1046(t *testing.T) {
	t.Parallel()
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()

	logger.LogBlocked(
		LogContext{method: testMethodGet, url: "https://internal.example", clientIP: testClientIP, requestID: "req-ssrf-2"},
		"ssrf",
		"SSRF blocked: internal.example resolves to internal IP 10.0.0.5",
	)
	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if ev.Fields["mitre_technique"] != "T1046" {
		t.Errorf("legacy LogBlocked wrapper must keep T1046 on threat class; got %v", ev.Fields["mitre_technique"])
	}
}

// TestLogBlockedDetail_ProtectiveAndConfigMismatchOmitMITRE captures a
// secondary improvement: protective (rate limit) and config-mismatch
// (api_allowlist gap) blocks are not threat evidence either. They were
// already classified internally; this surfaces that classification in the
// audit emit too, so SIEMs aggregating on mitre_technique do not see
// spurious values for non-adversarial blocks.
func TestLogBlockedDetail_ProtectiveAndConfigMismatchOmitMITRE(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		class string
	}{
		{"protective", BlockClassProtective},
		{"config mismatch", BlockClassConfigMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			logger, sink := newLoggerWithEmitter(t)
			defer logger.Close()
			logger.LogBlockedDetail(
				LogContext{method: testMethodGet, url: "https://api.example.com", clientIP: testClientIP, requestID: "req-x"},
				"ssrf",
				"protective block",
				BlockDetail{Class: tc.class},
			)
			ev, ok := sink.lastEvent()
			if !ok {
				t.Fatal("expected emitted event")
			}
			if tech, present := ev.Fields["mitre_technique"]; present && tech != "" {
				t.Errorf("%s class must not carry mitre_technique; got %v", tc.name, tech)
			}
		})
	}
}
