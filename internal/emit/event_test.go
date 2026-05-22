// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package emit

import "testing"

func TestSeverity_String(t *testing.T) {
	tests := []struct {
		name string
		sev  Severity
		want string
	}{
		{name: severityNameInfo, sev: SeverityInfo, want: severityNameInfo},
		{name: testSeverityWarn, sev: SeverityWarn, want: testSeverityWarn},
		{name: severityNameCritical, sev: SeverityCritical, want: severityNameCritical},
		{name: testCaseUnknownInfo, sev: Severity(99), want: severityNameInfo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.sev.String(); got != tt.want {
				t.Errorf("Severity(%d).String() = %q, want %q", tt.sev, got, tt.want)
			}
		})
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  Severity
	}{
		{name: severityNameInfo, input: severityNameInfo, want: SeverityInfo},
		{name: testSeverityWarn, input: testSeverityWarn, want: SeverityWarn},
		{name: severityNameCritical, input: severityNameCritical, want: SeverityCritical},
		{name: "empty string defaults to info", input: "", want: SeverityInfo},
		{name: testCaseUnknownInfo, input: "emergency", want: SeverityInfo},
		{name: "uppercase WARN", input: otlpSeverityTextWarn, want: SeverityWarn},
		{name: "mixed case Critical", input: "Critical", want: SeverityCritical},
		{name: "uppercase INFO", input: otlpSeverityTextInfo, want: SeverityInfo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseSeverity(tt.input); got != tt.want {
				t.Errorf("ParseSeverity(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseSeverity_Roundtrip(t *testing.T) {
	for _, sev := range []Severity{SeverityInfo, SeverityWarn, SeverityCritical} {
		t.Run(sev.String(), func(t *testing.T) {
			if got := ParseSeverity(sev.String()); got != sev {
				t.Errorf("ParseSeverity(%q) = %d, want %d", sev.String(), got, sev)
			}
		})
	}
}

func TestEventSeverity_CoverExpectedTypes(t *testing.T) {
	expectedTypes := []struct {
		eventType string
		wantSev   Severity
	}{
		// Critical
		{EventKillSwitchDeny, SeverityCritical},

		// Warn
		{testEventBlocked, SeverityWarn},
		{EventAnomaly, SeverityWarn},
		{EventSessionAnomaly, SeverityWarn},
		{EventMCPUnknownTool, SeverityWarn},
		{EventWSBlocked, SeverityWarn},
		{EventResponseScan, SeverityWarn},
		{EventWSScan, SeverityWarn},
		{EventAdaptiveEscalation, SeverityWarn},
		{EventAdaptiveUpgrade, SeverityWarn},
		{"error", SeverityWarn},

		// Warn: security-relevant operational
		{"response_scan_exempt", SeverityWarn},

		// Info
		{verdictAllowed, SeverityInfo},
		{EventTunnelOpen, SeverityInfo},
		{"tunnel_close", SeverityInfo},
		{EventWSOpen, SeverityInfo},
		{EventWSClose, SeverityInfo},
		{"config_reload", SeverityInfo},
		{EventRedirect, SeverityInfo},
		{"forward_http", SeverityInfo},
		{"tool_redirect", SeverityInfo},
	}

	for _, tt := range expectedTypes {
		t.Run(tt.eventType, func(t *testing.T) {
			sev, ok := EventSeverity[tt.eventType]
			if !ok {
				t.Fatalf("EventSeverity missing entry for %q", tt.eventType)
			}
			if sev != tt.wantSev {
				t.Errorf("EventSeverity[%q] = %v, want %v", tt.eventType, sev, tt.wantSev)
			}
		})
	}
}

func TestEventSeverity_NoUnexpectedEntries(t *testing.T) {
	known := map[string]bool{
		EventKillSwitchDeny:     true,
		testEventBlocked:        true,
		EventAnomaly:            true,
		EventSessionAnomaly:     true,
		EventMCPUnknownTool:     true,
		EventWSBlocked:          true,
		EventResponseScan:       true,
		EventWSScan:             true,
		EventAdaptiveEscalation: true,
		EventAdaptiveUpgrade:    true,
		"error":                 true,
		"response_scan_exempt":  true,
		EventMediaExposure:      true,
		EventTextStego:          true,
		verdictAllowed:          true,
		EventTunnelOpen:         true,
		"tunnel_close":          true,
		EventWSOpen:             true,
		EventWSClose:            true,
		"config_reload":         true,
		EventRedirect:           true,
		"forward_http":          true,
		"tool_redirect":         true,
	}

	for k := range EventSeverity {
		if !known[k] {
			t.Errorf("EventSeverity contains unexpected key %q — add it to tests", k)
		}
	}
}

func TestChainDetectionSeverity(t *testing.T) {
	tests := []struct {
		name   string
		action string
		want   Severity
	}{
		{name: testCaseBlockIsCritical, action: conventionVerdictBlocked, want: SeverityCritical},
		{name: testCaseWarnIsWarn, action: testSeverityWarn, want: SeverityWarn},
		{name: "log is warn", action: "log", want: SeverityWarn},
		{name: testCaseEmptyIsWarn, action: "", want: SeverityWarn},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ChainDetectionSeverity(tt.action); got != tt.want {
				t.Errorf("ChainDetectionSeverity(%q) = %v, want %v", tt.action, got, tt.want)
			}
		})
	}
}

func TestEscalationSeverity(t *testing.T) {
	tests := []struct {
		name     string
		toAction string
		want     Severity
	}{
		{name: testCaseBlockIsCritical, toAction: conventionVerdictBlocked, want: SeverityCritical},
		{name: testCaseWarnIsWarn, toAction: testSeverityWarn, want: SeverityWarn},
		{name: "throttle is warn", toAction: "throttle", want: SeverityWarn},
		{name: testCaseEmptyIsWarn, toAction: "", want: SeverityWarn},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EscalationSeverity(tt.toAction); got != tt.want {
				t.Errorf("EscalationSeverity(%q) = %v, want %v", tt.toAction, got, tt.want)
			}
		})
	}
}

func TestDefaultInstanceID_NonEmpty(t *testing.T) {
	id := DefaultInstanceID()
	if id == "" {
		t.Error("DefaultInstanceID() returned empty string")
	}
}

func TestUpgradeSeverity(t *testing.T) {
	tests := []struct {
		name     string
		toAction string
		want     Severity
	}{
		{name: testCaseBlockIsCritical, toAction: conventionVerdictBlocked, want: SeverityCritical},
		{name: testCaseWarnIsWarn, toAction: testSeverityWarn, want: SeverityWarn},
		{name: "strip is warn", toAction: testActionStrip, want: SeverityWarn},
		{name: testCaseEmptyIsWarn, toAction: "", want: SeverityWarn},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := UpgradeSeverity(tt.toAction); got != tt.want {
				t.Errorf("UpgradeSeverity(%q) = %v, want %v", tt.toAction, got, tt.want)
			}
		})
	}
}

func TestEventAdaptiveUpgrade_InMap(t *testing.T) {
	sev, ok := EventSeverity[EventAdaptiveUpgrade]
	if !ok {
		t.Fatalf("EventSeverity missing entry for EventAdaptiveUpgrade (%q)", EventAdaptiveUpgrade)
	}
	if sev != SeverityWarn {
		t.Errorf("EventSeverity[EventAdaptiveUpgrade] = %v, want warn", sev)
	}
}
