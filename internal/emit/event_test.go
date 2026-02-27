package emit

import "testing"

func TestSeverity_String(t *testing.T) {
	tests := []struct {
		name string
		sev  Severity
		want string
	}{
		{name: "info", sev: SeverityInfo, want: "info"},
		{name: "warn", sev: SeverityWarn, want: "warn"},
		{name: "critical", sev: SeverityCritical, want: "critical"},
		{name: "unknown defaults to info", sev: Severity(99), want: "info"},
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
		{name: "info", input: "info", want: SeverityInfo},
		{name: "warn", input: "warn", want: SeverityWarn},
		{name: "critical", input: "critical", want: SeverityCritical},
		{name: "empty string defaults to info", input: "", want: SeverityInfo},
		{name: "unknown defaults to info", input: "emergency", want: SeverityInfo},
		{name: "uppercase WARN", input: "WARN", want: SeverityWarn},
		{name: "mixed case Critical", input: "Critical", want: SeverityCritical},
		{name: "uppercase INFO", input: "INFO", want: SeverityInfo},
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
	//nolint:goconst // test values
	expectedTypes := []struct {
		eventType string
		wantSev   Severity
	}{
		// Critical
		{"kill_switch_deny", SeverityCritical},

		// Warn
		{"blocked", SeverityWarn},
		{"anomaly", SeverityWarn},
		{"session_anomaly", SeverityWarn},
		{"mcp_unknown_tool", SeverityWarn},
		{"ws_blocked", SeverityWarn},
		{"response_scan", SeverityWarn},
		{"ws_scan", SeverityWarn},
		{"adaptive_escalation", SeverityWarn},
		{"error", SeverityWarn},

		// Info
		{"allowed", SeverityInfo},
		{"tunnel_open", SeverityInfo},
		{"tunnel_close", SeverityInfo},
		{"ws_open", SeverityInfo},
		{"ws_close", SeverityInfo},
		{"config_reload", SeverityInfo},
		{"redirect", SeverityInfo},
		{"forward_http", SeverityInfo},
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
		"kill_switch_deny":    true,
		"blocked":             true,
		"anomaly":             true,
		"session_anomaly":     true,
		"mcp_unknown_tool":    true,
		"ws_blocked":          true,
		"response_scan":       true,
		"ws_scan":             true,
		"adaptive_escalation": true,
		"error":               true,
		"allowed":             true,
		"tunnel_open":         true,
		"tunnel_close":        true,
		"ws_open":             true,
		"ws_close":            true,
		"config_reload":       true,
		"redirect":            true,
		"forward_http":        true,
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
		{name: "block is critical", action: "block", want: SeverityCritical},
		{name: "warn is warn", action: "warn", want: SeverityWarn},
		{name: "log is warn", action: "log", want: SeverityWarn},
		{name: "empty is warn", action: "", want: SeverityWarn},
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
		name    string
		toLevel string
		want    Severity
	}{
		{name: "block is critical", toLevel: "block", want: SeverityCritical},
		{name: "warn is warn", toLevel: "warn", want: SeverityWarn},
		{name: "throttle is warn", toLevel: "throttle", want: SeverityWarn},
		{name: "empty is warn", toLevel: "", want: SeverityWarn},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EscalationSeverity(tt.toLevel); got != tt.want {
				t.Errorf("EscalationSeverity(%q) = %v, want %v", tt.toLevel, got, tt.want)
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
