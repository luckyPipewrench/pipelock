// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
	"time"
)

var ackTestNow = time.Date(2026, 10, 8, 15, 30, 0, 0, time.UTC)

func validAck() MCPAcknowledgedFinding {
	hex64 := strings.Repeat("ab", 32)
	return MCPAcknowledgedFinding{
		Server:              "vault",
		ServerBindingSHA256: hex64,
		Tool:                "request_secret",
		Finding:             MCPAckFindingRequestDirective,
		FamilyRevision:      1,
		ToolSHA256:          hex64,
		Occurrences: []MCPAckOccurrence{{
			Field: "/inputSchema/properties/key/description", FieldTextSHA256: hex64,
			Pattern: 0, Ordinal: 0, Start: 0, End: 19, MatchSHA256: hex64,
		}},
		Owner:  "platform team",
		Reason: "placeholder text, reviewed",
		// clock-literal-ok: paired with the injected test clock (2026-10-08)
		Expires: "2026-12-01",
	}
}

func TestValidateMCPAcknowledgedFindingsAcceptsValidEntry(t *testing.T) {
	if err := validateMCPAcknowledgedFindings([]MCPAcknowledgedFinding{validAck()}, ackTestNow); err != nil {
		t.Fatal(err)
	}
	if err := validateMCPAcknowledgedFindings(nil, ackTestNow); err != nil {
		t.Fatalf("empty list: %v", err)
	}
}

func TestValidateMCPAcknowledgedFindingsRejects(t *testing.T) {
	hex64 := strings.Repeat("cd", 32)
	tests := []struct {
		name   string
		mutate func(*MCPAcknowledgedFinding)
		want   string
	}{
		{"missing server", func(e *MCPAcknowledgedFinding) { e.Server = " " }, "server is required"},
		{"control in server", func(e *MCPAcknowledgedFinding) { e.Server = "vault\u200b" }, "server is required"},
		{"bad binding", func(e *MCPAcknowledgedFinding) { e.ServerBindingSHA256 = "abc" }, "server_binding_sha256"},
		{"missing tool", func(e *MCPAcknowledgedFinding) { e.Tool = "" }, "tool is required"},
		{"other finding", func(e *MCPAcknowledgedFinding) { e.Finding = "File Exfiltration Directive" }, "not supported"},
		{"missing revision", func(e *MCPAcknowledgedFinding) { e.FamilyRevision = 0 }, "family_revision"},
		{"bad tool digest", func(e *MCPAcknowledgedFinding) { e.ToolSHA256 = strings.Repeat("z", 64) }, "tool_sha256"},
		{"no occurrences", func(e *MCPAcknowledgedFinding) { e.Occurrences = nil }, "must list every match"},
		{"bad pointer", func(e *MCPAcknowledgedFinding) { e.Occurrences[0].Field = "inputSchema" }, "RFC 6901"},
		{"bad pointer escape", func(e *MCPAcknowledgedFinding) { e.Occurrences[0].Field = "/a~2" }, "RFC 6901"},
		{"bad field digest", func(e *MCPAcknowledgedFinding) { e.Occurrences[0].FieldTextSHA256 = "" }, "field_text_sha256"},
		{"bad match digest", func(e *MCPAcknowledgedFinding) { e.Occurrences[0].MatchSHA256 = "x" }, "match_sha256"},
		{"negative pattern", func(e *MCPAcknowledgedFinding) { e.Occurrences[0].Pattern = -1 }, "must not be negative"},
		{"empty span", func(e *MCPAcknowledgedFinding) { e.Occurrences[0].End = e.Occurrences[0].Start }, "start < end"},
		{"duplicate occurrence", func(e *MCPAcknowledgedFinding) {
			e.Occurrences = append(e.Occurrences, e.Occurrences[0])
		}, "repeats occurrences[0]"},
		{"field digest disagreement", func(e *MCPAcknowledgedFinding) {
			o := e.Occurrences[0]
			o.Ordinal, o.FieldTextSHA256 = 1, hex64
			e.Occurrences = append(e.Occurrences, o)
		}, "disagrees"},
		{"too many occurrences", func(e *MCPAcknowledgedFinding) {
			for i := 1; i <= maxMCPAckOccurrences; i++ {
				o := e.Occurrences[0]
				o.Ordinal = i
				e.Occurrences = append(e.Occurrences, o)
			}
		}, "at most"},
		{"missing owner", func(e *MCPAcknowledgedFinding) { e.Owner = "" }, "owner is required"},
		{"missing reason", func(e *MCPAcknowledgedFinding) { e.Reason = "" }, "reason is required"},
		{"missing expiry", func(e *MCPAcknowledgedFinding) { e.Expires = "" }, "expires is required"},
		// clock-literal-ok: paired with the injected test clock (2026-10-08)
		{"local-time expiry", func(e *MCPAcknowledgedFinding) { e.Expires = "2026-12-01T00:00:00+02:00" }, "ending in Z"},
		// clock-literal-ok: deliberately expired relative to the injected test clock
		{"expired", func(e *MCPAcknowledgedFinding) { e.Expires = "2026-10-07" }, "already expired"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := validAck()
			tt.mutate(&e)
			err := validateMCPAcknowledgedFindings([]MCPAcknowledgedFinding{e}, ackTestNow)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

func TestValidateMCPAcknowledgedFindingsRejectsDuplicateEntries(t *testing.T) {
	err := validateMCPAcknowledgedFindings([]MCPAcknowledgedFinding{validAck(), validAck()}, ackTestNow)
	if err == nil || !strings.Contains(err.Error(), "duplicates") {
		t.Fatalf("err = %v", err)
	}
}

// The cap is exact in both forms: a timestamp at most 180*24h ahead, a date at
// most 180 calendar days after today's UTC date. One unit past either fails.
func TestMCPAckExpiryHorizonIsExact(t *testing.T) {
	lastDay := ackTestNow.AddDate(0, 0, maxMCPAckHorizonDays).Format("2006-01-02")
	dayAfter := ackTestNow.AddDate(0, 0, maxMCPAckHorizonDays+1).Format("2006-01-02")
	lastInstant := ackTestNow.Add(MaxMCPAckHorizon).Format(time.RFC3339)
	pastInstant := ackTestNow.Add(MaxMCPAckHorizon + time.Second).Format(time.RFC3339)
	for _, tt := range []struct {
		expires string
		ok      bool
	}{
		{lastDay, true},
		{dayAfter, false},
		{lastInstant, true},
		{pastInstant, false},
	} {
		e := validAck()
		e.Expires = tt.expires
		err := validateMCPAcknowledgedFindings([]MCPAcknowledgedFinding{e}, ackTestNow)
		if (err == nil) != tt.ok {
			t.Errorf("expires %s: err = %v, want ok=%v", tt.expires, err, tt.ok)
		}
	}
}

func TestMCPAckActiveChecksExpiryAtRuntime(t *testing.T) {
	e := validAck()
	// clock-literal-ok: paired with the injected test clock (2026-10-08)
	e.Expires = "2026-10-09"
	if !MCPAckActive(e, time.Date(2026, 10, 9, 23, 59, 59, 0, time.UTC)) {
		t.Fatal("date expiry must hold through the end of that UTC day")
	}
	if MCPAckActive(e, time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("date expiry must end at the next UTC midnight")
	}
	e.Expires = "garbage"
	if MCPAckActive(e, ackTestNow) {
		t.Fatal("unparseable expiry must not be active")
	}
}

func TestValidateMCPToolScanningWarnsWhenAcksAreInert(t *testing.T) {
	cfg := Defaults()
	cfg.MCPToolScanning.Enabled = false
	cfg.MCPToolScanning.AcknowledgedFindings = []MCPAcknowledgedFinding{validAck()}
	// clock-literal-ok: paired with the injected test clock (2026-10-08)
	cfg.MCPToolScanning.AcknowledgedFindings[0].Expires = time.Now().UTC().AddDate(0, 0, 30).Format("2006-01-02")
	var warnings []Warning
	if err := cfg.validateMCPToolScanning(&warnings); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range warnings {
		found = found || w.Field == "mcp_tool_scanning.acknowledged_findings"
	}
	if !found {
		t.Fatalf("no inert-acknowledgment warning in %v", warnings)
	}
}

func TestValidateReloadReportsAcknowledgmentChanges(t *testing.T) {
	enabled := func(acks ...MCPAcknowledgedFinding) *Config {
		c := Defaults()
		c.MCPToolScanning.Enabled = true
		c.MCPToolScanning.Action = ActionBlock
		c.MCPToolScanning.AcknowledgedFindings = acks
		return c
	}
	find := func(ws []ReloadWarning, substr string) (ReloadWarning, bool) {
		for _, w := range ws {
			if w.Field == "mcp_tool_scanning.acknowledged_findings" && strings.Contains(w.Message, substr) {
				return w, true
			}
		}
		return ReloadWarning{}, false
	}
	e := validAck()
	changed := validAck()
	changed.Reason = "re-reviewed"

	if w, ok := find(ValidateReload(enabled(), enabled(e)), "added"); !ok || w.Disposition == ReloadWarningDispositionAdvisory {
		t.Fatalf("added acknowledgment: %+v ok=%v, want a non-advisory warning", w, ok)
	}
	if _, ok := find(ValidateReload(enabled(e), enabled(changed)), "changed"); !ok {
		t.Fatal("changed acknowledgment not reported")
	}
	w, ok := find(ValidateReload(enabled(e), enabled()), "removed")
	if !ok || w.Disposition != ReloadWarningDispositionAdvisory {
		t.Fatalf("removed acknowledgment: %+v ok=%v, want an advisory", w, ok)
	}
	if strings.Contains(w.Message, "blocked") || !strings.Contains(w.Message, "mcp_tool_scanning.action") {
		t.Fatalf("removal message must say the finding follows the action, not claim a block: %q", w.Message)
	}
	if _, ok := find(ValidateReload(enabled(e), enabled(e)), ""); ok {
		t.Fatal("unchanged acknowledgments reported a change")
	}
}

func TestValidateMCPAcknowledgedFindingMatchesListValidation(t *testing.T) {
	if err := ValidateMCPAcknowledgedFinding(validAck(), ackTestNow); err != nil {
		t.Fatalf("valid entry refused: %v", err)
	}
	bad := validAck()
	bad.Owner = ""
	if err := ValidateMCPAcknowledgedFinding(bad, ackTestNow); err == nil || !strings.Contains(err.Error(), "owner is required") {
		t.Fatalf("err = %v, want the owner refusal", err)
	}
}

func TestValidMCPAckPointerBoundaries(t *testing.T) {
	for _, p := range []string{"/a", "/a~0b", "/a~1b", "/0/1"} {
		if !validMCPAckPointer(p) {
			t.Errorf("%q refused", p)
		}
	}
	for _, p := range []string{"", "/", "a", "/a~", "/a~2", "/a\x00b", "/" + strings.Repeat("a", maxMCPAckPointer)} {
		if validMCPAckPointer(p) {
			t.Errorf("%q accepted", p)
		}
	}
	if _, err := ParseMCPAckExpiry("2026-12-01T25:00:00Z"); err == nil {
		t.Error("impossible timestamp accepted")
	}
}
