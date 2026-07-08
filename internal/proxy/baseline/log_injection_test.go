// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package baseline

import (
	"strings"
	"testing"
)

func TestSanitizeLogValueStripsCRLF(t *testing.T) {
	got := sanitizeLogValue("agent\r\nInjected: forged log line")
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("sanitizeLogValue left a line break: %q", got)
	}
	if got != "agent  Injected: forged log line" {
		t.Fatalf("sanitizeLogValue = %q, want CR/LF replaced with spaces", got)
	}
}

// sanitizeLogAttrs is the class-fix: every agent-influenced identifier logged
// through integrityLogAttrs (agent_key, declared_agent_key, profile names) must
// have CR/LF neutralized so it cannot forge or split a log line, while
// non-string values pass through unchanged and the caller's slice is not
// mutated.
func TestSanitizeLogAttrsNeutralizesStringValues(t *testing.T) {
	in := []any{
		"agent_key", "evil\nforged_admin=true",
		"generation", 7,
		"declared_agent_key", "a\rb",
	}
	out := sanitizeLogAttrs(in)

	for i, a := range out {
		if s, ok := a.(string); ok && strings.ContainsAny(s, "\r\n") {
			t.Fatalf("attr[%d] retained a line break after sanitize: %q", i, s)
		}
	}
	if out[3] != 7 {
		t.Fatalf("non-string attr value was mutated: got %v, want 7", out[3])
	}
	// The caller's original slice must be untouched (sanitizeLogAttrs copies).
	if in[1] != "evil\nforged_admin=true" {
		t.Fatalf("sanitizeLogAttrs mutated the caller's input: %q", in[1])
	}
}
