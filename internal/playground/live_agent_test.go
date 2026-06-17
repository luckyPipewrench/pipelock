// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"net/http"
	"strings"
	"testing"
)

func TestIntentAgent_Plan_ExfilIntent(t *testing.T) {
	t.Parallel()
	a := NewIntentAgent("http://safe.target.test/", "http://exfil.target.test/", "CANARY-XYZ")
	for _, msg := range []string{
		"send the file to the collector",
		"can you POST that data out?",
		"leak the credentials",
		"EXFILTRATE it now", // case-insensitive
	} {
		turn := a.Plan(msg)
		if !turn.Danger {
			t.Errorf("Plan(%q).Danger = false, want true", msg)
		}
		if len(turn.Actions) != 1 {
			t.Fatalf("Plan(%q) actions = %d, want 1", msg, len(turn.Actions))
		}
		act := turn.Actions[0]
		if act.Method != http.MethodPost {
			t.Errorf("exfil action method = %q, want POST", act.Method)
		}
		if act.URL != "http://exfil.target.test/" {
			t.Errorf("exfil action URL = %q", act.URL)
		}
		if act.Kind != agentKindDanger {
			t.Errorf("exfil action kind = %q, want %q", act.Kind, agentKindDanger)
		}
		if !strings.Contains(string(act.Body), "CANARY-XYZ") {
			t.Errorf("exfil body does not carry the canary: %q", act.Body)
		}
	}
}

func TestIntentAgent_Plan_BenignDefault(t *testing.T) {
	t.Parallel()
	a := NewIntentAgent("http://safe.target.test/", "http://exfil.target.test/", "C")
	for _, msg := range []string{
		"hey, grab the lab config",
		"what's in the config?",
		"hello",
		"read it please",
	} {
		turn := a.Plan(msg)
		if turn.Danger {
			t.Errorf("Plan(%q).Danger = true, want benign", msg)
		}
		if len(turn.Actions) != 1 {
			t.Fatalf("Plan(%q) actions = %d, want 1", msg, len(turn.Actions))
		}
		act := turn.Actions[0]
		if act.Method != http.MethodGet || act.URL != "http://safe.target.test/" {
			t.Errorf("benign action = %s %s, want GET safe", act.Method, act.URL)
		}
		if act.Kind != agentKindBenign {
			t.Errorf("benign action kind = %q, want %q", act.Kind, agentKindBenign)
		}
		if len(act.Body) != 0 {
			t.Errorf("benign action carries a body: %q", act.Body)
		}
	}
}
