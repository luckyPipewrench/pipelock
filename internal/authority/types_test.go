// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package authority

import (
	"encoding/json"
	"testing"
)

func TestDecisionJSONRoundTrip(t *testing.T) {
	t.Parallel()
	for _, decision := range []Decision{DecisionIndeterminate, DecisionAllow, DecisionDeny} {
		decision := decision
		t.Run(decision.String(), func(t *testing.T) {
			t.Parallel()
			encoded, err := json.Marshal(decision)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var decoded Decision
			if err := json.Unmarshal(encoded, &decoded); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if decoded != decision {
				t.Fatalf("round trip=%v, want %v", decoded, decision)
			}
		})
	}
}

func TestDecisionRejectsUnknownValues(t *testing.T) {
	t.Parallel()
	if got := Decision(99).String(); got != "invalid" {
		t.Fatalf("invalid decision string=%q", got)
	}
	if _, err := json.Marshal(Decision(99)); err == nil {
		t.Fatal("marshal invalid decision error=nil")
	}
	var decision Decision
	if err := json.Unmarshal([]byte(`"permit"`), &decision); err == nil {
		t.Fatal("unmarshal unknown decision error=nil")
	}
	if err := json.Unmarshal([]byte(`1`), &decision); err == nil {
		t.Fatal("unmarshal non-string decision error=nil")
	}
}
