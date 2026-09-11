// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"testing"
)

// POST /api/v1/sessions/{key}/reset is documented as clearing enforcement state
// WITHOUT cutting connections, and `pipelock session reset` is the command an
// operator reaches for when a destination scope has locked a session out. Both
// reset paths previously fired every registered airlock cancel function, so the
// recovery command also tore down the session's in-flight work.
//
// The two halves are separable and the distinction is the whole point: FIRING
// the callbacks kills live requests and tunnels, while CLEARING them is what
// stops a stale callback re-firing on a later hard or drain escalation. Only
// the clearing is a safety requirement, so both paths must still clear.
func TestReset_LeavesInFlightConnectionsAlone(t *testing.T) {
	for _, tt := range []struct {
		name           string
		cancelInFlight bool
		wantCancelled  bool
	}{
		{name: "reset keeps connections up", cancelInFlight: false, wantCancelled: false},
		{name: "terminate tears connections down", cancelInFlight: true, wantCancelled: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := &SessionState{kind: sessionKindIdentity}

			// Both lanes matter and they are separate code paths in Reset.
			// Adaptive escalation writes the tier PER DESTINATION SCOPE, so a
			// real session's live connections hang off the scoped airlock; a
			// test that only registers a global callback passes even when the
			// scoped branch still tears connections down.
			globalCancelled := false
			s.airlock.RegisterCancel(func() { globalCancelled = true })

			scopedCancelled := false
			scoped := s.AirlockForScope("api.example")
			if scoped == nil {
				t.Fatal("AirlockForScope returned nil; cannot exercise the scoped branch")
			}
			scoped.RegisterCancel(func() { scopedCancelled = true })

			s.Reset(tt.cancelInFlight)

			if globalCancelled != tt.wantCancelled {
				t.Errorf("global in-flight connection cancelled=%t, want %t", globalCancelled, tt.wantCancelled)
			}
			if scopedCancelled != tt.wantCancelled {
				t.Errorf("scoped in-flight connection cancelled=%t, want %t", scopedCancelled, tt.wantCancelled)
			}

			// Either way the callbacks must be dropped, or a later escalation
			// re-fires a cancel registered before the reset.
			s.airlock.mu.Lock()
			remaining := len(s.airlock.cancelFuncs)
			s.airlock.mu.Unlock()
			if remaining != 0 {
				t.Errorf("reset left %d global cancel func(s) registered; a later escalation would re-fire them", remaining)
			}

			// Reset drops s.scopes entirely, so the scoped callbacks go with
			// it. Assert on the slice captured above rather than re-reading
			// through the session, which would find no scope at all and pass
			// for the wrong reason.
			scoped.mu.Lock()
			scopedRemaining := len(scoped.cancelFuncs)
			scoped.mu.Unlock()
			if scopedRemaining != 0 {
				t.Errorf("reset left %d scoped cancel func(s) registered", scopedRemaining)
			}
		})
	}
}
