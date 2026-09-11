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

			cancelled := false
			s.airlock.RegisterCancel(func() { cancelled = true })

			s.Reset(tt.cancelInFlight)

			if cancelled != tt.wantCancelled {
				t.Fatalf("in-flight connection cancelled=%t, want %t", cancelled, tt.wantCancelled)
			}

			// Either way the callbacks must be dropped, or a later escalation
			// re-fires a cancel registered before the reset.
			s.airlock.mu.Lock()
			remaining := len(s.airlock.cancelFuncs)
			s.airlock.mu.Unlock()
			if remaining != 0 {
				t.Fatalf("reset left %d cancel func(s) registered; a later escalation would re-fire them", remaining)
			}
		})
	}
}
