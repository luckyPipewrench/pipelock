//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package emergency

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
)

// writeEnrolledMarker drops a minimal enrollment marker next to the replay
// state path, reproducing the on-disk shape of a follower that has enrolled.
func writeEnrolledMarker(t *testing.T, statePath string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(filepath.Dir(statePath), "enrolled.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write enrolled.json: %v", err)
	}
}

// TestEnrolledFollowerWithoutBaselineWedges documents the bug: a follower that
// has enrolled (marker present) but never received a kill (no replay state)
// fails closed on restart with no recovery path. This is the failure the
// InitializeReplayBaseline fix prevents.
func TestEnrolledFollowerWithoutBaselineWedges(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), RemoteKillStateFileName)
	writeEnrolledMarker(t, statePath)

	applier := &RemoteKillApplier{KillSwitch: &captureKillSwitch{}, StatePath: statePath}
	err := applier.RestorePersistedState()
	if err == nil || !strings.Contains(err.Error(), "replay state missing while follower context is present") {
		t.Fatalf("RestorePersistedState() error = %v, want enrolled-without-baseline wedge", err)
	}
}

// TestInitializeReplayBaselinePreventsRestartWedge proves the fix: after the
// baseline is written at enrollment, an enrolled follower restarts cleanly and
// the kill switch stays inactive (no spurious kill from the baseline).
func TestInitializeReplayBaselinePreventsRestartWedge(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), RemoteKillStateFileName)
	writeEnrolledMarker(t, statePath)

	if err := InitializeReplayBaseline(statePath, testNow); err != nil {
		t.Fatalf("InitializeReplayBaseline: %v", err)
	}

	ks := &captureKillSwitch{}
	applier := &RemoteKillApplier{KillSwitch: ks, StatePath: statePath}
	if err := applier.RestorePersistedState(); err != nil {
		t.Fatalf("RestorePersistedState() after baseline error = %v, want nil", err)
	}
	if ks.active {
		t.Fatalf("kill switch active after baseline restore, want inactive")
	}

	// The baseline is counter 0 / no decision, so the first real remote-kill
	// (counter > 0) still advances normally — equivalent to a never-enrolled
	// fresh follower, which the existing Apply tests already cover.
	st, err := readRemoteKillStateFile(statePath)
	if err != nil {
		t.Fatalf("readRemoteKillStateFile: %v", err)
	}
	if st.LastCounter != 0 || st.LastMessageHash != "" || st.State != conductor.KillSwitchInactive {
		t.Fatalf("baseline = counter=%d hash=%q state=%q, want 0/empty/inactive", st.LastCounter, st.LastMessageHash, st.State)
	}
}

// TestInitializeReplayBaselineDoesNotClobberExistingState is the replay-safety
// guard: if a real kill decision already exists, the baseline call must be a
// no-op. Overwriting it would reset the replay counter — a kill-switch replay
// hole.
func TestInitializeReplayBaselineDoesNotClobberExistingState(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), RemoteKillStateFileName)
	if err := writeRemoteKillState(statePath, remoteKillState{
		LastCounter:     9,
		LastMessageHash: strings.Repeat("b", 64),
		State:           conductor.KillSwitchActive,
		Reason:          "real kill",
		AppliedAt:       testNow,
	}); err != nil {
		t.Fatalf("writeRemoteKillState: %v", err)
	}

	if err := InitializeReplayBaseline(statePath, testNow.Add(time.Hour)); err != nil {
		t.Fatalf("InitializeReplayBaseline: %v", err)
	}

	st, err := readRemoteKillStateFile(statePath)
	if err != nil {
		t.Fatalf("readRemoteKillStateFile: %v", err)
	}
	if st.LastCounter != 9 || st.State != conductor.KillSwitchActive || st.Reason != "real kill" {
		t.Fatalf("existing kill state clobbered: counter=%d state=%q reason=%q", st.LastCounter, st.State, st.Reason)
	}

	ks := &captureKillSwitch{}
	applier := &RemoteKillApplier{KillSwitch: ks, StatePath: statePath}
	if err := applier.RestorePersistedState(); err != nil {
		t.Fatalf("RestorePersistedState: %v", err)
	}
	if !ks.active || ks.message != "real kill" {
		t.Fatalf("restored kill switch = active=%v message=%q, want preserved active kill", ks.active, ks.message)
	}
}

// TestInitializeReplayBaselineIdempotent: a second call is a no-op and never
// errors, so repeated enrollment attempts cannot reset the counter.
func TestInitializeReplayBaselineIdempotent(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), RemoteKillStateFileName)
	writeEnrolledMarker(t, statePath)

	if err := InitializeReplayBaseline(statePath, testNow); err != nil {
		t.Fatalf("InitializeReplayBaseline (first): %v", err)
	}
	if err := InitializeReplayBaseline(statePath, testNow.Add(time.Hour)); err != nil {
		t.Fatalf("InitializeReplayBaseline (second): %v", err)
	}

	st, err := readRemoteKillStateFile(statePath)
	if err != nil {
		t.Fatalf("readRemoteKillStateFile: %v", err)
	}
	if st.LastCounter != 0 || st.LastMessageHash != "" || st.State != conductor.KillSwitchInactive {
		t.Fatalf("baseline drifted after second call: counter=%d hash=%q state=%q", st.LastCounter, st.LastMessageHash, st.State)
	}
}
