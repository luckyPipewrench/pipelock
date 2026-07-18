//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package emergency

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	msg, resolver := signedRemoteKill(t, 9, conductor.KillSwitchActive)
	statePath := filepath.Join(t.TempDir(), RemoteKillStateFileName)
	// A real, signature-verified kill decision already exists.
	if err := (&RemoteKillApplier{
		OrgID:      "org-main",
		FleetID:    "prod",
		InstanceID: "pl-prod-1",
		Resolver:   resolver,
		KillSwitch: &captureKillSwitch{},
		StatePath:  statePath,
		Now:        func() time.Time { return testNow },
	}).Apply(msg); err != nil {
		t.Fatalf("Apply(existing kill): %v", err)
	}

	if err := InitializeReplayBaseline(statePath, testNow.Add(time.Hour)); err != nil {
		t.Fatalf("InitializeReplayBaseline: %v", err)
	}

	st, err := readRemoteKillStateFile(statePath)
	if err != nil {
		t.Fatalf("readRemoteKillStateFile: %v", err)
	}
	if st.LastCounter != 9 || st.State != conductor.KillSwitchActive || st.Reason != msg.Reason {
		t.Fatalf("existing kill state clobbered: counter=%d state=%q reason=%q", st.LastCounter, st.State, st.Reason)
	}

	ks := &captureKillSwitch{}
	applier := &RemoteKillApplier{
		OrgID:      "org-main",
		FleetID:    "prod",
		InstanceID: "pl-prod-1",
		Resolver:   resolver,
		KillSwitch: ks,
		StatePath:  statePath,
		Now:        func() time.Time { return testNow },
	}
	if err := applier.RestorePersistedState(); err != nil {
		t.Fatalf("RestorePersistedState: %v", err)
	}
	if !ks.active || ks.message != msg.Reason {
		t.Fatalf("restored kill switch = active=%v message=%q, want preserved active kill", ks.active, ks.message)
	}
}

// TestResetReplayStateToBaseline is the operator recovery: force-overwrite an
// existing (even active-kill) replay state with a clean baseline so a wedged
// follower can boot. The Conductor re-syncs the authoritative state on next poll.
func TestResetReplayStateToBaseline(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), RemoteKillStateFileName)
	// Pre-existing active kill state (the thing the operator is deliberately resetting).
	if err := writeRemoteKillState(statePath, remoteKillState{
		LastCounter:     5,
		LastMessageHash: strings.Repeat("c", 64),
		State:           conductor.KillSwitchActive,
		Reason:          "stuck kill",
		AppliedAt:       testNow,
	}); err != nil {
		t.Fatalf("writeRemoteKillState: %v", err)
	}

	if err := ResetReplayStateToBaseline(statePath, testNow.Add(time.Hour)); err != nil {
		t.Fatalf("ResetReplayStateToBaseline: %v", err)
	}

	st, err := readRemoteKillStateFile(statePath)
	if err != nil {
		t.Fatalf("readRemoteKillStateFile: %v", err)
	}
	if st.LastCounter != 0 || st.LastMessageHash != "" || st.State != conductor.KillSwitchInactive {
		t.Fatalf("reset baseline = counter=%d hash=%q state=%q, want 0/empty/inactive", st.LastCounter, st.LastMessageHash, st.State)
	}

	// The follower now boots clean (no wedge, kill switch not spuriously active).
	ks := &captureKillSwitch{}
	applier := &RemoteKillApplier{KillSwitch: ks, StatePath: statePath}
	if err := applier.RestorePersistedState(); err != nil {
		t.Fatalf("RestorePersistedState() after reset error = %v, want nil", err)
	}
	if ks.active {
		t.Fatal("kill switch active after reset-to-baseline, want inactive (re-sync from Conductor restores a live kill)")
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

func TestInitializeReplayBaselineConcurrentApplyPreservesKillState(t *testing.T) {
	msg, resolver := signedRemoteKill(t, 17, conductor.KillSwitchActive)
	statePath := filepath.Join(t.TempDir(), RemoteKillStateFileName)

	start := make(chan struct{})
	errs := make(chan error, 17)
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- InitializeReplayBaseline(statePath, testNow)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		applier := &RemoteKillApplier{
			OrgID:      "org-main",
			FleetID:    "prod",
			InstanceID: "pl-prod-1",
			Resolver:   resolver,
			KillSwitch: &captureKillSwitch{},
			StatePath:  statePath,
			Now:        func() time.Time { return testNow },
		}
		errs <- applier.Apply(msg)
	}()

	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent baseline/apply error = %v", err)
		}
	}
	st, err := readDurableRemoteKillState(statePath)
	if err != nil {
		t.Fatalf("readDurableRemoteKillState: %v", err)
	}
	if st.LastCounter != msg.Counter || st.State != conductor.KillSwitchActive || st.Reason != msg.Reason {
		t.Fatalf("state after concurrent baseline/apply = counter=%d state=%q reason=%q, want applied kill", st.LastCounter, st.State, st.Reason)
	}
}

func TestReadDurableRemoteKillStateConcurrentBackfillAndApply(t *testing.T) {
	msg, resolver := signedRemoteKill(t, 17, conductor.KillSwitchActive)
	statePath := filepath.Join(t.TempDir(), RemoteKillStateFileName)

	if err := writeRemoteKillStateFileForContext(statePath, filepath.Clean(statePath), remoteKillState{
		LastCounter:     11,
		LastMessageHash: strings.Repeat("d", 64),
		State:           conductor.KillSwitchInactive,
		Reason:          "primary only",
		AppliedAt:       testNow.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("write primary-only remote kill state: %v", err)
	}

	start := make(chan struct{})
	errs := make(chan error, 17)
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := readDurableRemoteKillState(statePath)
			errs <- err
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		applier := &RemoteKillApplier{
			OrgID:      "org-main",
			FleetID:    "prod",
			InstanceID: "pl-prod-1",
			Resolver:   resolver,
			KillSwitch: &captureKillSwitch{},
			StatePath:  statePath,
			Now:        func() time.Time { return testNow },
		}
		errs <- applier.Apply(msg)
	}()

	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent backfill/apply error = %v", err)
		}
	}
	st, err := readDurableRemoteKillState(statePath)
	if err != nil {
		t.Fatalf("readDurableRemoteKillState: %v", err)
	}
	if st.LastCounter != msg.Counter || st.State != conductor.KillSwitchActive || st.Reason != msg.Reason {
		t.Fatalf("state after concurrent backfill/apply = counter=%d state=%q reason=%q, want applied kill", st.LastCounter, st.State, st.Reason)
	}
}
