//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package emergency

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

var testNow = time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)

type captureKillSwitch struct {
	active  bool
	message string
}

func (c *captureKillSwitch) SetConductorRemote(active bool, message string) {
	c.active = active
	c.message = message
}

type blockingKillSwitch struct {
	reached chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingKillSwitch) SetConductorRemote(bool, string) {
	b.once.Do(func() { close(b.reached) })
	<-b.release
}

func TestRemoteKillApplier(t *testing.T) {
	msg, resolver := signedRemoteKill(t, 9, conductor.KillSwitchActive)
	ks := &captureKillSwitch{}
	applier := &RemoteKillApplier{
		OrgID:      "org-main",
		FleetID:    "prod",
		InstanceID: "pl-prod-1",
		Resolver:   resolver,
		KillSwitch: ks,
		StatePath:  filepath.Join(t.TempDir(), "remote-kill-state.json"),
		Now:        func() time.Time { return testNow },
	}
	if err := applier.Apply(msg); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !ks.active || ks.message != msg.Reason {
		t.Fatalf("kill switch = active=%v message=%q, want active reason", ks.active, ks.message)
	}
	if err := applier.Apply(msg); err != nil {
		t.Fatalf("Apply(reuse) error = %v, want idempotent re-apply", err)
	}

	var state remoteKillState
	data, err := os.ReadFile(applier.StatePath)
	if err != nil {
		t.Fatalf("ReadFile(state): %v", err)
	}
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("Unmarshal(state): %v", err)
	}
	if state.LastCounter != msg.Counter || state.LastMessageHash == "" || !state.AppliedAt.Equal(testNow) {
		t.Fatalf("state = %+v, want counter/hash/applied_at", state)
	}
	if state.State != conductor.KillSwitchActive || state.Reason != msg.Reason {
		t.Fatalf("state decision = state=%q reason=%q, want active reason", state.State, state.Reason)
	}

	restartedKS := &captureKillSwitch{}
	restarted := &RemoteKillApplier{
		OrgID:      "org-main",
		FleetID:    "prod",
		InstanceID: "pl-prod-1",
		Resolver:   resolver,
		KillSwitch: restartedKS,
		StatePath:  applier.StatePath,
		Now:        func() time.Time { return testNow },
	}
	if err := restarted.Apply(msg); err != nil {
		t.Fatalf("Apply(after restart same message) error = %v, want idempotent re-apply", err)
	}
	if !restartedKS.active || restartedKS.message != msg.Reason {
		t.Fatalf("restarted kill switch = active=%v message=%q, want active reason", restartedKS.active, restartedKS.message)
	}
}

func TestRemoteKillApplierDisabledAndWrongPurpose(t *testing.T) {
	msg, resolver := signedRemoteKill(t, 9, conductor.KillSwitchActive)
	var logs bytes.Buffer
	applier := &RemoteKillApplier{
		OrgID:             "org-main",
		FleetID:           "prod",
		InstanceID:        "pl-prod-1",
		Resolver:          resolver,
		KillSwitch:        &captureKillSwitch{},
		StatePath:         filepath.Join(t.TempDir(), "remote-kill-state.json"),
		DisableRemoteKill: true,
		Now:               func() time.Time { return testNow },
		Logger:            slog.New(slog.NewJSONHandler(&logs, nil)),
	}
	if err := applier.Apply(msg); !errors.Is(err, ErrRemoteKillDisabled) {
		t.Fatalf("Apply(disabled) error = %v, want ErrRemoteKillDisabled", err)
	}
	if !strings.Contains(logs.String(), `"reason":"disabled"`) {
		t.Fatalf("logs = %s, want disabled rejection reason", logs.String())
	}

	applier.DisableRemoteKill = false
	msg.Signatures[0].KeyPurpose = signing.PurposePolicyBundleSigning
	if err := applier.Apply(msg); !errors.Is(err, conductor.ErrWrongKeyPurpose) {
		t.Fatalf("Apply(wrong purpose) error = %v, want ErrWrongKeyPurpose", err)
	}
}

func TestRemoteKillApplierRejectsInvalidInputs(t *testing.T) {
	msg, resolver := signedRemoteKill(t, 9, conductor.KillSwitchActive)
	var nilApplier *RemoteKillApplier
	if err := nilApplier.Apply(msg); err == nil {
		t.Fatal("Apply(nil applier) error = nil, want error")
	}
	if err := (&RemoteKillApplier{StatePath: filepath.Join(t.TempDir(), "state.json")}).Apply(msg); err == nil {
		t.Fatal("Apply(nil kill switch) error = nil, want error")
	}

	applier := &RemoteKillApplier{
		OrgID:      "org-main",
		FleetID:    "prod",
		InstanceID: "pl-prod-2",
		Resolver:   resolver,
		KillSwitch: &captureKillSwitch{},
		StatePath:  filepath.Join(t.TempDir(), "state.json"),
		Now:        func() time.Time { return testNow },
	}
	if err := applier.Apply(msg); !errors.Is(err, conductor.ErrAudienceMismatch) {
		t.Fatalf("Apply(audience mismatch) error = %v, want ErrAudienceMismatch", err)
	}

	expired := msg
	expired.NotBefore = testNow.Add(-2 * time.Hour)
	expired.ExpiresAt = testNow.Add(-time.Hour)
	applier.InstanceID = "pl-prod-1"
	if err := applier.Apply(expired); !errors.Is(err, conductor.ErrExpired) {
		t.Fatalf("Apply(expired) error = %v, want ErrExpired", err)
	}

	badSig := msg
	badSig.Signatures = append([]conductor.SignatureProof(nil), msg.Signatures...)
	badSig.Signatures[0].Signature = conductor.SignaturePrefixEd25519 + strings.Repeat("0", ed25519.SignatureSize*2)
	if err := applier.Apply(badSig); !errors.Is(err, conductor.ErrSignatureVerification) {
		t.Fatalf("Apply(bad signature) error = %v, want ErrSignatureVerification", err)
	}

	blockedPath := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blockedPath, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile(blocked path): %v", err)
	}
	applier.StatePath = filepath.Join(blockedPath, "state.json")
	if err := applier.Apply(msg); err == nil || !strings.Contains(err.Error(), "read conductor remote kill state") {
		t.Fatalf("Apply(state path blocked) error = %v, want state read error", err)
	}
}

func TestRemoteKillApplierRequiresStatePath(t *testing.T) {
	msg, resolver := signedRemoteKill(t, 9, conductor.KillSwitchActive)
	applier := &RemoteKillApplier{
		OrgID:      "org-main",
		FleetID:    "prod",
		InstanceID: "pl-prod-1",
		Resolver:   resolver,
		KillSwitch: &captureKillSwitch{},
		Now:        func() time.Time { return testNow },
	}
	if err := applier.Apply(msg); !errors.Is(err, ErrRemoteKillStateRequired) {
		t.Fatalf("Apply(no state path) error = %v, want ErrRemoteKillStateRequired", err)
	}
}

func TestRemoteKillStateFileValidation(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.json")
	if state, err := readRemoteKillState(missing); err != nil || state.LastCounter != 0 {
		t.Fatalf("readRemoteKillState(missing) = %+v, %v; want zero nil", state, err)
	}

	dirState := filepath.Join(t.TempDir(), "state.json")
	if err := os.Mkdir(dirState, 0o750); err != nil {
		t.Fatalf("Mkdir(state): %v", err)
	}
	if _, err := readRemoteKillState(dirState); err == nil || !strings.Contains(err.Error(), "invalid conductor remote kill state file") {
		t.Fatalf("readRemoteKillState(directory) error = %v, want invalid file", err)
	}

	trailing := filepath.Join(t.TempDir(), "trailing.json")
	if err := os.WriteFile(trailing, []byte(`{"last_counter":1}{}`), 0o600); err != nil {
		t.Fatalf("WriteFile(trailing): %v", err)
	}
	if _, err := readRemoteKillState(trailing); err == nil || !strings.Contains(err.Error(), "trailing JSON document") {
		t.Fatalf("readRemoteKillState(trailing) error = %v, want trailing JSON error", err)
	}

	unknown := filepath.Join(t.TempDir(), "unknown.json")
	if err := os.WriteFile(unknown, []byte(`{"last_counter":1,"unknown":true}`), 0o600); err != nil {
		t.Fatalf("WriteFile(unknown): %v", err)
	}
	if _, err := readRemoteKillState(unknown); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("readRemoteKillState(unknown) error = %v, want unknown field error", err)
	}

	large := filepath.Join(t.TempDir(), "large.json")
	if err := os.WriteFile(large, bytes.Repeat([]byte("x"), maxRemoteKillStateBytes+1), 0o600); err != nil {
		t.Fatalf("WriteFile(large): %v", err)
	}
	if _, err := readRemoteKillState(large); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("readRemoteKillState(large) error = %v, want too large", err)
	}

	blockedDir := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blockedDir, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile(blocked dir): %v", err)
	}
	if err := writeRemoteKillState(filepath.Join(blockedDir, "state.json"), remoteKillState{LastCounter: 1}); err == nil ||
		!strings.Contains(err.Error(), "create conductor remote kill state dir") {
		t.Fatalf("writeRemoteKillState(blocked dir) error = %v, want create dir error", err)
	}
}

func TestRemoteKillApplierInactiveClearsSource(t *testing.T) {
	msg, resolver := signedRemoteKill(t, 10, conductor.KillSwitchInactive)
	ks := &captureKillSwitch{active: true}
	applier := &RemoteKillApplier{
		OrgID:      "org-main",
		FleetID:    "prod",
		InstanceID: "pl-prod-1",
		Resolver:   resolver,
		KillSwitch: ks,
		StatePath:  filepath.Join(t.TempDir(), "state.json"),
		Now:        func() time.Time { return testNow },
	}
	if err := applier.Apply(msg); err != nil {
		t.Fatalf("Apply(inactive) error = %v", err)
	}
	if ks.active {
		t.Fatal("kill switch active after inactive message, want false")
	}
}

func TestRemoteKillApplierRestoresPersistedState(t *testing.T) {
	msg, resolver := signedRemoteKill(t, 12, conductor.KillSwitchActive)
	statePath := filepath.Join(t.TempDir(), "state.json")
	// Apply persists the signed message alongside the decision.
	if err := (&RemoteKillApplier{
		OrgID:      "org-main",
		FleetID:    "prod",
		InstanceID: "pl-prod-1",
		Resolver:   resolver,
		KillSwitch: &captureKillSwitch{},
		StatePath:  statePath,
		Now:        func() time.Time { return testNow },
	}).Apply(msg); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// A fresh applier (simulating restart) must re-verify the persisted decision
	// against the trust roster, not blindly trust the on-disk state.
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
		t.Fatalf("RestorePersistedState() error = %v", err)
	}
	if !ks.active || ks.message != msg.Reason {
		t.Fatalf("kill switch = active=%v message=%q, want restored active", ks.active, ks.message)
	}
}

func TestRemoteKillApplierRestorePersistedStateValidation(t *testing.T) {
	var nilApplier *RemoteKillApplier
	if err := nilApplier.RestorePersistedState(); err == nil || !strings.Contains(err.Error(), "applier required") {
		t.Fatalf("RestorePersistedState(nil) error = %v, want applier required", err)
	}
	if err := (&RemoteKillApplier{StatePath: filepath.Join(t.TempDir(), "state.json")}).RestorePersistedState(); err == nil ||
		!strings.Contains(err.Error(), "kill switch required") {
		t.Fatalf("RestorePersistedState(no kill switch) error = %v, want kill switch required", err)
	}
	if err := (&RemoteKillApplier{KillSwitch: &captureKillSwitch{}}).RestorePersistedState(); !errors.Is(err, ErrRemoteKillStateRequired) {
		t.Fatalf("RestorePersistedState(no state path) error = %v, want ErrRemoteKillStateRequired", err)
	}
	if err := (&RemoteKillApplier{
		KillSwitch:        &captureKillSwitch{},
		StatePath:         filepath.Join(t.TempDir(), "missing.json"),
		DisableRemoteKill: true,
	}).RestorePersistedState(); err != nil {
		t.Fatalf("RestorePersistedState(disabled) error = %v, want nil", err)
	}
	if err := (&RemoteKillApplier{
		KillSwitch: &captureKillSwitch{},
		StatePath:  filepath.Join(t.TempDir(), "missing.json"),
	}).RestorePersistedState(); err != nil {
		t.Fatalf("RestorePersistedState(empty missing state) error = %v, want nil", err)
	}

	blockedPath := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blockedPath, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile(blocked path): %v", err)
	}
	if err := (&RemoteKillApplier{
		KillSwitch: &captureKillSwitch{},
		StatePath:  filepath.Join(blockedPath, "state.json"),
	}).RestorePersistedState(); err == nil {
		t.Fatal("RestorePersistedState(blocked path) error = nil, want read error")
	}

	for _, tc := range []struct {
		name  string
		state remoteKillState
		want  string
	}{
		{
			name: "invalid_state",
			state: remoteKillState{
				LastCounter:     1,
				LastMessageHash: strings.Repeat("a", 64),
				State:           conductor.KillSwitchState("paused"),
			},
			want: "invalid conductor remote kill persisted state",
		},
		{
			name: "reason_too_long",
			state: remoteKillState{
				LastCounter:     1,
				LastMessageHash: strings.Repeat("a", 64),
				State:           conductor.KillSwitchActive,
				Reason:          strings.Repeat("x", conductor.MaxReasonBytes+1),
			},
			want: "invalid conductor remote kill persisted reason",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			statePath := filepath.Join(t.TempDir(), "state.json")
			if err := writeRemoteKillState(statePath, tc.state); err != nil {
				t.Fatalf("writeRemoteKillState: %v", err)
			}
			err := (&RemoteKillApplier{KillSwitch: &captureKillSwitch{}, StatePath: statePath}).RestorePersistedState()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("RestorePersistedState() error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestRemoteKillApplierRejectsStaleCounter(t *testing.T) {
	msg, resolver := signedRemoteKill(t, 9, conductor.KillSwitchActive)
	statePath := filepath.Join(t.TempDir(), "state.json")
	if err := writeRemoteKillState(statePath, remoteKillState{
		LastCounter:     msg.Counter + 1,
		LastMessageHash: "older-hash",
		State:           conductor.KillSwitchActive,
		Reason:          "older active kill",
		AppliedAt:       testNow.Add(-time.Minute),
	}); err != nil {
		t.Fatalf("writeRemoteKillState: %v", err)
	}
	applier := &RemoteKillApplier{
		OrgID:      "org-main",
		FleetID:    "prod",
		InstanceID: "pl-prod-1",
		Resolver:   resolver,
		KillSwitch: &captureKillSwitch{},
		StatePath:  statePath,
		Now:        func() time.Time { return testNow },
	}
	if err := applier.Apply(msg); !errors.Is(err, ErrRemoteKillSuperseded) {
		t.Fatalf("Apply(stale counter) error = %v, want ErrRemoteKillSuperseded", err)
	}
}

func TestRemoteKillApplierSerializesCounterCheckAcrossInstances(t *testing.T) {
	lowMsg, lowResolver := signedRemoteKill(t, 11, conductor.KillSwitchActive)
	highMsg, highResolver := signedRemoteKill(t, 12, conductor.KillSwitchInactive)
	statePath := filepath.Join(t.TempDir(), "state.json")
	if err := ResetRemoteKillReplayState(statePath, 10, conductor.KillSwitchActive, "operator floor", testNow); err != nil {
		t.Fatalf("ResetRemoteKillReplayState: %v", err)
	}

	blockingKS := &blockingKillSwitch{
		reached: make(chan struct{}),
		release: make(chan struct{}),
	}
	lowApplier := &RemoteKillApplier{
		OrgID:      "org-main",
		FleetID:    "prod",
		InstanceID: "pl-prod-1",
		Resolver:   lowResolver,
		KillSwitch: blockingKS,
		StatePath:  statePath,
		Now:        func() time.Time { return testNow },
	}
	highApplier := &RemoteKillApplier{
		OrgID:      "org-main",
		FleetID:    "prod",
		InstanceID: "pl-prod-1",
		Resolver:   highResolver,
		KillSwitch: &captureKillSwitch{},
		StatePath:  statePath,
		Now:        func() time.Time { return testNow.Add(time.Second) },
	}

	lowErr := make(chan error, 1)
	go func() {
		lowErr <- lowApplier.Apply(lowMsg)
	}()
	select {
	case <-blockingKS.reached:
	case <-time.After(time.Second):
		t.Fatal("lower-counter Apply did not reach kill switch")
	}

	highErr := make(chan error, 1)
	go func() {
		highErr <- highApplier.Apply(highMsg)
	}()
	select {
	case err := <-highErr:
		close(blockingKS.release)
		if lowApplyErr := <-lowErr; lowApplyErr != nil {
			t.Fatalf("lower-counter Apply error after early higher-counter completion = %v", lowApplyErr)
		}
		if err != nil {
			t.Fatalf("higher-counter Apply returned early with error: %v", err)
		}
		t.Fatal("higher-counter Apply completed while lower-counter Apply held the replay-state critical section")
	case <-time.After(100 * time.Millisecond):
	}

	close(blockingKS.release)
	if err := <-lowErr; err != nil {
		t.Fatalf("lower-counter Apply error = %v", err)
	}
	if err := <-highErr; err != nil {
		t.Fatalf("higher-counter Apply error = %v", err)
	}

	state, err := readDurableRemoteKillState(statePath)
	if err != nil {
		t.Fatalf("readDurableRemoteKillState: %v", err)
	}
	if state.LastCounter != highMsg.Counter || state.State != highMsg.State || state.Reason != highMsg.Reason {
		t.Fatalf("state after concurrent appliers = counter=%d state=%q reason=%q, want counter=%d state=%q reason=%q",
			state.LastCounter, state.State, state.Reason, highMsg.Counter, highMsg.State, highMsg.Reason)
	}
}

func TestRemoteKillApplierRejectsReplayAfterPrimaryStateDeletion(t *testing.T) {
	oldMsg, resolver := signedRemoteKill(t, 9, conductor.KillSwitchActive)
	newMsg, newResolver := signedRemoteKill(t, 11, conductor.KillSwitchInactive)
	statePath := filepath.Join(t.TempDir(), "state.json")
	if err := writeRemoteKillState(statePath, remoteKillState{
		LastCounter:     10,
		LastMessageHash: "accepted-hash",
		State:           conductor.KillSwitchActive,
		Reason:          "accepted emergency stop",
		AppliedAt:       testNow.Add(-time.Minute),
	}); err != nil {
		t.Fatalf("writeRemoteKillState: %v", err)
	}
	if err := os.Remove(statePath); err != nil {
		t.Fatalf("Remove(primary state): %v", err)
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
	if err := applier.Apply(oldMsg); !errors.Is(err, ErrRemoteKillSuperseded) {
		t.Fatalf("Apply(old after primary deletion) error = %v, want ErrRemoteKillSuperseded", err)
	}
	applier.Resolver = newResolver
	if err := applier.Apply(newMsg); err != nil {
		t.Fatalf("Apply(new after primary deletion) error = %v", err)
	}
	state, err := readRemoteKillState(statePath)
	if err != nil {
		t.Fatalf("readRemoteKillState(restored primary): %v", err)
	}
	if state.LastCounter != newMsg.Counter || state.State != newMsg.State {
		t.Fatalf("restored primary state = %+v, want counter/state from newer message", state)
	}
}

func TestRemoteKillApplierRejectsReplayAfterPrimaryAndSecondaryDeletion(t *testing.T) {
	oldMsg, resolver := signedRemoteKill(t, 9, conductor.KillSwitchActive)
	statePath := filepath.Join(t.TempDir(), "state.json")
	if err := writeRemoteKillState(statePath, remoteKillState{
		LastCounter:     10,
		LastMessageHash: "accepted-hash",
		State:           conductor.KillSwitchActive,
		Reason:          "accepted emergency stop",
		AppliedAt:       testNow.Add(-time.Minute),
	}); err != nil {
		t.Fatalf("writeRemoteKillState: %v", err)
	}
	if err := os.Remove(statePath); err != nil {
		t.Fatalf("Remove(primary state): %v", err)
	}
	if err := os.Remove(remoteKillStateAnchorPath(statePath)); err != nil {
		t.Fatalf("Remove(secondary state): %v", err)
	}
	applier := &RemoteKillApplier{
		OrgID:      "org-main",
		FleetID:    "prod",
		InstanceID: "pl-prod-1",
		Resolver:   resolver,
		KillSwitch: &captureKillSwitch{},
		StatePath:  statePath,
		Now:        func() time.Time { return testNow },
	}
	if err := applier.Apply(oldMsg); err == nil || !strings.Contains(err.Error(), "replay state missing") {
		t.Fatalf("Apply(old after delete-all) error = %v, want missing replay state", err)
	}
	if err := ResetRemoteKillReplayState(statePath, 10, conductor.KillSwitchActive, "operator reset", testNow); err != nil {
		t.Fatalf("ResetRemoteKillReplayState: %v", err)
	}
	if err := applier.Apply(oldMsg); !errors.Is(err, ErrRemoteKillSuperseded) {
		t.Fatalf("Apply(old after reset) error = %v, want ErrRemoteKillSuperseded", err)
	}
}

func TestRemoteKillRestoreUsesAnchorAfterPrimaryStateDeletion(t *testing.T) {
	msg, resolver := signedRemoteKill(t, 12, conductor.KillSwitchActive)
	statePath := filepath.Join(t.TempDir(), "state.json")
	if err := (&RemoteKillApplier{
		OrgID:      "org-main",
		FleetID:    "prod",
		InstanceID: "pl-prod-1",
		Resolver:   resolver,
		KillSwitch: &captureKillSwitch{},
		StatePath:  statePath,
		Now:        func() time.Time { return testNow },
	}).Apply(msg); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := os.Remove(statePath); err != nil {
		t.Fatalf("Remove(primary state): %v", err)
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
	// Anchor recovery must still re-verify the signed message, not blindly trust it.
	if err := applier.RestorePersistedState(); err != nil {
		t.Fatalf("RestorePersistedState(anchor only) error = %v", err)
	}
	if !ks.active || ks.message != msg.Reason {
		t.Fatalf("kill switch = active=%v message=%q, want restored active", ks.active, ks.message)
	}
}

func TestResetRemoteKillReplayState(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	if err := ResetRemoteKillReplayState(statePath, 21, conductor.KillSwitchInactive, "operator reset after restore", testNow); err != nil {
		t.Fatalf("ResetRemoteKillReplayState: %v", err)
	}
	state, err := readDurableRemoteKillState(statePath)
	if err != nil {
		t.Fatalf("readDurableRemoteKillState: %v", err)
	}
	if state.LastCounter != 21 || state.State != conductor.KillSwitchInactive || state.Reason != "operator reset after restore" {
		t.Fatalf("state = %+v, want reset counter/state/reason", state)
	}
	err = (&RemoteKillApplier{
		OrgID:      "org-main",
		FleetID:    "prod",
		InstanceID: "pl-prod-1",
		KillSwitch: &captureKillSwitch{},
		StatePath:  statePath,
		Now:        func() time.Time { return testNow },
	}).RestorePersistedState()
	if err == nil || !strings.Contains(err.Error(), "not backed by a signed message") {
		t.Fatalf("RestorePersistedState(unsigned reset) error = %v, want signed-message rejection", err)
	}
	if err := ResetRemoteKillReplayState(filepath.Join(t.TempDir(), "bad.json"), 0, conductor.KillSwitchInactive, "", testNow); err == nil {
		t.Fatal("counter 0 reset must fail")
	}
	if err := ResetRemoteKillReplayState(filepath.Join(t.TempDir(), "bad.json"), 1, conductor.KillSwitchState("paused"), "", testNow); err == nil {
		t.Fatal("invalid reset state must fail")
	}
}

func TestRemoteKillApplierBackfillsLegacyStateOnDuplicateHash(t *testing.T) {
	msg, resolver := signedRemoteKill(t, 9, conductor.KillSwitchActive)
	hash, err := msg.CanonicalHash()
	if err != nil {
		t.Fatalf("CanonicalHash() error = %v", err)
	}
	statePath := filepath.Join(t.TempDir(), "state.json")
	legacyState, err := json.Marshal(map[string]any{
		"last_counter":      msg.Counter,
		"last_message_hash": hash,
		"applied_at":        testNow.Add(-time.Minute),
	})
	if err != nil {
		t.Fatalf("Marshal(legacy state) error = %v", err)
	}
	if err := os.WriteFile(statePath, legacyState, 0o600); err != nil {
		t.Fatalf("WriteFile(legacy state) error = %v", err)
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
	if err := applier.Apply(msg); err != nil {
		t.Fatalf("Apply(legacy duplicate hash) error = %v", err)
	}
	if !ks.active || ks.message != msg.Reason {
		t.Fatalf("kill switch = active=%v message=%q, want active reason", ks.active, ks.message)
	}
	state, err := readRemoteKillState(statePath)
	if err != nil {
		t.Fatalf("readRemoteKillState(backfilled) error = %v", err)
	}
	if state.State != msg.State || state.Reason != msg.Reason || state.LastMessageHash != hash {
		t.Fatalf("backfilled state = %+v, want state/reason/hash from verified message", state)
	}
}

// TestRemoteKillApplier_RejectsForgedPersistedStateOnRestore is the G6 red-team
// regression. An attacker with write access to the follower replay-state dir can
// craft a persisted decision (the Context/Digest binding is non-secret and
// deterministic) that lifts an operator kill or pins one for DoS. On restart the
// follower must NOT honor a persisted decision that is not backed by a
// re-verifiable signed Conductor message; it must fail closed and require an
// explicit operator reset-replay-state.
func TestRemoteKillApplier_RejectsForgedPersistedStateOnRestore(t *testing.T) {
	_, resolver := signedRemoteKill(t, 9, conductor.KillSwitchActive)
	statePath := filepath.Join(t.TempDir(), "state.json")
	// Attacker forges an "inactive" decision (kill lifted) with a valid binding
	// but no signed message. writeRemoteKillState computes the (non-secret)
	// Context/Digest exactly as a PVC-write attacker could.
	if err := writeRemoteKillState(statePath, remoteKillState{
		LastCounter:     12,
		LastMessageHash: "forged-by-attacker",
		State:           conductor.KillSwitchInactive,
		Reason:          "attacker lifted the kill",
		AppliedAt:       testNow,
	}); err != nil {
		t.Fatalf("writeRemoteKillState(forged): %v", err)
	}
	ks := &captureKillSwitch{active: true, message: "real operator kill"}
	applier := &RemoteKillApplier{
		OrgID:      "org-main",
		FleetID:    "prod",
		InstanceID: "pl-prod-1",
		Resolver:   resolver,
		KillSwitch: ks,
		StatePath:  statePath,
		Now:        func() time.Time { return testNow },
	}
	err := applier.RestorePersistedState()
	if err == nil {
		t.Fatal("RestorePersistedState() accepted a forged (unsigned) persisted decision; want fail-closed rejection")
	}
	if ks.message == "attacker lifted the kill" {
		t.Fatalf("forged decision was applied to the kill switch: active=%v message=%q", ks.active, ks.message)
	}
}

// TestRemoteKillApplier_RejectsTamperedPersistedDecisionOnRestore covers the
// harder G6 variants: a persisted decision whose on-disk fields were tampered
// away from the signed message, a signed kill bound to a different follower, and
// a signed message with a broken signature. All must fail closed on restore.
func TestRemoteKillApplier_RejectsTamperedPersistedDecisionOnRestore(t *testing.T) {
	seed := func(t *testing.T) (string, conductor.SignatureKeyResolver) {
		t.Helper()
		msg, resolver := signedRemoteKill(t, 9, conductor.KillSwitchActive)
		statePath := filepath.Join(t.TempDir(), "state.json")
		if err := (&RemoteKillApplier{
			OrgID: "org-main", FleetID: "prod", InstanceID: "pl-prod-1",
			Resolver: resolver, KillSwitch: &captureKillSwitch{}, StatePath: statePath,
			Now: func() time.Time { return testNow },
		}).Apply(msg); err != nil {
			t.Fatalf("seed Apply: %v", err)
		}
		return statePath, resolver
	}
	rewrite := func(t *testing.T, statePath string, mutate func(*remoteKillState)) {
		t.Helper()
		st, err := readDurableRemoteKillState(statePath)
		if err != nil {
			t.Fatalf("read seed state: %v", err)
		}
		mutate(&st)
		if err := writeRemoteKillState(statePath, st); err != nil {
			t.Fatalf("rewrite state: %v", err)
		}
	}
	applier := func(statePath, instanceID string, resolver conductor.SignatureKeyResolver, ks *captureKillSwitch) *RemoteKillApplier {
		return &RemoteKillApplier{
			OrgID: "org-main", FleetID: "prod", InstanceID: instanceID,
			Resolver: resolver, KillSwitch: ks, StatePath: statePath,
			Now: func() time.Time { return testNow },
		}
	}

	t.Run("state flipped to inactive without re-signing", func(t *testing.T) {
		statePath, resolver := seed(t)
		rewrite(t, statePath, func(s *remoteKillState) {
			s.State = conductor.KillSwitchInactive
			s.Reason = "attacker lifted the kill"
		})
		ks := &captureKillSwitch{active: true, message: "real operator kill"}
		if err := applier(statePath, "pl-prod-1", resolver, ks).RestorePersistedState(); err == nil {
			t.Fatal("accepted a decision that does not match its signed message")
		}
		if ks.message == "attacker lifted the kill" {
			t.Fatalf("forged decision applied: active=%v message=%q", ks.active, ks.message)
		}
	})

	t.Run("signed kill bound to a different follower", func(t *testing.T) {
		statePath, resolver := seed(t)
		ks := &captureKillSwitch{}
		if err := applier(statePath, "pl-prod-OTHER", resolver, ks).RestorePersistedState(); err == nil {
			t.Fatal("accepted a kill bound to a different follower's audience")
		}
	})

	t.Run("broken signature on the persisted message", func(t *testing.T) {
		statePath, resolver := seed(t)
		rewrite(t, statePath, func(s *remoteKillState) {
			var msg conductor.RemoteKillMessage
			if err := json.Unmarshal(s.SignedMessage, &msg); err != nil {
				t.Fatalf("unmarshal signed message: %v", err)
			}
			for i := range msg.Signatures {
				msg.Signatures[i].Signature = conductor.SignaturePrefixEd25519 + strings.Repeat("00", ed25519.SignatureSize)
			}
			b, err := json.Marshal(msg)
			if err != nil {
				t.Fatalf("remarshal tampered message: %v", err)
			}
			s.SignedMessage = b
		})
		ks := &captureKillSwitch{active: true}
		if err := applier(statePath, "pl-prod-1", resolver, ks).RestorePersistedState(); err == nil {
			t.Fatal("accepted a persisted message with an invalid signature")
		}
	})

	t.Run("resolver missing cannot apply a persisted decision", func(t *testing.T) {
		statePath, _ := seed(t)
		ks := &captureKillSwitch{}
		if err := applier(statePath, "pl-prod-1", nil, ks).RestorePersistedState(); err == nil {
			t.Fatal("applied a persisted decision with no resolver to verify it")
		}
	})
}

func signedRemoteKill(t *testing.T, counter uint64, state conductor.KillSwitchState) (conductor.RemoteKillMessage, conductor.SignatureKeyResolver) {
	t.Helper()
	pub1, priv1, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(1): %v", err)
	}
	pub2, priv2, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(2): %v", err)
	}
	msg := conductor.RemoteKillMessage{
		SchemaVersion: conductor.SchemaVersion,
		MessageID:     "kill-1",
		OrgID:         "org-main",
		FleetID:       "prod",
		Audience:      conductor.Audience{InstanceIDs: []string{"pl-prod-1"}},
		State:         state,
		Counter:       counter,
		Reason:        "operator emergency stop",
		CreatedAt:     testNow,
		NotBefore:     testNow.Add(-time.Minute),
		ExpiresAt:     testNow.Add(time.Hour),
	}
	preimage, err := msg.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage(): %v", err)
	}
	msg.Signatures = []conductor.SignatureProof{
		{
			SignerKeyID: "kill-signer-1",
			KeyPurpose:  signing.PurposeRemoteKillSigning,
			Algorithm:   conductor.SignatureAlgorithmEd25519,
			Signature:   conductor.SignaturePrefixEd25519 + hex.EncodeToString(ed25519.Sign(priv1, preimage)),
		},
		{
			SignerKeyID: "kill-signer-2",
			KeyPurpose:  signing.PurposeRemoteKillSigning,
			Algorithm:   conductor.SignatureAlgorithmEd25519,
			Signature:   conductor.SignaturePrefixEd25519 + hex.EncodeToString(ed25519.Sign(priv2, preimage)),
		},
	}
	resolver := func(keyID string) (conductor.SignatureKey, error) {
		switch keyID {
		case "kill-signer-1":
			return conductor.SignatureKey{PublicKey: pub1, KeyPurpose: signing.PurposeRemoteKillSigning}, nil
		case "kill-signer-2":
			return conductor.SignatureKey{PublicKey: pub2, KeyPurpose: signing.PurposeRemoteKillSigning}, nil
		default:
			return conductor.SignatureKey{}, conductor.ErrSignatureVerification
		}
	}
	return msg, resolver
}
