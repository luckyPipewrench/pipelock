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
	statePath := filepath.Join(t.TempDir(), "state.json")
	if err := writeRemoteKillState(statePath, remoteKillState{
		LastCounter:     12,
		LastMessageHash: strings.Repeat("a", 64),
		State:           conductor.KillSwitchActive,
		Reason:          "persisted emergency stop",
		AppliedAt:       testNow.Add(-time.Minute),
	}); err != nil {
		t.Fatalf("writeRemoteKillState: %v", err)
	}
	ks := &captureKillSwitch{}
	applier := &RemoteKillApplier{
		KillSwitch: ks,
		StatePath:  statePath,
	}
	if err := applier.RestorePersistedState(); err != nil {
		t.Fatalf("RestorePersistedState() error = %v", err)
	}
	if !ks.active || ks.message != "persisted emergency stop" {
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
