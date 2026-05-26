// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package emergency

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/conductor"
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
	if err := applier.Apply(msg); !errors.Is(err, ErrRemoteKillSuperseded) {
		t.Fatalf("Apply(reuse) error = %v, want ErrRemoteKillSuperseded", err)
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

	restarted := &RemoteKillApplier{
		OrgID:      "org-main",
		FleetID:    "prod",
		InstanceID: "pl-prod-1",
		Resolver:   resolver,
		KillSwitch: &captureKillSwitch{},
		StatePath:  applier.StatePath,
		Now:        func() time.Time { return testNow },
	}
	if err := restarted.Apply(msg); !errors.Is(err, ErrRemoteKillSuperseded) {
		t.Fatalf("Apply(after restart) error = %v, want ErrRemoteKillSuperseded", err)
	}
}

func TestRemoteKillApplierDisabledAndWrongPurpose(t *testing.T) {
	msg, resolver := signedRemoteKill(t, 9, conductor.KillSwitchActive)
	applier := &RemoteKillApplier{
		OrgID:             "org-main",
		FleetID:           "prod",
		InstanceID:        "pl-prod-1",
		Resolver:          resolver,
		KillSwitch:        &captureKillSwitch{},
		StatePath:         filepath.Join(t.TempDir(), "remote-kill-state.json"),
		DisableRemoteKill: true,
		Now:               func() time.Time { return testNow },
	}
	if err := applier.Apply(msg); !errors.Is(err, ErrRemoteKillDisabled) {
		t.Fatalf("Apply(disabled) error = %v, want ErrRemoteKillDisabled", err)
	}

	applier.DisableRemoteKill = false
	msg.Signatures[0].KeyPurpose = signing.PurposePolicyBundleSigning
	if err := applier.Apply(msg); !errors.Is(err, conductor.ErrWrongKeyPurpose) {
		t.Fatalf("Apply(wrong purpose) error = %v, want ErrWrongKeyPurpose", err)
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
