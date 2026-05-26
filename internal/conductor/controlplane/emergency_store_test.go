// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/conductor"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestFileEmergencyStoreRemoteKillLatest(t *testing.T) {
	store := mustEmergencyStore(t)
	first := signedRemoteKillMessage(t, "kill-1", 1, conductor.KillSwitchActive, testNow)
	second := signedRemoteKillMessage(t, "kill-2", 2, conductor.KillSwitchInactive, testNow.Add(time.Minute))

	if _, created, err := store.PublishRemoteKill(context.Background(), first, testNow); err != nil || !created {
		t.Fatalf("PublishRemoteKill(first) created=%v err=%v, want created", created, err)
	}
	if _, created, err := store.PublishRemoteKill(context.Background(), first, testNow); err != nil || created {
		t.Fatalf("PublishRemoteKill(duplicate) created=%v err=%v, want idempotent", created, err)
	}
	if _, created, err := store.PublishRemoteKill(context.Background(), second, testNow.Add(time.Minute)); err != nil || !created {
		t.Fatalf("PublishRemoteKill(second) created=%v err=%v, want created", created, err)
	}
	stale := signedRemoteKillMessage(t, "kill-stale", 1, conductor.KillSwitchActive, testNow.Add(2*time.Minute))
	if _, _, err := store.PublishRemoteKill(context.Background(), stale, testNow.Add(2*time.Minute)); !errors.Is(err, ErrEmergencyStaleCounter) {
		t.Fatalf("PublishRemoteKill(stale) err=%v, want ErrEmergencyStaleCounter", err)
	}

	got, err := store.LatestRemoteKill(context.Background(), defaultFollowerIdentity(), testNow.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("LatestRemoteKill() error = %v", err)
	}
	if got.Message.MessageID != "kill-2" || got.Message.State != conductor.KillSwitchInactive {
		t.Fatalf("LatestRemoteKill() = %+v, want kill-2 inactive", got.Message)
	}

	other := defaultFollowerIdentity()
	other.InstanceID = "pl-prod-2"
	if _, err := store.LatestRemoteKill(context.Background(), other, testNow.Add(2*time.Minute)); !errors.Is(err, ErrEmergencyNotFound) {
		t.Fatalf("LatestRemoteKill(other) err = %v, want ErrEmergencyNotFound", err)
	}

	reopened, err := OpenFileEmergencyStore(store.dir)
	if err != nil {
		t.Fatalf("OpenFileEmergencyStore(reopen) error = %v", err)
	}
	got, err = reopened.LatestRemoteKill(context.Background(), defaultFollowerIdentity(), testNow.Add(2*time.Minute))
	if err != nil || got.Message.MessageID != "kill-2" {
		t.Fatalf("reopened LatestRemoteKill() = %+v, %v; want kill-2", got.Message, err)
	}
}

func TestFileEmergencyStoreRollbackLookup(t *testing.T) {
	store := mustEmergencyStore(t)
	auth := signedRollbackAuthorization(t, "rollback-1", 7, testNow)
	if _, created, err := store.PublishRollbackAuthorization(context.Background(), auth, testNow); err != nil || !created {
		t.Fatalf("PublishRollbackAuthorization() created=%v err=%v, want created", created, err)
	}
	stale := signedRollbackAuthorization(t, "rollback-stale", 6, testNow.Add(time.Minute))
	if _, _, err := store.PublishRollbackAuthorization(context.Background(), stale, testNow.Add(time.Minute)); !errors.Is(err, ErrEmergencyStaleCounter) {
		t.Fatalf("PublishRollbackAuthorization(stale) err=%v, want ErrEmergencyStaleCounter", err)
	}
	newer := signedRollbackAuthorization(t, "rollback-2", 8, testNow.Add(2*time.Minute))
	if _, created, err := store.PublishRollbackAuthorization(context.Background(), newer, testNow.Add(2*time.Minute)); err != nil || !created {
		t.Fatalf("PublishRollbackAuthorization(newer) created=%v err=%v, want created", created, err)
	}
	lookup := RollbackLookup{
		CurrentBundleID: auth.CurrentBundleID,
		CurrentVersion:  auth.CurrentVersion,
		TargetBundleID:  auth.TargetBundleID,
		TargetVersion:   auth.TargetVersion,
	}
	got, err := store.LatestRollbackAuthorization(context.Background(), defaultFollowerIdentity(), lookup, testNow.Add(3*time.Minute))
	if err != nil {
		t.Fatalf("LatestRollbackAuthorization() error = %v", err)
	}
	if got.Authorization.AuthorizationID != newer.AuthorizationID {
		t.Fatalf("LatestRollbackAuthorization() = %q, want %q", got.Authorization.AuthorizationID, newer.AuthorizationID)
	}
	lookup.TargetVersion = 1
	if _, err := store.LatestRollbackAuthorization(context.Background(), defaultFollowerIdentity(), lookup, testNow.Add(3*time.Minute)); !errors.Is(err, ErrEmergencyNotFound) {
		t.Fatalf("LatestRollbackAuthorization(miss) err = %v, want ErrEmergencyNotFound", err)
	}
}

func TestFileEmergencyStoreRollsBackMemoryOnWriteFailure(t *testing.T) {
	store := mustEmergencyStore(t)
	msg := signedRemoteKillMessage(t, "kill-write-fail", 1, conductor.KillSwitchActive, testNow)
	store.statePath = filepath.Join(store.dir, "missing", emergencyStateFileName)
	if _, _, err := store.PublishRemoteKill(context.Background(), msg, testNow); err == nil {
		t.Fatal("PublishRemoteKill(write failure) error = nil, want error")
	}
	if len(store.remoteKills) != 0 || len(store.remoteKillHashes) != 0 || len(store.remoteKillIDs) != 0 {
		t.Fatalf("remote kill indexes after failed write = len(slice)=%d hashes=%d ids=%d, want empty",
			len(store.remoteKills), len(store.remoteKillHashes), len(store.remoteKillIDs))
	}
	store.statePath = filepath.Join(store.dir, emergencyStateFileName)
	if _, created, err := store.PublishRemoteKill(context.Background(), msg, testNow); err != nil || !created {
		t.Fatalf("PublishRemoteKill(after rollback) created=%v err=%v, want created", created, err)
	}

	store = mustEmergencyStore(t)
	auth := signedRollbackAuthorization(t, "rollback-write-fail", 1, testNow)
	store.statePath = filepath.Join(store.dir, "missing", emergencyStateFileName)
	if _, _, err := store.PublishRollbackAuthorization(context.Background(), auth, testNow); err == nil {
		t.Fatal("PublishRollbackAuthorization(write failure) error = nil, want error")
	}
	if len(store.rollbacks) != 0 || len(store.rollbackHashes) != 0 || len(store.rollbackAuthIDMap) != 0 {
		t.Fatalf("rollback indexes after failed write = len(slice)=%d hashes=%d ids=%d, want empty",
			len(store.rollbacks), len(store.rollbackHashes), len(store.rollbackAuthIDMap))
	}
	store.statePath = filepath.Join(store.dir, emergencyStateFileName)
	if _, created, err := store.PublishRollbackAuthorization(context.Background(), auth, testNow); err != nil || !created {
		t.Fatalf("PublishRollbackAuthorization(after rollback) created=%v err=%v, want created", created, err)
	}
}

func TestFileEmergencyStoreRejectsInvalidState(t *testing.T) {
	dir := t.TempDir()
	if _, err := OpenFileEmergencyStore(""); err == nil || !strings.Contains(err.Error(), "dir required") {
		t.Fatalf("OpenFileEmergencyStore(empty) err=%v, want dir required", err)
	}
	if err := os.WriteFile(filepath.Join(dir, emergencyStateFileName), []byte(`{"remote_kills":[]}{}`), 0o600); err != nil {
		t.Fatalf("WriteFile(trailing): %v", err)
	}
	if _, err := OpenFileEmergencyStore(dir); !errors.Is(err, ErrInvalidEmergencyRecord) {
		t.Fatalf("OpenFileEmergencyStore(trailing) err=%v, want ErrInvalidEmergencyRecord", err)
	}

	dir = t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, emergencyStateFileName), 0o750); err != nil {
		t.Fatalf("Mkdir(state path): %v", err)
	}
	if _, err := OpenFileEmergencyStore(dir); !errors.Is(err, ErrInvalidEmergencyRecord) {
		t.Fatalf("OpenFileEmergencyStore(directory state) err=%v, want ErrInvalidEmergencyRecord", err)
	}
}

func TestRollbackLookupValidate(t *testing.T) {
	valid := RollbackLookup{
		CurrentBundleID: "bundle-current",
		CurrentVersion:  42,
		TargetBundleID:  "bundle-target",
		TargetVersion:   41,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate(valid) error = %v", err)
	}
	missing := valid
	missing.CurrentVersion = 0
	if err := missing.Validate(); !errors.Is(err, conductor.ErrMissingField) {
		t.Fatalf("Validate(missing version) error = %v, want ErrMissingField", err)
	}
	badTarget := valid
	badTarget.TargetVersion = valid.CurrentVersion
	if err := badTarget.Validate(); !errors.Is(err, conductor.ErrInvalidRollback) {
		t.Fatalf("Validate(bad target) error = %v, want ErrInvalidRollback", err)
	}
}

func signedRemoteKillMessage(t *testing.T, id string, counter uint64, state conductor.KillSwitchState, created time.Time) conductor.RemoteKillMessage {
	t.Helper()
	msg, _ := signedRemoteKillMessageWithResolver(t, id, counter, state, created)
	return msg
}

func signedRemoteKillMessageWithResolver(t *testing.T, id string, counter uint64, state conductor.KillSwitchState, created time.Time) (conductor.RemoteKillMessage, conductor.SignatureKeyResolver) {
	t.Helper()
	return signedRemoteKillMessageWithTTL(t, id, counter, state, created, time.Hour)
}

func signedRemoteKillMessageWithTTL(t *testing.T, id string, counter uint64, state conductor.KillSwitchState, created time.Time, ttl time.Duration) (conductor.RemoteKillMessage, conductor.SignatureKeyResolver) {
	t.Helper()
	msg := conductor.RemoteKillMessage{
		SchemaVersion: conductor.SchemaVersion,
		MessageID:     id,
		OrgID:         "org-main",
		FleetID:       "prod",
		Audience:      conductor.Audience{InstanceIDs: []string{"pl-prod-1"}},
		State:         state,
		Counter:       counter,
		Reason:        "operator emergency stop",
		CreatedAt:     created,
		NotBefore:     created.Add(-time.Minute),
		ExpiresAt:     created.Add(ttl),
	}
	var resolver conductor.SignatureKeyResolver
	msg.Signatures, resolver = signConductorPreimage(t, msg.SignablePreimage, signing.PurposeRemoteKillSigning, "kill-signer-1", "kill-signer-2")
	if err := msg.Validate(); err != nil {
		t.Fatalf("remote kill Validate() error = %v", err)
	}
	return msg, resolver
}

func signedRollbackAuthorization(t *testing.T, id string, counter uint64, created time.Time) conductor.RollbackAuthorization {
	t.Helper()
	auth, _ := signedRollbackAuthorizationWithResolver(t, id, counter, created)
	return auth
}

func signedRollbackAuthorizationWithResolver(t *testing.T, id string, counter uint64, created time.Time) (conductor.RollbackAuthorization, conductor.SignatureKeyResolver) {
	t.Helper()
	return signedRollbackAuthorizationWithTTL(t, id, counter, created, time.Hour)
}

func signedRollbackAuthorizationWithTTL(t *testing.T, id string, counter uint64, created time.Time, ttl time.Duration) (conductor.RollbackAuthorization, conductor.SignatureKeyResolver) {
	t.Helper()
	auth := conductor.RollbackAuthorization{
		SchemaVersion:   conductor.SchemaVersion,
		AuthorizationID: id,
		OrgID:           "org-main",
		FleetID:         "prod",
		Audience:        conductor.Audience{InstanceIDs: []string{"pl-prod-1"}},
		CurrentBundleID: "bundle-current",
		CurrentVersion:  42,
		TargetBundleID:  "bundle-target",
		TargetVersion:   41,
		Counter:         counter,
		Reason:          "bad policy bundle",
		CreatedAt:       created,
		ExpiresAt:       created.Add(ttl),
	}
	var resolver conductor.SignatureKeyResolver
	auth.Signatures, resolver = signConductorPreimage(t, auth.SignablePreimage, signing.PurposePolicyBundleRollback, "rollback-signer-1", "rollback-signer-2")
	if err := auth.Validate(); err != nil {
		t.Fatalf("rollback authorization Validate() error = %v", err)
	}
	return auth, resolver
}

func signConductorPreimage(t *testing.T, preimage func() ([]byte, error), purpose signing.KeyPurpose, keyIDs ...string) ([]conductor.SignatureProof, conductor.SignatureKeyResolver) {
	t.Helper()
	data, err := preimage()
	if err != nil {
		t.Fatalf("SignablePreimage() error = %v", err)
	}
	proofs := make([]conductor.SignatureProof, 0, len(keyIDs))
	keys := make(map[string]conductor.SignatureKey, len(keyIDs))
	for _, keyID := range keyIDs {
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatalf("GenerateKey() error = %v", err)
		}
		keys[keyID] = conductor.SignatureKey{PublicKey: pub, KeyPurpose: purpose}
		proofs = append(proofs, conductor.SignatureProof{
			SignerKeyID: keyID,
			KeyPurpose:  purpose,
			Algorithm:   conductor.SignatureAlgorithmEd25519,
			Signature:   conductor.SignaturePrefixEd25519 + hex.EncodeToString(ed25519.Sign(priv, data)),
		})
	}
	return proofs, func(keyID string) (conductor.SignatureKey, error) {
		key, ok := keys[keyID]
		if !ok {
			return conductor.SignatureKey{}, conductor.ErrSignatureVerification
		}
		return key, nil
	}
}
