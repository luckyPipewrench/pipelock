//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

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

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
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

	dir = t.TempDir()
	large := filepath.Join(dir, emergencyStateFileName)
	if err := os.WriteFile(large, []byte(strings.Repeat("x", maxEmergencyStateJSONSize+1)), 0o600); err != nil {
		t.Fatalf("WriteFile(large): %v", err)
	}
	if _, err := OpenFileEmergencyStore(dir); !errors.Is(err, conductor.ErrPayloadTooLarge) {
		t.Fatalf("OpenFileEmergencyStore(large) err=%v, want ErrPayloadTooLarge", err)
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

func TestFileEmergencyStoreLoadsRollbackStateAndRejectsDuplicates(t *testing.T) {
	dir := t.TempDir()
	auth := signedRollbackAuthorization(t, "rollback-load", 7, testNow)
	hash, err := auth.CanonicalHash()
	if err != nil {
		t.Fatalf("CanonicalHash(rollback): %v", err)
	}
	record := StoredRollbackAuthorization{
		Authorization:     auth,
		AuthorizationHash: hash,
		PublishedAt:       testNow,
	}
	if err := writeEmergencyState(filepath.Join(dir, emergencyStateFileName), emergencyStateRecord{Rollbacks: []StoredRollbackAuthorization{record}}); err != nil {
		t.Fatalf("writeEmergencyState(rollback): %v", err)
	}
	store, err := OpenFileEmergencyStore(dir)
	if err != nil {
		t.Fatalf("OpenFileEmergencyStore(rollback) error = %v", err)
	}
	lookup := RollbackLookup{
		CurrentBundleID: auth.CurrentBundleID,
		CurrentVersion:  auth.CurrentVersion,
		TargetBundleID:  auth.TargetBundleID,
		TargetVersion:   auth.TargetVersion,
	}
	got, err := store.LatestRollbackAuthorization(context.Background(), defaultFollowerIdentity(), lookup, testNow)
	if err != nil || got.Authorization.AuthorizationID != auth.AuthorizationID {
		t.Fatalf("LatestRollbackAuthorization(reopened) = %+v, %v; want %q", got.Authorization, err, auth.AuthorizationID)
	}

	duplicateHashDir := t.TempDir()
	if err := writeEmergencyState(filepath.Join(duplicateHashDir, emergencyStateFileName), emergencyStateRecord{
		Rollbacks: []StoredRollbackAuthorization{record, record},
	}); err != nil {
		t.Fatalf("writeEmergencyState(duplicate hash): %v", err)
	}
	if _, err := OpenFileEmergencyStore(duplicateHashDir); !errors.Is(err, ErrInvalidEmergencyRecord) {
		t.Fatalf("OpenFileEmergencyStore(duplicate rollback hash) err=%v, want ErrInvalidEmergencyRecord", err)
	}

	duplicateIDDir := t.TempDir()
	newer := signedRollbackAuthorization(t, auth.AuthorizationID, 8, testNow.Add(time.Minute))
	newerHash, err := newer.CanonicalHash()
	if err != nil {
		t.Fatalf("CanonicalHash(newer rollback): %v", err)
	}
	newerRecord := StoredRollbackAuthorization{
		Authorization:     newer,
		AuthorizationHash: newerHash,
		PublishedAt:       testNow.Add(time.Minute),
	}
	if err := writeEmergencyState(filepath.Join(duplicateIDDir, emergencyStateFileName), emergencyStateRecord{
		Rollbacks: []StoredRollbackAuthorization{record, newerRecord},
	}); err != nil {
		t.Fatalf("writeEmergencyState(duplicate id): %v", err)
	}
	if _, err := OpenFileEmergencyStore(duplicateIDDir); !errors.Is(err, ErrInvalidEmergencyRecord) {
		t.Fatalf("OpenFileEmergencyStore(duplicate rollback id) err=%v, want ErrInvalidEmergencyRecord", err)
	}
}

func TestEmergencyStoreValidationAndOrderingHelpers(t *testing.T) {
	msg := signedRemoteKillMessage(t, "kill-helper", 3, conductor.KillSwitchActive, testNow)
	hash, err := msg.CanonicalHash()
	if err != nil {
		t.Fatalf("CanonicalHash(remote kill): %v", err)
	}
	remoteRecord := StoredRemoteKill{Message: msg, MessageHash: hash, PublishedAt: testNow}
	if err := validateStoredRemoteKill(remoteRecord); err != nil {
		t.Fatalf("validateStoredRemoteKill(valid) error = %v", err)
	}
	remoteRecord.PublishedAt = time.Time{}
	if err := validateStoredRemoteKill(remoteRecord); !errors.Is(err, ErrInvalidEmergencyRecord) {
		t.Fatalf("validateStoredRemoteKill(missing published_at) error = %v, want ErrInvalidEmergencyRecord", err)
	}
	remoteRecord = StoredRemoteKill{Message: msg, MessageHash: "bad-hash", PublishedAt: testNow}
	if err := validateStoredRemoteKill(remoteRecord); !errors.Is(err, ErrInvalidEmergencyRecord) {
		t.Fatalf("validateStoredRemoteKill(hash mismatch) error = %v, want ErrInvalidEmergencyRecord", err)
	}

	auth := signedRollbackAuthorization(t, "rollback-helper", 3, testNow)
	authHash, err := auth.CanonicalHash()
	if err != nil {
		t.Fatalf("CanonicalHash(rollback): %v", err)
	}
	rollbackRecord := StoredRollbackAuthorization{Authorization: auth, AuthorizationHash: authHash, PublishedAt: testNow}
	if err := validateStoredRollback(rollbackRecord); err != nil {
		t.Fatalf("validateStoredRollback(valid) error = %v", err)
	}
	rollbackRecord.PublishedAt = time.Time{}
	if err := validateStoredRollback(rollbackRecord); !errors.Is(err, ErrInvalidEmergencyRecord) {
		t.Fatalf("validateStoredRollback(missing published_at) error = %v, want ErrInvalidEmergencyRecord", err)
	}
	rollbackRecord = StoredRollbackAuthorization{Authorization: auth, AuthorizationHash: "bad-hash", PublishedAt: testNow}
	if err := validateStoredRollback(rollbackRecord); !errors.Is(err, ErrInvalidEmergencyRecord) {
		t.Fatalf("validateStoredRollback(hash mismatch) error = %v, want ErrInvalidEmergencyRecord", err)
	}

	olderMsg := signedRemoteKillMessage(t, "kill-old", 9, conductor.KillSwitchActive, testNow)
	newerMsg := signedRemoteKillMessage(t, "kill-new", 9, conductor.KillSwitchActive, testNow.Add(time.Minute))
	olderHash, err := olderMsg.CanonicalHash()
	if err != nil {
		t.Fatalf("CanonicalHash(old remote): %v", err)
	}
	newerHash, err := newerMsg.CanonicalHash()
	if err != nil {
		t.Fatalf("CanonicalHash(new remote): %v", err)
	}
	if !newerRemoteKill(
		StoredRemoteKill{Message: newerMsg, MessageHash: newerHash, PublishedAt: testNow.Add(time.Minute)},
		StoredRemoteKill{Message: olderMsg, MessageHash: olderHash, PublishedAt: testNow},
	) {
		t.Fatal("newerRemoteKill(created_at) = false, want true")
	}
	if got := newerRemoteKill(
		StoredRemoteKill{Message: olderMsg, MessageHash: "b", PublishedAt: testNow},
		StoredRemoteKill{Message: olderMsg, MessageHash: "a", PublishedAt: testNow},
	); !got {
		t.Fatal("newerRemoteKill(hash tie-breaker) = false, want true")
	}

	olderAuth := signedRollbackAuthorization(t, "rollback-old", 9, testNow)
	newerAuth := signedRollbackAuthorization(t, "rollback-new", 9, testNow.Add(time.Minute))
	olderAuthHash, err := olderAuth.CanonicalHash()
	if err != nil {
		t.Fatalf("CanonicalHash(old rollback): %v", err)
	}
	newerAuthHash, err := newerAuth.CanonicalHash()
	if err != nil {
		t.Fatalf("CanonicalHash(new rollback): %v", err)
	}
	if !newerRollback(
		StoredRollbackAuthorization{Authorization: newerAuth, AuthorizationHash: newerAuthHash, PublishedAt: testNow.Add(time.Minute)},
		StoredRollbackAuthorization{Authorization: olderAuth, AuthorizationHash: olderAuthHash, PublishedAt: testNow},
	) {
		t.Fatal("newerRollback(created_at) = false, want true")
	}
	if got := newerRollback(
		StoredRollbackAuthorization{Authorization: olderAuth, AuthorizationHash: "b", PublishedAt: testNow},
		StoredRollbackAuthorization{Authorization: olderAuth, AuthorizationHash: "a", PublishedAt: testNow},
	); !got {
		t.Fatal("newerRollback(hash tie-breaker) = false, want true")
	}
}

func TestEmergencyStoreEdgeCases(t *testing.T) {
	var nilStore *FileEmergencyStore
	msg := signedRemoteKillMessage(t, "kill-edge", 1, conductor.KillSwitchActive, testNow)
	if _, _, err := nilStore.PublishRemoteKill(context.Background(), msg, testNow); !errors.Is(err, ErrEmergencyStoreRequired) {
		t.Fatalf("PublishRemoteKill(nil) err=%v, want ErrEmergencyStoreRequired", err)
	}
	if _, err := nilStore.LatestRemoteKill(context.Background(), defaultFollowerIdentity(), testNow); !errors.Is(err, ErrEmergencyStoreRequired) {
		t.Fatalf("LatestRemoteKill(nil) err=%v, want ErrEmergencyStoreRequired", err)
	}
	auth := signedRollbackAuthorization(t, "rollback-edge", 1, testNow)
	if _, _, err := nilStore.PublishRollbackAuthorization(context.Background(), auth, testNow); !errors.Is(err, ErrEmergencyStoreRequired) {
		t.Fatalf("PublishRollbackAuthorization(nil) err=%v, want ErrEmergencyStoreRequired", err)
	}
	lookup := RollbackLookup{
		CurrentBundleID: auth.CurrentBundleID,
		CurrentVersion:  auth.CurrentVersion,
		TargetBundleID:  auth.TargetBundleID,
		TargetVersion:   auth.TargetVersion,
	}
	if _, err := nilStore.LatestRollbackAuthorization(context.Background(), defaultFollowerIdentity(), lookup, testNow); !errors.Is(err, ErrEmergencyStoreRequired) {
		t.Fatalf("LatestRollbackAuthorization(nil) err=%v, want ErrEmergencyStoreRequired", err)
	}

	store := mustEmergencyStore(t)
	badMsg := msg
	badMsg.MessageID = ""
	if _, _, err := store.PublishRemoteKill(context.Background(), badMsg, testNow); !errors.Is(err, conductor.ErrMissingField) {
		t.Fatalf("PublishRemoteKill(invalid) err=%v, want ErrMissingField", err)
	}
	if _, created, err := store.PublishRemoteKill(context.Background(), msg, testNow); err != nil || !created {
		t.Fatalf("PublishRemoteKill(edge) created=%v err=%v, want created", created, err)
	}
	conflict := signedRemoteKillMessage(t, msg.MessageID, 2, conductor.KillSwitchInactive, testNow.Add(time.Minute))
	if _, _, err := store.PublishRemoteKill(context.Background(), conflict, testNow.Add(time.Minute)); !errors.Is(err, ErrEmergencyConflict) {
		t.Fatalf("PublishRemoteKill(conflict) err=%v, want ErrEmergencyConflict", err)
	}
	badFollower := defaultFollowerIdentity()
	badFollower.OrgID = ""
	if _, err := store.LatestRemoteKill(context.Background(), badFollower, testNow); !errors.Is(err, ErrFollowerRequired) {
		t.Fatalf("LatestRemoteKill(invalid follower) err=%v, want ErrFollowerRequired", err)
	}

	badAuth := auth
	badAuth.AuthorizationID = ""
	if _, _, err := store.PublishRollbackAuthorization(context.Background(), badAuth, testNow); !errors.Is(err, conductor.ErrMissingField) {
		t.Fatalf("PublishRollbackAuthorization(invalid) err=%v, want ErrMissingField", err)
	}
	if _, created, err := store.PublishRollbackAuthorization(context.Background(), auth, testNow); err != nil || !created {
		t.Fatalf("PublishRollbackAuthorization(edge) created=%v err=%v, want created", created, err)
	}
	authConflict := signedRollbackAuthorization(t, auth.AuthorizationID, 2, testNow.Add(time.Minute))
	if _, _, err := store.PublishRollbackAuthorization(context.Background(), authConflict, testNow.Add(time.Minute)); !errors.Is(err, ErrEmergencyConflict) {
		t.Fatalf("PublishRollbackAuthorization(conflict) err=%v, want ErrEmergencyConflict", err)
	}
	if _, err := store.LatestRollbackAuthorization(context.Background(), badFollower, lookup, testNow); !errors.Is(err, ErrFollowerRequired) {
		t.Fatalf("LatestRollbackAuthorization(invalid follower) err=%v, want ErrFollowerRequired", err)
	}
	badLookup := lookup
	badLookup.TargetVersion = 0
	if _, err := store.LatestRollbackAuthorization(context.Background(), defaultFollowerIdentity(), badLookup, testNow); !errors.Is(err, conductor.ErrMissingField) {
		t.Fatalf("LatestRollbackAuthorization(invalid lookup) err=%v, want ErrMissingField", err)
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
