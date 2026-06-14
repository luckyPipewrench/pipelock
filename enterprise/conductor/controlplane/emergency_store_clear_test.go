//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestClearRollbackAuthorization_HappyPath(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenFileEmergencyStore(dir)
	if err != nil {
		t.Fatalf("OpenFileEmergencyStore: %v", err)
	}

	now := time.Now().UTC()
	auth := signedTestRollback(t, "clear-test-1", now, 100)

	_, created, err := store.PublishRollbackAuthorization(context.Background(), auth, now)
	if err != nil {
		t.Fatalf("PublishRollbackAuthorization: %v", err)
	}
	if !created {
		t.Fatal("expected created=true for first publish")
	}

	// Verify it's listed.
	all, err := store.RollbackAuthorizations(context.Background())
	if err != nil {
		t.Fatalf("RollbackAuthorizations: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected 1 rollback, got %d", len(all))
	}

	// Clear it.
	cleared, err := store.ClearRollbackAuthorization(context.Background(), "clear-test-1")
	if err != nil {
		t.Fatalf("ClearRollbackAuthorization: %v", err)
	}
	if !cleared {
		t.Fatal("expected cleared=true")
	}

	// Verify it's gone.
	all, err = store.RollbackAuthorizations(context.Background())
	if err != nil {
		t.Fatalf("RollbackAuthorizations after clear: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("expected 0 rollbacks after clear, got %d", len(all))
	}

	// Verify persistence: reopen the store and confirm empty.
	store2, err := OpenFileEmergencyStore(dir)
	if err != nil {
		t.Fatalf("OpenFileEmergencyStore (reopen): %v", err)
	}
	all2, err := store2.RollbackAuthorizations(context.Background())
	if err != nil {
		t.Fatalf("RollbackAuthorizations (reopened): %v", err)
	}
	if len(all2) != 0 {
		t.Fatalf("expected 0 rollbacks after reopen, got %d", len(all2))
	}
}

// TestClearRollbackAuthorization_RestoresStateOnWriteFailure proves the
// in-memory state is left intact (matching disk) when the durable write fails
// mid-clear, so a failed clear cannot silently stop an authorization from
// capping the stream head.
func TestClearRollbackAuthorization_RestoresStateOnWriteFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permissions; cannot force a write failure")
	}
	dir := t.TempDir()
	store, err := OpenFileEmergencyStore(dir)
	if err != nil {
		t.Fatalf("OpenFileEmergencyStore: %v", err)
	}

	now := time.Now().UTC()
	auth := signedTestRollback(t, "clear-restore-1", now, 100)
	if _, _, err := store.PublishRollbackAuthorization(context.Background(), auth, now); err != nil {
		t.Fatalf("PublishRollbackAuthorization: %v", err)
	}

	// Make the store directory read-only so the atomic write (temp file +
	// rename) fails when ClearRollbackAuthorization tries to persist.
	// #nosec G302 -- directory perms need the exec bit; this is a test-only
	// manipulation to make the atomic write fail (read-only dir).
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	// #nosec G302 -- restore owner rwx on the directory so t.TempDir cleanup
	// can remove it; directories require the exec bit.
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	cleared, err := store.ClearRollbackAuthorization(context.Background(), "clear-restore-1")
	if err == nil {
		t.Fatal("expected write failure error, got nil")
	}
	if cleared {
		t.Fatal("cleared must be false when the write fails")
	}

	// In-memory state must be unchanged: the authorization is still present.
	all, err := store.RollbackAuthorizations(context.Background())
	if err != nil {
		t.Fatalf("RollbackAuthorizations: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected 1 rollback retained after failed clear, got %d", len(all))
	}
	if all[0].Authorization.AuthorizationID != "clear-restore-1" {
		t.Fatalf("unexpected authorization retained: %s", all[0].Authorization.AuthorizationID)
	}
}

func TestClearRollbackAuthorization_NotFound(t *testing.T) {
	store, err := OpenFileEmergencyStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileEmergencyStore: %v", err)
	}

	cleared, err := store.ClearRollbackAuthorization(context.Background(), "nonexistent-id")
	if err != nil {
		t.Fatalf("ClearRollbackAuthorization error: %v", err)
	}
	if cleared {
		t.Fatal("expected cleared=false for nonexistent ID")
	}
}

func TestClearRollbackAuthorization_EmptyIDRejected(t *testing.T) {
	store, err := OpenFileEmergencyStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileEmergencyStore: %v", err)
	}

	_, err = store.ClearRollbackAuthorization(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "authorization_id required") {
		t.Fatalf("empty ID error = %v, want authorization_id required", err)
	}
}

func TestClearRollbackAuthorization_NilStoreRejected(t *testing.T) {
	var store *FileEmergencyStore
	_, err := store.ClearRollbackAuthorization(context.Background(), "some-id")
	if err == nil || !errors.Is(err, ErrEmergencyStoreRequired) {
		t.Fatalf("nil store error = %v, want ErrEmergencyStoreRequired", err)
	}
}

func TestClearRollbackAuthorization_PreservesOtherRecords(t *testing.T) {
	store, err := OpenFileEmergencyStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileEmergencyStore: %v", err)
	}

	now := time.Now().UTC()
	auth1 := signedTestRollback(t, "keep-this", now, 100)
	auth2 := signedTestRollback(t, "clear-this", now, 101)

	if _, _, err := store.PublishRollbackAuthorization(context.Background(), auth1, now); err != nil {
		t.Fatalf("Publish auth1: %v", err)
	}
	if _, _, err := store.PublishRollbackAuthorization(context.Background(), auth2, now); err != nil {
		t.Fatalf("Publish auth2: %v", err)
	}

	cleared, err := store.ClearRollbackAuthorization(context.Background(), "clear-this")
	if err != nil {
		t.Fatalf("Clear error: %v", err)
	}
	if !cleared {
		t.Fatal("expected cleared=true")
	}

	all, err := store.RollbackAuthorizations(context.Background())
	if err != nil {
		t.Fatalf("RollbackAuthorizations: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected 1 rollback, got %d", len(all))
	}
	if all[0].Authorization.AuthorizationID != "keep-this" {
		t.Fatalf("wrong record preserved: got %s", all[0].Authorization.AuthorizationID)
	}
}

// signedTestRollback creates a properly signed rollback authorization for
// testing. It generates two ed25519 keypairs (to meet the 2-of-N threshold)
// and signs the authorization with both.
func signedTestRollback(t *testing.T, id string, now time.Time, counter uint64) conductor.RollbackAuthorization {
	t.Helper()
	auth := conductor.RollbackAuthorization{
		SchemaVersion:   conductor.SchemaVersion,
		AuthorizationID: id,
		OrgID:           "test-org",
		FleetID:         "test-fleet",
		CurrentBundleID: "bundle-current",
		CurrentVersion:  2,
		TargetBundleID:  "bundle-target",
		TargetVersion:   1,
		Counter:         counter,
		Reason:          "test rollback",
		CreatedAt:       now,
		ExpiresAt:       now.Add(time.Hour),
	}

	// Generate two keypairs and sign.
	var sigs []conductor.SignatureProof
	for i := range 2 {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey(%d): %v", i, err)
		}
		preimage, err := auth.SignablePreimage()
		if err != nil {
			t.Fatalf("SignablePreimage: %v", err)
		}
		sig := ed25519.Sign(priv, preimage)
		keyID := "test-rollback-key-" + hex.EncodeToString([]byte{byte(i)})
		sigs = append(sigs, conductor.SignatureProof{
			SignerKeyID: keyID,
			KeyPurpose:  signing.PurposePolicyBundleRollback,
			Algorithm:   conductor.SignatureAlgorithmEd25519,
			Signature:   conductor.SignaturePrefixEd25519 + hex.EncodeToString(sig),
		})
	}
	auth.Signatures = sigs
	return auth
}

// TestClearRollbackAuthorization_HandlerEndpoint tests the handler's DELETE
// endpoint for clearing rollback authorizations.
func TestClearRollbackAuthorization_HandlerEndpoint(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenFileEmergencyStore(dir)
	if err != nil {
		t.Fatalf("OpenFileEmergencyStore: %v", err)
	}
	now := time.Now().UTC()
	auth := signedTestRollback(t, "handler-clear-test", now, 200)
	if _, _, err := store.PublishRollbackAuthorization(context.Background(), auth, now); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	// Verify it was stored.
	all, err := store.RollbackAuthorizations(context.Background())
	if err != nil {
		t.Fatalf("RollbackAuthorizations: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected 1 stored, got %d", len(all))
	}

	// Clear it.
	cleared, err := store.ClearRollbackAuthorization(context.Background(), "handler-clear-test")
	if err != nil {
		t.Fatalf("ClearRollbackAuthorization: %v", err)
	}
	if !cleared {
		t.Fatal("expected cleared=true")
	}

	// Confirm the state file on disk does not contain the cleared ID.
	statePath := filepath.Join(dir, emergencyStateFileName)
	data, err := os.ReadFile(filepath.Clean(statePath))
	if err != nil {
		t.Fatalf("ReadFile state: %v", err)
	}
	var record emergencyStateRecord
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("Unmarshal state: %v", err)
	}
	for _, rb := range record.Rollbacks {
		if rb.Authorization.AuthorizationID == "handler-clear-test" {
			t.Fatal("cleared authorization still present in on-disk state")
		}
	}
}
