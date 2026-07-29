//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package auditbatcher

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestQueueKeyMaintenanceLifecycleAcrossRecordStates(t *testing.T) {
	root := t.TempDir()
	queueDir := filepath.Join(root, "queue")
	keyringPath := filepath.Join(root, "secrets", "keyring.json")
	backupPath := filepath.Join(root, "backups", "keyring.json")
	if _, err := InspectQueueKeys(queueDir, 0, nil); err == nil {
		t.Fatal("InspectQueueKeys(nil keyring) error = nil")
	}

	keyring, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	if err := EnsureKeyringParent(keyringPath); err != nil {
		t.Fatal(err)
	}
	if err := keyring.Save(keyringPath); err != nil {
		t.Fatal(err)
	}
	if err := EnsureKeyringParent(backupPath); err != nil {
		t.Fatal(err)
	}
	oldID := keyring.ActiveKeyID()

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	q, err := Open(Config{Dir: queueDir, Keyring: keyring})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.Enqueue(signedTestBatch(t, "batch-dead", priv)); err != nil {
		t.Fatal(err)
	}
	deadLease, err := q.Claim()
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Drop(deadLease.ID, "maintenance-test"); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Enqueue(signedTestBatch(t, "batch-inflight", priv)); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Claim(); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Enqueue(signedTestBatch(t, "batch-pending", priv)); err != nil {
		t.Fatal(err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	legacyName := "00000000000000000004-batch-legacy-0000000000000000.json"
	legacyPath := filepath.Join(queueDir, "pending", legacyName)
	if err := writeDiskRecord(legacyPath, validDiskRecord(signedTestBatch(t, "batch-legacy-maintenance", priv))); err != nil {
		t.Fatal(err)
	}

	usage, err := InspectQueueKeys(queueDir, 0, keyring)
	if err != nil {
		t.Fatal(err)
	}
	if usage[oldID] != 3 || usage[LegacyKeyID] != 1 {
		t.Fatalf("initial key usage = %#v, want active=3 legacy=1", usage)
	}

	rotatedOldID, newID, err := RotateQueueKeyring(queueDir, keyringPath, backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if rotatedOldID != oldID || newID == oldID {
		t.Fatalf("rotation IDs old=%q new=%q, want old=%q and distinct new", rotatedOldID, newID, oldID)
	}
	for _, path := range []string{backupPath, backupPath + ".previous"} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("rotation backup %s: %v", path, err)
		}
	}

	rotated, err := LoadKeyring(keyringPath)
	if err != nil {
		t.Fatal(err)
	}
	usage, err = InspectQueueKeys(queueDir, 0, rotated)
	if err != nil {
		t.Fatal(err)
	}
	if usage[newID] != 4 || usage[oldID] != 0 || usage[LegacyKeyID] != 0 {
		t.Fatalf("rotated key usage = %#v, want new active=4", usage)
	}
	migratedID, err := MigrateQueueKeyring(queueDir, keyringPath)
	if err != nil {
		t.Fatal(err)
	}
	if migratedID != newID {
		t.Fatalf("MigrateQueueKeyring active = %q, want %q", migratedID, newID)
	}
	if err := RevokeQueueKeyringKey(queueDir, keyringPath, newID); err == nil {
		t.Fatal("RevokeQueueKeyringKey(active) error = nil")
	}
	if err := RevokeQueueKeyringKey(queueDir, keyringPath, oldID); err != nil {
		t.Fatal(err)
	}

	recoveredID, err := RecoverQueueKeyring(queueDir, keyringPath, backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if recoveredID != newID {
		t.Fatalf("RecoverQueueKeyring active = %q, want %q", recoveredID, newID)
	}

	wrong, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	wrongPath := filepath.Join(root, "secrets", "wrong.json")
	if err := wrong.Save(wrongPath); err != nil {
		t.Fatal(err)
	}
	if _, err := RecoverQueueKeyring(queueDir, keyringPath, wrongPath); err == nil {
		t.Fatal("RecoverQueueKeyring(wrong key) error = nil")
	}

	live, err := Open(Config{Dir: queueDir, Keyring: rotated})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = live.Close() }()
	if _, err := InspectQueueKeys(queueDir, 0, rotated); !errors.Is(err, ErrQueueLocked) {
		t.Fatalf("InspectQueueKeys(live queue) error = %v, want ErrQueueLocked", err)
	}
}
