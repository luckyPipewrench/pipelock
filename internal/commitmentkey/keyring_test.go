// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package commitmentkey

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

type committedReceipt struct {
	KeyID      string
	Epoch      uint64
	Source     contractreceipt.ProvenanceSource
	View       string
	Commitment string
}

func TestLifecycleInitializeRestartOpensCommitment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "commitment-keyring.json")
	keyring, err := Initialize(path, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	receipt := commitTestReceipt(t, keyring, "alpha")

	restarted, err := Load(path)
	if err != nil {
		t.Fatalf("Load after restart: %v", err)
	}
	openTestReceipt(t, restarted, receipt)
	assertMode(t, path, 0o600)
	if _, err := Initialize(path, time.Now()); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("second Initialize error = %v, want ErrAlreadyExists", err)
	}
}

func TestLifecycleRotationRestartOpensOldAndNew(t *testing.T) {
	path := filepath.Join(t.TempDir(), "commitment-keyring.json")
	keyring, err := Initialize(path, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	oldReceipt := commitTestReceipt(t, keyring, "before rotation")
	oldID := oldReceipt.KeyID
	if _, err := keyring.Rotate(path, time.Unix(1_700_000_100, 0)); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	newReceipt := commitTestReceipt(t, keyring, "after rotation")
	if newReceipt.KeyID == oldID || newReceipt.Epoch != oldReceipt.Epoch+1 {
		t.Fatalf("rotation did not produce opaque successor: old=%+v new=%+v", oldReceipt, newReceipt)
	}

	restarted, err := Load(path)
	if err != nil {
		t.Fatalf("Load after rotation restart: %v", err)
	}
	openTestReceipt(t, restarted, oldReceipt)
	openTestReceipt(t, restarted, newReceipt)
}

func TestRetireRefusesRetainedReferenceAndCanExplicitlyAcceptLoss(t *testing.T) {
	path := filepath.Join(t.TempDir(), "commitment-keyring.json")
	keyring, err := Initialize(path, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	old := commitTestReceipt(t, keyring, "retained")
	if _, err := keyring.Rotate(path, time.Unix(1_700_000_100, 0)); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	refs := []Reference{{KeyID: old.KeyID, Epoch: old.Epoch}}
	if err := keyring.Retire(path, old.KeyID, old.Epoch, refs, false); !errors.Is(err, ErrRetainedKey) {
		t.Fatalf("Retire with retained reference error = %v, want ErrRetainedKey", err)
	}
	openTestReceipt(t, keyring, old)
	if err := keyring.Retire(path, old.KeyID, old.Epoch, refs, true); err != nil {
		t.Fatalf("Retire with accept loss: %v", err)
	}
	if _, err := keyring.Open(old.KeyID, old.Epoch); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Open destroyed retired key error = %v, want ErrKeyNotFound", err)
	}
	if err := keyring.Retire(path, keyring.ActiveID, keyring.Epoch, nil, true); err == nil {
		t.Fatal("Retire active key succeeded")
	}
}

func TestLifecycleBackupDestroyRestoreAndOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "commitment-keyring.json")
	backup := filepath.Join(dir, "backup", "commitment-keyring.json")
	keyring, err := Initialize(path, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	receipt := commitTestReceipt(t, keyring, "backup")
	if err := Backup(path, backup); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("destroy temporary keyring: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load destroyed keyring succeeded")
	}
	restored, err := Restore(backup, path)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	openTestReceipt(t, restored, receipt)
	assertMode(t, backup, 0o600)
	assertMode(t, path, 0o600)
}

func TestLoadFailsClosedOnPermissionsAndSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "commitment-keyring.json")
	if _, err := Initialize(path, time.Now()); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	if _, err := Load(path); !errors.Is(err, ErrUnsafePermission) {
		t.Fatalf("Load mode 0644 error = %v, want ErrUnsafePermission", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("restore mode: %v", err)
	}
	link := filepath.Join(dir, "substituted.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if _, err := Load(link); !errors.Is(err, ErrSymlink) {
		t.Fatalf("Load symlink error = %v, want ErrSymlink", err)
	}
	if err := keyringSaveThroughSymlink(path, link); !errors.Is(err, ErrSymlink) {
		t.Fatalf("Save symlink error = %v, want ErrSymlink", err)
	}
}

func TestPurposeValidationRejectsReceiptSigning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "commitment-keyring.json")
	keyring, err := Initialize(path, time.Now())
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	keyring.Purpose = "receipt-signing"
	data, err := marshal(keyring)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write wrong-purpose keyring: %v", err)
	}
	if _, err := Load(path); !errors.Is(err, ErrInvalidKeyring) {
		t.Fatalf("Load receipt-signing keyring error = %v, want ErrInvalidKeyring", err)
	}
}

func TestInvalidKeyringShapesFailClosed(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"unknown_field": `{"format":"pipelock-commitment-keyring/v1","extra":true}`,
		"trailing":      `{} {}`,
		"empty":         `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name+".json")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			if _, err := Load(path); !errors.Is(err, ErrInvalidKeyring) {
				t.Fatalf("Load error = %v, want ErrInvalidKeyring", err)
			}
		})
	}
}

func commitTestReceipt(t *testing.T, keyring *Keyring, view string) committedReceipt {
	t.Helper()
	handle, err := keyring.Active()
	if err != nil {
		t.Fatalf("Active: %v", err)
	}
	source := contractreceipt.ProvenanceSource{
		SourceOrdinal: 1,
		SourceID:      "source-1",
		Recipe: normalize.Recipe{
			TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest,
		},
	}
	commitment, err := contractreceipt.CommitView(handle.Key, source, view)
	if err != nil {
		t.Fatalf("CommitView: %v", err)
	}
	return committedReceipt{KeyID: handle.KeyID, Epoch: handle.Epoch, Source: source, View: view, Commitment: commitment}
}

func openTestReceipt(t *testing.T, keyring *Keyring, receipt committedReceipt) {
	t.Helper()
	handle, err := keyring.Open(receipt.KeyID, receipt.Epoch)
	if err != nil {
		t.Fatalf("Open(%q, %d): %v", receipt.KeyID, receipt.Epoch, err)
	}
	got, err := contractreceipt.CommitView(handle.Key, receipt.Source, receipt.View)
	if err != nil {
		t.Fatalf("CommitView on open: %v", err)
	}
	if got != receipt.Commitment {
		t.Fatalf("opened commitment = %q, want %q", got, receipt.Commitment)
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%s): %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("mode(%s) = %04o, want %04o", path, got, want)
	}
}

func keyringSaveThroughSymlink(realPath, link string) error {
	keyring, err := Load(realPath)
	if err != nil {
		return err
	}
	return keyring.Save(link)
}
