// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package commitmentkey

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
	"github.com/luckyPipewrench/pipelock/internal/signing"
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
	if _, _, err := Rotate(path, time.Unix(1_700_000_100, 0)); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	keyring, err = Load(path)
	if err != nil {
		t.Fatalf("Load rotated keyring: %v", err)
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

func TestPersistenceRestartKeepsActiveMaterial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "commitment-keyring.json")
	keyring, err := Initialize(path, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	receipt := commitTestReceipt(t, keyring, "persistence guard")
	restarted, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	openTestReceipt(t, restarted, receipt)
}

func TestLifecycleMutationsReturnCommittedMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyring.json")
	initialized, err := Initialize(path, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	handle, rotated, err := Rotate(path, time.Unix(1_700_000_100, 0))
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if rotated.ActiveID != handle.KeyID || rotated.Epoch != handle.Epoch || len(rotated.Keys) != 2 {
		t.Fatalf("Rotate metadata = %+v, handle = %+v", rotated, handle)
	}
	retired, err := Retire(path, initialized.ActiveID, initialized.Epoch, true)
	if err != nil {
		t.Fatalf("Retire: %v", err)
	}
	if retired.ActiveID != handle.KeyID || retired.Epoch != handle.Epoch || len(retired.Keys) != 1 {
		t.Fatalf("Retire metadata = %+v, active handle = %+v", retired, handle)
	}
}

func TestKeyringDoesNotExportUnlockedSave(t *testing.T) {
	if _, exists := reflect.TypeFor[*Keyring]().MethodByName("Save"); exists {
		t.Fatal("Keyring exports Save without enforcing the lifecycle lock")
	}
}

func TestInvalidReadErrorClassificationDoesNotDependOnLabel(t *testing.T) {
	err := invalidReadError(ErrInvalidKeyring, "renamed keyring label", "not a regular file")
	if !errors.Is(err, ErrInvalidKeyring) {
		t.Fatalf("explicit keyring sentinel error = %v, want ErrInvalidKeyring", err)
	}
	err = invalidReadError(nil, "commitment keyring", "not a regular file")
	if errors.Is(err, ErrInvalidKeyring) {
		t.Fatalf("nil sentinel error = %v, classification leaked from label", err)
	}
}

func TestRetiredLookupOpensPriorEpoch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "commitment-keyring.json")
	keyring, err := Initialize(path, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	receipt := commitTestReceipt(t, keyring, "retired lookup guard")
	if _, err := keyring.rotate(path, time.Unix(1_700_000_100, 0)); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	openTestReceipt(t, keyring, receipt)
}

func TestRetireRequiresExplicitLossAcceptance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "commitment-keyring.json")
	keyring, err := Initialize(path, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	old := commitTestReceipt(t, keyring, "retained")
	if _, _, err := Rotate(path, time.Unix(1_700_000_100, 0)); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	keyring, err = Load(path)
	if err != nil {
		t.Fatalf("Load rotated keyring: %v", err)
	}
	if _, err := Retire(path, old.KeyID, old.Epoch, false); !errors.Is(err, ErrRetainedKey) {
		t.Fatalf("Retire without loss acceptance error = %v, want ErrRetainedKey", err)
	}
	openTestReceipt(t, keyring, old)
	if _, err := Retire(path, old.KeyID, old.Epoch, true); err != nil {
		t.Fatalf("Retire with accept loss: %v", err)
	}
	keyring, err = Load(path)
	if err != nil {
		t.Fatalf("Load after retirement: %v", err)
	}
	if _, err := keyring.Open(old.KeyID, old.Epoch); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Open destroyed retired key error = %v, want ErrKeyNotFound", err)
	}
	if _, err := Retire(path, keyring.ActiveID, keyring.Epoch, true); err == nil {
		t.Fatal("Retire active key succeeded")
	}
}

func TestConcurrentRotationsSerializeEpochs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "commitment-keyring.json")
	if _, err := Initialize(path, time.Unix(1_700_000_000, 0)); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	const rotations = 8
	errs := make(chan error, rotations)
	var wg sync.WaitGroup
	for i := range rotations {
		wg.Add(1)
		go func(offset int) {
			defer wg.Done()
			_, _, err := Rotate(path, time.Unix(1_700_000_100+int64(offset), 0))
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Rotate: %v", err)
		}
	}
	keyring, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if keyring.Epoch != rotations+1 || len(keyring.Keys) != rotations+1 {
		t.Fatalf("concurrent rotations produced epoch=%d keys=%d, want %d", keyring.Epoch, len(keyring.Keys), rotations+1)
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
	if _, err := Backup(path, backup); err != nil {
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
	if runtime.GOOS == "windows" {
		t.Skip("Windows ACL and symlink behavior differs from Unix mode semantics")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "commitment-keyring.json")
	if _, err := Initialize(path, time.Now()); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	link := filepath.Join(dir, "substituted.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	t.Run("wrong_permissions", func(t *testing.T) {
		unsafeMode := os.FileMode(0o600)
		unsafeMode |= 0o044
		if err := os.Chmod(path, unsafeMode); err != nil {
			t.Fatalf("Chmod: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
		if _, err := Load(path); !errors.Is(err, ErrUnsafePermission) {
			t.Fatalf("Load mode 0644 error = %v, want ErrUnsafePermission", err)
		}
	})
	t.Run("symlink_load", func(t *testing.T) {
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatalf("restore mode: %v", err)
		}
		if _, err := Load(link); !errors.Is(err, ErrSymlink) {
			t.Fatalf("Load symlink error = %v, want ErrSymlink", err)
		}
	})
	t.Run("symlink_save", func(t *testing.T) {
		before, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Fatalf("ReadFile before: %v", err)
		}
		if err := keyringSaveThroughSymlink(path, link); !errors.Is(err, ErrSymlink) {
			t.Fatalf("Save symlink error = %v, want ErrSymlink", err)
		}
		after, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Fatalf("ReadFile after: %v", err)
		}
		if string(after) != string(before) {
			t.Fatal("refused symlink save modified the target")
		}
	})
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

func TestCommitmentKeyringCannotLoadAsReceiptSigningKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "commitment-keyring.json")
	if _, err := Initialize(path, time.Now()); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if _, err := signing.LoadPrivateKeyFile(path); err == nil {
		t.Fatal("receipt-signing loader accepted commitment keyring")
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

func TestValidateRejectsMalformedLifecycleState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyring.json")
	base, err := Initialize(path, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	retired := cloneKeyring(base)
	if _, err := retired.rotate(path, time.Unix(1_700_000_100, 0)); err != nil {
		t.Fatalf("rotate fixture: %v", err)
	}
	retiredAt := time.Unix(1_700_000_100, 0).UTC()
	wantError := map[string]string{
		"duplicate key id":        "duplicate key ID",
		"duplicate epoch":         "duplicate epoch",
		"retired epoch not older": "retired key",
	}
	mutations := map[string]func(*Keyring){
		"missing active metadata": func(k *Keyring) { k.Epoch = 0 },
		"short key id":            func(k *Keyring) { k.Keys[0].KeyID = "ck_short" },
		"nonhex key id":           func(k *Keyring) { k.Keys[0].KeyID = "ck_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz" },
		"zero entry epoch":        func(k *Keyring) { k.Keys[0].Epoch = 0 },
		"zero created time":       func(k *Keyring) { k.Keys[0].CreatedAt = time.Time{} },
		"duplicate key id": func(k *Keyring) {
			duplicate := k.Keys[0]
			duplicate.Epoch = 2
			duplicate.State = StateRetired
			duplicate.RetiredAt = &retiredAt
			k.Keys = append(k.Keys, duplicate)
		},
		"duplicate epoch": func(k *Keyring) {
			duplicate, entryErr := newEntry(1, time.Unix(1_700_000_001, 0))
			if entryErr != nil {
				t.Fatalf("newEntry: %v", entryErr)
			}
			duplicate.State = StateRetired
			duplicate.RetiredAt = &retiredAt
			k.Keys = append(k.Keys, duplicate)
		},
		"invalid base64 key":       func(k *Keyring) { k.Keys[0].Key = "%%%" },
		"short decoded key":        func(k *Keyring) { k.Keys[0].Key = base64.StdEncoding.EncodeToString([]byte("short")) },
		"active id mismatch":       func(k *Keyring) { k.ActiveID = "ck_00000000000000000000000000000000" },
		"active retired timestamp": func(k *Keyring) { k.Keys[0].RetiredAt = &retiredAt },
		"unknown state":            func(k *Keyring) { k.Keys[0].State = State("unknown") },
		"no active key": func(k *Keyring) {
			k.Epoch = 2
			k.Keys[0].State = StateRetired
			k.Keys[0].RetiredAt = &retiredAt
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			keyring := cloneKeyring(base)
			mutate(keyring)
			err := keyring.Validate()
			if !errors.Is(err, ErrInvalidKeyring) {
				t.Fatalf("Validate error = %v, want ErrInvalidKeyring", err)
			}
			if want := wantError[name]; want != "" && !strings.Contains(err.Error(), want) {
				t.Fatalf("Validate error = %q, want substring %q", err, want)
			}
		})
	}
	for name, mutate := range map[string]func(*Keyring){
		"retired timestamp absent": func(k *Keyring) { k.Keys[0].RetiredAt = nil },
		"retired epoch not older":  func(k *Keyring) { k.Keys[0].Epoch = k.Epoch },
	} {
		t.Run(name, func(t *testing.T) {
			keyring := cloneKeyring(retired)
			mutate(keyring)
			err := keyring.Validate()
			if !errors.Is(err, ErrInvalidKeyring) {
				t.Fatalf("Validate error = %v, want ErrInvalidKeyring", err)
			}
			if want := wantError[name]; want != "" && !strings.Contains(err.Error(), want) {
				t.Fatalf("Validate error = %q, want substring %q", err, want)
			}
		})
	}
}

func TestFilesystemErrorPathsFailClosed(t *testing.T) {
	t.Run("initialize below file parent", func(t *testing.T) {
		parentFile := filepath.Join(t.TempDir(), "parent-file")
		if err := os.WriteFile(parentFile, []byte("not a directory"), 0o600); err != nil {
			t.Fatalf("WriteFile parent: %v", err)
		}
		if _, err := Initialize(filepath.Join(parentFile, "keyring.json"), time.Now()); err == nil {
			t.Fatal("Initialize below file parent succeeded")
		}
	})

	t.Run("invalid saves", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "keyring.json")
		keyring, err := Initialize(path, time.Now())
		if err != nil {
			t.Fatalf("Initialize: %v", err)
		}
		invalid := cloneKeyring(keyring)
		invalid.Purpose = "receipt-signing"
		if err := invalid.saveLocked(path); !errors.Is(err, ErrInvalidKeyring) {
			t.Fatalf("saveLocked invalid keyring error = %v, want ErrInvalidKeyring", err)
		}
		if err := keyring.saveLocked(dir); err == nil {
			t.Fatal("saveLocked over directory succeeded")
		}
	})

	t.Run("unknown and corrupt key material", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "keyring.json")
		keyring, err := Initialize(path, time.Now())
		if err != nil {
			t.Fatalf("Initialize: %v", err)
		}
		if _, err := keyring.Open(keyring.ActiveID, keyring.Epoch+1); !errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("Open unknown epoch error = %v, want ErrKeyNotFound", err)
		}
		corrupt := cloneKeyring(keyring)
		corrupt.Keys[0].Key = "invalid"
		if _, err := corrupt.Open(corrupt.ActiveID, corrupt.Epoch); !errors.Is(err, ErrInvalidKeyring) {
			t.Fatalf("Open corrupt key error = %v, want ErrInvalidKeyring", err)
		}
	})

	t.Run("backup and restore refusals", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "keyring.json")
		if _, err := Initialize(path, time.Now()); err != nil {
			t.Fatalf("Initialize: %v", err)
		}
		parentFile := filepath.Join(dir, "parent-file")
		if err := os.WriteFile(parentFile, []byte("not a directory"), 0o600); err != nil {
			t.Fatalf("WriteFile parent: %v", err)
		}
		missing := filepath.Join(dir, "missing.json")
		if _, err := Backup(missing, filepath.Join(dir, "unused-backup.json")); err == nil {
			t.Fatal("Backup missing source succeeded")
		}
		if _, err := Restore(missing, filepath.Join(dir, "unused-restore.json")); err == nil {
			t.Fatal("Restore missing source succeeded")
		}
		if _, err := Backup(path, filepath.Join(parentFile, "backup.json")); err == nil {
			t.Fatal("Backup below file parent succeeded")
		}
		if _, err := Restore(path, filepath.Join(parentFile, "restore.json")); err == nil {
			t.Fatal("Restore below file parent succeeded")
		}
		backup := filepath.Join(dir, "backup.json")
		if _, err := Backup(path, backup); err != nil {
			t.Fatalf("Backup: %v", err)
		}
		if _, err := Backup(path, backup); err == nil {
			t.Fatal("Backup over existing destination succeeded")
		}
		if _, err := Restore(backup, path); err == nil {
			t.Fatal("Restore over existing destination succeeded")
		}
	})

	t.Run("load refusals", func(t *testing.T) {
		dir := t.TempDir()
		if _, err := Load(filepath.Join(dir, "absent-parent", "keyring.json")); err == nil {
			t.Fatal("Load below absent parent succeeded")
		}
		if supportsUnixModeAssertions(runtime.GOOS) {
			if _, err := Load(dir); !errors.Is(err, ErrInvalidKeyring) {
				t.Fatalf("Load directory error = %v, want ErrInvalidKeyring", err)
			}
		}
		oversized := filepath.Join(dir, "oversized.json")
		file, err := os.OpenFile(filepath.Clean(oversized), os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatalf("OpenFile oversized: %v", err)
		}
		if err := file.Truncate(maxBytes + 1); err != nil {
			_ = file.Close()
			t.Fatalf("Truncate oversized: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("Close oversized: %v", err)
		}
		if _, err := Load(oversized); !errors.Is(err, ErrInvalidKeyring) {
			t.Fatalf("Load oversized error = %v, want ErrInvalidKeyring", err)
		}
	})
}

func cloneKeyring(keyring *Keyring) *Keyring {
	clone := *keyring
	clone.Keys = append([]Entry(nil), keyring.Keys...)
	return &clone
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
	if !supportsUnixModeAssertions(runtime.GOOS) {
		t.Log("skipping Unix mode assertion: Windows represents access through ACLs")
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%s): %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("mode(%s) = %04o, want %04o", path, got, want)
	}
}

func TestModeAssertionPlatformGuard(t *testing.T) {
	if supportsUnixModeAssertions("windows") {
		t.Fatal("Windows selected for Unix mode assertion")
	}
	if !supportsUnixModeAssertions("linux") {
		t.Fatal("Linux excluded from Unix mode assertion")
	}
}

func supportsUnixModeAssertions(goos string) bool {
	return goos != "windows"
}

func keyringSaveThroughSymlink(realPath, link string) error {
	keyring, err := Load(realPath)
	if err != nil {
		return err
	}
	return withLifecycleLock(link, func() error {
		return keyring.saveLocked(link)
	})
}
