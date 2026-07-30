//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package auditbatcher

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
)

func TestQueueEncryptsRecordsAtRest(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	q := openTestQueue(t, Config{})
	payload := []byte(`{"events":[{"message":"plaintext-sentinel"}]}`)
	envelope := validUnsignedEnvelope(t, "batch-encrypted-at-rest", payload)
	signed, err := SignEnvelope(envelope, "audit-key-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	batch := Batch{Envelope: signed, Payload: payload}

	id, err := q.Enqueue(batch)
	if err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	data, err := os.ReadFile(filepath.Clean(filepath.Join(q.pendingDir, id)))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("plaintext-sentinel")) {
		t.Fatal("durable record contains plaintext payload")
	}
	if !bytes.Contains(data, []byte(`"version":2`)) || !bytes.Contains(data, []byte(`"ciphertext"`)) {
		t.Fatalf("durable record is not the encrypted v2 envelope: %s", data)
	}
	var encrypted encryptedDiskRecord
	if err := json.Unmarshal(data, &encrypted); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted.Ciphertext, []byte("plaintext-sentinel")) {
		t.Fatal("decoded ciphertext field contains plaintext payload")
	}
}

func TestEncryptedRecordMaxPayloadSurvivesRestartAndClaim(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	q, err := Open(Config{Dir: dir, Keyring: keyring})
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0xff}, conductor.MaxAuditPayloadBytes)
	envelope := validUnsignedEnvelope(t, "batch-max-payload", payload)
	signed, err := SignEnvelope(envelope, "audit-key-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	id, err := q.Enqueue(Batch{Envelope: signed, Payload: payload})
	if err != nil {
		t.Fatalf("Enqueue(max payload) error = %v", err)
	}
	oldLimit, err := recordReadLimit(conductor.MaxAuditPayloadBytes)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(q.pendingDir, id))
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() <= oldLimit+encryptedRecordMetadataBytes {
		t.Fatalf("encrypted record size = %d, want above old flat-overhead ceiling %d", info.Size(), oldLimit+encryptedRecordMetadataBytes)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(Config{Dir: dir, Keyring: keyring})
	if err != nil {
		t.Fatalf("Open(max payload record) error = %v", err)
	}
	defer func() { _ = reopened.Close() }()
	lease, err := reopened.Claim()
	if err != nil {
		t.Fatalf("Claim(max payload record) error = %v", err)
	}
	if !bytes.Equal(lease.Batch.Payload, payload) {
		t.Fatal("claimed max payload differs from enqueued bytes")
	}
}

func TestEncryptedRecordTamperFailsClosed(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	q := openTestQueue(t, Config{})
	id, err := q.Enqueue(signedTestBatch(t, "batch-tamper", priv))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(q.pendingDir, id)
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), data...)
	needle := []byte(`"ciphertext":"`)
	start := bytes.Index(data, needle)
	if start < 0 {
		t.Fatal("ciphertext field absent")
	}
	at := start + len(needle)
	if data[at] == 'A' {
		data[at] = 'B'
	} else {
		data[at] = 'A'
	}
	if err := os.WriteFile(path, data, fileMode); err != nil {
		t.Fatal(err)
	}

	_, err = q.readRecord(path)
	if err == nil || !errors.Is(err, ErrRecordAuthFailed) || errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("tampered read error = %v, want dedicated authentication failure", err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Config{Dir: q.dir, Keyring: q.keyring}); !errors.Is(err, ErrRecordAuthFailed) {
		t.Fatalf("Open(tampered record) error = %v, want ErrRecordAuthFailed", err)
	}
	if err := os.WriteFile(path, original, fileMode); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(Config{Dir: q.dir, Keyring: q.keyring})
	if err != nil {
		t.Fatalf("Open after failed startup retained queue lock: %v", err)
	}
	defer func() { _ = reopened.Close() }()
}

func TestEncryptedRecordTamperBlocksStartupInEveryQueueState(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"pending", "inflight", "dead"} {
		t.Run(state, func(t *testing.T) {
			dir := t.TempDir()
			keyring, err := NewKeyring()
			if err != nil {
				t.Fatal(err)
			}
			q, err := Open(Config{Dir: dir, Keyring: keyring})
			if err != nil {
				t.Fatal(err)
			}
			id, err := q.Enqueue(signedTestBatch(t, "batch-tamper-"+state, priv))
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(q.pendingDir, id)
			switch state {
			case "inflight":
				if _, err := q.Claim(); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(q.inflightDir, id)
			case "dead":
				lease, err := q.Claim()
				if err != nil {
					t.Fatal(err)
				}
				if err := q.Drop(lease.ID, "tamper fixture"); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(q.deadDir, id)
			}
			data, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatal(err)
			}
			needle := []byte(`"ciphertext":"`)
			at := bytes.Index(data, needle) + len(needle)
			if at < len(needle) || at >= len(data) {
				t.Fatal("ciphertext field absent")
			}
			if data[at] == 'A' {
				data[at] = 'B'
			} else {
				data[at] = 'A'
			}
			if err := os.WriteFile(path, data, fileMode); err != nil {
				t.Fatal(err)
			}
			if err := q.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(Config{Dir: dir, Keyring: keyring}); !errors.Is(err, ErrRecordAuthFailed) {
				t.Fatalf("Open(tampered %s record) error = %v, want ErrRecordAuthFailed", state, err)
			}
		})
	}
}

func TestOpenMigratesLegacyAndRotatedRecords(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyring, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	q, err := Open(Config{Dir: dir, Keyring: keyring})
	if err != nil {
		t.Fatal(err)
	}
	batch := signedTestBatch(t, "batch-rotate", priv)
	id, err := q.Enqueue(batch)
	if err != nil {
		t.Fatal(err)
	}
	oldID := keyring.ActiveKeyID()
	if _, err := keyring.Rotate(); err != nil {
		t.Fatal(err)
	}
	legacyID := "00000000000000000001-batch-legacy-0000000000000000.json"
	if err := writeDiskRecord(filepath.Join(q.pendingDir, legacyID), validDiskRecord(signedTestBatch(t, "batch-legacy", priv))); err != nil {
		t.Fatal(err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(Config{Dir: dir, Keyring: keyring})
	if err != nil {
		t.Fatalf("Open(migrate) error = %v", err)
	}
	defer func() { _ = reopened.Close() }()
	for _, name := range []string{id, legacyID} {
		_, keyID, legacy, err := readRecordWithKeyring(filepath.Join(reopened.pendingDir, name), reopened.maxPayloadBytes, keyring)
		if err != nil {
			t.Fatalf("read migrated %s: %v", name, err)
		}
		if legacy || keyID != keyring.ActiveKeyID() {
			t.Fatalf("migrated %s legacy=%t key=%q, want active %q", name, legacy, keyID, keyring.ActiveKeyID())
		}
	}
	if err := keyring.Revoke(oldID, nil); err != nil {
		t.Fatalf("Revoke(old key after migration) error = %v", err)
	}
}

func TestOpenFailsClosedWhenRecordKeyUnavailable(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writerKeys, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	q, err := Open(Config{Dir: dir, Keyring: writerKeys})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.Enqueue(signedTestBatch(t, "batch-missing-key", priv)); err != nil {
		t.Fatal(err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	wrongKeys, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}

	_, err = Open(Config{Dir: dir, Keyring: wrongKeys})
	if err == nil || errors.Is(err, ErrCorruptRecord) || !errors.Is(err, errQueueKeyUnavailable) {
		t.Fatalf("Open(wrong keyring) error = %v, want dedicated unavailable-key failure", err)
	}
}

func TestOpenQuarantinesCorruptLiveRecordAndIgnoresUnreadableDeadRecord(t *testing.T) {
	dir := t.TempDir()
	keyring, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	q, err := Open(Config{Dir: dir, Keyring: keyring})
	if err != nil {
		t.Fatal(err)
	}
	corruptID := "00000000000000000001-corrupt-0000000000000000.json"
	if err := os.WriteFile(filepath.Join(q.pendingDir, corruptID), []byte("{bad"), fileMode); err != nil {
		t.Fatal(err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(Config{Dir: dir, Keyring: keyring})
	if err != nil {
		t.Fatalf("Open with corrupt pending record: %v", err)
	}
	stats, err := reopened.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Pending != 0 || stats.Dead != 1 {
		t.Fatalf("Stats after migration quarantine = %+v, want pending=0 dead=1", stats)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}

	afterDead, err := Open(Config{Dir: dir, Keyring: keyring})
	if err != nil {
		t.Fatalf("Open with unreadable dead-letter record: %v", err)
	}
	defer func() { _ = afterDead.Close() }()
}

func TestEncryptedRecordsUseDistinctNonces(t *testing.T) {
	keyring, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	record := diskRecord{Version: recordVersion}
	first, err := encryptDiskRecord(record, keyring)
	if err != nil {
		t.Fatal(err)
	}
	second, err := encryptDiskRecord(record, keyring)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("identical plaintext encrypted to identical record; nonce reuse suspected")
	}
}

func TestKeyringRevocationGuards(t *testing.T) {
	keyring, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	active := keyring.ActiveKeyID()
	if err := keyring.Revoke(active, nil); err == nil || !strings.Contains(err.Error(), "active") {
		t.Fatalf("Revoke(active) error = %v, want active-key refusal", err)
	}
	old := active
	if _, err := keyring.Rotate(); err != nil {
		t.Fatal(err)
	}
	if err := keyring.Revoke(old, map[string]int{old: 1}); err == nil || !strings.Contains(err.Error(), "still use") {
		t.Fatalf("Revoke(in-use) error = %v, want usage refusal", err)
	}
}

func TestLoadKeyringRejectsWorldReadableFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not preserve POSIX mode bits")
	}
	keyring, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "keyring.json")
	if err := keyring.Save(path); err != nil {
		t.Fatal(err)
	}
	chmodTestFixture(t, path, 0o604)
	if _, err := LoadKeyring(path); err == nil {
		t.Fatal("LoadKeyring(world-readable) error = nil, want refusal")
	}
}

func chmodTestFixture(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not preserve POSIX mode bits")
	}
	if err := os.Chmod(filepath.Clean(path), mode); err != nil {
		t.Fatalf("Chmod(%s, %04o) error = %v", path, mode, err)
	}
}

func TestOpenRequiresEncryptionKeyring(t *testing.T) {
	if _, err := Open(Config{Dir: t.TempDir()}); err == nil || !strings.Contains(err.Error(), "keyring required") {
		t.Fatalf("Open(nil keyring) error = %v, want required refusal", err)
	}
}

func TestMigrationAndEncryptedReadErrorPaths(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	q, err := Open(Config{Dir: t.TempDir(), Keyring: keyring})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = q.Close() }()

	if err := os.RemoveAll(q.deadDir); err != nil {
		t.Fatal(err)
	}
	if err := q.migrateRecordsLocked(); err == nil {
		t.Fatal("migrateRecordsLocked(missing dir) error = nil")
	}
	if err := os.MkdirAll(q.deadDir, dirMode); err != nil {
		t.Fatal(err)
	}

	legacyID := "00000000000000000001-legacy.json"
	legacyPath := filepath.Join(q.pendingDir, legacyID)
	if err := writeDiskRecord(legacyPath, validDiskRecord(signedTestBatch(t, "migration-error", priv))); err != nil {
		t.Fatal(err)
	}
	q.keyring = &Keyring{}
	if err := q.migrateRecordsLocked(); err == nil || !strings.Contains(err.Error(), "encrypt queue record") {
		t.Fatalf("migrateRecordsLocked(empty keyring) error = %v", err)
	}

	q.keyring = keyring
	data, err := encryptDiskRecord(diskRecord{Version: 99, EnqueuedAt: time.Now().UTC()}, keyring)
	if err != nil {
		t.Fatal(err)
	}
	invalidVersionPath := filepath.Join(q.pendingDir, "00000000000000000002-version.json")
	if err := os.WriteFile(invalidVersionPath, data, fileMode); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := readRecordWithKeyring(invalidVersionPath, conductor.MaxAuditPayloadBytes, keyring); err == nil || !strings.Contains(err.Error(), "plaintext version") {
		t.Fatalf("readRecordWithKeyring(version) error = %v", err)
	}

	if _, err := encryptedRecordReadLimit(-1); err == nil {
		t.Fatal("encryptedRecordReadLimit(negative) error = nil")
	}
	if _, err := encryptedRecordReadLimit(math.MaxInt64); err == nil {
		t.Fatal("encryptedRecordReadLimit(oversized plaintext) error = nil")
	}
	threshold := int64(((maxRecordReadBytes-encryptedRecordMetadataBytes)/4)*3 - 2)
	if _, err := encryptedRecordReadLimit(threshold); err == nil {
		t.Fatal("encryptedRecordReadLimit(oversized ciphertext) error = nil")
	}
}

func TestMigrationQuarantineAndRewriteFailures(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	newQueue := func(t *testing.T) (*Queue, *Keyring) {
		t.Helper()
		keyring, err := NewKeyring()
		if err != nil {
			t.Fatal(err)
		}
		q, err := Open(Config{Dir: t.TempDir(), Keyring: keyring})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = q.Close() })
		return q, keyring
	}

	t.Run("dead path failure", func(t *testing.T) {
		q, _ := newQueue(t)
		id := "00000000000000000001-corrupt.json"
		if err := os.WriteFile(filepath.Join(q.pendingDir, id), []byte("{bad"), fileMode); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(q.deadDir); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(q.deadDir, []byte("not a directory"), fileMode); err != nil {
			t.Fatal(err)
		}
		if err := q.migrateRecordsLocked(); err == nil || !strings.Contains(err.Error(), "quarantine queue record") {
			t.Fatalf("migrateRecordsLocked(dead path) error = %v", err)
		}
	})

	t.Run("dead move failure", func(t *testing.T) {
		q, _ := newQueue(t)
		id := "00000000000000000001-corrupt.json"
		if err := os.WriteFile(filepath.Join(q.pendingDir, id), []byte("{bad"), fileMode); err != nil {
			t.Fatal(err)
		}
		restrictDirectoryWrites(t, q.deadDir)
		if err := q.migrateRecordsLocked(); err == nil || !strings.Contains(err.Error(), "quarantine queue record") {
			t.Fatalf("migrateRecordsLocked(dead move) error = %v", err)
		}
	})

	t.Run("rewrite failure", func(t *testing.T) {
		q, keyring := newQueue(t)
		id := "00000000000000000001-legacy.json"
		if err := writeDiskRecord(filepath.Join(q.pendingDir, id), validDiskRecord(signedTestBatch(t, "rewrite-error", priv))); err != nil {
			t.Fatal(err)
		}
		restrictDirectoryWrites(t, q.pendingDir)
		q.keyring = keyring
		if err := q.migrateRecordsLocked(); err == nil || !strings.Contains(err.Error(), "migrate queue record") {
			t.Fatalf("migrateRecordsLocked(rewrite) error = %v", err)
		}
	})
}

func restrictDirectoryWrites(t *testing.T, path string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not preserve POSIX directory mode bits")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	original := info.Mode().Perm()
	readOnly := original &^ 0o222
	if err := os.Chmod(path, readOnly); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, original) })
}

func TestEncryptedRecordReadLimitAndFileReadFailures(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not preserve POSIX unreadable-file mode bits")
	}
	keyring, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "record.json")
	if err := os.WriteFile(path, []byte("{}"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, fileMode) })
	if _, _, _, err := readRecordWithKeyring(path, conductor.MaxAuditPayloadBytes, keyring); err == nil || !errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("readRecordWithKeyring(unreadable) error = %v", err)
	}

	maxAcceptedPayload := ((maxRecordReadBytes-maxRecordMetadataBytes)/4)*3 - 2
	if _, _, _, err := readRecordWithKeyring(path, maxAcceptedPayload, keyring); err == nil {
		t.Fatal("readRecordWithKeyring(encrypted limit) error = nil")
	}
}
