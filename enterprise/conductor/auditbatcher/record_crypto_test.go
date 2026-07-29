//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package auditbatcher

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	if err == nil || !errors.Is(err, ErrCorruptRecord) || !strings.Contains(err.Error(), "decrypt record") {
		t.Fatalf("tampered read error = %v, want fail-closed decrypt ErrCorruptRecord", err)
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
	if err == nil || !errors.Is(err, ErrCorruptRecord) || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("Open(wrong keyring) error = %v, want unavailable-key ErrCorruptRecord", err)
	}
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
	if err := os.Chmod(filepath.Clean(path), mode); err != nil {
		t.Fatalf("Chmod(%s, %04o) error = %v", path, mode, err)
	}
}

func TestOpenRequiresEncryptionKeyring(t *testing.T) {
	if _, err := Open(Config{Dir: t.TempDir()}); err == nil || !strings.Contains(err.Error(), "keyring required") {
		t.Fatalf("Open(nil keyring) error = %v, want required refusal", err)
	}
}
