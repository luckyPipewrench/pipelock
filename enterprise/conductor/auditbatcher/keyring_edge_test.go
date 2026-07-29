//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package auditbatcher

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestKeyringValidationAndAccessors(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, queueKeyBytes)
	id := queueKeyID(key)
	encoded := hex.EncodeToString(key)
	for _, tc := range []struct {
		name string
		file KeyringFile
	}{
		{name: "version", file: KeyringFile{Version: 2, ActiveKeyID: id, Keys: map[string]string{id: encoded}}},
		{name: "empty", file: KeyringFile{Version: keyringVersion}},
		{name: "invalid hex", file: KeyringFile{Version: keyringVersion, ActiveKeyID: id, Keys: map[string]string{id: "zz"}}},
		{name: "derived id mismatch", file: KeyringFile{Version: keyringVersion, ActiveKeyID: "wrong", Keys: map[string]string{"wrong": encoded}}},
		{name: "active absent", file: KeyringFile{Version: keyringVersion, ActiveKeyID: "missing", Keys: map[string]string{id: encoded}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseKeyringFile(tc.file); err == nil {
				t.Fatal("parseKeyringFile error = nil")
			}
		})
	}

	if _, err := (*Keyring)(nil).File(); err == nil {
		t.Fatal("nil File error = nil")
	}
	if err := (*Keyring)(nil).Save(filepath.Join(t.TempDir(), "keyring.json")); err == nil {
		t.Fatal("nil Save error = nil")
	}
	if _, err := (*Keyring)(nil).Rotate(); err == nil {
		t.Fatal("nil Rotate error = nil")
	}
	if err := (*Keyring)(nil).Revoke("missing", nil); err == nil {
		t.Fatal("nil Revoke error = nil")
	}
	if got := (*Keyring)(nil).ActiveKeyID(); got != "" {
		t.Fatalf("nil ActiveKeyID = %q", got)
	}
	if got := (*Keyring)(nil).KeyIDs(); got != nil {
		t.Fatalf("nil KeyIDs = %#v", got)
	}
	if _, ok := (*Keyring)(nil).key("missing"); ok {
		t.Fatal("nil key lookup succeeded")
	}
	if _, _, err := (*Keyring)(nil).activeKey(); err == nil {
		t.Fatal("nil activeKey error = nil")
	}

	empty := &Keyring{}
	if _, _, err := empty.activeKey(); err == nil {
		t.Fatal("empty activeKey error = nil")
	}
	first, err := empty.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	second, err := empty.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	ids := empty.KeyIDs()
	if len(ids) != 2 || !slices.IsSorted(ids) {
		t.Fatalf("KeyIDs = %#v, want two sorted IDs", ids)
	}
	if err := empty.Revoke("missing", nil); err == nil {
		t.Fatal("Revoke(missing) error = nil")
	}
	if err := empty.Revoke(first, nil); err != nil {
		t.Fatalf("Revoke(retained): %v", err)
	}
	if _, ok := empty.key(first); ok {
		t.Fatal("revoked key remains readable")
	}
	if empty.ActiveKeyID() != second {
		t.Fatalf("ActiveKeyID = %q, want %q", empty.ActiveKeyID(), second)
	}
}

func TestKeyringLoadSaveAndParentErrors(t *testing.T) {
	malformed := filepath.Join(t.TempDir(), "malformed.json")
	if err := os.WriteFile(malformed, []byte("{bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyring(malformed); err == nil || !strings.Contains(err.Error(), "decode queue keyring") {
		t.Fatalf("LoadKeyring(malformed) error = %v", err)
	}

	parentFile := filepath.Join(t.TempDir(), "parent-file")
	if err := os.WriteFile(parentFile, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(parentFile, "keyring.json")
	if err := EnsureKeyringParent(child); err == nil {
		t.Fatal("EnsureKeyringParent(file parent) error = nil")
	}
	keyring, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	if err := keyring.Save(child); err == nil || !strings.Contains(err.Error(), "write queue keyring") {
		t.Fatalf("Save(file parent) error = %v", err)
	}
}

func TestEncryptedRecordEnvelopeValidation(t *testing.T) {
	keyring, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := encryptDiskRecord(diskRecord{}, nil); err == nil {
		t.Fatal("encryptDiskRecord(nil keyring) error = nil")
	}

	for _, tc := range []struct {
		name string
		data []byte
	}{
		{name: "malformed", data: []byte("{bad")},
		{name: "missing version", data: []byte(`{"key_id":"x"}`)},
		{name: "invalid version", data: []byte(`{"version":"two"}`)},
		{name: "invalid legacy", data: []byte(`{"version":1,"unexpected":true}`)},
		{name: "invalid encrypted", data: []byte(`{"version":2,"unexpected":true}`)},
		{name: "unsupported", data: []byte(`{"version":99}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, _, err := decryptDiskRecord(tc.data, keyring); err == nil {
				t.Fatal("decryptDiskRecord error = nil")
			}
		})
	}

	badNonce, err := json.Marshal(encryptedDiskRecord{Version: encryptedRecordVersion, KeyID: keyring.ActiveKeyID(), Nonce: []byte{1}, Ciphertext: []byte{2}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := decryptDiskRecord(badNonce, keyring); err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("bad nonce error = %v", err)
	}

	id, key, err := keyring.activeKey()
	if err != nil {
		t.Fatal(err)
	}
	aead, err := queueAEAD(key)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	invalidPlaintext, err := json.Marshal(encryptedDiskRecord{
		Version: encryptedRecordVersion, KeyID: id, Nonce: nonce,
		Ciphertext: aead.Seal(nil, nonce, []byte("{bad"), recordAAD(id)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := decryptDiskRecord(invalidPlaintext, keyring); err == nil || !strings.Contains(err.Error(), "decode record plaintext") {
		t.Fatalf("invalid plaintext error = %v", err)
	}
}
