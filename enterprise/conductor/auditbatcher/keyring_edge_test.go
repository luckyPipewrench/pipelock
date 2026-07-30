//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package auditbatcher

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
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

func TestLoadKeyringRejectsOversizedAndPermissiveFiles(t *testing.T) {
	oversized := filepath.Join(t.TempDir(), "oversized.json")
	if err := os.WriteFile(oversized, bytes.Repeat([]byte{'x'}, keyringMaxSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyring(oversized); err == nil {
		t.Fatal("LoadKeyring(oversized) error = nil")
	}

	if runtime.GOOS == "windows" {
		return
	}
	keyring, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	permissive := filepath.Join(t.TempDir(), "permissive.json")
	if err := keyring.Save(permissive); err != nil {
		t.Fatal(err)
	}
	chmodTestFixture(t, permissive, 0o622)
	if _, err := LoadKeyring(permissive); err == nil {
		t.Fatal("LoadKeyring(permissive) error = nil")
	}
}

func TestKeyringRefusesUnreloadableRotation(t *testing.T) {
	keyring, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; ; i++ {
		key := sha256.Sum256([]byte(fmt.Sprintf("retained-key-%d", i)))
		id := queueKeyID(key[:])
		keyring.keys[id] = key
		if _, err := keyring.marshal(); err != nil {
			delete(keyring.keys, id)
			break
		}
	}
	activeBefore := keyring.ActiveKeyID()
	countBefore := len(keyring.KeyIDs())
	if _, err := keyring.Rotate(); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("Rotate(oversized) error = %v, want size-limit refusal", err)
	}
	if keyring.ActiveKeyID() != activeBefore || len(keyring.KeyIDs()) != countBefore {
		t.Fatal("failed rotation mutated the keyring")
	}
	path := filepath.Join(t.TempDir(), "keyring.json")
	if err := keyring.Save(path); err != nil {
		t.Fatalf("Save(keyring after refused rotation): %v", err)
	}
	reloaded, err := LoadKeyring(path)
	if err != nil {
		t.Fatalf("LoadKeyring(after refused rotation): %v", err)
	}
	if reloaded.ActiveKeyID() != activeBefore {
		t.Fatalf("reloaded active key = %q, want %q", reloaded.ActiveKeyID(), activeBefore)
	}
}

func TestLoadOrCreateKeyringReusesAndConvergesConcurrently(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets", "keyring.json")
	const callers = 8
	ids := make(chan string, callers)
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			keyring, err := LoadOrCreateKeyring(path)
			if err != nil {
				errs <- err
				return
			}
			ids <- keyring.ActiveKeyID()
		}()
	}
	wg.Wait()
	close(ids)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	want := ""
	for id := range ids {
		if want == "" {
			want = id
		}
		if id != want {
			t.Fatalf("concurrent keyring id = %q, want %q", id, want)
		}
	}
	loaded, err := LoadOrCreateKeyring(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ActiveKeyID() != want {
		t.Fatalf("reused keyring id = %q, want %q", loaded.ActiveKeyID(), want)
	}
}

func TestLoadOrCreateKeyringFailsClosedOnInvalidExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyring.json")
	if err := os.WriteFile(path, []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKeyring(path); err == nil || !strings.Contains(err.Error(), "decode queue keyring") {
		t.Fatalf("LoadOrCreateKeyring(invalid) error = %v", err)
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "not-json" {
		t.Fatalf("invalid durable keyring was overwritten: %q", data)
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
