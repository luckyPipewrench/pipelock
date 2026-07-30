//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package auditbatcher

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/securefile"
)

const (
	keyringVersion = 1
	queueKeyBytes  = 32
	keyringMaxSize = 64 * 1024
)

// KeyringFile is the durable operator format for audit-queue encryption keys.
// The active key encrypts new records; retained keys decrypt records written
// before rotation. Key IDs are derived from key material and cannot be chosen
// independently.
type KeyringFile struct {
	Version     int               `json:"version"`
	ActiveKeyID string            `json:"active_key_id"`
	Keys        map[string]string `json:"keys"`
}

// Keyring is a validated in-memory keyring. Lifecycle commands mutate a
// private instance and persist it atomically; runtimes only read their loaded
// instance.
type Keyring struct {
	active string
	keys   map[string][queueKeyBytes]byte
}

func NewKeyring() (*Keyring, error) {
	key, err := randomQueueKey()
	if err != nil {
		return nil, err
	}
	id := queueKeyID(key[:])
	return &Keyring{active: id, keys: map[string][queueKeyBytes]byte{id: key}}, nil
}

func LoadKeyring(path string) (*Keyring, error) {
	data, err := securefile.Read(filepath.Clean(path), securefile.Options{
		MaxBytes:        keyringMaxSize,
		DisallowedPerms: 0o037,
	})
	if err != nil {
		return nil, fmt.Errorf("auditbatcher: read queue keyring: %w", err)
	}
	var file KeyringFile
	if err := contract.DecodeStrictJSON(data, &file); err != nil {
		return nil, fmt.Errorf("auditbatcher: decode queue keyring: %w", err)
	}
	return parseKeyringFile(file)
}

func parseKeyringFile(file KeyringFile) (*Keyring, error) {
	if file.Version != keyringVersion {
		return nil, fmt.Errorf("auditbatcher: queue keyring version=%d want=%d", file.Version, keyringVersion)
	}
	if len(file.Keys) == 0 {
		return nil, errors.New("auditbatcher: queue keyring has no keys")
	}
	keys := make(map[string][queueKeyBytes]byte, len(file.Keys))
	for id, encoded := range file.Keys {
		raw, err := hex.DecodeString(strings.TrimSpace(encoded))
		if err != nil || len(raw) != queueKeyBytes {
			return nil, fmt.Errorf("auditbatcher: queue keyring key %q must be %d-byte hex", id, queueKeyBytes)
		}
		derived := queueKeyID(raw)
		if id != derived {
			return nil, fmt.Errorf("auditbatcher: queue keyring key id %q does not match derived id %q", id, derived)
		}
		var key [queueKeyBytes]byte
		copy(key[:], raw)
		keys[id] = key
	}
	if _, ok := keys[file.ActiveKeyID]; !ok {
		return nil, fmt.Errorf("auditbatcher: active queue key %q is absent", file.ActiveKeyID)
	}
	return &Keyring{active: file.ActiveKeyID, keys: keys}, nil
}

func (k *Keyring) File() (KeyringFile, error) {
	if k == nil || k.active == "" || len(k.keys) == 0 {
		return KeyringFile{}, errors.New("auditbatcher: invalid empty queue keyring")
	}
	keys := make(map[string]string, len(k.keys))
	for id, key := range k.keys {
		keys[id] = hex.EncodeToString(key[:])
	}
	return KeyringFile{Version: keyringVersion, ActiveKeyID: k.active, Keys: keys}, nil
}

func (k *Keyring) Save(path string) error {
	data, err := k.marshal()
	if err != nil {
		return err
	}
	if err := atomicfile.Write(filepath.Clean(path), data, 0o600); err != nil {
		return fmt.Errorf("auditbatcher: write queue keyring: %w", err)
	}
	return nil
}

func (k *Keyring) marshal() ([]byte, error) {
	file, err := k.File()
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(file)
	if err != nil {
		return nil, fmt.Errorf("auditbatcher: encode queue keyring: %w", err)
	}
	data = append(data, '\n')
	if len(data) > keyringMaxSize {
		return nil, fmt.Errorf("auditbatcher: queue keyring size %d exceeds %d-byte limit; revoke unused keys before rotating further", len(data), keyringMaxSize)
	}
	return data, nil
}

// LoadOrCreateKeyring reuses a valid durable keyring and creates one only when
// absent. Creation publishes a fully written temporary file with an atomic
// no-replace hard link, so concurrent callers cannot overwrite or observe a
// partially written keyring.
func LoadOrCreateKeyring(path string) (*Keyring, error) {
	clean := filepath.Clean(path)
	keyring, err := LoadKeyring(clean)
	if err == nil {
		return keyring, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := EnsureKeyringParent(clean); err != nil {
		return nil, err
	}
	keyring, err = NewKeyring()
	if err != nil {
		return nil, err
	}
	data, err := keyring.marshal()
	if err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(clean), ".keyring-init-*")
	if err != nil {
		return nil, fmt.Errorf("auditbatcher: create queue keyring temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("auditbatcher: chmod queue keyring temporary file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("auditbatcher: write queue keyring temporary file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("auditbatcher: sync queue keyring temporary file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("auditbatcher: close queue keyring temporary file: %w", err)
	}
	if err := os.Link(tmpPath, clean); err != nil {
		if errors.Is(err, os.ErrExist) {
			return LoadKeyring(clean)
		}
		return nil, fmt.Errorf("auditbatcher: publish queue keyring exclusively: %w", err)
	}
	if err := fsyncDir(filepath.Dir(clean)); err != nil {
		return nil, fmt.Errorf("auditbatcher: sync queue keyring parent: %w", err)
	}
	return keyring, nil
}

func (k *Keyring) Rotate() (string, error) {
	if k == nil {
		return "", errors.New("auditbatcher: nil queue keyring")
	}
	key, err := randomQueueKey()
	if err != nil {
		return "", err
	}
	id := queueKeyID(key[:])
	if k.keys == nil {
		k.keys = make(map[string][queueKeyBytes]byte)
	}
	oldActive := k.active
	k.keys[id] = key
	k.active = id
	if _, err := k.marshal(); err != nil {
		delete(k.keys, id)
		k.active = oldActive
		return "", err
	}
	return id, nil
}

func (k *Keyring) Revoke(id string, inUse map[string]int) error {
	if k == nil {
		return errors.New("auditbatcher: nil queue keyring")
	}
	if id == k.active {
		return fmt.Errorf("auditbatcher: cannot revoke active queue key %q", id)
	}
	if inUse[id] > 0 {
		return fmt.Errorf("auditbatcher: cannot revoke queue key %q: %d record(s) still use it", id, inUse[id])
	}
	if _, ok := k.keys[id]; !ok {
		return fmt.Errorf("auditbatcher: queue key %q not found", id)
	}
	delete(k.keys, id)
	return nil
}

func (k *Keyring) ActiveKeyID() string {
	if k == nil {
		return ""
	}
	return k.active
}

func (k *Keyring) KeyIDs() []string {
	if k == nil {
		return nil
	}
	ids := make([]string, 0, len(k.keys))
	for id := range k.keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (k *Keyring) activeKey() (string, [queueKeyBytes]byte, error) {
	if k == nil {
		return "", [queueKeyBytes]byte{}, errors.New("auditbatcher: queue encryption keyring required")
	}
	key, ok := k.keys[k.active]
	if !ok {
		return "", [queueKeyBytes]byte{}, errors.New("auditbatcher: active queue encryption key unavailable")
	}
	return k.active, key, nil
}

func (k *Keyring) key(id string) ([queueKeyBytes]byte, bool) {
	if k == nil {
		return [queueKeyBytes]byte{}, false
	}
	key, ok := k.keys[id]
	return key, ok
}

func randomQueueKey() ([queueKeyBytes]byte, error) {
	var key [queueKeyBytes]byte
	if _, err := rand.Read(key[:]); err != nil {
		return key, fmt.Errorf("auditbatcher: generate queue encryption key: %w", err)
	}
	return key, nil
}

func queueKeyID(key []byte) string {
	sum := sha256.Sum256(key)
	return "sha256:" + hex.EncodeToString(sum[:8])
}

// EnsureKeyringParent creates the private parent used by lifecycle commands.
func EnsureKeyringParent(path string) error {
	dir := filepath.Dir(filepath.Clean(path))
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("auditbatcher: create queue keyring parent: %w", err)
	}
	return nil
}
