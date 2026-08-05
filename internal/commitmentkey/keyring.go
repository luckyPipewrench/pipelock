// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package commitmentkey owns the symmetric keys used to open private evidence
// commitments. These keys are deliberately not signing keys.
package commitmentkey

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"
)

const (
	FormatV1 = "pipelock-commitment-keyring/v1"
	Purpose  = "evidence-commitment"
	keyBytes = 32
	maxBytes = 1 << 20
)

var (
	ErrInvalidKeyring   = errors.New("invalid commitment keyring")
	ErrKeyNotFound      = errors.New("commitment key not found")
	ErrRetainedKey      = errors.New("commitment key has retained references")
	ErrAlreadyExists    = errors.New("commitment keyring already exists")
	ErrSymlink          = errors.New("commitment keyring path is a symlink")
	ErrUnsafePermission = errors.New("commitment keyring has unsafe permissions")
)

type State string

const (
	StateActive  State = "active"
	StateRetired State = "retired"
)

type Entry struct {
	KeyID     string     `json:"key_id"`
	Epoch     uint64     `json:"epoch"`
	State     State      `json:"state"`
	Key       string     `json:"key"`
	CreatedAt time.Time  `json:"created_at"`
	RetiredAt *time.Time `json:"retired_at,omitempty"`
}

type Keyring struct {
	Format   string  `json:"format"`
	Purpose  string  `json:"purpose"`
	ActiveID string  `json:"active_key_id"`
	Epoch    uint64  `json:"epoch"`
	Keys     []Entry `json:"keys"`
}

type Metadata struct {
	Format   string          `json:"format"`
	Purpose  string          `json:"purpose"`
	ActiveID string          `json:"active_key_id"`
	Epoch    uint64          `json:"epoch"`
	Keys     []EntryMetadata `json:"keys"`
}

type EntryMetadata struct {
	KeyID     string     `json:"key_id"`
	Epoch     uint64     `json:"epoch"`
	State     State      `json:"state"`
	CreatedAt time.Time  `json:"created_at"`
	RetiredAt *time.Time `json:"retired_at,omitempty"`
}

type Handle struct {
	KeyID string
	Epoch uint64
	Key   []byte
}

func Initialize(path string, now time.Time) (*Keyring, error) {
	if err := ensureParent(path); err != nil {
		return nil, err
	}
	entry, err := newEntry(1, now)
	if err != nil {
		return nil, err
	}
	keyring := &Keyring{Format: FormatV1, Purpose: Purpose, ActiveID: entry.KeyID, Epoch: 1, Keys: []Entry{entry}}
	data, err := marshal(keyring)
	if err != nil {
		return nil, err
	}
	if err := writeSecureNew(path, data); err != nil {
		if errors.Is(err, ErrAlreadyExists) {
			return nil, ErrAlreadyExists
		}
		return nil, fmt.Errorf("initialize commitment keyring: %w", err)
	}
	return keyring, nil
}

func Load(path string) (*Keyring, error) {
	raw, err := readSecure(path)
	if err != nil {
		return nil, err
	}
	var keyring Keyring
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&keyring); err != nil {
		return nil, fmt.Errorf("%w: decode: %w", ErrInvalidKeyring, err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing JSON", ErrInvalidKeyring)
	}
	if err := keyring.Validate(); err != nil {
		return nil, err
	}
	return &keyring, nil
}

func (k *Keyring) Validate() error {
	if k.Format != FormatV1 {
		return fmt.Errorf("%w: format %q", ErrInvalidKeyring, k.Format)
	}
	if k.Purpose != Purpose {
		return fmt.Errorf("%w: purpose %q, want %q", ErrInvalidKeyring, k.Purpose, Purpose)
	}
	if k.Epoch == 0 || len(k.Keys) == 0 || k.ActiveID == "" {
		return fmt.Errorf("%w: missing active key metadata", ErrInvalidKeyring)
	}
	seenID := make(map[string]struct{}, len(k.Keys))
	seenEpoch := make(map[uint64]struct{}, len(k.Keys))
	active := 0
	var highest uint64
	for i := range k.Keys {
		entry := &k.Keys[i]
		if len(entry.KeyID) != 35 || entry.KeyID[:3] != "ck_" {
			return fmt.Errorf("%w: key %d has malformed opaque ID", ErrInvalidKeyring, i)
		}
		if _, err := hex.DecodeString(entry.KeyID[3:]); err != nil {
			return fmt.Errorf("%w: key %d has malformed opaque ID", ErrInvalidKeyring, i)
		}
		if entry.Epoch == 0 || entry.CreatedAt.IsZero() {
			return fmt.Errorf("%w: key %q has incomplete metadata", ErrInvalidKeyring, entry.KeyID)
		}
		if _, exists := seenID[entry.KeyID]; exists {
			return fmt.Errorf("%w: duplicate key ID %q", ErrInvalidKeyring, entry.KeyID)
		}
		if _, exists := seenEpoch[entry.Epoch]; exists {
			return fmt.Errorf("%w: duplicate epoch %d", ErrInvalidKeyring, entry.Epoch)
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(entry.Key)
		if err != nil || len(decoded) != keyBytes {
			return fmt.Errorf("%w: key %q material must be %d base64-encoded bytes", ErrInvalidKeyring, entry.KeyID, keyBytes)
		}
		switch entry.State {
		case StateActive:
			active++
			if entry.KeyID != k.ActiveID || entry.Epoch != k.Epoch || entry.RetiredAt != nil {
				return fmt.Errorf("%w: active key metadata is inconsistent", ErrInvalidKeyring)
			}
		case StateRetired:
			if entry.RetiredAt == nil || entry.Epoch >= k.Epoch {
				return fmt.Errorf("%w: retired key %q metadata is inconsistent", ErrInvalidKeyring, entry.KeyID)
			}
		default:
			return fmt.Errorf("%w: key %q has state %q", ErrInvalidKeyring, entry.KeyID, entry.State)
		}
		seenID[entry.KeyID] = struct{}{}
		seenEpoch[entry.Epoch] = struct{}{}
		if entry.Epoch > highest {
			highest = entry.Epoch
		}
	}
	if active != 1 || highest != k.Epoch {
		return fmt.Errorf("%w: want exactly one active key at highest epoch", ErrInvalidKeyring)
	}
	return nil
}

func (k *Keyring) Active() (Handle, error) {
	return k.Open(k.ActiveID, k.Epoch)
}

func (k *Keyring) Open(keyID string, epoch uint64) (Handle, error) {
	for _, entry := range k.Keys {
		if entry.KeyID != keyID || entry.Epoch != epoch {
			continue
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(entry.Key)
		if err != nil || len(decoded) != keyBytes {
			return Handle{}, fmt.Errorf("%w: corrupt key material", ErrInvalidKeyring)
		}
		return Handle{KeyID: entry.KeyID, Epoch: entry.Epoch, Key: append([]byte(nil), decoded...)}, nil
	}
	return Handle{}, fmt.Errorf("%w: key_id=%q epoch=%d", ErrKeyNotFound, keyID, epoch)
}

// Rotate serializes the complete load-modify-save cycle across processes and
// returns metadata from the same in-memory state that was durably committed.
func Rotate(path string, now time.Time) (Handle, Metadata, error) {
	var handle Handle
	var metadata Metadata
	err := withLifecycleLock(path, func() error {
		keyring, err := Load(path)
		if err != nil {
			return err
		}
		handle, err = keyring.rotate(path, now)
		if err == nil {
			metadata = keyring.Metadata()
		}
		return err
	})
	return handle, metadata, err
}

func (k *Keyring) rotate(path string, now time.Time) (Handle, error) {
	if err := k.Validate(); err != nil {
		return Handle{}, err
	}
	for i := range k.Keys {
		if k.Keys[i].State == StateActive {
			k.Keys[i].State = StateRetired
			retiredAt := now.UTC()
			k.Keys[i].RetiredAt = &retiredAt
		}
	}
	entry, err := newEntry(k.Epoch+1, now)
	if err != nil {
		return Handle{}, err
	}
	k.Keys = append(k.Keys, entry)
	k.Epoch = entry.Epoch
	k.ActiveID = entry.KeyID
	handle, err := k.Active()
	if err != nil {
		return Handle{}, err
	}
	if err := k.saveLocked(path); err != nil {
		return Handle{}, err
	}
	return handle, nil
}

// Retire serializes the complete load-check-destroy-save cycle across processes.
func Retire(path, keyID string, epoch uint64, acceptLoss bool) (Metadata, error) {
	var metadata Metadata
	err := withLifecycleLock(path, func() error {
		keyring, err := Load(path)
		if err != nil {
			return err
		}
		if err := keyring.retire(path, keyID, epoch, acceptLoss); err != nil {
			return err
		}
		metadata = keyring.Metadata()
		return nil
	})
	return metadata, err
}

func (k *Keyring) retire(path, keyID string, epoch uint64, acceptLoss bool) error {
	if keyID == k.ActiveID && epoch == k.Epoch {
		return fmt.Errorf("cannot retire the active commitment key; rotate first")
	}
	index := -1
	for i, entry := range k.Keys {
		if entry.KeyID == keyID && entry.Epoch == epoch {
			index = i
			break
		}
	}
	if index < 0 {
		return fmt.Errorf("%w: key_id=%q epoch=%d", ErrKeyNotFound, keyID, epoch)
	}
	if !acceptLoss {
		return fmt.Errorf("%w: no authoritative retained-evidence inventory exists; --accept-loss is required to destroy key_id=%q epoch=%d", ErrRetainedKey, keyID, epoch)
	}
	k.Keys = append(k.Keys[:index], k.Keys[index+1:]...)
	return k.saveLocked(path)
}

// saveLocked persists a validated lifecycle mutation. Callers must hold the
// cross-process lifecycle lock for path.
func (k *Keyring) saveLocked(path string) error {
	if err := k.Validate(); err != nil {
		return err
	}
	data, err := marshal(k)
	if err != nil {
		return err
	}
	if err := writeSecureReplace(path, data); err != nil {
		return fmt.Errorf("write commitment keyring: %w", err)
	}
	return nil
}

func (k *Keyring) Metadata() Metadata {
	metadata := Metadata{Format: k.Format, Purpose: k.Purpose, ActiveID: k.ActiveID, Epoch: k.Epoch, Keys: make([]EntryMetadata, 0, len(k.Keys))}
	for _, entry := range k.Keys {
		metadata.Keys = append(metadata.Keys, EntryMetadata{KeyID: entry.KeyID, Epoch: entry.Epoch, State: entry.State, CreatedAt: entry.CreatedAt, RetiredAt: entry.RetiredAt})
	}
	sort.Slice(metadata.Keys, func(i, j int) bool { return metadata.Keys[i].Epoch < metadata.Keys[j].Epoch })
	return metadata
}

func Backup(source, destination string) (*Keyring, error) {
	return copyValidated(source, destination, "load backup source", "write commitment keyring backup")
}

func Restore(source, destination string) (*Keyring, error) {
	return copyValidated(source, destination, "load commitment keyring backup", "restore commitment keyring")
}

func copyValidated(source, destination, loadContext, writeContext string) (*Keyring, error) {
	keyring, err := Load(source)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", loadContext, err)
	}
	if err := ensureParent(destination); err != nil {
		return nil, err
	}
	data, err := marshal(keyring)
	if err != nil {
		return nil, err
	}
	if err := writeSecureNew(destination, data); err != nil {
		return nil, fmt.Errorf("%s: %w", writeContext, err)
	}
	return keyring, nil
}

func newEntry(epoch uint64, now time.Time) (Entry, error) {
	material := make([]byte, keyBytes)
	if _, err := io.ReadFull(rand.Reader, material); err != nil {
		return Entry{}, fmt.Errorf("generate commitment key: %w", err)
	}
	idBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, idBytes); err != nil {
		return Entry{}, fmt.Errorf("generate commitment key ID: %w", err)
	}
	return Entry{KeyID: "ck_" + hex.EncodeToString(idBytes), Epoch: epoch, State: StateActive, Key: base64.StdEncoding.EncodeToString(material), CreatedAt: now.UTC()}, nil
}

func marshal(keyring *Keyring) ([]byte, error) {
	data, err := json.MarshalIndent(keyring, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal commitment keyring: %w", err)
	}
	return append(data, '\n'), nil
}
