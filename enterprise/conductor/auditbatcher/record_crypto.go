//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package auditbatcher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/luckyPipewrench/pipelock/internal/contract"
)

const (
	encryptedRecordVersion = 2
	queueAEADOverheadBytes = 16
	// encryptedRecordMetadataBytes bounds the v2 JSON fields outside
	// ciphertext. The ciphertext itself is base64-expanded by encoding/json
	// and must be accounted for separately.
	encryptedRecordMetadataBytes = 1024
)

var (
	errQueueKeyUnavailable = errors.New("auditbatcher: queue encryption key unavailable")
	ErrRecordAuthFailed    = errors.New("auditbatcher: encrypted record authentication failed")
)

var queueRecordAAD = []byte("pipelock/conductor/audit-queue/v2")

type encryptedDiskRecord struct {
	Version    int    `json:"version"`
	KeyID      string `json:"key_id"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

func encryptDiskRecord(record diskRecord, keyring *Keyring) ([]byte, error) {
	plaintext, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("auditbatcher: marshal record plaintext: %w", err)
	}
	id, key, err := keyring.activeKey()
	if err != nil {
		return nil, err
	}
	aead, err := queueAEAD(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("auditbatcher: generate record nonce: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, recordAAD(id))
	data, err := json.Marshal(encryptedDiskRecord{
		Version:    encryptedRecordVersion,
		KeyID:      id,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	})
	if err != nil {
		return nil, fmt.Errorf("auditbatcher: marshal encrypted record: %w", err)
	}
	return data, nil
}

func decryptDiskRecord(data []byte, keyring *Keyring) (diskRecord, string, bool, error) {
	var fields map[string]json.RawMessage
	if err := contract.DecodeStrictJSON(data, &fields); err != nil {
		return diskRecord{}, "", false, fmt.Errorf("auditbatcher: decode record version: %w", err)
	}
	rawVersion, ok := fields["version"]
	if !ok {
		return diskRecord{}, "", false, errors.New("auditbatcher: record version missing")
	}
	var version int
	if err := json.Unmarshal(rawVersion, &version); err != nil {
		return diskRecord{}, "", false, fmt.Errorf("auditbatcher: decode record version: %w", err)
	}
	switch version {
	case recordVersion:
		var record diskRecord
		if err := contract.DecodeStrictJSON(data, &record); err != nil {
			return diskRecord{}, "", true, fmt.Errorf("auditbatcher: decode legacy record: %w", err)
		}
		return record, "", true, nil
	case encryptedRecordVersion:
		var encrypted encryptedDiskRecord
		if err := contract.DecodeStrictJSON(data, &encrypted); err != nil {
			return diskRecord{}, "", false, fmt.Errorf("auditbatcher: decode encrypted record: %w", err)
		}
		key, ok := keyring.key(encrypted.KeyID)
		if !ok {
			return diskRecord{}, encrypted.KeyID, false, fmt.Errorf("%w: %q", errQueueKeyUnavailable, encrypted.KeyID)
		}
		aead, err := queueAEAD(key)
		if err != nil {
			return diskRecord{}, encrypted.KeyID, false, err
		}
		if len(encrypted.Nonce) != aead.NonceSize() {
			return diskRecord{}, encrypted.KeyID, false, fmt.Errorf("%w: invalid nonce length", ErrRecordAuthFailed)
		}
		plaintext, err := aead.Open(nil, encrypted.Nonce, encrypted.Ciphertext, recordAAD(encrypted.KeyID))
		if err != nil {
			return diskRecord{}, encrypted.KeyID, false, fmt.Errorf("%w: decrypt record: %w", ErrRecordAuthFailed, err)
		}
		var record diskRecord
		if err := contract.DecodeStrictJSON(plaintext, &record); err != nil {
			return diskRecord{}, encrypted.KeyID, false, fmt.Errorf("auditbatcher: decode record plaintext: %w", err)
		}
		return record, encrypted.KeyID, false, nil
	default:
		return diskRecord{}, "", false, fmt.Errorf("auditbatcher: record version=%d unsupported", version)
	}
}

func queueAEAD(key [queueKeyBytes]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("auditbatcher: create queue cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("auditbatcher: create queue AEAD: %w", err)
	}
	return aead, nil
}

func recordAAD(keyID string) []byte {
	aad := make([]byte, 0, len(queueRecordAAD)+1+len(keyID))
	aad = append(aad, queueRecordAAD...)
	aad = append(aad, 0)
	aad = append(aad, keyID...)
	return aad
}
