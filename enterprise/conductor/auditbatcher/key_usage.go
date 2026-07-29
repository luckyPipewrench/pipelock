//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package auditbatcher

import (
	"fmt"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
)

const LegacyKeyID = "legacy-plaintext"

// InspectQueueKeys takes the queue's exclusive lock and reports which key
// protects every durable record. It never rewrites queue state.
func InspectQueueKeys(dir string, maxPayloadBytes uint64, keyring *Keyring) (map[string]int, error) {
	if keyring == nil {
		return nil, fmt.Errorf("auditbatcher: queue encryption keyring required")
	}
	if maxPayloadBytes == 0 {
		maxPayloadBytes = conductor.MaxAuditPayloadBytes
	}
	q, err := lockQueueForKeyMaintenance(dir, maxPayloadBytes)
	if err != nil {
		return nil, err
	}
	defer func() { _ = q.releaseLock() }()
	q.keyring = keyring
	return q.keyUsageLocked()
}

func (q *Queue) keyUsageLocked() (map[string]int, error) {
	usage := make(map[string]int)
	for _, recordDir := range []string{q.pendingDir, q.inflightDir, q.deadDir} {
		names, err := listRecordFiles(recordDir)
		if err != nil {
			return nil, err
		}
		for _, name := range names {
			_, keyID, legacy, err := readRecordWithKeyring(filepath.Join(recordDir, name), q.maxPayloadBytes, q.keyring)
			if err != nil {
				return nil, fmt.Errorf("auditbatcher: inspect queue record %s: %w", name, err)
			}
			if legacy {
				keyID = LegacyKeyID
			}
			usage[keyID]++
		}
	}
	return usage, nil
}

func RotateQueueKeyring(queueDir, keyringPath, backupPath string) (string, string, error) {
	q, err := lockQueueForKeyMaintenance(queueDir, 0)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = q.releaseLock() }()
	keyring, err := LoadKeyring(keyringPath)
	if err != nil {
		return "", "", err
	}
	q.keyring = keyring
	if _, err := q.keyUsageLocked(); err != nil {
		return "", "", err
	}
	oldID := keyring.ActiveKeyID()
	if err := keyring.Save(backupPath + ".previous"); err != nil {
		return "", "", fmt.Errorf("save pre-rotation keyring backup: %w", err)
	}
	newID, err := keyring.Rotate()
	if err != nil {
		return "", "", err
	}
	// Persist both decryptors before any record uses the new key.
	if err := keyring.Save(keyringPath); err != nil {
		return "", "", err
	}
	// The ordinary recovery backup is post-rotation and can therefore decrypt
	// both old records and records written under the new active key.
	if err := keyring.Save(backupPath); err != nil {
		return "", "", fmt.Errorf("save rotated keyring backup: %w", err)
	}
	if err := q.migrateRecordsLocked(); err != nil {
		return oldID, newID, fmt.Errorf("new key saved but queue migration incomplete; rerun migrate: %w", err)
	}
	return oldID, newID, nil
}

func MigrateQueueKeyring(queueDir, keyringPath string) (string, error) {
	q, err := lockQueueForKeyMaintenance(queueDir, 0)
	if err != nil {
		return "", err
	}
	defer func() { _ = q.releaseLock() }()
	keyring, err := LoadKeyring(keyringPath)
	if err != nil {
		return "", err
	}
	q.keyring = keyring
	if err := q.migrateRecordsLocked(); err != nil {
		return "", err
	}
	return keyring.ActiveKeyID(), nil
}

func RevokeQueueKeyringKey(queueDir, keyringPath, keyID string) error {
	q, err := lockQueueForKeyMaintenance(queueDir, 0)
	if err != nil {
		return err
	}
	defer func() { _ = q.releaseLock() }()
	keyring, err := LoadKeyring(keyringPath)
	if err != nil {
		return err
	}
	q.keyring = keyring
	usage, err := q.keyUsageLocked()
	if err != nil {
		return err
	}
	if err := keyring.Revoke(keyID, usage); err != nil {
		return err
	}
	return keyring.Save(keyringPath)
}

func RecoverQueueKeyring(queueDir, livePath, backupPath string) (string, error) {
	q, err := lockQueueForKeyMaintenance(queueDir, 0)
	if err != nil {
		return "", err
	}
	defer func() { _ = q.releaseLock() }()
	backup, err := LoadKeyring(backupPath)
	if err != nil {
		return "", fmt.Errorf("load recovery keyring: %w", err)
	}
	q.keyring = backup
	if _, err := q.keyUsageLocked(); err != nil {
		return "", fmt.Errorf("recovery keyring cannot decrypt the queue: %w", err)
	}
	if err := backup.Save(livePath); err != nil {
		return "", err
	}
	return backup.ActiveKeyID(), nil
}

func lockQueueForKeyMaintenance(dir string, maxPayloadBytes uint64) (*Queue, error) {
	if maxPayloadBytes == 0 {
		maxPayloadBytes = conductor.MaxAuditPayloadBytes
	}
	root, pending, inflight, dead, err := ensurePrivateQueueDirs(filepath.Clean(dir))
	if err != nil {
		return nil, err
	}
	lock, err := acquireQueueLock(root)
	if err != nil {
		return nil, err
	}
	return &Queue{
		dir:             root,
		pendingDir:      pending,
		inflightDir:     inflight,
		deadDir:         dead,
		maxPayloadBytes: maxPayloadBytes,
		lockFile:        lock,
	}, nil
}
