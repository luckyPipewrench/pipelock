//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package auditbatcher

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
)

const (
	LegacyKeyID        = "legacy-plaintext"
	UnreadableRecordID = "unreadable-record"
)

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
				if errors.Is(err, ErrCorruptRecord) {
					usage[UnreadableRecordID]++
					continue
				}
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
	usage, err := q.keyUsageLocked()
	if err != nil {
		return "", "", err
	}
	if usage[UnreadableRecordID] > 0 {
		return "", "", fmt.Errorf("auditbatcher: rotate refused: %d unreadable queue record(s)", usage[UnreadableRecordID])
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
		return oldID, newID, fmt.Errorf("new key saved but rotated keyring backup failed; rerun with a valid backup path: %w", err)
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
	if usage[UnreadableRecordID] > 0 {
		return fmt.Errorf("auditbatcher: revoke refused: %d unreadable queue record(s) may still use the key", usage[UnreadableRecordID])
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
	usage, err := q.keyUsageLocked()
	if err != nil {
		return "", fmt.Errorf("recovery keyring cannot decrypt the queue: %w", err)
	}
	if usage[UnreadableRecordID] > 0 {
		return "", fmt.Errorf("recovery keyring cannot decrypt %d queue record(s)", usage[UnreadableRecordID])
	}
	// Recovery intentionally reinstates the backup verbatim, including any key
	// revoked after that backup was taken. Preserve the current live keyring so
	// the operator can reverse an accidental or stale recovery.
	live, err := LoadKeyring(livePath)
	if err != nil {
		return "", fmt.Errorf("load live keyring before recovery: %w", err)
	}
	if err := live.Save(livePath + ".pre-recover"); err != nil {
		return "", fmt.Errorf("preserve live keyring before recovery: %w", err)
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
	cleanDir := filepath.Clean(dir)
	for _, required := range []string{cleanDir, filepath.Join(cleanDir, "pending"), filepath.Join(cleanDir, "inflight"), filepath.Join(cleanDir, "dead")} {
		info, err := os.Lstat(required)
		if err != nil {
			return nil, fmt.Errorf("auditbatcher: maintenance requires an initialized queue at %s: %w", cleanDir, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, fmt.Errorf("auditbatcher: maintenance queue path %s must be a real directory", required)
		}
	}
	root, pending, inflight, dead, err := ensurePrivateQueueDirs(cleanDir)
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
