// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// PublishLateReceiptGroupClose completes an already durable group whose writer
// crashed before linking its close manifest. It cannot add evidence, use a
// later signing key, or change a predecessor frozen by a transition.
func PublishLateReceiptGroupClose(dir, groupID string, key ed25519.PrivateKey) (string, error) {
	return publishLateReceiptGroupClose(dir, groupID, key, nil)
}

func publishLateReceiptGroupClose(dir, groupID string, key ed25519.PrivateKey, beforeFinalCheck func()) (string, error) {
	if len(key) != ed25519.PrivateKeySize {
		return "", errors.New("late receipt group close requires the opening private key")
	}
	lock, err := recorder.AcquireEvidenceCeremonyLock(dir)
	if err != nil {
		return "", err
	}
	defer func() { _ = lock.Close() }()
	openName, err := ReceiptGroupFileName(groupID, "open")
	if err != nil {
		return "", err
	}
	rootInfo, aelInfo, err := receiptGroupDirectoryIdentity(dir)
	if err != nil {
		return "", err
	}
	before, err := fingerprintGroupDirectory(dir)
	if err != nil {
		return "", fmt.Errorf("inventory receipt group directory: %w", err)
	}
	openBytes, err := readBoundedGroupFile(dir, openName)
	if err != nil {
		return "", err
	}
	keyHex := hex.EncodeToString(key.Public().(ed25519.PublicKey))
	open, err := UnmarshalReceiptGroupOpen(openBytes, []string{keyHex})
	if err != nil || open.GroupID != groupID || open.SignerKey != keyHex {
		return "", errors.New("late receipt group close requires the exact opening key and manifest")
	}
	openDigest := sha256.Sum256(openBytes)
	openHash := hex.EncodeToString(openDigest[:])
	closeName, _ := ReceiptGroupFileName(groupID, "close")
	if _, err := os.Lstat(filepath.Join(filepath.Clean(dir), closeName)); err == nil {
		return "", errors.New("receipt group close already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := refuseSuccessorTransition(dir, openHash); err != nil {
		return "", err
	}
	heads := make([]ReceiptGroupShardHead, len(open.Shards))
	for i := range heads {
		head, err := VerifyGroupShardHead(dir, open, openHash, i)
		if err != nil {
			return "", fmt.Errorf("late receipt group close shard %d: %w", i, err)
		}
		heads[i] = head
	}
	// Reopen evidence before signing: a completed set must still match the
	// exact heads after all reads, even if an out-of-band writer ignored locks.
	for i, head := range heads {
		again, err := VerifyGroupShardHead(dir, open, openHash, i)
		if err != nil || again != head {
			return "", fmt.Errorf("receipt group shard %d changed before late close: %w", i, err)
		}
	}
	if err := verifyGroupAELInventory(dir, open, []string{keyHex}); err != nil && !errors.Is(err, errGroupAELNeighborOpenTail) {
		return "", fmt.Errorf("late receipt group close AEL inventory: %w", err)
	}
	again, err := readBoundedGroupFile(dir, openName)
	if err != nil || string(again) != string(openBytes) {
		return "", errors.New("receipt group opening changed before late close")
	}
	if err := refuseSuccessorTransition(dir, openHash); err != nil {
		return "", err
	}
	if beforeFinalCheck != nil {
		beforeFinalCheck()
	}
	after, err := fingerprintGroupDirectory(dir)
	if err != nil || after != before {
		return "", errors.New("receipt group directory changed before late close")
	}
	endRoot, endAEL, err := receiptGroupDirectoryIdentity(dir)
	if err != nil || !os.SameFile(rootInfo, endRoot) || !os.SameFile(aelInfo, endAEL) {
		return "", errors.New("receipt group directory identity changed before late close")
	}
	closed, err := SignReceiptGroupClose(ReceiptGroupClose{
		GroupID: groupID, OpenManifestSHA256: openHash, Shards: heads,
		ClosedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}, open, openHash, key)
	if err != nil {
		return "", err
	}
	return PublishReceiptGroupArtifact(dir, closeName, closed)
}

func readBoundedGroupFile(dir, name string) ([]byte, error) {
	path := filepath.Join(filepath.Clean(dir), name)
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Size() > maxGroupFileBytes {
		return nil, errors.New("receipt group artifact is not a bounded regular file")
	}
	f, _, err := recorder.OpenEvidenceFile(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	// Read failures keep their cause and a file that changes under the read
	// is reported as changed evidence, so verification can tell unavailable
	// evidence from a stable invalid artifact.
	opened, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat receipt group artifact: %w", err)
	}
	if !os.SameFile(before, opened) {
		return nil, fmt.Errorf("%w: receipt group artifact changed during open", recorder.ErrEvidenceChanged)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxGroupFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read receipt group artifact: %w", err)
	}
	after, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat receipt group artifact: %w", err)
	}
	if !os.SameFile(opened, after) || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) {
		return nil, fmt.Errorf("%w: receipt group artifact changed during read", recorder.ErrEvidenceChanged)
	}
	if len(raw) > maxGroupFileBytes {
		return nil, errors.New("receipt group artifact exceeds read bound")
	}
	return raw, nil
}

func refuseSuccessorTransition(dir, openHash string) error {
	f, err := recorder.OpenEvidenceDirectory(dir)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	for {
		names, err := f.Readdirnames(128)
		for _, name := range names {
			if !strings.HasPrefix(name, "receipt-group-") || !strings.HasSuffix(name, "-transition.json") {
				continue
			}
			raw, readErr := readBoundedGroupFile(dir, name)
			if readErr != nil {
				return readErr
			}
			tr, parseErr := strictGroupArtifact[ReceiptGroupTransition](raw)
			if parseErr != nil {
				return fmt.Errorf("invalid receipt group transition inventory: %w", parseErr)
			}
			if tr.PreviousOpenManifestSHA256 == openHash {
				return errors.New("successor transition already froze receipt group close state")
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
