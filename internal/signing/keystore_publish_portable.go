// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"errors"
	"fmt"
	"os"
)

// ErrPublishedNotDurable reports that the new key pair is ALREADY the active
// identity and only the durability confirmation failed. It is not a failed
// publication and must not be handled as one.
//
// The distinction matters because the two demand opposite responses. A failed
// publication leaves the old pair active, so a caller should keep using it. This
// leaves the NEW pair active and signing, so a caller that treats it as a
// failure keeps distributing a public key the keystore no longer signs with.
// Anything reporting this error has already changed the active identity.
var ErrPublishedNotDurable = errors.New("agent key pair published but durability could not be confirmed")

func publishAgentDirectoryPortable(targetDir, stageDir, backupDir string) error {
	if err := os.RemoveAll(backupDir); err != nil {
		return fmt.Errorf("removing stale agent backup: %w", err)
	}
	if err := os.Rename(targetDir, backupDir); err != nil {
		return fmt.Errorf("backing up active agent directory: %w", err)
	}
	if err := installStagedAgentDirectory(targetDir, stageDir); err != nil {
		if removeErr := removeEmptyDirectory(targetDir); removeErr != nil && !os.IsNotExist(removeErr) {
			return fmt.Errorf("installing staged agent directory: %w", errors.Join(err, fmt.Errorf("clearing active path for rollback: %w", removeErr)))
		}
		if restoreErr := os.Rename(backupDir, targetDir); restoreErr != nil {
			return fmt.Errorf("installing staged agent directory: %w", errors.Join(err, fmt.Errorf("restoring prior key pair: %w", restoreErr)))
		}
		return fmt.Errorf("installing staged agent directory: %w", err)
	}
	// The new pair is already committed. Cleanup is best-effort so a cleanup
	// failure cannot turn a successful force-regenerate into an ambiguous error.
	// The next generation recovers by keeping the coherent active pair.
	_ = os.RemoveAll(backupDir)
	return nil
}

func installStagedAgentDirectory(targetDir, stageDir string) error {
	const maxConcurrentPreflightRetries = 64
	var lastErr error
	for range maxConcurrentPreflightRetries {
		if err := os.Rename(stageDir, targetDir); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if err := removeEmptyDirectory(targetDir); err != nil {
			return lastErr
		}
	}
	return lastErr
}

func removeEmptyDirectory(path string) error {
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("active agent directory is not empty")
	}
	return os.Remove(path)
}
