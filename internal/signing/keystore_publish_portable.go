// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"fmt"
	"os"
)

func publishAgentDirectoryPortable(targetDir, stageDir, backupDir string) error {
	if err := os.RemoveAll(backupDir); err != nil {
		return fmt.Errorf("removing stale agent backup: %w", err)
	}
	if err := os.Rename(targetDir, backupDir); err != nil {
		return fmt.Errorf("backing up active agent directory: %w", err)
	}
	if err := os.Rename(stageDir, targetDir); err != nil {
		if restoreErr := os.Rename(backupDir, targetDir); restoreErr != nil {
			return fmt.Errorf("installing staged agent directory: %w (restoring prior key pair: %v)", err, restoreErr)
		}
		return fmt.Errorf("installing staged agent directory: %w", err)
	}
	// The new pair is already committed. Cleanup is best-effort so a cleanup
	// failure cannot turn a successful force-regenerate into an ambiguous error.
	// The next generation recovers by keeping the coherent active pair.
	_ = os.RemoveAll(backupDir)
	return nil
}
