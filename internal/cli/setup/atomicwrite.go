// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

func atomicWriteFile(path string, data []byte, doBackup bool) error {
	path = filepath.Clean(path)
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}

	if doBackup {
		bakData, readErr := os.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("reading original for backup: %w", readErr)
		}
		if writeErr := os.WriteFile(path+".bak", bakData, info.Mode()); writeErr != nil {
			return fmt.Errorf("creating backup: %w", writeErr)
		}
	}

	tmpFile := path + ".tmp." + strconv.FormatInt(time.Now().UnixNano(), 36)
	if err := os.WriteFile(tmpFile, data, info.Mode()); err != nil {
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := os.Rename(tmpFile, path); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("atomic rename: %w", err)
	}
	return nil
}

// writeInstallerBackup writes path+".bak" with 0o600. os.WriteFile applies the
// mode only when it creates the file, so an existing backup left at a broader
// mode would keep it and expose copied MCP env values; restrict it first. A
// missing backup is the normal case and is not an error.
func writeInstallerBackup(path string, data []byte) error {
	backup := path + ".bak"
	if err := os.Chmod(backup, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("restricting existing backup %s: %w", backup, err)
	}
	return os.WriteFile(backup, data, 0o600)
}
