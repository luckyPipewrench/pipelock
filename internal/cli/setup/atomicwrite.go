// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
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
		// Same helper as every other installer: private mode, never follows a
		// planted symlink at the backup path.
		if writeErr := writeInstallerBackup(path, bakData); writeErr != nil {
			return writeErr
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

// writeInstallerBackup writes path+".bak" with 0o600 without ever operating on
// the final path by name in more than one step. The 0o600 mode is a Unix
// contract; on Windows the file inherits its directory's ACL and Go's Chmod
// only toggles the read-only bit, so the privacy guarantee there is the
// operator's home-directory ACL, not this call. The bytes go to a private
// temporary file in the same directory and are renamed over the backup path,
// so a symlink planted there is replaced rather than followed and its target
// is never touched; a directory there makes the rename fail and the install
// stop. Inspecting the path first and then writing it would leave a window
// where the path could change between the two operations.
func writeInstallerBackup(path string, data []byte) error {
	backup := path + ".bak"
	tmp, err := os.CreateTemp(filepath.Dir(backup), filepath.Base(backup)+".tmp-*")
	if err != nil {
		return fmt.Errorf("creating backup for %s: %w", path, err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("restricting backup for %s: %w", path, err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("writing backup for %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("closing backup for %s: %w", path, err)
	}
	if err := os.Rename(tmpName, backup); err != nil {
		cleanup()
		return fmt.Errorf("placing backup %s: %w", backup, err)
	}
	return nil
}
