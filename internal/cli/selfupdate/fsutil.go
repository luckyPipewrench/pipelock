// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package selfupdate

import (
	"os"
	"path/filepath"
)

// dirOf returns the directory containing path.
func dirOf(path string) string {
	return filepath.Dir(path)
}

// joinDir joins a directory and a file name.
func joinDir(dir, name string) string {
	return filepath.Join(dir, name)
}

// writeFileQuiet writes data with 0o600 perms (these are signature/checksum
// staging files, not the executable — the 0o600 rule applies here).
func writeFileQuiet(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}

// removeQuiet removes a path, ignoring "not exist".
func removeQuiet(path string) error {
	return os.Remove(path)
}
