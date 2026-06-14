// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package selfupdate

import (
	"errors"
	"os"
)

// writeFileQuiet writes data with 0o600 perms (these are signature/checksum
// staging files, not the executable — the 0o600 rule applies here).
func writeFileQuiet(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}

// removeQuiet removes a path, ignoring "not exist".
func removeQuiet(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
