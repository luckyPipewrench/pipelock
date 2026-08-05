// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package commitmentkey

import (
	"errors"
	"fmt"
)

const maxPrivateViewBytes = 64 << 20

// ReadPrivateView reads an operator-supplied transformed evidence view without
// following a final-component symlink. Files must use the same owner-only mode
// and trusted-parent rules as the keyring.
func ReadPrivateView(path string) ([]byte, error) {
	return readSecureLimited(path, maxPrivateViewBytes, "private evidence view", nil)
}

func invalidReadError(sentinel error, label, format string, args ...any) error {
	detail := fmt.Sprintf(format, args...)
	if sentinel != nil {
		return fmt.Errorf("%w: %s", sentinel, detail)
	}
	return errors.New("invalid " + label + ": " + detail)
}
