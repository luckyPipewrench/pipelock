// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package sandbox

import "fmt"

// ApplyRlimits is not used on macOS — seatbelt handles resource containment.
func ApplyRlimits() error {
	return fmt.Errorf("%w: rlimits not applied on macOS", ErrUnavailable)
}
