// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !(linux || darwin)

package sandbox

import "fmt"

// ApplyRlimits is a no-op on non-Linux platforms.
func ApplyRlimits() error {
	return fmt.Errorf("%w: unsupported platform", ErrUnavailable)
}
