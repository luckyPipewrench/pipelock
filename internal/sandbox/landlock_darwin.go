// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package sandbox

import "fmt"

// ApplyLandlock is not used on macOS — seatbelt (sandbox-exec) handles
// filesystem restrictions. Returns ErrUnavailable.
func ApplyLandlock(_ Policy) (LayerStatus, error) {
	return LayerStatus{
		Name:   LayerLandlock,
		Active: false,
		Reason: "macOS uses seatbelt (sandbox-exec) instead of Landlock",
	}, fmt.Errorf("%w: not linux", ErrUnavailable)
}
