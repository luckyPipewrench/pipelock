// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package sandbox

import "fmt"

// ApplyLandlock is a no-op on non-Linux platforms.
func ApplyLandlock(_ Policy) (LayerStatus, error) {
	return LayerStatus{
		Name:   LayerLandlock,
		Active: false,
		Reason: "landlock requires Linux 5.13+",
	}, fmt.Errorf("%w: not linux", ErrUnavailable)
}
