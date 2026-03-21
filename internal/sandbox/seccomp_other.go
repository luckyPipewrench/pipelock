// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !(linux && amd64)

package sandbox

import "fmt"

// ApplySeccomp is a no-op on non-Linux platforms.
func ApplySeccomp() (LayerStatus, error) {
	return LayerStatus{
		Name:   LayerSeccomp,
		Active: false,
		Reason: "seccomp requires Linux",
	}, fmt.Errorf("%w: not linux", ErrUnavailable)
}

// SetNoNewPrivs is a no-op on non-Linux platforms.
func SetNoNewPrivs() error {
	return fmt.Errorf("%w: not linux", ErrUnavailable)
}
