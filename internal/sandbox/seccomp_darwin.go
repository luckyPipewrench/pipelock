// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package sandbox

import "fmt"

// ApplySeccomp is not available on macOS. Returns ErrUnavailable.
func ApplySeccomp() (LayerStatus, error) {
	return LayerStatus{
		Name:   LayerSeccomp,
		Active: false,
		Reason: "macOS does not support seccomp",
	}, fmt.Errorf("%w: seccomp is not available on macOS", ErrUnavailable)
}

// SetNoNewPrivs is not available on macOS. Returns ErrUnavailable.
func SetNoNewPrivs() error {
	return fmt.Errorf("%w: no_new_privs is not available on macOS", ErrUnavailable)
}
