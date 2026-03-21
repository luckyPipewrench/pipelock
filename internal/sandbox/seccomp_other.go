// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !(linux && amd64)

package sandbox

import "fmt"

// ApplySeccomp is a no-op on non-Linux/amd64 platforms.
func ApplySeccomp() (LayerStatus, error) {
	return LayerStatus{
		Name:   LayerSeccomp,
		Active: false,
		Reason: "seccomp requires Linux amd64",
	}, fmt.Errorf("%w: requires linux/amd64", ErrUnavailable)
}

// SetNoNewPrivs is a no-op on non-Linux/amd64 platforms.
func SetNoNewPrivs() error {
	return fmt.Errorf("%w: requires linux/amd64", ErrUnavailable)
}
