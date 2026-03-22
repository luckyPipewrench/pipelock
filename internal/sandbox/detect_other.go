// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package sandbox

// Capabilities reports what sandbox layers are available on this system.
type Capabilities struct {
	LandlockABI    int
	UserNamespaces bool
	Seccomp        bool
	MaxUserNS      int
	SELinux        string
}

// Detect returns empty capabilities on non-Linux platforms.
func Detect() Capabilities {
	return Capabilities{}
}

// Summary returns a human-readable summary.
func (c Capabilities) Summary() string {
	return "sandbox requires Linux"
}
