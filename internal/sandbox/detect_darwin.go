// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package sandbox

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

// Capabilities reports what sandbox layers are available on macOS.
type Capabilities struct {
	// Seatbelt is true if /usr/bin/sandbox-exec is available.
	Seatbelt bool

	// Arch is the CPU architecture (arm64 or amd64).
	Arch string

	// These fields exist for API compatibility with the Linux Capabilities
	// struct but are always zero/false on macOS.
	LandlockABI    int
	UserNamespaces bool
	Seccomp        bool
	MaxUserNS      int
	SELinux        string
}

// Detect probes the current system for sandbox capability support.
func Detect() Capabilities {
	c := Capabilities{
		Arch: runtime.GOARCH,
	}

	if _, err := os.Stat(seatbeltBinary); err == nil {
		c.Seatbelt = true
	}

	return c
}

// Summary returns a human-readable summary of available capabilities.
func (c Capabilities) Summary() string {
	var parts []string

	if c.Seatbelt {
		parts = append(parts, fmt.Sprintf("seatbelt (sandbox-exec): available (%s)", c.Arch))
	} else {
		parts = append(parts, "seatbelt (sandbox-exec): unavailable")
	}

	// macOS does not support Landlock, user namespaces, or seccomp.
	parts = append(parts, "Landlock: N/A (macOS)")
	parts = append(parts, "user namespaces: N/A (macOS)")
	parts = append(parts, "seccomp: N/A (macOS)")

	return strings.Join(parts, ", ")
}
