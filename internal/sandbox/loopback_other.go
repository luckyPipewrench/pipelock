// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package sandbox

import "fmt"

// loopbackUp is a no-op on non-Linux platforms.
// Linux uses raw netlink syscalls to bring up loopback.
func loopbackUp() error {
	return fmt.Errorf("loopback setup not supported on this platform")
}
