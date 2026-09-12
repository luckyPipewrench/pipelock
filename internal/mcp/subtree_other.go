// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package mcp

import "os/exec"

// cleanupPlatformSupported reports that this platform cannot provide
// subreaper-based orphan cleanup. PR_SET_CHILD_SUBREAPER is Linux-specific,
// so the classification in cleanup_capability.go returns CleanupUnsupported
// here rather than reading enableSubreaper's nil no-op as available.
const cleanupPlatformSupported = false

// enableSubreaper is a no-op on non-Linux builds. PR_SET_CHILD_SUBREAPER
// is Linux-specific; pipelock's MCP stdio proxy still works on macOS for
// developer testing, it just cannot claim subtree ownership of orphaned
// grandchildren there.
func enableSubreaper() error { return nil }

// killAdoptedDescendants is a no-op on non-Linux builds. Without a
// subreaper mechanism there is nothing orphaned to clean up, and /proc
// scanning is Linux-specific anyway.
func killAdoptedDescendants() {}

// setPdeathsig is a no-op on non-Linux builds. Pdeathsig is a Linux
// kernel feature; macOS and other Unix targets have no parent-death
// signal and rely entirely on the post-Wait cleanup path for teardown.
func setPdeathsig(_ *exec.Cmd) {}
