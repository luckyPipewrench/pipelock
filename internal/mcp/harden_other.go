// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package mcp

// HardenProxyProcess is a no-op outside Linux, matching the playground
// hardening fallback. The containment deployment that needs PR_SET_DUMPABLE
// runs on Linux/amd64.
func HardenProxyProcess() error {
	return nil
}
