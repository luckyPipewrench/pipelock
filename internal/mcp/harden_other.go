// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !(linux && amd64)

package mcp

// HardenProxyProcess is a no-op outside Linux/amd64, matching the playground
// hardening fallback. The containment deployment that needs PR_SET_DUMPABLE
// runs on Linux/amd64.
func HardenProxyProcess() error {
	return nil
}
