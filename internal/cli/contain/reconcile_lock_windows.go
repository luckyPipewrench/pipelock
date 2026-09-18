// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package contain

// withContainmentReconcileLock on Windows runs fn without file locking.
// Windows does not support flock, and Pipelock's Linux nftables containment
// (`contain install` / `contain reload-nft-rules`) is not offered on this
// platform, so no concurrent install/reload interleaving is possible here.
func withContainmentReconcileLock(_ string, fn func() error) error {
	return fn()
}
