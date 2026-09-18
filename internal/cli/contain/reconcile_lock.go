// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

// containmentReconcileLockPathFor derives the reconcile lock path from the
// nft rules path: they live beside each other under /etc/nftables.d/, a
// root-owned directory, never under the pipelock-proxy-owned data
// directory (see withContainmentReconcileLock's doc comment for why that
// distinction matters). Deriving it from rulesPath, rather than a separate
// fixed constant, also means every test that injects a custom rulesPath
// gets a matching, collision-free lock path automatically.
func containmentReconcileLockPathFor(rulesPath string) string {
	return rulesPath + ".reconcile.lock"
}
