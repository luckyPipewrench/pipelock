// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package workspacediff

// mountID has no portable equivalent outside Linux's statx(STATX_MNT_ID);
// ok=false everywhere it's consulted, so callers fall back to the
// device-only mount-boundary check. contain run is Linux-only today (see
// containRunSupported); this exists only to keep the package buildable
// elsewhere for tooling/tests.
func mountID(_ string) (id uint64, ok bool) {
	return 0, false
}

func crossedMount(_, _ uint64, _, _ bool) bool {
	return false
}
