// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package diag

import "errors"

// enumerateListenerHolders is a no-op on non-Linux platforms because the
// implementation reads /proc/net/tcp + /proc/<pid>/fd, neither of which
// exists on macOS or Windows. Doctor surfaces this as an info-tier
// "unavailable on this platform" check rather than a failure.
func enumerateListenerHolders() (map[uint16][]procListener, error) {
	return nil, errors.New("port-collision check requires Linux /proc; not available on this platform")
}
