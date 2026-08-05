// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !unix && !windows

package commitmentkey

import "sync"

// lifecycleLock serializes lifecycle operations only within this process.
// Targets outside the Unix and Windows build tags have no cross-process lock.
var lifecycleLock sync.Mutex

func withLifecycleLock(_ string, fn func() error) error {
	lifecycleLock.Lock()
	defer lifecycleLock.Unlock()
	return fn()
}
