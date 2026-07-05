// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows && !js

package baseline

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func acquireIntegrityHighWaterLock(integrityKeyPath string) (func(), error) {
	lockPath := filepath.Clean(integrityKeyPath) + ".generation.lock"
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o750); err != nil {
		return nil, fmt.Errorf("create baseline integrity generation high-water lock dir: %w", err)
	}
	f, err := os.OpenFile(filepath.Clean(lockPath), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open baseline integrity generation high-water lock: %w", err)
	}
	fd := int(f.Fd()) // #nosec G115 -- file descriptors fit in int
	// Blocking exclusive lock. The critical section is a tiny
	// read-compare-atomic-write already serialized in-process by
	// integrityHighWaterMu, so a brief cross-process wait is safe. A
	// non-blocking lock would surface benign concurrent verification as a
	// fail-closed baseline startup or ratification error.
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("acquire baseline integrity generation high-water lock: %w", err)
	}
	return func() {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
