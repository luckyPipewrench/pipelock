// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package license

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func acquireCRLHighWaterLock(crlFile string) (func(), error) {
	lockPath := CRLHighWaterPath(crlFile) + ".lock"
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o750); err != nil {
		return nil, fmt.Errorf("create license CRL high-water lock dir: %w", err)
	}
	f, err := os.OpenFile(filepath.Clean(lockPath), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open license CRL high-water lock: %w", err)
	}
	fd := int(f.Fd()) // #nosec G115 -- file descriptors fit in int
	// Blocking exclusive lock. The critical section is a tiny
	// read-compare-atomic-write already serialized in-process by
	// crlHighWaterMu, so a brief cross-process wait is safe. A non-blocking
	// lock would surface benign concurrent verification (e.g. an operator CLI
	// command running alongside the runtime's periodic CRL check) as a
	// verification error, which the runtime watcher treats as fail-closed
	// teardown of the agent listeners and conductor.
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("acquire license CRL high-water lock: %w", err)
	}
	return func() {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
