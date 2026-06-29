// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows && !js

package anchor

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func acquireLocalLogLock(logPath string) (func(), error) {
	lockPath := filepath.Clean(logPath) + ".lock"
	if err := os.MkdirAll(filepath.Dir(lockPath), dirPermissions); err != nil {
		return nil, fmt.Errorf("create local anchor log lock directory: %w", err)
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, filePermissions) // #nosec G304 -- lock path derives from operator-configured local anchor log path
	if err != nil {
		return nil, fmt.Errorf("open local anchor log lock: %w", err)
	}
	fd := int(f.Fd()) // #nosec G115 -- file descriptors fit in int
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("acquire local anchor log lock: %w", err)
	}
	return func() {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
