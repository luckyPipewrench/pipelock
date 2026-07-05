// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows && !js

package baseline

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const (
	// integrityHighWaterLockTimeout bounds how long we wait for another
	// process to release the lock. The critical section is a tiny atomic write,
	// so real contention clears in milliseconds; the timeout only guards
	// against a wedged holder rather than failing instantly on a benign race.
	integrityHighWaterLockTimeout = 2 * time.Second
	integrityHighWaterLockPoll    = 20 * time.Millisecond
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
	deadline := time.Now().Add(integrityHighWaterLockTimeout)
	for {
		if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
			return func() {
				_ = syscall.Flock(fd, syscall.LOCK_UN)
				_ = f.Close()
			}, nil
		} else if !retryableIntegrityHighWaterLockError(err) {
			_ = f.Close()
			return nil, fmt.Errorf("acquire baseline integrity generation high-water lock: %w", err)
		}
		if time.Now().After(deadline) {
			_ = f.Close()
			return nil, fmt.Errorf("baseline integrity generation high-water locked by another process: %s", lockPath)
		}
		time.Sleep(integrityHighWaterLockPoll)
	}
}

func retryableIntegrityHighWaterLockError(err error) bool {
	return errors.Is(err, syscall.EWOULDBLOCK) ||
		errors.Is(err, syscall.EAGAIN) ||
		errors.Is(err, syscall.EINTR)
}
