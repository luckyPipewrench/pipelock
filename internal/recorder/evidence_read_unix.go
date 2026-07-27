// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix && !aix

package recorder

import (
	"errors"
	"os"
	"syscall"
)

const (
	evidenceReadNoFollowFlag = syscall.O_NOFOLLOW
	evidenceReadNonblockFlag = syscall.O_NONBLOCK
)

// validateEvidenceFileAccess permits evidence access where no-follow,
// nonblocking opens and advisory locks are available.
func validateEvidenceFileAccess() error {
	return nil
}

// lockEvidenceFileForWrite advertises a live writer with a shared lock.
func lockEvidenceFileForWrite(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_SH)
}

// unlockEvidenceFile releases a writer-presence lock.
func unlockEvidenceFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}

// tryLockEvidenceFileForExpiry claims exclusive ownership without blocking.
func tryLockEvidenceFileForExpiry(f *os.File) (bool, error) {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
		return false, nil
	}
	return false, err
}
