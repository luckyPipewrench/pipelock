// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

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

func lockEvidenceFileForWrite(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_SH)
}

func unlockEvidenceFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}

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
