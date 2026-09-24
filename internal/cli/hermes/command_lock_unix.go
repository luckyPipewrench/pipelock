// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hermes

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func ensureHermesLockDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("hermes command lock: create %s: %w", path, err)
	}
	// The cache root is followed (a dotfiles-managed symlinked ~/.cache is
	// legitimate); the pipelock and locks directories Pipelock creates are
	// not, so a swapped symlink there is refused.
	cacheRoot := filepath.Dir(filepath.Dir(path))
	for _, dir := range []string{cacheRoot, filepath.Dir(path), path} {
		stat := os.Lstat
		if dir == cacheRoot {
			stat = os.Stat
		}
		info, err := stat(dir)
		if err != nil {
			return err
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !hermesLockDirSafe(info.Mode(), owner.Uid) {
			return fmt.Errorf("hermes command lock: unsafe lock directory %s: must be owned by invoking user and not group/world-writable", dir)
		}
	}

	return nil
}

func acquireHermesLock(path string, deadline time.Time) (func(), error) {
	fd, err := syscall.Open(filepath.Clean(path), syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("hermes command lock: open %s: %w", path, err)
	}
	closeFile := func() { _ = syscall.Close(fd) }
	var info syscall.Stat_t
	if err := syscall.Fstat(fd, &info); err != nil {
		closeFile()
		return nil, fmt.Errorf("hermes command lock: stat %s: %w", path, err)
	}
	if info.Mode&syscall.S_IFMT != syscall.S_IFREG || !hermesLockFileOwnerOK(info.Uid) {
		closeFile()
		return nil, fmt.Errorf("hermes command lock: unsafe lock file %s: must be regular and owned by invoking user", path)
	}
	for {
		err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { _ = syscall.Flock(fd, syscall.LOCK_UN); closeFile() }, nil
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			closeFile()
			return nil, fmt.Errorf("hermes command lock: lock %s: %w", path, err)
		}
		if !time.Now().Before(deadline) {
			closeFile()
			return nil, hermesLockBusy(path)
		}
		time.Sleep(min(10*time.Millisecond, time.Until(deadline)))
	}
}

func hermesLockFileOwnerOK(uid uint32) bool { return int(uid) == os.Getuid() }

func hermesLockDirSafe(mode os.FileMode, uid uint32) bool {
	return mode.IsDir() && mode.Perm()&0o022 == 0 && hermesLockFileOwnerOK(uid)
}
