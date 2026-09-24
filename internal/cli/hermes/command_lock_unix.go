// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hermes

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"syscall"
	"time"
)

// hermesStableCacheDir returns ~/.cache for the invoking account, with the home
// taken from the account database rather than $HOME or $XDG_CACHE_HOME.
func hermesStableCacheDir() (string, error) {
	account, err := user.Current()
	if err != nil {
		return "", err
	}
	if account.HomeDir == "" {
		return "", fmt.Errorf("account %s has no home directory", account.Username)
	}
	return filepath.Join(account.HomeDir, ".cache"), nil
}

func ensureHermesLockDir(path string) error {
	// The cache root is followed (a dotfiles-managed symlinked ~/.cache is
	// legitimate); the pipelock-hermes and locks directories Pipelock creates
	// are not. Each of those is checked without following symlinks before
	// anything is created inside it, so a swapped symlink is refused before a
	// directory can be written through it.
	cacheRoot := filepath.Dir(filepath.Dir(path))
	if err := os.MkdirAll(cacheRoot, 0o700); err != nil {
		return fmt.Errorf("hermes command lock: create %s: %w", cacheRoot, err)
	}
	for _, dir := range []string{cacheRoot, filepath.Dir(path), path} {
		stat := os.Lstat
		if dir == cacheRoot {
			stat = os.Stat
		}
		info, err := stat(dir)
		if errors.Is(err, os.ErrNotExist) && dir != cacheRoot {
			if mkErr := os.Mkdir(dir, 0o700); mkErr != nil && !errors.Is(mkErr, os.ErrExist) {
				return fmt.Errorf("hermes command lock: create %s: %w", dir, mkErr)
			}
			info, err = os.Lstat(dir)
		}
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
	// flock works on a read-only descriptor, so any group or other access to
	// the file would let another user hold the lock.
	if info.Mode&syscall.S_IFMT != syscall.S_IFREG || !hermesLockFileOwnerOK(info.Uid) || info.Mode&0o077 != 0 {
		closeFile()
		return nil, fmt.Errorf("hermes command lock: unsafe lock file %s: must be a regular file owned by and private to the invoking user", path)
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
