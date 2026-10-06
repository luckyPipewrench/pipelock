//go:build !windows

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package launchcontract

import (
	"fmt"
	"os"
	"syscall"
)

// privateMode decides whether a cache entry may hold a trust anchor. An entry
// the invoking user owns is tightened so only that user can write it. A
// root-owned entry is accepted only when group and other cannot write it.
// Anything else could let another account replace the bundle after its
// content check, so it is refused.
func privateMode(info os.FileInfo, euid int) (tighten bool, err error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false, nil
	}
	owner := int(st.Uid)
	writable := info.Mode().Perm()&0o022 != 0
	switch {
	case owner == euid:
		return writable, nil
	case owner == 0 && !writable:
		return false, nil
	default:
		return false, fmt.Errorf("CA cache path is owned by uid %d or writable by other accounts", owner)
	}
}

// requirePrivate applies privateMode to path, tightening an entry the user
// owns. It inspects path with Lstat so a symlink is never followed.
func requirePrivate(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect CA cache path: %w", err)
	}
	tighten, err := privateMode(info, os.Geteuid())
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if tighten {
		if err := os.Chmod(path, info.Mode().Perm()&^0o022); err != nil {
			return fmt.Errorf("restrict CA cache path %s: %w", path, err)
		}
	}
	return nil
}

// requireCacheRoot refuses a cache root that other accounts can write without
// the sticky bit, because they could rename the Pipelock directory under it.
func requireCacheRoot(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("inspect cache directory: %w", err)
	}
	if info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
		return fmt.Errorf("cache directory %s is writable by other accounts; run chmod go-w on it or set XDG_CACHE_HOME to a private directory", path)
	}
	return nil
}
