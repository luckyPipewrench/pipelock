//go:build !windows

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package posturebinding

import (
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// proofOwnerGroup returns numeric ownership where the calling principal can
// inspect the proof or its direct parent. A denied parent deliberately remains
// unknown: guessing ownership would turn an unreadable state into a false claim.
func proofOwnerGroup(path string) (string, string, bool) {
	for _, candidate := range []string{path, filepath.Dir(path)} {
		info, err := os.Stat(candidate)
		if err != nil {
			continue
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return "", "", false
		}
		return strconv.FormatUint(uint64(stat.Uid), 10), strconv.FormatUint(uint64(stat.Gid), 10), true
	}
	return "", "", false
}
