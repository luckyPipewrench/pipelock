// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build unix || (js && wasm)

package recorder

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func historyFileIdentity(_ EvidenceLocation, _ string, info os.FileInfo) (string, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", errors.New("cannot identify evidence shard")
	}
	return fmt.Sprintf("%d:%d:%s", stat.Dev, stat.Ino, historyChangeTime(stat)), nil
}

func historyHandleIdentity(_ *os.File, info os.FileInfo) (string, error) {
	return historyFileIdentity(EvidenceLocation{}, "", info)
}

// EvidenceMetadataIdentity returns an opaque identity and change-time stamp
// for an inventory entry. Reads do not change it; a local rewrite does.
// This consistency check depends on the filesystem's metadata semantics.
func EvidenceMetadataIdentity(_ string, info os.FileInfo) (string, error) {
	return historyFileIdentity(EvidenceLocation{}, "", info)
}
