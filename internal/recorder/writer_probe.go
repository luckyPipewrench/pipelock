// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"fmt"
	"os"
	"path/filepath"
)

// EvidenceWriterGone reports whether no live writer holds the evidence file at
// path. A live recorder advertises itself with a shared presence lock on the
// shard it is appending to; a non-blocking exclusive probe succeeds only when
// no such lock is held. The probe lock is released before returning, so it
// never blocks or holds anything.
//
// Platforms without the advisory lock always report false: a writer's absence
// cannot be proven there, so a caller relying on this (the predecessor claim)
// starts unlinked rather than risk linking to a chain that is still growing.
func EvidenceWriterGone(path string) (bool, error) {
	f, err := os.OpenFile(filepath.Clean(path), os.O_RDONLY|evidenceReadNoFollowFlag|evidenceReadNonblockFlag, 0)
	if err != nil {
		return false, fmt.Errorf("opening evidence file for writer probe: %w", err)
	}
	defer func() { _ = f.Close() }()
	locked, err := tryLockEvidenceFileForExpiry(f)
	if err != nil {
		return false, fmt.Errorf("probing evidence writer lock: %w", err)
	}
	if locked {
		_ = unlockEvidenceFile(f)
	}
	return locked, nil
}
