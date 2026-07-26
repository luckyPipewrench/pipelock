// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package recorder

import "os"

const (
	evidenceReadNoFollowFlag = 0
	evidenceReadNonblockFlag = 0
)

// Windows has no advisory whole-file lock equivalent to flock here, so the
// writer-presence lock is a no-op. That is safe on its own: it only means
// writers advertise nothing.
func lockEvidenceFileForWrite(_ *os.File) error {
	return nil
}

func unlockEvidenceFile(_ *os.File) error {
	return nil
}

// tryLockEvidenceFileForExpiry reports that the exclusive lock could NOT be
// acquired on Windows.
//
// It must never return true here. The caller treats true as "no other process
// holds this file, so it is safe to delete", and with lockEvidenceFileForWrite
// a no-op there is nothing on this platform that could contradict that claim.
// Returning true would therefore let automatic expiry delete a file a live
// writer is still appending to, with no coordination at all - a fail-open on a
// destructive path. Refusing the lock makes expiry skip the file instead, which
// merely retains evidence longer. Retaining too much is recoverable; deleting
// evidence is not.
//
// Real Windows locking via LockFileEx would let expiry run here safely and is
// the follow-up; until then this fails closed.
func tryLockEvidenceFileForExpiry(_ *os.File) (bool, error) {
	return false, nil
}
