//go:build aix || (js && wasm) || (wasip1 && wasm)

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"errors"
	"os"
)

var errEvidenceFileAccessUnsupported = errors.New("evidence file access unsupported on this platform")

const (
	evidenceReadNoFollowFlag = 0
	evidenceReadNonblockFlag = 0
)

// validateEvidenceFileAccess rejects filesystem evidence operations.
func validateEvidenceFileAccess() error {
	return errEvidenceFileAccessUnsupported
}

// lockEvidenceFileForWrite rejects writes without a real platform lock.
func lockEvidenceFileForWrite(_ *os.File) error {
	return errEvidenceFileAccessUnsupported
}

// unlockEvidenceFile rejects the unsupported lock lifecycle.
func unlockEvidenceFile(_ *os.File) error {
	return errEvidenceFileAccessUnsupported
}

// tryLockEvidenceFileForExpiry refuses exclusive ownership without a platform lock.
func tryLockEvidenceFileForExpiry(_ *os.File) (bool, error) {
	return false, errEvidenceFileAccessUnsupported
}
