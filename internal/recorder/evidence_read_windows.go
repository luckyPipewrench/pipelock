// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package recorder

import "os"

const (
	evidenceReadNoFollowFlag = 0
	evidenceReadNonblockFlag = 0
)

func lockEvidenceFileForWrite(_ *os.File) error {
	return nil
}

func unlockEvidenceFile(_ *os.File) error {
	return nil
}

func tryLockEvidenceFileForExpiry(_ *os.File) (bool, error) {
	return true, nil
}
