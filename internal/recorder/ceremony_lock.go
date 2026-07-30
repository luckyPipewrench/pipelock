// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const ceremonyLockFilename = ".pipelock-receipt-ceremony.lock"

// EvidenceCeremonyLock proves that no recorder is writing in an evidence
// directory and prevents a recorder from starting until the lock is released.
type EvidenceCeremonyLock struct {
	file *os.File
}

// AcquireEvidenceCeremonyLock takes exclusive, non-blocking ownership of an
// evidence directory for an offline receipt ceremony.
func AcquireEvidenceCeremonyLock(dir string) (*EvidenceCeremonyLock, error) {
	if !supportsEvidenceCeremonyLock() {
		return nil, errors.New("receipt ceremony locking is unsupported on this platform")
	}
	file, err := openEvidenceCeremonyLockFile(dir)
	if err != nil {
		return nil, err
	}
	locked, err := tryLockEvidenceFileForExpiry(file)
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("locking receipt ceremony: %w", err)
	}
	if !locked {
		_ = file.Close()
		return nil, errors.New("receipt ceremony requires a stopped recorder; evidence directory is still in use")
	}
	return &EvidenceCeremonyLock{file: file}, nil
}

// Close releases exclusive ceremony ownership.
func (l *EvidenceCeremonyLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	unlockErr := unlockEvidenceFile(l.file)
	closeErr := l.file.Close()
	l.file = nil
	return errors.Join(unlockErr, closeErr)
}

func acquireEvidenceWriterCeremonyLock(dir string) (*os.File, error) {
	if !supportsEvidenceCeremonyLock() {
		return nil, nil
	}
	file, err := openEvidenceCeremonyLockFile(dir)
	if err != nil {
		return nil, err
	}
	if err := tryLockEvidenceFileForCeremonyWrite(file); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("locking recorder against receipt ceremonies: %w", err)
	}
	return file, nil
}

func openEvidenceCeremonyLockFile(dir string) (*os.File, error) {
	path := filepath.Join(filepath.Clean(dir), ceremonyLockFilename)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|evidenceReadNoFollowFlag, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening receipt ceremony lock: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("stating receipt ceremony lock: %w", err)
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, errors.New("receipt ceremony lock is not a regular file")
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("setting receipt ceremony lock permissions: %w", err)
	}
	return file, nil
}
