// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var tryAcquireEvidenceCeremonyLock = tryLockEvidenceFileForExpiry

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
	file, _, err := openEvidenceCeremonyLock(dir)
	if err != nil {
		return nil, err
	}
	locked, err := tryAcquireEvidenceCeremonyLock(file)
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

func acquireEvidenceWriterCeremonyLock(dir string) (*os.File, os.FileInfo, error) {
	if !supportsEvidenceCeremonyLock() {
		return nil, nil, nil
	}
	file, info, err := openEvidenceCeremonyLock(dir)
	if err != nil {
		return nil, nil, err
	}
	if err := tryLockEvidenceFileForCeremonyWrite(file); err != nil {
		_ = file.Close()
		return nil, nil, fmt.Errorf("locking recorder against receipt ceremonies: %w", err)
	}
	return file, info, nil
}

func (r *Recorder) ensureEvidenceWriterCeremonyLock(dirInfo os.FileInfo) error {
	if !supportsEvidenceCeremonyLock() {
		return nil
	}
	if r.ceremonyLock != nil && r.ceremonyDir != nil &&
		dirInfo != nil && os.SameFile(dirInfo, r.ceremonyDir) {
		return nil
	}
	if err := r.releaseEvidenceWriterCeremonyLock(); err != nil {
		return fmt.Errorf("release stale receipt ceremony lock: %w", err)
	}
	lock, lockDirInfo, err := acquireEvidenceWriterCeremonyLock(r.cfg.Dir)
	if err != nil {
		return err
	}
	r.ceremonyLock = lock
	r.ceremonyDir = lockDirInfo
	return nil
}

func (r *Recorder) releaseEvidenceWriterCeremonyLock() error {
	if r.ceremonyLock == nil {
		return nil
	}
	unlockErr := unlockEvidenceFile(r.ceremonyLock)
	closeErr := r.ceremonyLock.Close()
	r.ceremonyLock = nil
	r.ceremonyDir = nil
	return errors.Join(unlockErr, closeErr)
}

func openEvidenceCeremonyLock(dir string) (*os.File, os.FileInfo, error) {
	file, err := os.Open(filepath.Clean(dir))
	if err != nil {
		return nil, nil, fmt.Errorf("opening evidence directory for receipt ceremony lock: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, fmt.Errorf("stat evidence directory for receipt ceremony lock: %w", err)
	}
	if !info.IsDir() {
		_ = file.Close()
		return nil, nil, errors.New("receipt ceremony lock target is not an evidence directory")
	}
	return file, info, nil
}
