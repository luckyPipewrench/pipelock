// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// WalkEvidenceFileReader supplies a seekable snapshot of a regular no-follow
// evidence file. The consumer applies its format's line rules; this reader
// imposes no aggregate byte budget. An error invalidates the entire read.
func WalkEvidenceFileReader(path string, consume func(io.ReadSeeker) error) error {
	if consume == nil {
		return errors.New("evidence file consumer is required")
	}
	file, before, err := OpenEvidenceFile(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	identity, err := historyHandleIdentity(file, before)
	if err != nil {
		return err
	}
	err = consume(io.NewSectionReader(file, 0, before.Size()))
	return finishHistoryPathRead(file, before, identity, err)
}

// The descriptor can stay unchanged after its pathname was replaced. Bind
// standalone path readers to both, just as session walks bind to their inventory.
func finishHistoryPathRead(file *os.File, before os.FileInfo, identity string, readErr error) error {
	err := finishHistoryRead(file, before, identity, readErr)
	if errors.Is(err, ErrEvidenceChanged) {
		return err
	}
	current, info, openErr := OpenEvidenceFile(file.Name())
	if openErr != nil {
		return fmt.Errorf("%w: evidence path unavailable: %s", ErrEvidenceChanged, openErr.Error())
	}
	defer func() { _ = current.Close() }()
	stamp, stampErr := historyHandleIdentity(current, info)
	if stampErr != nil || !os.SameFile(before, info) || identity != stamp || before.Size() != info.Size() || !before.ModTime().Equal(info.ModTime()) {
		return fmt.Errorf("%w: evidence path replaced or modified", ErrEvidenceChanged)
	}
	return err
}
