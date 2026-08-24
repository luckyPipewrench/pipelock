// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package evidence

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

type inspectOutput struct {
	file     *os.File
	parentFD int
	name     string
}

func prepareInspectOutput(parent, name, evidenceRoot string) (*inspectOutput, error) {
	parentFD, err := unix.Open(parent, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	if err := inspectParentOutsideEvidence(parentFD, evidenceRoot); err != nil {
		_ = unix.Close(parentFD)
		return nil, err
	}
	fd, err := unix.Openat(parentFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		_ = unix.Close(parentFD)
		return nil, err
	}
	return &inspectOutput{file: os.NewFile(uintptr(fd), name), parentFD: parentFD, name: name}, nil
}

func inspectParentOutsideEvidence(parentFD int, evidenceRoot string) error {
	rootFD, err := unix.Open(evidenceRoot, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(rootFD) }()
	var rootStat unix.Stat_t
	if err := unix.Fstat(rootFD, &rootStat); err != nil {
		return err
	}
	current, err := unix.Dup(parentFD)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(current) }()
	for {
		var currentStat unix.Stat_t
		if err := unix.Fstat(current, &currentStat); err != nil {
			return err
		}
		if currentStat.Dev == rootStat.Dev && currentStat.Ino == rootStat.Ino {
			return errors.New("--out must be outside the evidence directory")
		}
		up, err := unix.Openat(current, "..", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		var upStat unix.Stat_t
		if err := unix.Fstat(up, &upStat); err != nil {
			_ = unix.Close(up)
			return err
		}
		if currentStat.Dev == upStat.Dev && currentStat.Ino == upStat.Ino {
			_ = unix.Close(up)
			return nil
		}
		_ = unix.Close(current)
		current = up
	}
}

func (o *inspectOutput) syncParent() error { return unix.Fsync(o.parentFD) }

func (o *inspectOutput) parentMatches(path string) (bool, error) {
	currentFD, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return false, err
	}
	defer func() { _ = unix.Close(currentFD) }()
	var held, current unix.Stat_t
	if err := unix.Fstat(o.parentFD, &held); err != nil {
		return false, err
	}
	if err := unix.Fstat(currentFD, &current); err != nil {
		return false, err
	}
	return held.Dev == current.Dev && held.Ino == current.Ino, nil
}

func (o *inspectOutput) remove() error { return unix.Unlinkat(o.parentFD, o.name, 0) }

func (o *inspectOutput) close() error { return errors.Join(o.file.Close(), unix.Close(o.parentFD)) }
