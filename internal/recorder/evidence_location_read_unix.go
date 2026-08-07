// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix && !aix

package recorder

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func openEvidenceLocationDirectory(location EvidenceLocation) (*os.File, error) {
	if err := validateEvidenceLocation(location); err != nil {
		return nil, err
	}
	fd, err := unix.Open(filepath.Clean(location.Root), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open evidence root: %w", err)
	}
	currentFD := fd
	for _, part := range strings.Split(filepath.FromSlash(location.ID), string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		nextFD, openErr := unix.Openat(currentFD, part, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		_ = unix.Close(currentFD)
		if openErr != nil {
			return nil, fmt.Errorf("open evidence location component %q: %w", part, openErr)
		}
		currentFD = nextFD
	}
	file := os.NewFile(uintptr(currentFD), filepath.Clean(location.Dir))
	if file == nil {
		_ = unix.Close(currentFD)
		return nil, errors.New("open evidence location: invalid file descriptor")
	}
	return file, nil
}

func openEvidenceLocationFile(location EvidenceLocation, name string) (*os.File, os.FileInfo, error) {
	if name != filepath.Base(name) || name == "." || name == ".." {
		return nil, nil, errors.New("evidence filename must be a base name")
	}
	directory, err := openEvidenceLocationDirectory(location)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = directory.Close() }()
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open evidence file %q: %w", name, err)
	}
	file := os.NewFile(uintptr(fd), filepath.Join(location.Dir, name))
	if file == nil {
		_ = unix.Close(fd)
		return nil, nil, errors.New("open evidence file: invalid file descriptor")
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, nil, errors.New("evidence file is non-regular")
	}
	return file, info, nil
}
