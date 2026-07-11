// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package baseline

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

var errELOOP error = unix.ELOOP

func openRegularFileNoSymlinkBelowRoot(canonicalRoot, relPath, displayPath string) (*os.File, error) {
	rootFD, err := unix.Open(canonicalRoot, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open trusted root %q: %w", canonicalRoot, err)
	}
	dirFD := rootFD
	closeDir := true
	defer func() {
		if closeDir {
			_ = unix.Close(dirFD)
		}
	}()

	parts := splitRelativePath(relPath)
	if len(parts) == 0 {
		return nil, fmt.Errorf("%s has no file component", displayPath)
	}
	for _, part := range parts[:len(parts)-1] {
		nextFD, err := unix.Openat(dirFD, part, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if err != nil {
			return nil, fmt.Errorf("open parent directory %q below trusted root: %w", part, err)
		}
		_ = unix.Close(dirFD)
		dirFD = nextFD
	}

	fileFD, err := unix.Openat(dirFD, parts[len(parts)-1], unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fileFD), displayPath)
	if f == nil {
		_ = unix.Close(fileFD)
		return nil, fmt.Errorf("open %s: invalid file descriptor", displayPath)
	}
	return f, nil
}

func splitRelativePath(relPath string) []string {
	clean := filepath.Clean(relPath)
	if clean == "." {
		return nil
	}
	parts := make([]string, 0)
	for _, part := range strings.Split(clean, string(os.PathSeparator)) {
		if part != "" && part != "." {
			parts = append(parts, part)
		}
	}
	return parts
}
