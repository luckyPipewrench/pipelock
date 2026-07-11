//go:build !windows

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func writeBundleFile(path string, data []byte) error {
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, dirPermissions); err != nil {
		return fmt.Errorf("create anchor bundle directory: %w", err)
	}
	return writeBundleFileUnderDir(parent, filepath.Base(path), data)
}

func writeBundleFileUnderDir(root, rel string, data []byte) error {
	rootFD, err := openAnchorDir(root)
	if err != nil {
		return fmt.Errorf("open anchor bundle directory: %w", err)
	}
	defer func() { _ = unix.Close(rootFD) }()
	return writeFileUnderDir(rootFD, rel, data)
}

func writeStateMarkerFile(cleanDir string, marker StateMarker, data []byte) error {
	if err := os.MkdirAll(cleanDir, dirPermissions); err != nil {
		return fmt.Errorf("create anchor-state directory: %w", err)
	}
	rootFD, err := openAnchorDir(cleanDir)
	if err != nil {
		return fmt.Errorf("create anchor-state directory: %w", err)
	}
	defer func() { _ = unix.Close(rootFD) }()
	if err := unix.Mkdirat(rootFD, stateMarkerIndexDir, dirPermissions); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("create anchor-state directory: %w", err)
	}
	indexFD, err := unix.Openat(rootFD, stateMarkerIndexDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if validateErr := validateStateMarkerIndexDir(filepath.Join(cleanDir, stateMarkerIndexDir)); validateErr != nil {
			return validateErr
		}
		return fmt.Errorf("inspect anchor-state directory: %w", err)
	}
	defer func() { _ = unix.Close(indexFD) }()
	name, err := stateMarkerFileName(marker)
	if err != nil {
		return err
	}
	var tempName string
	tempFD := -1
	for attempts := 0; attempts < 16; attempts++ {
		tempName, err = stateMarkerTempName()
		if err != nil {
			return err
		}
		tempFD, err = unix.Openat(indexFD, tempName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, filePermissions)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("create anchor-state temp file: %w", err)
		}
	}
	if tempFD < 0 {
		return fmt.Errorf("create anchor-state temp file: %w", err)
	}
	tempFile := os.NewFile(uintptr(tempFD), tempName)
	defer func() { _ = unix.Unlinkat(indexFD, tempName, 0) }()
	if _, err := tempFile.Write(data); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("write anchor-state temp file: %w", err)
	}
	if err := tempFile.Chmod(filePermissions); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("chmod anchor-state temp file: %w", err)
	}
	if err := tempFile.Sync(); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("sync anchor-state temp file: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("close anchor-state temp file: %w", err)
	}
	if err := unix.Renameat(indexFD, tempName, indexFD, name); err != nil {
		return fmt.Errorf("rename anchor-state marker: %w", err)
	}
	if err := unix.Fsync(indexFD); err != nil {
		return fmt.Errorf("sync anchor-state directory: %w", err)
	}
	return nil
}

func openAnchorDir(path string) (int, error) {
	return unix.Open(filepath.Clean(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
}

func writeFileUnderDir(rootFD int, rel string, data []byte) error {
	cleanRel := filepath.Clean(rel)
	parts := strings.Split(cleanRel, string(filepath.Separator))
	dirFD := rootFD
	closeDir := false
	for _, part := range parts[:len(parts)-1] {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("anchor bundle path must stay under receipt directory")
		}
		if err := unix.Mkdirat(dirFD, part, dirPermissions); err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("create anchor bundle directory: %w", err)
		}
		nextFD, err := unix.Openat(dirFD, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return fmt.Errorf("open anchor bundle directory: %w", err)
		}
		if closeDir {
			_ = unix.Close(dirFD)
		}
		dirFD = nextFD
		closeDir = true
	}
	if closeDir {
		defer func() { _ = unix.Close(dirFD) }()
	}
	name := parts[len(parts)-1]
	if name == "" || name == "." || name == ".." {
		return fmt.Errorf("anchor bundle path must name a file")
	}
	if err := validateBundleFinalAt(dirFD, name); err != nil {
		return err
	}
	var tempName string
	var err error
	tempFD := -1
	for attempts := 0; attempts < 16; attempts++ {
		tempName, err = stateMarkerTempName()
		if err != nil {
			return err
		}
		tempFD, err = unix.Openat(dirFD, tempName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, filePermissions)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("create anchor bundle temp file: %w", err)
		}
	}
	if tempFD < 0 {
		return fmt.Errorf("create anchor bundle temp file: %w", err)
	}
	file := os.NewFile(uintptr(tempFD), tempName)
	defer func() { _ = unix.Unlinkat(dirFD, tempName, 0) }()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write anchor bundle: %w", err)
	}
	if err := file.Chmod(filePermissions); err != nil {
		_ = file.Close()
		return fmt.Errorf("chmod anchor bundle: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close anchor bundle: %w", err)
	}
	if err := unix.Renameat(dirFD, tempName, dirFD, name); err != nil {
		return fmt.Errorf("rename anchor bundle: %w", err)
	}
	if err := unix.Fsync(dirFD); err != nil {
		return fmt.Errorf("sync anchor bundle directory: %w", err)
	}
	return nil
}

func validateBundleFinalAt(dirFD int, name string) error {
	var stat unix.Stat_t
	if err := unix.Fstatat(dirFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("inspect anchor bundle: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("write anchor bundle: not a regular file")
	}
	return nil
}
