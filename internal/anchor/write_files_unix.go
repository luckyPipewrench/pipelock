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
	return writeStateMarkerAt(indexFD, name, data, false)
}

func writeLatestStateMarkerFile(cleanDir string, data []byte) error {
	rootFD, err := openAnchorDir(cleanDir)
	if err != nil {
		return fmt.Errorf("open anchor-state directory: %w", err)
	}
	defer func() { _ = unix.Close(rootFD) }()
	var stat unix.Stat_t
	if err := unix.Fstatat(rootFD, legacyStateMarker, &stat, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		if stat.Mode&unix.S_IFMT != unix.S_IFREG {
			return errors.New("anchor-state latest marker is not a regular file")
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("inspect anchor-state latest marker: %w", err)
	}
	return writeStateMarkerAt(rootFD, legacyStateMarker, data, true)
}

func writeStateMarkerAt(dirFD int, name string, data []byte, replace bool) error {
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
			return fmt.Errorf("create anchor-state temp file: %w", err)
		}
	}
	if tempFD < 0 {
		return fmt.Errorf("create anchor-state temp file: %w", err)
	}
	tempFile := os.NewFile(uintptr(tempFD), tempName)
	defer func() { _ = unix.Unlinkat(dirFD, tempName, 0) }()
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
	if replace {
		if err := unix.Renameat(dirFD, tempName, dirFD, name); err != nil {
			return fmt.Errorf("rename anchor-state marker: %w", err)
		}
	} else if err := unix.Linkat(dirFD, tempName, dirFD, name, 0); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return errStateMarkerExists
		}
		return fmt.Errorf("create immutable anchor-state marker: %w", err)
	}
	if err := unix.Fsync(dirFD); err != nil {
		return fmt.Errorf("sync anchor-state directory: %w", err)
	}
	return nil
}

func lockStateMarkerDir(cleanDir string) (func(), error) {
	if err := os.MkdirAll(cleanDir, dirPermissions); err != nil {
		return nil, fmt.Errorf("create anchor-state directory: %w", err)
	}
	rootFD, err := openAnchorDir(cleanDir)
	if err != nil {
		return nil, fmt.Errorf("create anchor-state directory: %w", err)
	}
	lockFD, err := unix.Openat(rootFD, stateMarkerLockFile, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, filePermissions)
	_ = unix.Close(rootFD)
	if err != nil {
		return nil, fmt.Errorf("open anchor-state lock: %w", err)
	}
	if err := unix.Flock(lockFD, unix.LOCK_EX); err != nil {
		_ = unix.Close(lockFD)
		return nil, fmt.Errorf("lock anchor-state writer: %w", err)
	}
	return func() {
		_ = unix.Flock(lockFD, unix.LOCK_UN)
		_ = unix.Close(lockFD)
	}, nil
}

func openAnchorDir(path string) (int, error) {
	return unix.Open(filepath.Clean(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
}

type stateMarkerIndexReader struct {
	file *os.File
}

func openStateMarkerIndex(cleanDir string) (*stateMarkerIndexReader, error) {
	rootFD, err := unix.Open(filepath.Clean(cleanDir), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, os.ErrNotExist
		}
		return nil, err
	}
	defer func() { _ = unix.Close(rootFD) }()
	indexFD, err := unix.Openat(rootFD, stateMarkerIndexDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, os.ErrNotExist
		}
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
			return nil, errors.New("anchor-state directory is not a regular directory")
		}
		return nil, err
	}
	return &stateMarkerIndexReader{file: os.NewFile(uintptr(indexFD), stateMarkerIndexDir)}, nil
}

func (r *stateMarkerIndexReader) Close() error {
	if r == nil || r.file == nil {
		return nil
	}
	return r.file.Close()
}

func (r *stateMarkerIndexReader) ReadDir() ([]os.DirEntry, error) {
	return r.file.ReadDir(-1)
}

func (r *stateMarkerIndexReader) LoadStateMarker(name string) (StateMarker, bool, error) {
	if strings.ContainsRune(name, filepath.Separator) || name == "." || name == ".." {
		return StateMarker{}, false, fmt.Errorf("anchor-state marker name %q is invalid", name)
	}
	fd, err := unix.Openat(int(r.file.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return StateMarker{}, false, nil
		}
		return StateMarker{}, false, fmt.Errorf("read anchor-state marker %q: %w", name, err)
	}
	file := os.NewFile(uintptr(fd), name)
	defer func() { _ = file.Close() }()
	marker, err := loadOpenedStateMarkerFile(file)
	if err != nil {
		return StateMarker{}, false, err
	}
	return marker, true, nil
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
