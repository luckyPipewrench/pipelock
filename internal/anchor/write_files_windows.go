//go:build windows

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func writeBundleFile(path string, data []byte) error {
	clean := filepath.Clean(path)
	parent := filepath.Dir(clean)
	if err := ensureWindowsDirNoReparse(parent, "anchor bundle directory"); err != nil {
		return fmt.Errorf("create anchor bundle directory: %w", err)
	}
	if err := validateWindowsFinalFile(clean, "anchor bundle"); err != nil {
		return err
	}
	if err := os.WriteFile(clean, data, filePermissions); err != nil {
		return fmt.Errorf("write anchor bundle: %w", err)
	}
	return nil
}

func writeBundleFileUnderDir(root, rel string, data []byte) error {
	cleanRoot := filepath.Clean(root)
	cleanRel := filepath.Clean(rel)
	if filepath.IsAbs(cleanRel) || cleanRel == "." || cleanRel == ".." || strings.HasPrefix(cleanRel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("anchor bundle path must stay under receipt directory")
	}
	parentRel := filepath.Dir(cleanRel)
	if parentRel == "." {
		parentRel = ""
	}
	parent := filepath.Join(cleanRoot, parentRel)
	if err := ensureWindowsDirNoReparse(parent, "anchor bundle directory"); err != nil {
		return fmt.Errorf("create anchor bundle directory: %w", err)
	}
	path := filepath.Join(cleanRoot, cleanRel)
	if err := validateWindowsFinalFile(path, "anchor bundle"); err != nil {
		return err
	}
	return writeBundleFile(path, data)
}

func writeStateMarkerFile(cleanDir string, marker StateMarker, data []byte) error {
	indexDir := filepath.Join(cleanDir, stateMarkerIndexDir)
	path, err := StateMarkerPath(cleanDir, marker)
	if err != nil {
		return err
	}
	if err := ensureWindowsDirNoReparse(indexDir, "anchor-state directory"); err != nil {
		return fmt.Errorf("create anchor-state directory: %w", err)
	}
	if err := validateStateMarkerIndexDir(indexDir); err != nil {
		return err
	}
	return writeStateMarkerFileAtomic(indexDir, path, data, false)
}

func writeLatestStateMarkerFile(cleanDir string, data []byte) error {
	if err := ensureWindowsDirNoReparse(cleanDir, "anchor-state directory"); err != nil {
		return fmt.Errorf("open anchor-state directory: %w", err)
	}
	path := filepath.Join(cleanDir, legacyStateMarker)
	if err := validateWindowsFinalFile(path, "anchor-state latest marker"); err != nil {
		return err
	}
	return writeStateMarkerFileAtomic(cleanDir, path, data, true)
}

func writeStateMarkerFileAtomic(dir, path string, data []byte, replace bool) error {
	tmp, err := os.CreateTemp(dir, ".anchor-state-*.tmp")
	if err != nil {
		return fmt.Errorf("create anchor-state temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write anchor-state temp file: %w", err)
	}
	if err := tmp.Chmod(filePermissions); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod anchor-state temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync anchor-state temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close anchor-state temp file: %w", err)
	}
	if err := ensureWindowsDirNoReparse(dir, "anchor-state directory"); err != nil {
		return err
	}
	if replace {
		if err := windows.Rename(tmpPath, path); err != nil {
			return fmt.Errorf("rename anchor-state marker: %w", err)
		}
	} else {
		from, err := windows.UTF16PtrFromString(tmpPath)
		if err != nil {
			return fmt.Errorf("encode anchor-state temp path: %w", err)
		}
		to, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return fmt.Errorf("encode anchor-state marker path: %w", err)
		}
		if err := windows.MoveFile(from, to); errors.Is(err, windows.ERROR_ALREADY_EXISTS) || errors.Is(err, windows.ERROR_FILE_EXISTS) {
			return errStateMarkerExists
		} else if err != nil {
			return fmt.Errorf("create immutable anchor-state marker: %w", err)
		}
	}
	return nil
}

func lockStateMarkerDir(cleanDir string) (func(), error) {
	if err := ensureWindowsDirNoReparse(cleanDir, "anchor-state directory"); err != nil {
		return nil, fmt.Errorf("open anchor-state directory: %w", err)
	}
	path := filepath.Join(cleanDir, stateMarkerLockFile)
	if err := validateWindowsFinalFile(path, "anchor-state lock"); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, filePermissions)
	if err != nil {
		return nil, fmt.Errorf("open anchor-state lock: %w", err)
	}
	var overlapped windows.Overlapped
	handle := windows.Handle(file.Fd())
	if err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &overlapped); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock anchor-state writer: %w", err)
	}
	return func() {
		_ = windows.UnlockFileEx(handle, 0, 1, 0, &overlapped)
		_ = file.Close()
	}, nil
}

func ensureWindowsDirNoReparse(path, label string) error {
	clean := filepath.Clean(path)
	parent := filepath.Dir(clean)
	if parent != clean {
		if err := ensureWindowsDirNoReparse(parent, label); err != nil {
			return err
		}
	}
	info, err := os.Lstat(clean)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(clean, dirPermissions); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		info, err = os.Lstat(clean)
	}
	if err != nil {
		return err
	}
	if isWindowsReparseOrSymlink(info) || !info.IsDir() {
		return fmt.Errorf("%s is not a regular directory", label)
	}
	return nil
}

func validateWindowsFinalFile(path, label string) error {
	info, err := os.Lstat(filepath.Clean(path))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect %s: %w", label, err)
	}
	if isWindowsReparseOrSymlink(info) || !info.Mode().IsRegular() {
		return fmt.Errorf("write %s: not a regular file", label)
	}
	return nil
}

func isWindowsReparseOrSymlink(info os.FileInfo) bool {
	mode := info.Mode()
	return mode&os.ModeSymlink != 0 || mode&os.ModeIrregular != 0
}

type stateMarkerIndexReader struct {
	dir string
}

func openStateMarkerIndex(cleanDir string) (*stateMarkerIndexReader, error) {
	indexDir := filepath.Join(cleanDir, stateMarkerIndexDir)
	info, err := os.Lstat(indexDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, err
	}
	if isWindowsReparseOrSymlink(info) || !info.IsDir() {
		return nil, errors.New("anchor-state directory is not a regular directory")
	}
	return &stateMarkerIndexReader{dir: indexDir}, nil
}

func (r *stateMarkerIndexReader) Close() error {
	return nil
}

func (r *stateMarkerIndexReader) ReadDir() ([]os.DirEntry, error) {
	return os.ReadDir(r.dir)
}

func (r *stateMarkerIndexReader) LoadStateMarker(name string) (StateMarker, bool, error) {
	if strings.ContainsRune(name, filepath.Separator) || name == "." || name == ".." {
		return StateMarker{}, false, fmt.Errorf("anchor-state marker name %q is invalid", name)
	}
	if err := ensureWindowsDirNoReparse(r.dir, "anchor-state directory"); err != nil {
		return StateMarker{}, false, err
	}
	return LoadStateMarkerFile(filepath.Join(r.dir, name))
}
