// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package recorder

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func openEvidenceLocationDirectory(location EvidenceLocation) (*os.File, error) {
	if err := validateEvidenceLocation(location); err != nil {
		return nil, err
	}
	current := filepath.Clean(location.Root)
	parts := []string{""}
	if location.ID != "" {
		parts = strings.Split(filepath.FromSlash(location.ID), string(filepath.Separator))
	}
	for i, part := range parts {
		if part != "" {
			current = filepath.Join(current, part)
		}
		info, err := os.Lstat(current)
		if err != nil {
			return nil, fmt.Errorf("inspect evidence location component: %w", err)
		}
		if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 || !info.IsDir() {
			return nil, fmt.Errorf("refuse reparse point or non-directory in evidence location: %q", current)
		}
		if i+1 < len(parts) {
			continue
		}
	}
	pointer, err := windows.UTF16PtrFromString(current)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(pointer, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fmt.Errorf("open evidence location: %w", err)
	}
	file := os.NewFile(uintptr(handle), current)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("open evidence location: invalid handle")
	}
	info, err := file.Stat()
	if err != nil || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 || !info.IsDir() {
		_ = file.Close()
		return nil, errors.New("opened evidence location is a reparse point or non-directory")
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
	_ = directory.Close()
	path := filepath.Join(location.Dir, name)
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, nil, err
	}
	handle, err := windows.CreateFile(pointer, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open evidence file %q: %w", name, err)
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, nil, errors.New("open evidence file: invalid handle")
	}
	info, err := file.Stat()
	if err != nil || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, nil, errors.New("opened evidence file is a reparse point or non-regular")
	}
	return file, info, nil
}
