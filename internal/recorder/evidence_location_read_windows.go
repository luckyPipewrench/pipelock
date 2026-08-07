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
	"unsafe"

	"golang.org/x/sys/windows"
)

func openEvidenceLocationDirectory(location EvidenceLocation) (*os.File, error) {
	if err := validateEvidenceLocation(location); err != nil {
		return nil, err
	}
	root := filepath.Clean(location.Root)
	pointer, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(pointer, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fmt.Errorf("open evidence root: %w", err)
	}
	current := os.NewFile(uintptr(handle), root)
	if current == nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("open evidence root: invalid handle")
	}
	if err := validateWindowsHandle(current, true); err != nil {
		_ = current.Close()
		return nil, fmt.Errorf("validate evidence root: %w", err)
	}
	for _, part := range strings.Split(filepath.FromSlash(location.ID), string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		next, openErr := openWindowsRelative(current, part, true, filepath.Join(root, filepath.FromSlash(location.ID)))
		_ = current.Close()
		if openErr != nil {
			return nil, fmt.Errorf("open evidence location component %q: %w", part, openErr)
		}
		current = next
	}
	return current, nil
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
	file, err := openWindowsRelative(directory, name, false, filepath.Join(location.Dir, name))
	if err != nil {
		return nil, nil, fmt.Errorf("open evidence file %q: %w", name, err)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, nil, errors.New("opened evidence file is non-regular")
	}
	return file, info, nil
}

type windowsFileAttributeTagInfo struct {
	FileAttributes uint32
	ReparseTag     uint32
}

func validateWindowsHandle(file *os.File, wantDirectory bool) error {
	var tagInfo windowsFileAttributeTagInfo
	if err := windows.GetFileInformationByHandleEx(
		windows.Handle(file.Fd()),
		windows.FileAttributeTagInfo,
		(*byte)(unsafe.Pointer(&tagInfo)),
		uint32(unsafe.Sizeof(tagInfo)),
	); err != nil {
		return err
	}
	if tagInfo.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("opened evidence path is a reparse point")
	}
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if wantDirectory && !info.IsDir() {
		return errors.New("opened evidence path is not a directory")
	}
	if !wantDirectory && !info.Mode().IsRegular() {
		return errors.New("opened evidence path is not a regular file")
	}
	return nil
}

func openWindowsRelative(parent *os.File, name string, directory bool, displayPath string) (*os.File, error) {
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return nil, err
	}
	attributes := windows.OBJECT_ATTRIBUTES{
		RootDirectory: windows.Handle(parent.Fd()),
		ObjectName:    objectName,
		Attributes:    windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
	}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	options := uint32(windows.FILE_OPEN_REPARSE_POINT | windows.FILE_SYNCHRONOUS_IO_NONALERT)
	if directory {
		options |= windows.FILE_DIRECTORY_FILE
	} else {
		options |= windows.FILE_NON_DIRECTORY_FILE
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(
		&handle,
		windows.FILE_GENERIC_READ,
		&attributes,
		&status,
		nil,
		0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_OPEN,
		options,
		0,
		0,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), displayPath)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("open evidence path: invalid handle")
	}
	if err := validateWindowsHandle(file, directory); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}
