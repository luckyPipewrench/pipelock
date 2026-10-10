// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package recorder

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func historyFileIdentity(location EvidenceLocation, name string, info os.FileInfo) (string, error) {
	file, opened, err := openEvidenceLocationFile(location, name)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	if !os.SameFile(info, opened) || info.Size() != opened.Size() || !info.ModTime().Equal(opened.ModTime()) {
		return "", fmt.Errorf("%w: shard changed while listing", ErrEvidenceChanged)
	}
	return historyHandleIdentity(file, opened)
}

type historyWindowsBasicInfo struct {
	CreationTime   int64
	LastAccessTime int64
	LastWriteTime  int64
	ChangeTime     int64
	FileAttributes uint32
}

func historyHandleIdentity(file *os.File, _ os.FileInfo) (string, error) {
	var id windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &id); err != nil {
		return "", err
	}
	var basic historyWindowsBasicInfo
	if err := windows.GetFileInformationByHandleEx(windows.Handle(file.Fd()), windows.FileBasicInfo, (*byte)(unsafe.Pointer(&basic)), uint32(unsafe.Sizeof(basic))); err != nil {
		return "", err
	}
	return fmt.Sprintf("%d:%d:%d:%d", id.VolumeSerialNumber, id.FileIndexHigh, id.FileIndexLow, basic.ChangeTime), nil
}

// EvidenceMetadataIdentity returns an opaque handle identity and change-time
// stamp. It is a consistency check, not an atomic filesystem snapshot.
func EvidenceMetadataIdentity(path string, info os.FileInfo) (string, error) {
	var file *os.File
	var opened os.FileInfo
	var err error
	if info.IsDir() {
		file, err = OpenEvidenceDirectory(path)
		if err == nil {
			opened, err = file.Stat()
		}
	} else {
		file, opened, err = OpenEvidenceFile(path)
	}
	if file != nil {
		defer func() { _ = file.Close() }()
	}
	if err != nil {
		return "", err
	}
	if !os.SameFile(info, opened) || info.Size() != opened.Size() || !info.ModTime().Equal(opened.ModTime()) {
		return "", fmt.Errorf("%w: inventory entry changed while opening", ErrEvidenceChanged)
	}
	return historyHandleIdentity(file, opened)
}
