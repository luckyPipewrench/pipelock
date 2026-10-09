// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package recorder

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func historyFileIdentity(location EvidenceLocation, name string, info os.FileInfo) (string, error) {
	file, opened, err := openEvidenceLocationFile(location, name)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	if !os.SameFile(info, opened) {
		return "", errors.New("evidence shard changed while listing")
	}
	var id windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &id); err != nil {
		return "", err
	}
	return fmt.Sprintf("%d:%d:%d", id.VolumeSerialNumber, id.FileIndexHigh, id.FileIndexLow), nil
}
