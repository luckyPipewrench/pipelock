//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func openRegularDashboardFile(path, label string) (*os.File, os.FileInfo, error) {
	cleanPath := filepath.Clean(path)
	before, err := os.Lstat(cleanPath)
	if err != nil {
		return nil, nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%s is symlinked or non-regular", label)
	}
	file, err := os.OpenFile(cleanPath, os.O_RDONLY|evidenceNoFollowFlag|evidenceNonblockFlag, 0)
	if err != nil {
		return nil, nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() || !os.SameFile(before, info) {
		_ = file.Close()
		return nil, nil, fmt.Errorf("%s changed or is non-regular", label)
	}
	return file, info, nil
}

func requireOwnerOnlyDashboardFile(file *os.File, info os.FileInfo, label string) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s must be a regular file", label)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s permissions must be 0600, got %#o", label, info.Mode().Perm())
	}
	if !dashboardFileOwnedByCurrentUser(file, info) {
		return errors.New(label + " must be owned by the current user")
	}
	return nil
}
