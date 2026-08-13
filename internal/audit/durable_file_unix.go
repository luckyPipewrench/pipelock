// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package audit

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// DurableAuditFileSupported reports whether this target can bind the final
// lifecycle audit path to a no-follow file descriptor.
func DurableAuditFileSupported() bool { return true }

// openDurableAuditFile binds a lifecycle sink to a non-blocking, final-symlink
// refusing descriptor before callers inspect its type or identity.
func openDurableAuditFile(path string) (*os.File, bool, error) {
	cleanPath := filepath.Clean(path)
	flags := syscall.O_APPEND | syscall.O_WRONLY | syscall.O_CREAT | syscall.O_EXCL | syscall.O_CLOEXEC | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	fd, err := syscall.Open(cleanPath, flags, 0o600)
	created := err == nil
	if errors.Is(err, fs.ErrExist) {
		fd, err = syscall.Open(cleanPath, syscall.O_APPEND|syscall.O_WRONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	}
	if err != nil {
		return nil, false, fmt.Errorf("open durable audit log file %s: %w", cleanPath, err)
	}
	file := os.NewFile(uintptr(fd), cleanPath)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, false, errors.New("wrap durable audit log file descriptor")
	}
	return file, created, nil
}

// validateDurableAuditPath ensures that the opened sink and each containing
// directory cannot be modified by a lower-privileged Unix identity. A trusted
// sticky directory remains safe for a securely owned file, which permits
// ordinary single-user paths below /tmp.
func validateDurableAuditPath(fileInfo fs.FileInfo, path string) error {
	if err := validateDurableAuditOwnership(fileInfo, "audit log file", false); err != nil {
		return err
	}
	for dir := filepath.Dir(filepath.Clean(path)); ; dir = filepath.Dir(dir) {
		info, err := os.Stat(dir)
		if err != nil {
			return fmt.Errorf("stat audit log directory: %w", err)
		}
		if !info.IsDir() {
			return fmt.Errorf("audit log parent is not a directory: %s", dir)
		}
		if err := validateDurableAuditOwnership(info, "audit log directory", true); err != nil {
			return err
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
	}
}

func validateDurableAuditOwnership(info fs.FileInfo, kind string, directory bool) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("inspect %s ownership", kind)
	}
	if owner := int(stat.Uid); owner != 0 && owner != os.Geteuid() {
		return fmt.Errorf("%s must be owned by the service user or root", kind)
	}
	if info.Mode().Perm()&0o022 == 0 {
		return nil
	}
	if directory && info.Mode()&os.ModeSticky != 0 {
		return nil
	}
	return fmt.Errorf("%s must not be group or world writable", kind)
}
