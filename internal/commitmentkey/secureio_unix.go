// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package commitmentkey

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const secureFileMode = 0o600

func ensureParent(path string) error {
	fd, _, err := openSecureParent(path, true)
	if err != nil {
		return fmt.Errorf("create commitment keyring directory: %w", err)
	}
	return unix.Close(fd)
}

func readSecure(path string) ([]byte, error) {
	return readSecureLimited(path, maxBytes, "commitment keyring", ErrInvalidKeyring)
}

func readSecureLimited(path string, limit int64, label string, invalidErr error) ([]byte, error) {
	parentFD, base, err := openSecureParent(path, false)
	if err != nil {
		return nil, fmt.Errorf("open %s directory: %w", label, err)
	}
	defer func() { _ = unix.Close(parentFD) }()
	fd, err := unix.Openat(parentFD, base, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, mapOpenError(label, path, err)
	}
	f := os.NewFile(uintptr(fd), filepath.Clean(path))
	defer func() { _ = f.Close() }()
	stat, err := validateOpenedFile(fd, label, invalidErr)
	if err != nil {
		return nil, err
	}
	if stat.Size > limit {
		return nil, invalidReadError(invalidErr, label, "file exceeds %d bytes", limit)
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}
	if int64(len(raw)) > limit {
		return nil, invalidReadError(invalidErr, label, "file exceeds %d bytes", limit)
	}
	return raw, nil
}

func writeSecureNew(path string, data []byte) error {
	parentFD, base, err := openSecureParent(path, true)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parentFD) }()
	return writeSecureAt(parentFD, base, data, false)
}

func writeSecureReplace(path string, data []byte) error {
	parentFD, base, err := openSecureParent(path, false)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parentFD) }()
	fd, err := unix.Openat(parentFD, base, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return mapOpenError("commitment keyring", path, err)
	}
	if _, err := validateOpenedFile(fd, "commitment keyring", ErrInvalidKeyring); err != nil {
		_ = unix.Close(fd)
		return err
	}
	_ = unix.Close(fd)
	return writeSecureAt(parentFD, base, data, true)
}

func openSecureLock(path string) (*os.File, error) {
	parentFD, base, err := openSecureParent(path, false)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(parentFD) }()
	fd, err := unix.Openat(parentFD, base, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, secureFileMode)
	created := err == nil
	if errors.Is(err, unix.EEXIST) {
		fd, err = unix.Openat(parentFD, base, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	}
	if err != nil {
		return nil, mapOpenError("commitment keyring lock", path, err)
	}
	if created {
		if err := chmodSecure(fd, "commitment keyring lock"); err != nil {
			_ = unix.Close(fd)
			return nil, err
		}
	}
	if _, err := validateOpenedFile(fd, "commitment keyring lock", nil); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), filepath.Clean(path)), nil
}

func writeSecureAt(parentFD int, base string, data []byte, replace bool) error {
	tempName, tempFD, err := createSecureTemp(parentFD)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Unlinkat(parentFD, tempName, 0) }()
	temp := os.NewFile(uintptr(tempFD), tempName)
	if err := writeAndSync(temp, data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close commitment keyring temporary file: %w", err)
	}
	if replace {
		err = unix.Renameat(parentFD, tempName, parentFD, base)
	} else {
		err = unix.Linkat(parentFD, tempName, parentFD, base, 0)
		if errors.Is(err, unix.EEXIST) {
			return ErrAlreadyExists
		}
	}
	if err != nil {
		return fmt.Errorf("install commitment keyring: %w", err)
	}
	return syncDescriptor(parentFD, "commitment keyring directory")
}

func createSecureTemp(parentFD int) (string, int, error) {
	for range 16 {
		name := ".commitment-keyring-" + rand.Text() + ".tmp"
		fd, err := unix.Openat(parentFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, secureFileMode)
		if err == nil {
			if chmodErr := chmodSecure(fd, "commitment keyring temporary file"); chmodErr != nil {
				_ = unix.Close(fd)
				_ = unix.Unlinkat(parentFD, name, 0)
				return "", -1, chmodErr
			}
			return name, fd, nil
		}
		if !errors.Is(err, unix.EEXIST) {
			return "", -1, fmt.Errorf("create commitment keyring temporary file: %w", err)
		}
	}
	return "", -1, errors.New("create commitment keyring temporary file: name collisions exhausted")
}

func chmodSecure(fd int, label string) error {
	if err := unix.Fchmod(fd, secureFileMode); err != nil {
		return fmt.Errorf("secure %s: %w", label, err)
	}
	return nil
}

func writeAndSync(file *os.File, data []byte) error {
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write commitment keyring temporary file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync commitment keyring temporary file: %w", err)
	}
	return nil
}

func syncDescriptor(fd int, label string) error {
	if err := unix.Fsync(fd); err != nil {
		return fmt.Errorf("sync %s: %w", label, err)
	}
	return nil
}

func openSecureParent(path string, create bool) (int, string, error) {
	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return -1, "", fmt.Errorf("resolve commitment keyring path: %w", err)
	}
	base := filepath.Base(abs)
	if base == "." || base == string(filepath.Separator) {
		return -1, "", errors.New("commitment keyring path has no file component")
	}
	fd, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, "", fmt.Errorf("open filesystem root: %w", err)
	}
	if err := validateOpenedDirectory(fd, string(filepath.Separator)); err != nil {
		_ = unix.Close(fd)
		return -1, "", err
	}
	current := string(filepath.Separator)
	parts := strings.Split(strings.TrimPrefix(filepath.Dir(abs), string(filepath.Separator)), string(filepath.Separator))
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		nextFD, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if errors.Is(openErr, unix.ENOENT) && create {
			if mkdirErr := unix.Mkdirat(fd, part, 0o750); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				_ = unix.Close(fd)
				return -1, "", fmt.Errorf("create parent directory %q: %w", part, mkdirErr)
			}
			nextFD, openErr = unix.Openat(fd, part, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		}
		if openErr != nil {
			var entryStat unix.Stat_t
			entryErr := unix.Fstatat(fd, part, &entryStat, unix.AT_SYMLINK_NOFOLLOW)
			_ = unix.Close(fd)
			if errors.Is(openErr, unix.ELOOP) || (entryErr == nil && entryStat.Mode&unix.S_IFMT == unix.S_IFLNK) {
				return -1, "", fmt.Errorf("%w: parent directory %s", ErrSymlink, filepath.Join(current, part))
			}
			return -1, "", fmt.Errorf("open parent directory %s: %w", filepath.Join(current, part), openErr)
		}
		_ = unix.Close(fd)
		fd = nextFD
		current = filepath.Join(current, part)
		if err := validateOpenedDirectory(fd, current); err != nil {
			_ = unix.Close(fd)
			return -1, "", err
		}
	}
	return fd, base, nil
}

func validateOpenedDirectory(fd int, path string) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("stat parent directory %s: %w", path, err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("parent path is not a directory: %s", path)
	}
	effectiveUID := int64(os.Geteuid())
	if stat.Uid != 0 && int64(stat.Uid) != effectiveUID {
		return fmt.Errorf("%w: parent directory %s owner uid %d is neither root nor effective uid %d", ErrUnsafePermission, path, stat.Uid, os.Geteuid())
	}
	// A group- or world-writable parent normally lets another user rename or
	// replace the keyring between validation and use, which is the substitution
	// attack this check exists to stop. The sticky bit removes that ability:
	// with S_ISVTX set, only the entry's owner (or root) may rename or delete
	// it, so a shared directory such as /tmp mode 1777 cannot be used to swap
	// our directory or file for someone else's. Rejecting sticky directories
	// outright would refuse the standard temporary-directory layout on every
	// Unix system without closing any real attack, which is an availability
	// failure rather than hardening.
	if stat.Mode&0o022 != 0 && stat.Mode&unix.S_ISVTX == 0 {
		return fmt.Errorf("%w: parent directory %s mode %04o is group/world-writable without the sticky bit", ErrUnsafePermission, path, stat.Mode&0o7777)
	}
	return nil
}

func validateOpenedFile(fd int, label string, invalidErr error) (unix.Stat_t, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return unix.Stat_t{}, fmt.Errorf("stat %s: %w", label, err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return unix.Stat_t{}, invalidReadError(invalidErr, label, "not a regular file")
	}
	if int64(stat.Uid) != int64(os.Geteuid()) {
		return unix.Stat_t{}, fmt.Errorf("%w: %s owner uid %d, want effective uid %d", ErrUnsafePermission, label, stat.Uid, os.Geteuid())
	}
	if stat.Mode&0o777 != secureFileMode {
		return unix.Stat_t{}, fmt.Errorf("%w: %s mode %04o, want 0600", ErrUnsafePermission, label, stat.Mode&0o777)
	}
	return stat, nil
}

func mapOpenError(label, path string, err error) error {
	if isNoFollowSymlinkError(err, noFollowSymlinkErrors) {
		return fmt.Errorf("%w: %s", ErrSymlink, filepath.Clean(path))
	}
	if errors.Is(err, unix.EACCES) {
		return fmt.Errorf("%w: cannot open %s: %w", ErrUnsafePermission, label, err)
	}
	return fmt.Errorf("open %s: %w", label, err)
}

func isNoFollowSymlinkError(err error, symlinkErrors []error) bool {
	for _, symlinkErr := range symlinkErrors {
		if errors.Is(err, symlinkErr) {
			return true
		}
	}
	return false
}

type noFollowErrnos struct {
	loop, link, fileType error
}

// noFollowSymlinkErrorsFor returns every errno this platform may use to report
// that O_NOFOLLOW refused a final-component symlink.
//
// The set is derived from the errnos the platform file actually declares rather
// than from a platform NAME. A name-keyed switch silently degrades the control:
// renaming a label to something the switch does not recognize drops the platform
// to the ELOOP-only default, so EMLINK or EFTYPE stops being recognized as a
// symlink refusal and the guard quietly stops guarding. That regression compiles
// and cross-compiles cleanly on every target, because the label is a runtime
// string rather than a build constraint, and it is invisible to a test that
// passes its own label. Deriving from the declared errnos removes the class.
func noFollowSymlinkErrorsFor(errnos noFollowErrnos) []error {
	selected := make([]error, 0, 3)
	for _, candidate := range []error{errnos.loop, errnos.link, errnos.fileType} {
		if candidate != nil {
			selected = append(selected, candidate)
		}
	}
	return selected
}
