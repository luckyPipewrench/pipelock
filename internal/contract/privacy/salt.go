// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package privacy

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Sentinel errors for salt resolution. All are errors.Is-comparable.
var (
	// ErrSaltUnset indicates the salt source resolves to an empty value.
	// Returned for empty source strings, env vars set to empty values, and
	// env vars that are not set at all. Callers must fail closed.
	ErrSaltUnset = errors.New("learn salt source resolves to empty value")

	// ErrSaltMode indicates a file: salt source has filesystem permissions
	// that allow group or world read (any bit in 0o077 set).
	ErrSaltMode = errors.New("learn salt file must have mode 0o600 or stricter")

	// ErrSaltNotAbsolute indicates a file: salt source whose path is not
	// absolute or not in canonical form (contains "..", redundant separators,
	// or trailing slash).
	ErrSaltNotAbsolute = errors.New("learn salt file path must be absolute")

	// ErrSaltMissing indicates a file: salt source pointing to a path that
	// does not exist on disk at resolution time.
	ErrSaltMissing = errors.New("learn salt file not found")
)

const (
	envPrefix  = "${"
	envSuffix  = "}"
	filePrefix = "file:"
)

// LoadSalt resolves the configured salt source into the actual salt bytes.
// Resolution rules:
//
//   - "${VAR}"       -> os.Getenv("VAR"); empty/unset value -> ErrSaltUnset
//   - "file:/abs/p"  -> os.ReadFile, trims one trailing newline; mode > 0o600
//     returns ErrSaltMode; non-canonical or relative path returns
//     ErrSaltNotAbsolute; missing file returns ErrSaltMissing
//   - ""             -> ErrSaltUnset
//   - other          -> the literal value
//
// LoadSalt is called once at startup (or on hot reload). The returned salt
// is passed to NewEnforcer; the salt itself never leaves the process.
//
// The file: validation mirrors validateLearnSaltSource in internal/config.
// Both checkpoints must agree; the runtime resolver is a defense-in-depth
// re-check in case the file was rotated, chmod'd, or removed between
// config-load and observe-time.
func LoadSalt(source string) ([]byte, error) {
	if source == "" {
		return nil, ErrSaltUnset
	}
	if strings.HasPrefix(source, envPrefix) && strings.HasSuffix(source, envSuffix) {
		name := strings.TrimSuffix(strings.TrimPrefix(source, envPrefix), envSuffix)
		val := os.Getenv(name)
		if val == "" {
			return nil, fmt.Errorf("%w: env var %q", ErrSaltUnset, name)
		}
		return []byte(val), nil
	}
	if strings.HasPrefix(source, filePrefix) {
		return loadSaltFile(strings.TrimPrefix(source, filePrefix))
	}
	return []byte(source), nil
}

// loadSaltFile resolves a file: salt source. Path validation mirrors
// validateLearnSaltSource in internal/config (absolute, canonical, regular
// file, mode 0o600 or stricter) and then opens with O_NOFOLLOW + checks the
// mode on the opened fd to close the stat-then-read TOCTOU window.
//
// Why two checks: Lstat rejects symlinks at the directory entry level
// (defense in depth against an attacker who points the configured path at a
// shadow file before the resolver runs); O_NOFOLLOW + fd-stat handles the
// race where the symlink is swapped in between Lstat and Open. After the
// fd is open it pins the inode, so the mode check is no longer racy.
func loadSaltFile(rawPath string) ([]byte, error) {
	if !filepath.IsAbs(rawPath) {
		return nil, fmt.Errorf("%w: %q", ErrSaltNotAbsolute, rawPath)
	}
	if filepath.Clean(rawPath) != rawPath {
		return nil, fmt.Errorf("%w: path is not in canonical form: %q", ErrSaltNotAbsolute, rawPath)
	}
	cleanPath := filepath.Clean(rawPath)

	li, err := os.Lstat(cleanPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %q", ErrSaltMissing, cleanPath)
		}
		return nil, fmt.Errorf("learn salt file lstat %q: %w", cleanPath, err)
	}
	if li.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: symlinks not permitted: %q", ErrSaltMode, cleanPath)
	}
	if !li.Mode().IsRegular() {
		return nil, fmt.Errorf("learn salt file %q is not a regular file", cleanPath)
	}

	f, err := os.OpenFile(cleanPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %q", ErrSaltMissing, cleanPath)
		}
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%w: symlink raced into place: %q", ErrSaltMode, cleanPath)
		}
		return nil, fmt.Errorf("learn salt file open %q: %w", cleanPath, err)
	}
	defer func() { _ = f.Close() }()

	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("learn salt file fstat %q: %w", cleanPath, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("learn salt file %q is not a regular file", cleanPath)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: got mode 0o%03o for %q", ErrSaltMode, fi.Mode().Perm(), cleanPath)
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("learn salt file read %q: %w", cleanPath, err)
	}
	// Trim one trailing newline so operators using `echo "salt" > /path` get
	// the salt they expect, not "salt\n". Only ONE newline; multi-line files
	// keep their internal structure intact.
	if n := len(data); n > 0 && data[n-1] == '\n' {
		data = data[:n-1]
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: file %q", ErrSaltUnset, cleanPath)
	}
	return data, nil
}
