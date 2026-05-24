// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package hermes

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// DefaultPluginSubpath is the per-user Hermes plugins directory pipelock
	// installs into. Resolved against the operator's HOME unless callers
	// provide an explicit override.
	DefaultPluginSubpath = ".hermes/plugins/pipelock"

	// pluginFilePerm is the locked-down mode used for files written into the
	// Hermes plugin tree. Matches pipelock's repo-wide 0o600 floor.
	pluginFilePerm fs.FileMode = 0o600

	// pluginDirPerm is the mode used for directories created by the
	// installer. Matches pipelock's repo-wide 0o750 floor.
	pluginDirPerm fs.FileMode = 0o750
)

// PluginTarget describes where the plugin tree should be installed.
type PluginTarget struct {
	// Root is the directory the plugin tree is materialised into. It is
	// created if missing. Existing files at conflicting paths are rotated to
	// a sibling `.bak.<timestamp>` before being overwritten.
	Root string
}

// PluginInstallResult summarises the outcome of an Install call.
type PluginInstallResult struct {
	// Root is the absolute path the plugin tree was written into.
	Root string
	// FilesWritten counts the number of files materialised by this run,
	// excluding directories.
	FilesWritten int
	// BackupsCreated is the list of paths rotated to .bak before write.
	BackupsCreated []string
}

// ResolveDefaultPluginRoot returns the default install root computed from the
// supplied home directory. It does not touch the filesystem.
func ResolveDefaultPluginRoot(home string) string {
	return filepath.Join(home, DefaultPluginSubpath)
}

// Install materialises the embedded plugin tree into target.Root. It is
// idempotent across reruns: existing files at the same paths are rotated to
// `<name>.bak.<unix-nanos>` before being overwritten, mirroring the
// `pipelock contain install` rotation pattern.
//
// The installer never deletes files it did not write. Operators with hand-
// edited plugins keep their changes under the `.bak.*` siblings.
func Install(target PluginTarget) (PluginInstallResult, error) {
	if target.Root == "" {
		return PluginInstallResult{}, errors.New("hermes: install target root is empty")
	}

	rootAbs, err := filepath.Abs(target.Root)
	if err != nil {
		return PluginInstallResult{}, fmt.Errorf("hermes: resolve install root: %w", err)
	}

	if err := os.MkdirAll(rootAbs, pluginDirPerm); err != nil {
		return PluginInstallResult{}, fmt.Errorf("hermes: create install root: %w", err)
	}

	// Resolve the install root through any symlinks once, after creating it,
	// so the per-file containment check below compares against the real
	// directory. Every dest must stay within this resolved root; a relPath
	// that escaped it (now or after a future embedded-tree change) is
	// refused rather than written outside the plugin tree.
	rootReal, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return PluginInstallResult{}, fmt.Errorf("hermes: resolve install root symlinks: %w", err)
	}

	result := PluginInstallResult{Root: rootReal}
	walkErr := fs.WalkDir(pluginFS, pluginRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relPath := strings.TrimPrefix(path, pluginRoot)
		relPath = strings.TrimPrefix(relPath, "/")
		if relPath == "" {
			return nil
		}
		dest := filepath.Join(rootReal, relPath)
		if err := ensureContained(rootReal, dest); err != nil {
			return err
		}

		if d.IsDir() {
			if err := os.MkdirAll(dest, pluginDirPerm); err != nil {
				return fmt.Errorf("hermes: create %s: %w", dest, err)
			}
			return nil
		}

		data, readErr := pluginFS.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("hermes: read embedded %s: %w", path, readErr)
		}

		backup, backupErr := rotateExisting(dest)
		if backupErr != nil {
			return backupErr
		}
		if backup != "" {
			result.BackupsCreated = append(result.BackupsCreated, backup)
		}

		if err := writeFileAtomic(dest, data); err != nil {
			return err
		}
		result.FilesWritten++
		return nil
	})
	if walkErr != nil {
		return result, walkErr
	}
	return result, nil
}

// ensureContained returns an error when dest is not within root. Mirrors the
// containment guard used by `pipelock contain install` (walkAndChown): resolve
// the relative path and reject any result that climbs out via "..". Protects
// the plugin tree from path traversal even if the embedded source were ever
// changed to include a "../" segment.
func ensureContained(root, dest string) error {
	rel, err := filepath.Rel(root, dest)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("hermes: refusing to write outside install root %s: %s", root, dest)
	}
	return nil
}

// rotateExisting renames dest to `<dest>.bak.<unix-nanos>` when dest exists
// and is a regular file. Returns the backup path (empty string when no
// rotation was needed). The timestamp uses UTC nanoseconds so reruns within
// the same wall-clock second still produce distinct backups.
func rotateExisting(dest string) (string, error) {
	info, err := os.Lstat(dest)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("hermes: stat %s: %w", dest, err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("hermes: %s is a directory; refusing to rotate", dest)
	}
	backup := fmt.Sprintf("%s.bak.%d", dest, time.Now().UTC().UnixNano())
	if err := os.Rename(dest, backup); err != nil {
		return "", fmt.Errorf("hermes: rotate %s: %w", dest, err)
	}
	return backup, nil
}

// writeFileAtomic writes data to dest via an `<dest>.<unix-nanos>.tmp`
// sibling + rename, so a crashed install never leaves a half-written plugin
// file in place. The output file is always created with pluginFilePerm; no
// caller has a legitimate reason to widen permissions beyond pipelock's
// 0o600 floor, so the mode is not parameterised.
func writeFileAtomic(dest string, data []byte) error {
	dir := filepath.Dir(dest)
	tmp := filepath.Clean(fmt.Sprintf("%s.%d.tmp", dest, time.Now().UTC().UnixNano()))

	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, pluginFilePerm)
	if err != nil {
		return fmt.Errorf("hermes: open %s: %w", tmp, err)
	}
	if _, werr := f.Write(data); werr != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("hermes: write %s: %w", tmp, werr)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("hermes: sync %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("hermes: close %s: %w", tmp, err)
	}
	if err := os.Chmod(tmp, pluginFilePerm); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("hermes: chmod %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("hermes: rename %s -> %s: %w", tmp, dest, err)
	}
	// Ensure the directory entry is durable so the freshly installed plugin
	// survives a power loss between install and Hermes boot.
	dh, derr := os.Open(filepath.Clean(dir))
	if derr == nil {
		_ = dh.Sync()
		_ = dh.Close()
	}
	return nil
}
