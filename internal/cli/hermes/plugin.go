// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package hermes

import (
	"bytes"
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
	// a sibling `.bak.<timestamp>` before being overwritten when their content
	// differs from the embedded plugin file.
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

// configSidecarName is the file the installer writes into the plugin dir to
// record the pipelock config path the hook should use. The bundled Python
// plugin reads it (see plugin_template/plugin.py CONFIG_SIDECAR) so config
// flows without depending on Hermes' runtime environment.
const configSidecarName = "pipelock.conf"

// ResolveDefaultPluginRoot returns the default install root computed from the
// supplied home directory. It does not touch the filesystem.
func ResolveDefaultPluginRoot(home string) string {
	return filepath.Join(home, DefaultPluginSubpath)
}

// writeConfigSidecar records configPath in <root>/pipelock.conf so the plugin
// passes it to `pipelock hermes hook --config`. A blank configPath removes any
// existing sidecar (the hook falls back to built-in defaults). root must be
// the already-resolved plugin directory.
func writeConfigSidecar(root, configPath string) error {
	dest := filepath.Join(root, configSidecarName)
	if configPath == "" {
		if err := os.Remove(dest); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("hermes: remove stale config sidecar: %w", err)
		}
		return nil
	}
	_, _, err := writeManagedFile(dest, []byte(configPath+"\n"))
	return err
}

// removePluginTree removes only pipelock-managed plugin files from root. Used
// by rollback. It intentionally does not os.RemoveAll(root): --plugin-root is
// operator-controlled, and deleting unknown files from an override path would
// be a surprising destructive action. If the directory becomes empty after the
// managed files are removed, it is removed too.
func removePluginTree(root string) error {
	clean := filepath.Clean(root)
	if clean == "" || clean == "/" || clean == "." {
		return fmt.Errorf("hermes: refusing to remove unsafe plugin root %q", root)
	}
	entries, err := os.ReadDir(clean)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("hermes: read plugin tree %s: %w", clean, err)
	}
	for _, entry := range entries {
		if !isManagedPluginPath(entry.Name()) {
			continue
		}
		path := filepath.Join(clean, entry.Name())
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("hermes: remove plugin file %s: %w", path, err)
		}
	}
	// Remove the plugin directory only if it is now empty. Ignore "not empty"
	// so operator-created files survive rollback.
	if err := os.Remove(clean); err != nil && !errors.Is(err, fs.ErrNotExist) {
		if entries, readErr := os.ReadDir(clean); readErr == nil && len(entries) > 0 {
			return nil
		}
		return fmt.Errorf("hermes: remove plugin dir %s: %w", clean, err)
	}
	return nil
}

func isManagedPluginPath(name string) bool {
	for _, base := range []string{"__init__.py", "plugin.py", "README.md", configSidecarName} {
		if name == base || strings.HasPrefix(name, base+".bak.") ||
			(strings.HasPrefix(name, base+".") && strings.HasSuffix(name, ".tmp")) {
			return true
		}
	}
	return false
}

// pluginInstalled reports whether the core plugin files are present under root.
func pluginInstalled(root string) bool {
	for _, name := range []string{"__init__.py", "plugin.py"} {
		if _, err := os.Stat(filepath.Join(root, name)); err != nil {
			return false
		}
	}
	return true
}

// Install materialises the embedded plugin tree into target.Root. It is
// idempotent across reruns: byte-identical files are left in place, while
// changed files at the same paths are rotated to `<name>.bak.<unix-nanos>`
// before being overwritten, mirroring the `pipelock contain install` rotation
// pattern without backup churn.
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

		backup, wrote, writeErr := writeManagedFile(dest, data)
		if writeErr != nil {
			return writeErr
		}
		if backup != "" {
			result.BackupsCreated = append(result.BackupsCreated, backup)
		}
		if wrote {
			result.FilesWritten++
		}
		return nil
	})
	if walkErr != nil {
		return result, walkErr
	}
	return result, nil
}

// writeManagedFile writes data to dest only when the existing file differs.
// Different existing files are rotated first; identical files are left in place
// so rerunning install does not create noisy .bak churn.
func writeManagedFile(dest string, data []byte) (backup string, wrote bool, err error) {
	same, err := regularFileContentEqual(dest, data)
	if err != nil {
		return "", false, err
	}
	if same {
		return "", false, nil
	}

	backup, err = rotateExisting(dest)
	if err != nil {
		return "", false, err
	}
	if err := writeFileAtomic(dest, data); err != nil {
		return "", false, err
	}
	return backup, true, nil
}

func regularFileContentEqual(dest string, data []byte) (bool, error) {
	info, err := os.Lstat(dest)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("hermes: stat %s: %w", dest, err)
	}
	if !info.Mode().IsRegular() {
		return false, nil
	}
	//nolint:gosec // install intentionally compares an operator-selected plugin file before rotating it.
	existing, err := os.ReadFile(dest)
	if err != nil {
		return false, fmt.Errorf("hermes: read %s: %w", dest, err)
	}
	return bytes.Equal(existing, data), nil
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
