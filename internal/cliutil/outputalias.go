// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cliutil

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
)

// RefuseOutputAliases rejects an output path that names a protected input.
//
// Commands that both read key material and write a result can be handed the
// same path for each. The writers involved replace their target: an atomic
// writer renames over it and a ledger writer appends to it, so either would
// overwrite the protected file with command output and still report success.
// The check runs before anything is written, so the protected file survives.
//
// protectedPaths maps a human label used in the error ("--key", "the roster
// root key") to the path it protects. outputs maps an output flag name to the
// path it will write. Empty paths on either side are ignored, so a caller can
// pass optional flags without pre-filtering them.
// ExistingFileLabels maps flag labels onto paths that currently exist as
// regular files. Use it for --key values that may be hex or a file path so
// a hex blob is not treated as a path to protect.
func ExistingFileLabels(flag string, paths []string) map[string]string {
	out := make(map[string]string, len(paths))
	for i, path := range paths {
		if path == "" {
			continue
		}
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		label := flag
		if len(paths) > 1 {
			label = fmt.Sprintf("%s[%d]", flag, i)
		}
		out[label] = path
	}
	return out
}

// ExistingRegularFiles labels every regular file in dir. A missing or
// unlistable directory yields an empty map so callers can pass optional roots.
func ExistingRegularFiles(label, dir string) map[string]string {
	if dir == "" {
		return map[string]string{}
	}
	entries, err := os.ReadDir(filepath.Clean(dir))
	if err != nil {
		return map[string]string{}
	}
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			paths = append(paths, filepath.Join(dir, entry.Name()))
		}
	}
	return ExistingFileLabels(label, paths)
}

// RefuseOutputCollisions rejects two output paths that name the same file.
// RefuseOutputAliases only compares outputs to protected inputs, so two
// outputs that collide with each other would both pass and then overwrite
// each other.
func RefuseOutputCollisions(outputs map[string]string) error {
	flags := slices.Sorted(maps.Keys(outputs))
	for i, left := range flags {
		for _, right := range flags[i+1:] {
			if err := RefuseOutputAliases(
				map[string]string{left: outputs[left]},
				map[string]string{right: outputs[right]},
			); err != nil {
				return err
			}
		}
	}
	return nil
}

func RefuseOutputAliases(protectedPaths map[string]string, outputs map[string]string) error {
	for _, outputFlag := range slices.Sorted(maps.Keys(outputs)) {
		outputPath := outputs[outputFlag]
		if outputPath == "" {
			continue
		}
		for _, protectedLabel := range slices.Sorted(maps.Keys(protectedPaths)) {
			protectedPath := protectedPaths[protectedLabel]
			if protectedPath == "" {
				continue
			}
			same, err := SamePathIdentity(protectedPath, outputPath)
			if err != nil {
				return fmt.Errorf("resolve %s against %s: %w", outputFlag, protectedLabel, err)
			}
			if same {
				return fmt.Errorf("%s must not name %s (%s): writing it would destroy that file",
					outputFlag, protectedLabel, filepath.Clean(protectedPath))
			}
		}
	}
	return nil
}

// SamePathIdentity reports whether two paths name the same file. It resolves
// symlinks on the parent directory so a not-yet-created output is still
// comparable, and compares inode identity when both paths exist, so a symlink
// or a hard link to the protected file is recognised.
func SamePathIdentity(left, right string) (bool, error) {
	// Ask the filesystem first, using the paths exactly as written. This is the
	// authoritative answer and it is immune to spelling: the kernel resolves
	// symlinks and ".." in the order they appear, so it catches an alias that no
	// amount of string comparison would.
	//
	// Lexical normalization must NOT decide identity, because filepath.Clean
	// collapses ".." BEFORE any symlink is resolved and the filesystem does not.
	// With "a/link" a symlink to "b/sub", the path "a/link/../license.key"
	// resolves to "b/license.key" on disk while Clean yields "a/license.key".
	// Deciding on the cleaned string therefore misses a real alias.
	leftInfo, leftErr := os.Stat(left)
	rightInfo, rightErr := os.Stat(right)
	if leftErr == nil && rightErr == nil {
		return os.SameFile(leftInfo, rightInfo), nil
	}

	// One side does not exist, so there is no identity to compare and the output
	// is usually a file about to be created. Fall back to comparing resolved
	// names, which is the only thing available for a path with no inode yet. A
	// stat failure is not reported as an error here: it would replace the
	// caller's real failure, such as an output path whose parent is not a
	// directory, with a confusing resolution error.
	leftPath, err := resolvedPath(left)
	if err != nil {
		return false, err
	}
	rightPath, err := resolvedPath(right)
	if err != nil {
		return false, err
	}
	return leftPath == rightPath, nil
}

func resolvedPath(path string) (string, error) {
	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return abs, nil
		}
		return "", err
	}
	return filepath.Join(parent, filepath.Base(abs)), nil
}

// RefuseOpenedFileAliases compares an already-opened output file against every
// protected input and refuses when they are the same file.
//
// Pathname validation happens before an open, which leaves a window in which a
// writable output directory lets the path be swapped for a link to a protected
// file. This checks what the open actually produced, so it closes that window.
// A pathname check alone cannot pin a mutable namespace.
//
// It fails CLOSED on a protected path it cannot stat. A caller reaching this
// point has already read that file, so a stat failure means the filesystem
// changed underneath the command, which is exactly when writing is unsafe.
func RefuseOpenedFileAliases(opened *os.File, protected map[string]string) error {
	if len(protected) == 0 {
		return nil
	}
	openedInfo, err := opened.Stat()
	if err != nil {
		return fmt.Errorf("stat opened output file: %w", err)
	}
	for _, label := range slices.Sorted(maps.Keys(protected)) {
		protectedPath := protected[label]
		if protectedPath == "" {
			continue
		}
		protectedInfo, statErr := os.Stat(protectedPath)
		if statErr != nil {
			return fmt.Errorf("verify the opened output file is not %s: %w", label, statErr)
		}
		if os.SameFile(openedInfo, protectedInfo) {
			return fmt.Errorf("the output file resolved to %s: refusing to write over it", label)
		}
	}
	return nil
}
