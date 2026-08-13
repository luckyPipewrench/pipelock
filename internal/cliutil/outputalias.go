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
	leftPath, err := resolvedPath(left)
	if err != nil {
		return false, err
	}
	rightPath, err := resolvedPath(right)
	if err != nil {
		return false, err
	}
	if leftPath == rightPath {
		return true, nil
	}
	// Identity can only match when both paths resolve to an existing file, so a
	// stat failure on either side means they are not the same file and is not an
	// error here. Reporting it would replace the caller's real failure, such as
	// an output path whose parent is not a directory, with a resolution error.
	leftInfo, leftErr := os.Stat(leftPath)
	if leftErr != nil {
		return false, nil
	}
	rightInfo, rightErr := os.Stat(rightPath)
	if rightErr != nil {
		return false, nil
	}
	return os.SameFile(leftInfo, rightInfo), nil
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
