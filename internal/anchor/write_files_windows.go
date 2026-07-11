//go:build windows

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"fmt"
	"os"
	"path/filepath"
)

func writeBundleFile(path string, data []byte) error {
	clean := filepath.Clean(path)
	if err := os.MkdirAll(filepath.Dir(clean), dirPermissions); err != nil {
		return fmt.Errorf("create anchor bundle directory: %w", err)
	}
	if err := os.WriteFile(clean, data, filePermissions); err != nil {
		return fmt.Errorf("write anchor bundle: %w", err)
	}
	return nil
}

func writeBundleFileUnderDir(root, rel string, data []byte) error {
	return writeBundleFile(filepath.Join(filepath.Clean(root), filepath.Clean(rel)), data)
}

func writeStateMarkerFile(cleanDir string, marker StateMarker, data []byte) error {
	indexDir := filepath.Join(cleanDir, stateMarkerIndexDir)
	path, err := StateMarkerPath(cleanDir, marker)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(indexDir, dirPermissions); err != nil {
		return fmt.Errorf("create anchor-state directory: %w", err)
	}
	if err := validateStateMarkerIndexDir(indexDir); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(indexDir, ".anchor-state-*.tmp")
	if err != nil {
		return fmt.Errorf("create anchor-state temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write anchor-state temp file: %w", err)
	}
	if err := tmp.Chmod(filePermissions); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod anchor-state temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync anchor-state temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close anchor-state temp file: %w", err)
	}
	if err := validateStateMarkerIndexDir(indexDir); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename anchor-state marker: %w", err)
	}
	return nil
}
