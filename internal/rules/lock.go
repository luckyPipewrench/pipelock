// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// lockFilename is the expected name of the bundle lock file.
const lockFilename = "bundle.lock"

// LockFile represents the bundle.lock provenance file.
// It is managed by pipelock and should never be user-edited.
type LockFile struct {
	InstalledVersion  string `yaml:"installed_version"`
	InstalledAt       string `yaml:"installed_at"`
	Source            string `yaml:"source"`
	LastCheck         string `yaml:"last_check"`
	BundleSHA256      string `yaml:"bundle_sha256"`
	SignerFingerprint string `yaml:"signer_fingerprint"`
	Unsigned          bool   `yaml:"unsigned"`
}

// ReadLockFile reads and unmarshals a lock file from the given path.
func ReadLockFile(path string) (*LockFile, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read lock file: %w", err)
	}

	var lf LockFile
	if err := yaml.Unmarshal(data, &lf); err != nil {
		return nil, fmt.Errorf("parse lock file: %w", err)
	}

	return &lf, nil
}

// WriteLockFile marshals the lock file to YAML and writes it atomically.
// The file is written with 0o600 permissions.
func WriteLockFile(path string, lf *LockFile) error {
	path = filepath.Clean(path)
	data, err := yaml.Marshal(lf)
	if err != nil {
		return fmt.Errorf("marshal lock file: %w", err)
	}

	if err := atomicWriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write lock file: %w", err)
	}

	return nil
}

// atomicWriteFile writes data to a temporary file in the same directory as
// path, then renames it to the target. This ensures the target is never
// partially written.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	path = filepath.Clean(path)
	dir := filepath.Dir(path)

	tmp, err := os.CreateTemp(dir, ".lock-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()

	defer func() {
		// Clean up on failure.
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}

	if err := os.Chmod(tmpName, perm); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}

	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}

	tmpName = "" // Prevent cleanup on success.
	return nil
}
