// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
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

	if err := atomicWriteFile(path, data); err != nil {
		return fmt.Errorf("write lock file: %w", err)
	}

	return nil
}

// atomicWriteFile writes data to a temporary file in the same directory as
// path, then renames it to the target with 0o600 permissions. This ensures
// the target is never partially written.
func atomicWriteFile(path string, data []byte) error {
	return atomicfile.Write(filepath.Clean(path), data, 0o600)
}
