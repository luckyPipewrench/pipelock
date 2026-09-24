// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package hermes

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"
)

var hermesLockTimeout = 30 * time.Second

// hermesUserCacheDir locates the per-account cache that holds the lock files.
// It ignores per-process overrides such as XDG_CACHE_HOME and LOCALAPPDATA, so
// every run by the same account finds the same locks.
var hermesUserCacheDir = hermesStableCacheDir

// hermesLockDirName is created directly under the cache root, so its
// permissions are the ones this code sets rather than whatever a shared
// pipelock cache directory inherited.
const hermesLockDirName = "pipelock-hermes"

func canonicalLockResource(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	// A missing config directory still has existing ancestors that may be symlinks.
	suffix := []string{}
	current := absolute
	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			return resolved, nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", err
		}
		suffix = append(suffix, filepath.Base(current))
		current = parent
	}
}

// hermesLockResources returns the canonical directories a command locks: the
// Hermes config directory plus every other directory the command writes,
// deduplicated and sorted so every command acquires them in the same order.
func hermesLockResources(configPath string, dirs []string) ([]string, error) {
	configDir, err := canonicalLockResource(filepath.Dir(configPath))
	if err != nil {
		return nil, fmt.Errorf("hermes command lock: config directory: %w", err)
	}
	resources := []string{configDir}
	for _, dir := range dirs {
		canonical, err := canonicalLockResource(dir)
		if err != nil {
			return nil, fmt.Errorf("hermes command lock: %s: %w", dir, err)
		}
		if !slices.Contains(resources, canonical) {
			resources = append(resources, canonical)
		}
	}
	sort.Strings(resources)
	return resources, nil
}

// withHermesCommandLock runs fn while holding the locks for the Hermes config
// directory and every directory in dirs.
func withHermesCommandLock(configPath string, dirs []string, fn func() error) error {
	resources, err := hermesLockResources(configPath, dirs)
	if err != nil {
		return err
	}
	cache, err := hermesUserCacheDir()
	if err != nil {
		return fmt.Errorf("hermes command lock: cache directory: %w", err)
	}
	lockDir := filepath.Join(cache, hermesLockDirName, "locks")
	if err := ensureHermesLockDir(lockDir); err != nil {
		return err
	}
	release := []func(){}
	defer func() {
		for i := len(release) - 1; i >= 0; i-- {
			release[i]()
		}
	}()
	deadline := time.Now().Add(hermesLockTimeout)
	for _, resource := range resources {
		lockPath := hermesLockPath(lockDir, resource)
		unlock, err := acquireHermesLock(lockPath, deadline)
		if err != nil {
			return err
		}
		release = append(release, unlock)
	}
	return fn()
}

func hermesLockBusy(path string) error {
	return fmt.Errorf("hermes command lock: timed out waiting for %s: another pipelock hermes install or rollback for the same Hermes user is running", path)
}

func hermesLockPath(lockDir, resource string) string {
	digest := sha256.Sum256([]byte(resource))
	return filepath.Join(lockDir, fmt.Sprintf("%x.lock", digest))
}
