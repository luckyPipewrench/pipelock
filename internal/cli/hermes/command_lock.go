// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package hermes

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"

	"golang.org/x/text/unicode/norm"
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
	paths := []string{configDir}
	for _, dir := range dirs {
		canonical, err := canonicalLockResource(dir)
		if err != nil {
			return nil, fmt.Errorf("hermes command lock: %s: %w", dir, err)
		}
		paths = append(paths, canonical)
	}
	return lockResourceKeys(runtime.GOOS, paths), nil
}

// lockResourceKeys reduces paths to their lock keys, deduplicated and sorted
// by key. Two spellings of one directory share a key on case- or
// Unicode-insensitive filesystems, so deduplicating by the raw path would make
// a command wait on a lock it already holds.
func lockResourceKeys(goos string, paths []string) []string {
	keys := make([]string, 0, len(paths))
	for _, path := range paths {
		if key := hermesLockKey(goos, path); !slices.Contains(keys, key) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
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

// hermesLockKey is the resource identity hashed into a lock file name. The
// default macOS and Windows filesystems ignore case, so two spellings of one
// directory must share a lock there. Lowercasing can only make two distinct
// directories share a lock, which waits longer but never lets them run together.
func hermesLockKey(goos, resource string) string {
	switch goos {
	case "darwin":
		// APFS also treats canonically equivalent Unicode spellings, such as a
		// precomposed and a decomposed accent, as one name.
		return norm.NFC.String(strings.ToLower(norm.NFC.String(resource)))
	case "windows":
		return strings.ToLower(resource)
	}
	return resource
}

func hermesLockPath(lockDir, resource string) string {
	digest := sha256.Sum256([]byte(hermesLockKey(runtime.GOOS, resource)))
	return filepath.Join(lockDir, fmt.Sprintf("%x.lock", digest))
}
