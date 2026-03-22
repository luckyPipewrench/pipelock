// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package sandbox implements unprivileged process containment using Linux
// kernel primitives: Landlock (filesystem), network namespaces (network
// isolation), and seccomp (syscall restriction). The sandbox is applied to
// child processes via a re-exec launcher pattern, ensuring pipelock itself
// remains unrestricted while the agent subprocess is fully contained.
package sandbox

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrUnavailable indicates that a sandbox layer is not supported on the
// current platform or kernel.
var ErrUnavailable = errors.New("sandbox layer unavailable")

// LayerName identifies a containment layer.
type LayerName string

const osLinux = "linux"

const (
	LayerLandlock LayerName = "filesystem"
	LayerNetNS    LayerName = "network"
	LayerSeccomp  LayerName = "syscall"
)

// LayerStatus reports whether a single containment layer is active.
type LayerStatus struct {
	Name    LayerName `json:"name"`
	Active  bool      `json:"active"`
	Reason  string    `json:"reason,omitempty"`  // why unavailable
	Version int       `json:"version,omitempty"` // e.g. Landlock ABI version
}

// Result captures the outcome of applying sandbox containment.
type Result struct {
	Layers []LayerStatus `json:"layers"`
}

// ActiveCount returns how many layers are active.
func (r Result) ActiveCount() int {
	n := 0
	for _, l := range r.Layers {
		if l.Active {
			n++
		}
	}
	return n
}

// TotalCount returns the total number of layers attempted.
func (r Result) TotalCount() int {
	return len(r.Layers)
}

// IsFullyContained returns true if all layers are active.
func (r Result) IsFullyContained() bool {
	return r.ActiveCount() == r.TotalCount()
}

// Policy defines the sandbox containment rules applied to a child process.
type Policy struct {
	// Workspace is the agent's working directory (resolved to absolute).
	// The child's CWD is set to this path. Must not be HOME, /, or other
	// dangerous broad paths.
	Workspace string `json:"workspace"`

	// Filesystem rules (Landlock).
	//
	// Landlock is an allowlist model: anything NOT in an allow rule is denied.
	// Execute access is bundled with read access (RODirs grants execute).
	// RWDirs grants full access including execute, so writable dirs like
	// workspace and /tmp are executable by default.
	//
	// DenyReadDirs is a validation-only field: we verify no AllowRead entry
	// overlaps with a denied path. The kernel enforcement comes from
	// exclusion (denied paths are simply not added to the Landlock ruleset).
	AllowReadDirs  []string `json:"allow_read_dirs,omitempty"`
	AllowReadFiles []string `json:"allow_read_files,omitempty"`
	AllowRWDirs    []string `json:"allow_rw_dirs,omitempty"`
	AllowRWFiles   []string `json:"allow_rw_files,omitempty"`
	DenyReadDirs   []string `json:"deny_read_dirs,omitempty"`
}

// dangerousRoots are paths that must never be used as the workspace root.
// These are checked after symlink resolution.
var dangerousRoots = []string{
	"/", "/tmp", "/home", "/etc", "/usr", "/var",
	// macOS: /tmp → /private/tmp, /var → /private/var, /etc → /private/etc.
	// /home → /System/Volumes/Data/home via synthetic firmlink.
	"/private/tmp", "/private/var", "/private/etc",
	"/System/Volumes/Data/home",
}

// ValidateWorkspace checks that the workspace path is safe for use as a
// sandbox root. It rejects dangerous broad paths, symlinks that escape
// allowed directories, and nonexistent paths.
func ValidateWorkspace(workspace string) error {
	if workspace == "" {
		return fmt.Errorf("sandbox workspace must not be empty")
	}

	// Resolve symlinks to catch escape attempts.
	resolved, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("sandbox workspace does not exist: %s", workspace)
		}
		return fmt.Errorf("resolving sandbox workspace: %w", err)
	}

	// Check against dangerous roots.
	home := os.Getenv("HOME")
	if home != "" {
		resolvedHome, herr := filepath.EvalSymlinks(home)
		if herr == nil {
			home = resolvedHome
		}
	}

	if home != "" && resolved == home {
		return fmt.Errorf("sandbox workspace must not be your home directory (%s)", home)
	}

	for _, root := range dangerousRoots {
		if resolved == root {
			return fmt.Errorf("sandbox workspace must not be %s", root)
		}
	}

	// Reject if workspace is an ancestor of sensitive directories.
	sensitiveChildren := []string{"/home", "/etc", "/usr", "/var", "/lib", "/lib64"}
	for _, child := range sensitiveChildren {
		if strings.HasPrefix(child, resolved+"/") {
			return fmt.Errorf("sandbox workspace %s is too broad (contains %s)", resolved, child)
		}
	}

	// Verify it's a directory.
	fi, err := os.Stat(resolved)
	if err != nil {
		return fmt.Errorf("stat sandbox workspace: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("sandbox workspace is not a directory: %s", resolved)
	}

	return nil
}

// DefaultPolicy returns a sandbox policy with sensible defaults for Python,
// Node.js, and Go agents. The workspace parameter must be an absolute path
// that passes ValidateWorkspace.
func DefaultPolicy(workspace string) Policy {
	return Policy{
		Workspace: workspace,
		AllowReadDirs: []string{
			"/usr/",
			"/lib/",
			"/lib64/",
			"/bin/",  // real dir on non-Fedora distros (symlink on Fedora → /usr/bin)
			"/sbin/", // real dir on non-Fedora distros (symlink on Fedora → /usr/sbin)
			"/etc/ssl/",
			"/etc/pki/",
			"/proc/self/",
		},
		AllowReadFiles: []string{
			"/etc/resolv.conf",
			"/etc/hosts",
			"/etc/nsswitch.conf",
			"/etc/ld.so.cache",
			"/etc/ld.so.conf",
			"/etc/passwd",
			"/etc/group",
			"/usr/bin/env",
		},
		AllowRWDirs: []string{
			workspace,
			// NOTE: /tmp/ is NOT included. The child dynamically adds its
			// per-sandbox temp dir (e.g., /tmp/pipelock-sandbox-<pid>/) before
			// applying Landlock. This prevents cross-sandbox data leakage and
			// access to other users' temp files.
			//
			// /dev/shm/ is allowed for Python multiprocessing and Chromium.
			// This is a known limitation — sandboxed processes can access
			// same-user shared memory segments. Future: private tmpfs mount.
			"/dev/shm/",
		},
		AllowRWFiles: []string{
			"/dev/null",
			"/dev/zero",
			"/dev/urandom",
		},
		// Note: execute access follows from RODirs (grants execute on /usr/*)
		// and RWDirs (grants execute on workspace, /tmp/). No separate exec
		// field needed — Landlock bundles execute with read.
		DenyReadDirs: secretDirs(),
	}
}

// secretDirs returns paths that should never be readable inside the sandbox.
func secretDirs() []string {
	home := os.Getenv("HOME")
	if home == "" {
		return nil
	}
	return []string{
		filepath.Join(home, ".ssh"),
		filepath.Join(home, ".aws"),
		filepath.Join(home, ".config", "pipelock"),
		filepath.Join(home, ".gnupg"),
		filepath.Join(home, ".kube"),
		filepath.Join(home, ".docker"),
	}
}

// ValidatePolicy checks that a sandbox policy does not accidentally
// re-authorize access to secret directories. Returns an error if any
// AllowReadDirs or AllowRWDirs entry would grant access to a secret path.
//
// All allow paths are resolved through EvalSymlinks before comparison,
// because Landlock resolves symlinks when rules are added. Without this,
// a symlink like /tmp/link → $HOME would pass string-prefix validation
// but grant access to the real home directory.
func ValidatePolicy(p Policy) error {
	secrets := secretDirs()
	if len(secrets) == 0 {
		return nil
	}

	// Resolve secret paths too — symlinks in HOME could affect comparison.
	resolvedSecrets := make([]string, 0, len(secrets))
	for _, s := range secrets {
		resolved, err := filepath.EvalSymlinks(s)
		if err != nil {
			resolved = filepath.Clean(s)
		}
		resolvedSecrets = append(resolvedSecrets, resolved)
	}

	checkDirs := func(paths []string, label string) error {
		for _, allowed := range paths {
			resolved, err := filepath.EvalSymlinks(allowed)
			if err != nil {
				resolved = filepath.Clean(allowed)
			}
			for _, denied := range resolvedSecrets {
				if pathCovers(resolved, denied) {
					return fmt.Errorf("sandbox %s %q (resolves to %q) covers protected directory %q — remove it or use a narrower path", label, allowed, resolved, denied)
				}
			}
		}
		return nil
	}

	// Check file allowlists: reject if a file is inside a protected dir.
	checkFiles := func(paths []string, label string) error {
		for _, allowed := range paths {
			resolved, err := filepath.EvalSymlinks(allowed)
			if err != nil {
				resolved = filepath.Clean(allowed)
			}
			for _, denied := range resolvedSecrets {
				if pathCovers(denied, resolved) {
					return fmt.Errorf("sandbox %s %q (resolves to %q) is inside protected directory %q", label, allowed, resolved, denied)
				}
			}
		}
		return nil
	}

	if err := checkDirs(p.AllowReadDirs, "allow_read"); err != nil {
		return err
	}
	if err := checkDirs(p.AllowRWDirs, "allow_write"); err != nil {
		return err
	}
	if err := checkFiles(p.AllowReadFiles, "allow_read_file"); err != nil {
		return err
	}
	return checkFiles(p.AllowRWFiles, "allow_write_file")
}

// pathCovers returns true if the allowed path would grant access to the
// protected path. This is true when the protected path is equal to or a
// child of the allowed directory.
func pathCovers(allowed, protected string) bool {
	// Clean both paths for consistent comparison.
	allowed = filepath.Clean(allowed)
	protected = filepath.Clean(protected)

	if allowed == protected {
		return true
	}
	// Check if protected is under allowed (allowed is a parent directory).
	prefix := allowed
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return strings.HasPrefix(protected, prefix)
}
