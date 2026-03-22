// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// LayerSeatbelt identifies the macOS sandbox layer (sandbox-exec / Seatbelt).
const LayerSeatbelt LayerName = "seatbelt"

// seatbeltBinary is the path to the sandbox-exec CLI.
const seatbeltBinary = "/usr/bin/sandbox-exec"

// GenerateSBPL converts a Policy struct into a Seatbelt Profile Language
// (SBPL) string for use with sandbox-exec -p. Uses a deny-all baseline
// with explicit allow rules, matching pipelock's Landlock model.
func GenerateSBPL(p Policy) string {
	var b strings.Builder

	b.WriteString("(version 1)\n\n")
	b.WriteString(";; Deny-all baseline\n")
	b.WriteString("(deny default)\n\n")

	// Allow process execution and forking (subprocess tree inherits sandbox).
	b.WriteString(";; Process operations\n")
	b.WriteString("(allow process-exec*)\n")
	b.WriteString("(allow process-fork)\n")
	b.WriteString("(allow signal (target self))\n\n")

	// Allow basic system operations needed for any process.
	b.WriteString(";; System operations\n")
	b.WriteString("(allow sysctl-read)\n")
	b.WriteString("(allow mach-lookup)\n")
	b.WriteString("(allow mach-register)\n")
	b.WriteString("(allow ipc-posix-shm-read-data)\n")
	b.WriteString("(allow ipc-posix-shm-write-data)\n")
	b.WriteString("(allow ipc-posix-shm-read-metadata)\n\n")

	// Read-only directories.
	b.WriteString(";; Read-only filesystem access\n")
	for _, dir := range p.AllowReadDirs {
		seatbeltAllowRead(&b, resolveMacOSPath(dir))
	}
	for _, file := range p.AllowReadFiles {
		seatbeltAllowReadFile(&b, resolveMacOSPath(file))
	}
	b.WriteString("\n")

	// Read-write directories.
	b.WriteString(";; Read-write filesystem access\n")
	for _, dir := range p.AllowRWDirs {
		seatbeltAllowRW(&b, resolveMacOSPath(dir))
	}
	for _, file := range p.AllowRWFiles {
		seatbeltAllowRWFile(&b, resolveMacOSPath(file))
	}
	b.WriteString("\n")

	// Deny reads to secret directories (must come after allow rules
	// because SBPL evaluates rules in order, last match wins for
	// overlapping deny/allow on the same operation).
	if len(p.DenyReadDirs) > 0 {
		b.WriteString(";; Denied secret directories\n")
		for _, dir := range p.DenyReadDirs {
			seatbeltDenyRead(&b, resolveMacOSPath(dir))
		}
		b.WriteString("\n")
	}

	// Network: deny all except localhost (agent must go through pipelock proxy).
	b.WriteString(";; Network: localhost only (agent routes through pipelock proxy)\n")
	b.WriteString("(allow network* (local ip \"localhost:*\"))\n")
	b.WriteString("(allow network* (remote ip \"localhost:*\"))\n")
	b.WriteString("(allow network* (local ip \"127.0.0.1:*\"))\n")
	b.WriteString("(allow network* (remote ip \"127.0.0.1:*\"))\n")
	b.WriteString("(allow network* (local unix-socket))\n")
	b.WriteString("(allow network* (remote unix-socket))\n")

	return b.String()
}

// seatbeltAllowRead emits an SBPL allow rule for read access to a directory subtree.
func seatbeltAllowRead(b *strings.Builder, path string) {
	_, _ = fmt.Fprintf(b, "(allow file-read* (subpath %q))\n", path)
}

// seatbeltAllowReadFile emits an SBPL allow rule for read access to a single file.
func seatbeltAllowReadFile(b *strings.Builder, path string) {
	_, _ = fmt.Fprintf(b, "(allow file-read* (literal %q))\n", path)
}

// seatbeltAllowRW emits SBPL allow rules for read+write access to a directory subtree.
func seatbeltAllowRW(b *strings.Builder, path string) {
	_, _ = fmt.Fprintf(b, "(allow file-read* (subpath %q))\n", path)
	_, _ = fmt.Fprintf(b, "(allow file-write* (subpath %q))\n", path)
}

// seatbeltAllowRWFile emits SBPL allow rules for read+write access to a single file.
func seatbeltAllowRWFile(b *strings.Builder, path string) {
	_, _ = fmt.Fprintf(b, "(allow file-read* (literal %q))\n", path)
	_, _ = fmt.Fprintf(b, "(allow file-write* (literal %q))\n", path)
}

// seatbeltDenyRead emits an SBPL deny rule for read access to a directory subtree.
func seatbeltDenyRead(b *strings.Builder, path string) {
	_, _ = fmt.Fprintf(b, "(deny file-read* (subpath %q))\n", path)
}

// resolveMacOSPath translates Linux-style paths to their macOS equivalents.
// On macOS, /etc, /tmp, and /var are symlinks to /private/{etc,tmp,var}.
// sandbox-exec requires the real (resolved) paths.
func resolveMacOSPath(path string) string {
	// These are standard macOS symlinks.
	macOSSymlinks := []struct {
		prefix string
		target string
	}{
		{"/etc/", "/private/etc/"},
		{"/tmp/", "/private/tmp/"},
		{"/tmp", "/private/tmp"},
		{"/var/", "/private/var/"},
	}

	for _, sl := range macOSSymlinks {
		if strings.HasPrefix(path, sl.prefix) {
			return sl.target + strings.TrimPrefix(path, sl.prefix)
		}
		if path == strings.TrimSuffix(sl.prefix, "/") {
			return strings.TrimSuffix(sl.target, "/")
		}
	}

	return path
}

// DefaultPolicyDarwin returns a sandbox policy with macOS-appropriate defaults.
// Extends the base DefaultPolicy with macOS-specific paths.
func DefaultPolicyDarwin(workspace string) Policy {
	home := os.Getenv("HOME")

	p := Policy{
		Workspace: workspace,
		AllowReadDirs: []string{
			"/usr/",
			"/bin/",
			"/sbin/",
			"/Library/",
			"/System/",
			"/private/etc/ssl/",
			"/private/etc/pki/",
			"/private/var/db/",
			"/Applications/",
		},
		AllowReadFiles: []string{
			"/private/etc/resolv.conf",
			"/private/etc/hosts",
			"/private/etc/nsswitch.conf",
			"/private/etc/passwd",
			"/private/etc/group",
		},
		AllowRWDirs: []string{
			workspace,
			// NOTE: /private/tmp/ is NOT included globally. The child gets a
			// per-sandbox temp dir to prevent cross-sandbox data leakage,
			// matching the Linux policy model.
		},
		AllowRWFiles: []string{
			"/dev/null",
			"/dev/zero",
			"/dev/urandom",
			"/dev/random",
		},
		DenyReadDirs: []string{},
	}

	// Add Homebrew path based on architecture.
	if runtime.GOARCH == "arm64" {
		p.AllowReadDirs = append(p.AllowReadDirs, "/opt/homebrew/")
	}
	// /usr/local/ is already under /usr/, covers Intel Homebrew.

	// Deny secret directories if HOME is set.
	if home != "" {
		p.DenyReadDirs = append(p.DenyReadDirs,
			filepath.Join(home, ".ssh"),
			filepath.Join(home, ".aws"),
			filepath.Join(home, ".gnupg"),
			filepath.Join(home, ".kube"),
			filepath.Join(home, ".docker"),
			filepath.Join(home, "Library", "Keychains"),
			filepath.Join(home, "Library", "Cookies"),
			filepath.Join(home, ".config", "pipelock"),
		)
	}

	return p
}
