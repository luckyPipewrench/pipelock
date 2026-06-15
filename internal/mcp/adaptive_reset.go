// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"fmt"
	"io"
	"os"

	"github.com/luckyPipewrench/pipelock/internal/secperm"
)

// adaptiveResetter is the optional capability ForwardScanned uses to clear a
// session's adaptive-enforcement escalation when the operator triggers a local
// reset. *proxy.SessionState satisfies it via Reset(); the interface keeps the
// mcp package decoupled from internal/proxy.
type adaptiveResetter interface {
	Reset() (prevScore float64, prevLevel int)
}

// resetFileDisallowedBits rejects any group/other permission bit. The adaptive
// reset file authorizes a privilege DE-escalation (clearing an airlock), so it
// must be owner-only (0600): a group- or world-accessible file could be written
// by the wrapped agent to clear its own airlock.
const resetFileDisallowedBits = 0o077

// consumeAdaptiveResetFile reports whether the operator has requested an
// adaptive-enforcement reset via the control file at path, removing the file so
// the request is one-shot.
//
// It is fail-safe: a missing/unreadable file is a silent no-op; a file that is
// a symlink, not a regular file, group/other-accessible, or not owned by this
// process's user is IGNORED and removed with a warning - such a file may have
// been planted by the wrapped agent to clear its own airlock, which must never
// be honored. On Windows, mode bits are not security-meaningful
// (secperm.Enforced() is false); access control there is the deployment's NTFS
// ACL responsibility, matching the rest of pipelock's secret-file handling.
func consumeAdaptiveResetFile(path string, logW io.Writer) bool {
	if path == "" {
		return false
	}
	info, err := os.Lstat(path)
	if err != nil {
		return false // missing/unreadable: no reset requested
	}
	if info.Mode()&os.ModeSymlink != 0 {
		warnResetFile(logW, path, "is a symlink")
		_ = os.Remove(path)
		return false
	}
	if !info.Mode().IsRegular() {
		warnResetFile(logW, path, "is not a regular file")
		// Best-effort cleanup so a persistent invalid path (FIFO, device,
		// socket) is not re-checked and re-warned on every message. Never
		// remove a directory.
		if info.Mode()&os.ModeDir == 0 {
			_ = os.Remove(path)
		}
		return false
	}
	// secperm.TooPermissive is a no-op on Windows (mode bits there do not
	// reflect the NTFS ACL), matching how readHeaderFile gates --header-file.
	if secperm.TooPermissive(info.Mode().Perm(), resetFileDisallowedBits) {
		warnResetFile(logW, path, fmt.Sprintf("has unsafe mode %#o (must be 0600, owner-only)", info.Mode().Perm()))
		_ = os.Remove(path)
		return false
	}
	if !resetFileOwnedBySelf(info) {
		warnResetFile(logW, path, "is not owned by the proxy user")
		_ = os.Remove(path)
		return false
	}
	if err := os.Remove(path); err != nil {
		warnResetFile(logW, path, fmt.Sprintf("could not be removed (%v); reset skipped to avoid a loop", err))
		return false
	}
	return true
}

func warnResetFile(logW io.Writer, path, reason string) {
	_, _ = fmt.Fprintf(logW, "pipelock: adaptive reset file %q %s - ignored\n", path, reason)
}
