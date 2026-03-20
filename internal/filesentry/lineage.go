// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package filesentry

// Lineage tracks which OS processes belong to the agent's process tree.
// Used to attribute filesystem writes to agent activity vs unrelated processes.
type Lineage interface {
	// EnableSubreaper makes this process adopt orphaned descendants.
	// Linux only (PR_SET_CHILD_SUBREAPER). No-op on other platforms.
	EnableSubreaper() error

	// TrackPID adds a root PID to the tracked tree.
	TrackPID(pid int)

	// IsDescendant returns true if pid is a descendant of any tracked root.
	// Walks /proc/[pid]/children recursively on Linux. Returns false on
	// other platforms or if /proc is unavailable.
	IsDescendant(pid int) bool

	// HasFileOpen returns true if any tracked process has the given path
	// open. Checks /proc/[pid]/fd symlinks for all tracked PIDs and their
	// descendants. Returns false on non-Linux or if processes have exited.
	HasFileOpen(path string) bool
}
