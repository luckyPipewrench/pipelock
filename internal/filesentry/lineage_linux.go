// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package filesentry

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

type linuxLineage struct {
	mu   sync.Mutex
	pids map[int]struct{} // root PIDs being tracked
}

// NewLineage returns a Linux-specific process lineage tracker.
func NewLineage() Lineage {
	return &linuxLineage{pids: make(map[int]struct{})}
}

func (l *linuxLineage) EnableSubreaper() error {
	return unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
}

func (l *linuxLineage) TrackPID(pid int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pids[pid] = struct{}{}
}

func (l *linuxLineage) IsDescendant(pid int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Direct match.
	if _, ok := l.pids[pid]; ok {
		return true
	}

	// Walk up the process tree via /proc/[pid]/status PPid field.
	current := pid
	visited := make(map[int]struct{})
	for {
		if _, seen := visited[current]; seen {
			return false // cycle protection
		}
		visited[current] = struct{}{}

		ppid, err := parentPID(current)
		if err != nil || ppid <= 1 {
			return false
		}
		if _, ok := l.pids[ppid]; ok {
			return true
		}
		current = ppid
	}
}

func (l *linuxLineage) HasFileOpen(path string) bool {
	l.mu.Lock()
	roots := make([]int, 0, len(l.pids))
	for pid := range l.pids {
		roots = append(roots, pid)
	}
	l.mu.Unlock()

	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}

	// Check each tracked root and its descendants.
	for _, root := range roots {
		pids := collectDescendants(root)
		pids = append(pids, root)
		for _, pid := range pids {
			if pidHasFileOpen(pid, absPath) {
				return true
			}
		}
	}
	return false
}

// parentPID reads the PPid from /proc/[pid]/status.
func parentPID(pid int) (int, error) {
	data, err := os.ReadFile(filepath.Clean(fmt.Sprintf("/proc/%d/status", pid)))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return strconv.Atoi(fields[1])
			}
		}
	}
	return 0, fmt.Errorf("PPid not found for pid %d", pid)
}

// collectDescendants walks /proc/[pid]/task/[tid]/children recursively.
func collectDescendants(pid int) []int {
	var result []int
	// Read children from all threads of this process.
	taskDir := filepath.Clean(fmt.Sprintf("/proc/%d/task", pid))
	entries, err := os.ReadDir(taskDir)
	if err != nil {
		return result
	}
	for _, entry := range entries {
		childrenPath := filepath.Join(taskDir, entry.Name(), "children")
		data, err := os.ReadFile(filepath.Clean(childrenPath))
		if err != nil {
			continue
		}
		for _, field := range strings.Fields(string(data)) {
			childPID, err := strconv.Atoi(field)
			if err != nil {
				continue
			}
			result = append(result, childPID)
			result = append(result, collectDescendants(childPID)...)
		}
	}
	return result
}

// pidHasFileOpen checks if a process has a file descriptor pointing to path.
func pidHasFileOpen(pid int, absPath string) bool {
	fdDir := filepath.Clean(fmt.Sprintf("/proc/%d/fd", pid))
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return false // process may have exited
	}
	for _, entry := range entries {
		link, err := os.Readlink(filepath.Join(fdDir, entry.Name()))
		if err != nil {
			continue
		}
		if link == absPath {
			return true
		}
	}
	return false
}
