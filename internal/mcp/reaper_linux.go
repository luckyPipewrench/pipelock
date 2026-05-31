// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package mcp

import (
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

var (
	protectedDirectPIDsMu sync.Mutex
	protectedDirectPIDs   = make(map[int]int)
)

// startAdoptedReaper drains exited adopted descendants while the direct
// MCP child is still alive. Without it, long-running wraps (codex
// mcp-server, playwright MCP) accumulate zombies under pipelock because
// the post-Wait killAdoptedDescendants sweep only fires when the direct
// child exits - which can be hours later for those servers.
//
// The reaper only Wait4's processes whose PPID is pipelock's own and
// whose PID is not the direct child. exec.Cmd.Wait()'s ownership of
// the direct child's exit status is therefore preserved: we never call
// Wait4(-1, ...) and we never call Wait4(directPID, ...).
//
// Why signal.Notify(SIGCHLD) doesn't break exec.Cmd.Wait(): Go's
// runtime reaps subprocess children with wait4(pid, ..., 0) bound to
// the specific cmd.Process.Pid, not via SIGCHLD-driven dispatch. The
// kernel keeps a zombie until SOMEONE waitpids it, regardless of
// which process catches SIGCHLD. As long as we never wait4(directPID),
// we cannot consume the direct child's exit status - even with
// signal.Notify subscribing to SIGCHLD process-wide.
//
// Stop the reaper by closing done. The goroutine exits on the next
// SIGCHLD or when done closes - whichever comes first.
//
// Linux-only because PR_SET_CHILD_SUBREAPER (the precondition that
// causes pipelock to adopt orphans in the first place) is Linux-only.
// Non-Linux builds use the no-op stub.
func startAdoptedReaper(directPID int, done <-chan struct{}) {
	unregister := registerProtectedDirectPID(directPID)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGCHLD)
	go func() {
		defer unregister()
		defer signal.Stop(sigCh)
		// Initial sweep covers two narrow windows:
		//   1. A grandchild that exited before cmd.Start finished
		//      and we got here with the direct PID.
		//   2. A SIGCHLD that fired before signal.Notify took effect
		//      above (kernel delivers to the default handler, which
		//      ignores it - the zombie sits until someone wait4's it).
		// Without this initial sweep, those zombies would sit until the
		// direct child exits and the post-Wait sweep runs - exactly
		// the bug we're fixing.
		reapAdoptedZombies(directPID)
		for {
			select {
			case <-done:
				return
			case <-sigCh:
				reapAdoptedZombies(directPID)
			}
		}
	}()
}

// reapAdoptedZombies walks /proc once, finds zombies whose parent PID
// is pipelock's own and whose PID is not directPID, and Wait4's each
// one with WNOHANG. Wait4 against a specific PID cannot consume the
// direct child's exit, which is what makes this safe to run alongside
// exec.Cmd.Wait().
//
// Active direct-child PIDs are also held in a shared protected registry
// so concurrent RunProxy calls in one process cannot steal each other's
// child exits while still draining adopted descendants.
//
// Best-effort throughout - ESRCH on PID-recycle race, EINTR on signal,
// EPERM on namespace boundary all fall through silently.
func reapAdoptedZombies(directPID int) {
	selfPID := os.Getpid()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		childPID, convErr := strconv.Atoi(name)
		if convErr != nil {
			continue
		}
		if childPID == selfPID || childPID == directPID || isProtectedDirectPID(childPID) {
			continue
		}
		if !isAdoptedZombie(name, selfPID) {
			continue
		}
		var status syscall.WaitStatus
		_, _ = syscall.Wait4(childPID, &status, syscall.WNOHANG, nil)
	}
}

func registerProtectedDirectPID(pid int) func() {
	if pid <= 0 {
		return func() {}
	}
	protectedDirectPIDsMu.Lock()
	protectedDirectPIDs[pid]++
	protectedDirectPIDsMu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			protectedDirectPIDsMu.Lock()
			defer protectedDirectPIDsMu.Unlock()
			n := protectedDirectPIDs[pid]
			if n <= 1 {
				delete(protectedDirectPIDs, pid)
				return
			}
			protectedDirectPIDs[pid] = n - 1
		})
	}
}

func isProtectedDirectPID(pid int) bool {
	if pid <= 0 {
		return false
	}
	protectedDirectPIDsMu.Lock()
	_, ok := protectedDirectPIDs[pid]
	protectedDirectPIDsMu.Unlock()
	return ok
}

// isAdoptedZombie returns true iff /proc/<name>/stat shows state "Z"
// and ppid == selfPID. Mirrors the parser in killAdoptedDescendants:
// field 2 is a parenthesized comm string that may itself contain
// spaces or close-parens, so we locate the LAST ')' and index from
// there before whitespace-splitting.
func isAdoptedZombie(procName string, selfPID int) bool {
	statPath := filepath.Clean("/proc/" + procName + "/stat")
	statBytes, readErr := os.ReadFile(statPath)
	if readErr != nil {
		return false
	}
	stat := string(statBytes)
	cmdEnd := strings.LastIndex(stat, ")")
	if cmdEnd < 0 || cmdEnd+2 > len(stat) {
		return false
	}
	// After "<pid> (<comm>) ", fields are: state(1) ppid(2) pgrp(3) ...
	rest := strings.Fields(stat[cmdEnd+1:])
	if len(rest) < 2 {
		return false
	}
	if rest[0] != "Z" {
		return false
	}
	ppid, convErr := strconv.Atoi(rest[1])
	if convErr != nil {
		return false
	}
	return ppid == selfPID
}
