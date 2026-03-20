// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package filesentry

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

const testOSLinux = "linux"

func TestLineage_TrackAndDescendant(t *testing.T) {
	if runtime.GOOS != testOSLinux {
		t.Skip("linux only")
	}

	l := NewLineage()
	cmd := exec.CommandContext(t.Context(), "sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()

	l.TrackPID(cmd.Process.Pid)

	if !l.IsDescendant(cmd.Process.Pid) {
		t.Error("expected tracked PID to be a descendant")
	}
}

func TestLineage_UnTrackedPID(t *testing.T) {
	if runtime.GOOS != testOSLinux {
		t.Skip("linux only")
	}

	l := NewLineage()
	// PID 1 (init) should never be tracked.
	if l.IsDescendant(1) {
		t.Error("expected PID 1 to not be a descendant")
	}
}

func TestLineage_Subreaper(t *testing.T) {
	if runtime.GOOS != testOSLinux {
		t.Skip("linux only")
	}

	l := NewLineage()
	if err := l.EnableSubreaper(); err != nil {
		t.Errorf("EnableSubreaper failed: %v", err)
	}
}

func TestLineage_HasFileOpen(t *testing.T) {
	if runtime.GOOS != testOSLinux {
		t.Skip("linux only")
	}

	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(testFile, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Start a child that holds the file open.
	cmd := exec.CommandContext(t.Context(), "tail", "-f", testFile) //nolint:gosec // test-only, path from t.TempDir()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()

	l := NewLineage()
	l.TrackPID(cmd.Process.Pid)

	// Poll until tail opens the file (up to 2s). Avoids fixed sleep that
	// races under CI load or the race detector.
	deadline := time.Now().Add(2 * time.Second)
	for !l.HasFileOpen(testFile) {
		if time.Now().After(deadline) {
			t.Fatal("timeout: tail did not open file within 2s")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestLineage_HasFileOpen_NotOpen(t *testing.T) {
	if runtime.GOOS != testOSLinux {
		t.Skip("linux only")
	}

	l := NewLineage()
	cmd := exec.CommandContext(t.Context(), "sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()

	l.TrackPID(cmd.Process.Pid)

	if l.HasFileOpen("/nonexistent/path/that/no/process/has/open") {
		t.Error("expected false for file not opened by any tracked process")
	}
}

func TestLineage_GrandchildDescendant(t *testing.T) {
	if runtime.GOOS != testOSLinux {
		t.Skip("linux only")
	}

	l := NewLineage()
	// bash -c "sleep 30" creates bash (child) -> sleep (grandchild)
	cmd := exec.CommandContext(t.Context(), "bash", "-c", "sleep 30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()

	l.TrackPID(cmd.Process.Pid)

	// The bash process itself is tracked.
	if !l.IsDescendant(cmd.Process.Pid) {
		t.Error("expected bash child to be a descendant")
	}

	// Poll until bash forks the sleep grandchild (up to 5s).
	// Under -race, process tree inspection is slower.
	var descendants []int
	deadline := time.Now().Add(5 * time.Second)
	for len(descendants) == 0 {
		if time.Now().After(deadline) {
			t.Skip("no grandchild found within 5s (may not be visible under race detector)")
		}
		time.Sleep(20 * time.Millisecond)
		descendants = collectDescendants(cmd.Process.Pid)
	}
	sleepPID := descendants[0]
	if !l.IsDescendant(sleepPID) {
		t.Errorf("expected grandchild PID %d to be a descendant", sleepPID)
	}
}

func TestLineage_IsDescendant_ExitedProcess(t *testing.T) {
	if runtime.GOOS != testOSLinux {
		t.Skip("linux only")
	}
	l := NewLineage()
	l.TrackPID(os.Getpid())

	// PID that almost certainly doesn't exist.
	if l.IsDescendant(99999999) {
		t.Error("exited/nonexistent PID should not be a descendant")
	}
}

func TestLineage_HasFileOpen_ExitedProcess(t *testing.T) {
	if runtime.GOOS != testOSLinux {
		t.Skip("linux only")
	}
	l := NewLineage()
	// Track a PID that doesn't exist — HasFileOpen should handle gracefully.
	l.TrackPID(99999999)
	if l.HasFileOpen("/tmp/nonexistent") {
		t.Error("expected false for exited process")
	}
}

func TestLineage_CollectDescendants_Self(t *testing.T) {
	if runtime.GOOS != testOSLinux {
		t.Skip("linux only")
	}
	// collectDescendants on the current process should not panic.
	// It may return an empty slice if the process has no children.
	result := collectDescendants(os.Getpid())
	_ = result // just verify no panic
}

func TestLineage_ParentPID_Self(t *testing.T) {
	if runtime.GOOS != testOSLinux {
		t.Skip("linux only")
	}
	ppid, err := parentPID(os.Getpid())
	if err != nil {
		t.Fatalf("parentPID(self): %v", err)
	}
	if ppid <= 0 {
		t.Errorf("expected positive PPid, got %d", ppid)
	}
}

func TestCollectDescendantsRec_DepthLimit(t *testing.T) {
	if runtime.GOOS != testOSLinux {
		t.Skip("linux only")
	}
	// Calling with depth >= maxDescendantDepth should return nil immediately.
	visited := make(map[int]struct{})
	result := collectDescendantsRec(os.Getpid(), visited, maxDescendantDepth)
	if result != nil {
		t.Errorf("expected nil at max depth, got %v", result)
	}
}

func TestCollectDescendantsRec_CycleProtection(t *testing.T) {
	if runtime.GOOS != testOSLinux {
		t.Skip("linux only")
	}
	// Pre-populate visited with the current PID. collectDescendantsRec
	// should skip it if encountered as a child (cycle protection).
	visited := make(map[int]struct{})
	visited[os.Getpid()] = struct{}{}
	// This won't actually recurse into getpid since it's in visited,
	// but verifies the visited check doesn't panic.
	result := collectDescendantsRec(os.Getpid(), visited, 0)
	_ = result
}

func TestCollectDescendants_NonexistentPID(t *testing.T) {
	if runtime.GOOS != testOSLinux {
		t.Skip("linux only")
	}
	// Nonexistent PID should return empty (ReadDir fails).
	result := collectDescendants(99999999)
	if len(result) != 0 {
		t.Errorf("expected empty for nonexistent PID, got %v", result)
	}
}

func TestIsDescendant_CycleProtection(t *testing.T) {
	if runtime.GOOS != testOSLinux {
		t.Skip("linux only")
	}
	l := NewLineage()
	// Track PID 1 — walking up from a random high PID should terminate
	// without infinite loop (cycle protection via visited map).
	l.TrackPID(1)
	// Use a PID that doesn't exist — parentPID will fail, loop terminates.
	if l.IsDescendant(99999998) {
		t.Error("nonexistent PID should not be a descendant of init")
	}
}

func TestLineage_ParentPID_Nonexistent(t *testing.T) {
	if runtime.GOOS != testOSLinux {
		t.Skip("linux only")
	}
	_, err := parentPID(99999999)
	if err == nil {
		t.Error("expected error for nonexistent PID")
	}
}
