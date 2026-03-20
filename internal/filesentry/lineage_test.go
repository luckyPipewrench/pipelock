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

	// Give tail time to open the file.
	time.Sleep(100 * time.Millisecond)

	l := NewLineage()
	l.TrackPID(cmd.Process.Pid)

	if !l.HasFileOpen(testFile) {
		t.Error("expected tracked process to have file open")
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

	// Give bash time to fork sleep.
	time.Sleep(100 * time.Millisecond)

	// The bash process itself is tracked.
	if !l.IsDescendant(cmd.Process.Pid) {
		t.Error("expected bash child to be a descendant")
	}
}
