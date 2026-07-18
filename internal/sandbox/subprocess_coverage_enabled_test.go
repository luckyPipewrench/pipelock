// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build subprocess_coverage

package sandbox

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestPrepareSubprocessCoverageEnabled(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "pipelock-covdata-")
	if err != nil {
		t.Fatalf("create coverage directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	t.Setenv("GOCOVERDIR", dir)
	t.Setenv(subprocessCoverageMarker, "1")

	policy, env := prepareSubprocessCoverage(Policy{}, nil)

	cleanDir := filepath.Clean(dir)
	if !slices.Contains(policy.AllowRWDirs, cleanDir) {
		t.Fatalf("AllowRWDirs = %v, want %q", policy.AllowRWDirs, cleanDir)
	}
	if !slices.Contains(env, "GOCOVERDIR="+cleanDir) {
		t.Fatalf("environment = %v, want GOCOVERDIR", env)
	}
}

func TestPrepareSubprocessCoverageRejectsUnsafeDirectories(t *testing.T) {
	tests := []string{"/tmp", "relative", "/tmp/not-pipelock-coverage"}
	for _, dir := range tests {
		t.Run(dir, func(t *testing.T) {
			t.Setenv("GOCOVERDIR", dir)
			t.Setenv(subprocessCoverageMarker, "1")
			policy, env := prepareSubprocessCoverage(Policy{}, nil)
			if len(policy.AllowRWDirs) != 0 || len(env) != 0 {
				t.Fatalf("unsafe directory widened policy: policy=%v env=%v", policy.AllowRWDirs, env)
			}
			if err := flushSubprocessCoverage(); err == nil {
				t.Fatal("unsafe directory accepted for coverage output")
			}
		})
	}
}

func TestPrepareSubprocessCoverageEnabledWithoutDirectory(t *testing.T) {
	t.Setenv("GOCOVERDIR", "")
	t.Setenv(subprocessCoverageMarker, "1")

	policy, env := prepareSubprocessCoverage(Policy{}, nil)

	if len(policy.AllowRWDirs) != 0 {
		t.Fatalf("AllowRWDirs = %v, want empty", policy.AllowRWDirs)
	}
	if len(env) != 0 {
		t.Fatalf("environment = %v, want empty", env)
	}
	if err := flushSubprocessCoverage(); err != nil {
		t.Fatalf("flushSubprocessCoverage() without GOCOVERDIR: %v", err)
	}
}

func TestReportSubprocessCoverageError(t *testing.T) {
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stderr pipe: %v", err)
	}
	oldStderr := os.Stderr
	os.Stderr = writeEnd
	reportSubprocessCoverageError(errors.New("forced coverage failure"))
	os.Stderr = oldStderr
	if err := writeEnd.Close(); err != nil {
		t.Fatalf("close stderr writer: %v", err)
	}
	data, err := io.ReadAll(readEnd)
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	if err := readEnd.Close(); err != nil {
		t.Fatalf("close stderr reader: %v", err)
	}
	if !strings.Contains(string(data), "forced coverage failure") {
		t.Fatalf("stderr = %q, want coverage failure", data)
	}
}

func TestValidatedSubprocessCoverageDirRejectsUnsafeFilesystemState(t *testing.T) {
	t.Run("marker absent", func(t *testing.T) {
		t.Setenv(subprocessCoverageMarker, "")
		t.Setenv("GOCOVERDIR", "/tmp/pipelock-covdata-ignored")
		if dir, err := validatedSubprocessCoverageDir(); err != nil || dir != "" {
			t.Fatalf("validatedSubprocessCoverageDir() = (%q, %v), want empty", dir, err)
		}
	})

	tests := []struct {
		name  string
		setup func(*testing.T) string
	}{
		{
			name: "missing",
			setup: func(t *testing.T) string {
				t.Helper()
				return filepath.Join("/tmp", "pipelock-covdata-missing-"+filepath.Base(t.TempDir()))
			},
		},
		{
			name: "regular file",
			setup: func(t *testing.T) string {
				t.Helper()
				file, err := os.CreateTemp("/tmp", "pipelock-covdata-")
				if err != nil {
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Remove(file.Name()) })
				return file.Name()
			},
		},
		{
			name: "symlink",
			setup: func(t *testing.T) string {
				t.Helper()
				target, err := os.MkdirTemp("/tmp", "pipelock-covdata-target-")
				if err != nil {
					t.Fatal(err)
				}
				link := target + "-link"
				if err := os.Symlink(target, link); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					_ = os.Remove(link)
					_ = os.RemoveAll(target)
				})
				return link
			},
		},
		{
			name: "loose mode",
			setup: func(t *testing.T) string {
				t.Helper()
				dir, err := os.MkdirTemp("/tmp", "pipelock-covdata-")
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(dir, 0o750); err != nil { // #nosec G302 -- deliberately loose fixture.
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.RemoveAll(dir) })
				return dir
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(subprocessCoverageMarker, "1")
			t.Setenv("GOCOVERDIR", tc.setup(t))
			if dir, err := validatedSubprocessCoverageDir(); err == nil || dir != "" {
				t.Fatalf("validatedSubprocessCoverageDir() = (%q, %v), want rejection", dir, err)
			}
		})
	}
}
