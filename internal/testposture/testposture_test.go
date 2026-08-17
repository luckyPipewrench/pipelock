// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package testposture

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/posturebinding"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

func TestPinAbsentIsolatesFromHostPosture(t *testing.T) {
	t.Setenv(posturebinding.RuntimeProofEnv, "")

	cleanup, err := PinAbsent()
	if err != nil {
		t.Fatalf("PinAbsent: %v", err)
	}

	got := os.Getenv(posturebinding.RuntimeProofEnv)
	if got == "" {
		t.Fatal("PinAbsent left the override unset")
	}
	if got == posturebinding.DefaultContainRunProofPath {
		t.Fatalf("PinAbsent pinned the host path %q", got)
	}

	// LoadRuntime rejects a relative override outright, so the pinned path must
	// be absolute no matter what TMPDIR held.
	if !filepath.IsAbs(got) {
		t.Fatalf("pinned path is not absolute: %q", got)
	}

	// The proof must be absent: that is the state CI runs in, and the state the
	// zero binding represents.
	if _, statErr := os.Stat(got); !os.IsNotExist(statErr) {
		t.Fatalf("pinned proof should not exist, stat error = %v", statErr)
	}

	// An absent proof yields the zero binding rather than an error, which is what
	// makes callers take their no-attested-containment path.
	binding, loadErr := posturebinding.LoadRuntime()
	if loadErr != nil {
		t.Fatalf("LoadRuntime with an absent pinned proof: %v", loadErr)
	}
	if binding != (receipt.PostureBinding{}) {
		t.Fatalf("expected the zero binding, got %+v", binding)
	}

	dir := filepath.Dir(got)
	info, statErr := os.Stat(dir)
	if statErr != nil {
		t.Fatalf("stat pinned dir: %v", statErr)
	}
	if perm := info.Mode().Perm(); perm != dirMode {
		t.Fatalf("pinned dir mode = %#o, want %#o", perm, dirMode)
	}

	cleanup()
	if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
		t.Fatalf("cleanup left the directory behind, stat error = %v", statErr)
	}
}

func TestPinAbsentSurvivesRelativeTempDir(t *testing.T) {
	// os.MkdirTemp returns a relative path when TMPDIR is relative, and an
	// unnormalized override would then be rejected by LoadRuntime.
	base := t.TempDir()
	t.Chdir(base)
	if err := os.Mkdir("relative-tmp", dirMode); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Setenv("TMPDIR", "relative-tmp")

	cleanup, err := PinAbsent()
	if err != nil {
		t.Fatalf("PinAbsent: %v", err)
	}
	defer cleanup()

	got := os.Getenv(posturebinding.RuntimeProofEnv)
	if !filepath.IsAbs(got) {
		t.Fatalf("relative TMPDIR produced a relative override: %q", got)
	}
	if _, loadErr := posturebinding.LoadRuntime(); loadErr != nil {
		t.Fatalf("LoadRuntime rejected the pinned path: %v", loadErr)
	}
}

func TestPinAbsentReportsUnusableTempDir(t *testing.T) {
	// A TMPDIR that cannot be created under makes setup fail rather than leaving
	// the tests pointed at the host proof.
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "does-not-exist"))

	cleanup, err := PinAbsent()
	if cleanup == nil {
		t.Fatal("cleanup must be safe to defer even when pinning fails")
	}
	defer cleanup()
	if err == nil {
		t.Fatal("expected an error for an unusable TMPDIR")
	}
}

func TestPinIntoRefusesAMissingDirectory(t *testing.T) {
	// A directory that no longer exists makes the mode change fail, which must
	// refuse rather than leave the override pointed at the host proof.
	dir := filepath.Join(t.TempDir(), "gone")

	if err := pinInto(dir); err == nil {
		t.Fatal("expected an error for a missing directory")
	}
}
