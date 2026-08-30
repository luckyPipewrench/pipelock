// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package testposture

import (
	"os"
	"path/filepath"
	"runtime"
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
	result, loadErr := posturebinding.LoadRuntime()
	if loadErr != nil {
		t.Fatalf("LoadRuntime with an absent pinned proof: %v", loadErr)
	}
	if result.Availability != posturebinding.AvailabilityAbsent {
		t.Fatalf("availability = %q, want %q", result.Availability, posturebinding.AvailabilityAbsent)
	}
	if result.Binding != (receipt.PostureBinding{}) {
		t.Fatalf("expected an absent binding, got %+v", result.Binding)
	}

	dir := filepath.Dir(got)
	assertOwnerOnlyDir(t, dir)

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

// assertOwnerOnlyDir checks the pinned directory grants nobody but its owner.
// Windows does not model POSIX permission bits, so the check is Unix-only.
func assertOwnerOnlyDir(t *testing.T, dir string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat pinned dir: %v", err)
	}
	if perm := info.Mode().Perm(); perm != dirMode {
		t.Fatalf("pinned dir mode = %#o, want %#o", perm, dirMode)
	}
}

func TestPinAbsentRestoresThePriorOverride(t *testing.T) {
	// The override is process-wide, so cleanup must put back whatever was there
	// rather than leave a path to a directory it just deleted.
	const prior = "/var/lib/pipelock/contain/posture/prior-proof.json"
	t.Setenv(posturebinding.RuntimeProofEnv, prior)

	cleanup, err := PinAbsent()
	if err != nil {
		t.Fatalf("PinAbsent: %v", err)
	}
	if got := os.Getenv(posturebinding.RuntimeProofEnv); got == prior {
		t.Fatal("PinAbsent did not replace the prior override")
	}

	cleanup()
	if got := os.Getenv(posturebinding.RuntimeProofEnv); got != prior {
		t.Fatalf("cleanup left the override as %q, want %q", got, prior)
	}
}

func TestPinAbsentUnsetsAnOverrideItIntroduced(t *testing.T) {
	t.Setenv(posturebinding.RuntimeProofEnv, "")
	if err := os.Unsetenv(posturebinding.RuntimeProofEnv); err != nil {
		t.Fatalf("unsetenv: %v", err)
	}

	cleanup, err := PinAbsent()
	if err != nil {
		t.Fatalf("PinAbsent: %v", err)
	}
	cleanup()

	if got, ok := os.LookupEnv(posturebinding.RuntimeProofEnv); ok {
		t.Fatalf("cleanup left the override set to %q", got)
	}
}
