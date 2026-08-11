// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package guard

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// TestWritableDirectory_Outcomes pins the three answers the probe can give.
//
// The unsupported case is the one that matters most: it must not be reported as
// a denial. A filesystem that cannot create an unnamed inode has said nothing
// about whether an outer restriction narrowed the grant, and treating silence
// as a denial would refuse a correct policy.
func TestWritableDirectory_Outcomes(t *testing.T) {
	root := t.TempDir()

	switch got := writableDirectory(root); got {
	case dirWriteOK:
		// The probe leaves nothing behind: an unnamed inode never gets a name.
		if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
			t.Errorf("probe left %d entries (err=%v), want none", len(entries), err)
		}
	case dirWriteUnsupported:
		// A real Linux filesystem can lack unnamed-inode support, and the helper
		// classifies that as unsupported by design. Asserting success here would
		// fail the suite for the filesystem under the temp directory rather than
		// for a defect.
		t.Skip("temp filesystem does not support unnamed inodes; success path not assertable here")
	default:
		t.Errorf("writableDirectory(writable dir) = %v, want ok or unsupported", got)
	}

	// A path that is not a directory cannot answer the question, and that is
	// reported as unsupported rather than as a denial.
	file := filepath.Join(root, "regular")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := writableDirectory(file); got != dirWriteUnsupported {
		t.Errorf("writableDirectory(regular file) = %v, want unsupported", got)
	}

	if got := writableDirectory(filepath.Join(root, "absent")); got != dirWriteUnsupported {
		t.Errorf("writableDirectory(absent) = %v, want unsupported", got)
	}
}

// A floor that cannot answer must propagate its error for every declared grant
// shape, not only the first one the planner happens to walk.
func TestPlanManifests_FloorErrorPropagatesForEveryGrantShape(t *testing.T) {
	root := t.TempDir()
	boom := errors.New("floor unavailable")

	for _, tt := range []struct {
		name     string
		manifest config.GuardManifest
	}{
		{"read file", config.GuardManifest{Name: "m", ReadOnly: []string{filepath.Join(root, "a")}}},
		{"read directory", config.GuardManifest{Name: "m", ReadOnlyDirectories: []string{filepath.Join(root, "b")}}},
		{"write file", config.GuardManifest{Name: "m", ReadWrite: []string{filepath.Join(root, "c")}}},
		{"write directory", config.GuardManifest{Name: "m", ReadWriteDirectories: []string{filepath.Join(root, "d")}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := planConfig([]config.GuardManifest{tt.manifest}, []string{"m"})
			_, err := planManifestsWithFloor(cfg, "agent",
				func(string, config.GuardAccess) (config.GuardFloorDecision, error) {
					return config.GuardFloorDecision{}, boom
				})
			if !errors.Is(err, boom) {
				t.Fatalf("err = %v, want the floor error propagated", err)
			}
		})
	}
}
