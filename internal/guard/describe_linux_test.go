// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package guard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// TestEnforcementRecord_DescribeStatesLeadWithTheOutcome checks the two
// not-enforced renderings.
//
// These strings are what an operator reads to decide whether a run was
// protected, so the assertion is that each leads with the outcome rather than
// the excuse. A record that opened with the reason would read as a caveat on a
// protected run instead of a statement that the run was not protected.
func TestEnforcementRecord_DescribeStatesLeadWithTheOutcome(t *testing.T) {
	abi := MinimumABI
	for _, tt := range []struct {
		name   string
		state  EnforcementState
		leads  string
		absent string
	}{
		{"accepted unenforced", EnforcementUnenforcedAccepted, "NOT ENFORCED", "ENFORCED via"},
		{"refused", EnforcementRefused, "REFUSED", "ENFORCED via"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := EnforcementRecord{
				State:       tt.state,
				Mechanism:   "landlock",
				RequiredABI: ThreadSyncABI,
				ObservedABI: &abi,
				Reason:      "kernel too old",
			}.Describe()

			if !strings.HasPrefix(got, tt.leads) {
				t.Errorf("Describe() = %q, want it to lead with %q", got, tt.leads)
			}
			if strings.Contains(got, tt.absent) {
				t.Errorf("Describe() = %q, must not read as an enforced run", got)
			}
			if !strings.Contains(got, "kernel too old") {
				t.Errorf("Describe() = %q, want the reason retained", got)
			}
		})
	}
}

// An unread ABI renders as unknown rather than as zero, so a record whose
// version could not be read is not mistaken for one reporting ABI 0.
func TestEnforcementRecord_DescribeUnreadABI(t *testing.T) {
	got := EnforcementRecord{State: EnforcementRefused, Mechanism: "landlock"}.Describe()
	if !strings.Contains(got, "unread") {
		t.Errorf("Describe() = %q, want an unread ABI to say so", got)
	}
}

func TestOpenNoSymlinks_RejectsRelativeAndRoot(t *testing.T) {
	if _, err := openNoSymlinks("relative/path", true); err == nil ||
		!strings.Contains(err.Error(), "absolute") {
		t.Errorf("err = %v, want an absolute-path requirement", err)
	}
	// Pinning "/" would grant the whole filesystem through one rule, so it is
	// refused here as well as by the compiled floor.
	if _, err := openNoSymlinks("/", true); err == nil ||
		!strings.Contains(err.Error(), "filesystem root") {
		t.Errorf("err = %v, want the root refused", err)
	}
}

// A declaration whose object is the wrong shape is refused, in both directions.
// The mask for a directory is invalid on a regular file and would make the
// kernel reject the entire ruleset, so this has to be caught before the rules
// are built.
func TestPrepare_RefusesShapeMismatch(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "adirectory")
	file := filepath.Join(root, "afile")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("directory declared as exact file", func(t *testing.T) {
		cfg := planConfig([]config.GuardManifest{{Name: "m", ReadOnly: []string{dir}}}, []string{"m"})
		prepared, err := Prepare(cfg, "agent", os.Getuid())
		if err != nil {
			t.Fatalf("Prepare: %v", err)
		}
		defer func() { _ = prepared.Close() }()
		out := prepared.Outcomes()
		if len(out) != 1 || out[0].State != StateRefused {
			t.Fatalf("outcomes = %+v, want refused", out)
		}
		if !strings.Contains(out[0].Reason, "declared as an exact file") {
			t.Errorf("reason = %q, want the shape mismatch named", out[0].Reason)
		}
	})

	t.Run("regular file declared as directory", func(t *testing.T) {
		cfg := planConfig([]config.GuardManifest{{Name: "m", ReadOnlyDirectories: []string{file}}}, []string{"m"})
		prepared, err := Prepare(cfg, "agent", os.Getuid())
		if err != nil {
			t.Fatalf("Prepare: %v", err)
		}
		defer func() { _ = prepared.Close() }()
		out := prepared.Outcomes()
		if len(out) != 1 || out[0].State.Granted() {
			t.Fatalf("outcomes = %+v, want the grant withheld", out)
		}
		if prepared.Complete() {
			t.Error("a shape mismatch must leave the manifest incomplete")
		}
	})
}
