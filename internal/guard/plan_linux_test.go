// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package guard

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// mockFloorAllows is a floor that refuses nothing, for tests whose subject is
// downstream of the floor.
func mockFloorAllows(string, config.GuardAccess) (config.GuardFloorDecision, error) {
	return config.GuardFloorDecision{}, nil
}

func planConfig(manifests []config.GuardManifest, selects []string) *config.Config {
	cfg := config.Defaults()
	cfg.Guard = config.Guard{
		Profiles:  []config.GuardProfile{{Name: "agent", Manifests: selects}},
		Manifests: manifests,
	}
	return cfg
}

func TestPlanManifests_UnknownProfileIsAnError(t *testing.T) {
	cfg := planConfig(nil, nil)
	if _, err := planManifests(cfg, "absent"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("err = %v, want a profile-not-found error", err)
	}
}

// A profile naming a manifest that does not exist must fail loudly. Validation
// is expected to catch it first, but planning a profile with silently fewer
// grants than declared is the failure mode worth refusing outright.
func TestPlanManifests_UnknownManifestIsAnError(t *testing.T) {
	cfg := planConfig(nil, []string{"ghost"})
	_, err := planManifests(cfg, "agent")
	if err == nil || !strings.Contains(err.Error(), "unknown manifest") {
		t.Fatalf("err = %v, want an unknown-manifest error", err)
	}
}

// The same path declared twice yields one grant, and grants come back in a
// stable order regardless of declaration order, so a record derived from them
// is reproducible.
func TestPlanManifests_DeduplicatesAndOrdersDeterministically(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(root, "alpha")
	b := filepath.Join(root, "beta")

	cfg := planConfig([]config.GuardManifest{
		{Name: "m", ReadOnlyDirectories: []string{b, a, b}},
	}, []string{"m"})

	grants, err := planManifests(cfg, "agent")
	if err != nil {
		t.Fatalf("planManifests: %v", err)
	}
	if len(grants) != 2 {
		t.Fatalf("grants = %+v, want the duplicate collapsed to 2", grants)
	}
	if grants[0].declared != a || grants[1].declared != b {
		t.Fatalf("order = %q,%q, want deterministic %q,%q", grants[0].declared, grants[1].declared, a, b)
	}
}

// A floor that cannot answer must refuse, not allow. "The floor errored" is not
// the same as "the floor said yes", and treating it as such would be a
// fail-open at the very first gate.
func TestPlanManifests_FloorErrorRefusesRatherThanAllows(t *testing.T) {
	root := t.TempDir()
	cfg := planConfig([]config.GuardManifest{
		{Name: "m", ReadOnly: []string{filepath.Join(root, "f")}},
	}, []string{"m"})

	boom := errors.New("floor unavailable")
	_, err := planManifestsWithFloor(cfg, "agent", func(string, config.GuardAccess) (config.GuardFloorDecision, error) {
		return config.GuardFloorDecision{}, boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the floor error propagated", err)
	}
}

func TestPrepare_GrantsExactFiles(t *testing.T) {
	root := t.TempDir()
	ro := filepath.Join(root, "config.yaml")
	rw := filepath.Join(root, "state.db")
	for _, f := range []string{ro, rw} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	cfg := planConfig([]config.GuardManifest{
		{Name: "m", ReadOnly: []string{ro}, ReadWrite: []string{rw}},
	}, []string{"m"})

	prepared, err := Prepare(cfg, "agent", os.Getuid())
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer func() { _ = prepared.Close() }()

	if !prepared.Complete() {
		t.Fatalf("outcomes = %+v, want complete", prepared.Outcomes())
	}
	// Assert the count first: a loop over an empty slice passes every check
	// inside it without examining anything.
	if len(prepared.rules) != 2 {
		t.Fatalf("rules = %d, want one per declared exact file", len(prepared.rules))
	}
	// Each exact-file grant must carry the file right set, never a directory
	// set: a directory mask on a regular file is rejected by the kernel and
	// would take the whole ruleset down with it.
	for _, r := range prepared.rules {
		if r.isDir {
			t.Fatalf("rule for %q marked as directory", r.declared)
		}
		if r.access != rightsReadFile && r.access != rightsWriteFile {
			t.Fatalf("rule for %q has access %#x, want a file right set", r.declared, r.access)
		}
	}
}

// A floor that errors on the RESOLVED target refuses too. This is the second
// floor call, after symlink resolution, and it has its own failure branch.
func TestPrepareGrants_ResolvedFloorErrorRefuses(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "state")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	grants := []grant{{declared: dir, access: AccessWriteDirectory}}

	prepared, err := prepareGrants(grants, os.Getuid(), func(string, config.GuardAccess) (config.GuardFloorDecision, error) {
		return config.GuardFloorDecision{}, errors.New("floor unavailable")
	})
	if err != nil {
		t.Fatalf("prepareGrants: %v", err)
	}
	defer func() { _ = prepared.Close() }()

	out := prepared.Outcomes()
	if len(out) != 1 || out[0].State != StateRefused {
		t.Fatalf("outcomes = %+v, want refused", out)
	}
	if !strings.Contains(out[0].Reason, "floor evaluation failed") {
		t.Errorf("reason = %q, want it to name the floor failure", out[0].Reason)
	}
	if prepared.Complete() {
		t.Error("a refused path must leave the manifest incomplete")
	}
}

// A declared state directory whose parent is a regular file is withheld, and
// nothing is created. This is the typo case.
func TestCreateLeaf_ParentIsNotADirectory(t *testing.T) {
	root := t.TempDir()
	notADir := filepath.Join(root, "file")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(notADir, "state")

	fd, state, reason := createLeaf(target, os.Getuid())
	if fd != -1 || state != StateWithheld {
		t.Fatalf("state = %q fd = %d, want withheld", state, fd)
	}
	if !strings.Contains(reason, "not an existing directory") {
		t.Errorf("reason = %q, want it to name the parent", reason)
	}
}

// Guard refuses to create state under a parent other users can write, because
// such a parent lets them pre-create or swap the leaf.
func TestCreateLeaf_RefusesWorldWritableParent(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "shared")
	if err := os.Mkdir(parent, 0o750); err != nil {
		t.Fatal(err)
	}
	// Composed at runtime rather than written as a wide literal.
	worldWritable := os.FileMode(0o750) | os.FileMode(1)<<1
	if err := os.Chmod(parent, worldWritable); err != nil {
		t.Fatal(err)
	}

	fd, state, reason := createLeaf(filepath.Join(parent, "state"), os.Getuid())
	if fd != -1 || state != StateRefused {
		t.Fatalf("state = %q fd = %d, want refused", state, fd)
	}
	if !strings.Contains(reason, "writable parent") {
		t.Errorf("reason = %q, want it to name the parent's mode", reason)
	}
}
