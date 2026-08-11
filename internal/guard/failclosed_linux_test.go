// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package guard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRightsFor_UnknownAccessGrantsNothing pins the direction of the default.
//
// The earlier default returned the writable-directory set, so an access kind
// this package had never seen received the widest rights it issues. The test
// asserts the zero result rather than a specific alternative set, because any
// non-zero answer to an unrecognized input is the bug.
func TestRightsFor_UnknownAccessGrantsNothing(t *testing.T) {
	if got := rightsFor(AccessKind("something-nobody-defined")); got != 0 {
		t.Fatalf("rightsFor(unknown) = %#x, want no rights", got)
	}
	// The four known kinds must keep their sets, so failing closed on the
	// unknown case cannot quietly disarm the real ones.
	for _, k := range []AccessKind{AccessReadFile, AccessReadDirectory, AccessWriteFile, AccessWriteDirectory} {
		if rightsFor(k) == 0 {
			t.Errorf("rightsFor(%q) = 0, want a right set", k)
		}
	}
}

// An unrecognized kind must refuse the grant rather than build a rule with no
// rights, which the kernel rejects and which would take the whole ruleset with
// it.
func TestPrepareGrants_UnknownAccessIsRefused(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "state")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}

	prepared, err := prepareGrants(
		[]grant{{declared: dir, access: AccessKind("unknown")}},
		os.Getuid(),
		mockFloorAllows,
	)
	if err != nil {
		t.Fatalf("prepareGrants: %v", err)
	}
	defer func() { _ = prepared.Close() }()

	out := prepared.Outcomes()
	if len(out) != 1 || out[0].State != StateRefused {
		t.Fatalf("outcomes = %+v, want refused", out)
	}
	if !strings.Contains(out[0].Reason, "unrecognized access kind") {
		t.Errorf("reason = %q, want it to name the unrecognized kind", out[0].Reason)
	}
	if prepared.Complete() {
		t.Error("a refused grant must leave the manifest incomplete")
	}
	if len(prepared.rules) != 0 {
		t.Errorf("rules = %d, want no rule built for an unrecognized kind", len(prepared.rules))
	}
}

// Prepare returns a nil manifest when planning fails, and its contract tells
// callers to Close on every path out, so the documented usage must not panic.
func TestPreparedManifest_CloseOnNilReceiver(t *testing.T) {
	var p *PreparedManifest
	if err := p.Close(); err != nil {
		t.Fatalf("Close() on nil = %v, want nil", err)
	}

	cfg := planConfig(nil, []string{"ghost"})
	prepared, err := Prepare(cfg, "agent", os.Getuid())
	if err == nil {
		t.Fatal("expected a planning error for an unknown manifest")
	}
	// This is the exact line the documented contract asks callers to write.
	if cerr := prepared.Close(); cerr != nil {
		t.Fatalf("Close() after a failed Prepare = %v, want nil", cerr)
	}
}

// TestEnforcementRecord_DescribeAppliedNarrowed: the process IS restricted, and
// the first clause has to say so.
func TestEnforcementRecord_DescribeAppliedNarrowed(t *testing.T) {
	abi := SocketMediationABI
	got := EnforcementRecord{
		State:       EnforcementAppliedNarrowed,
		Mechanism:   "landlock",
		ObservedABI: &abi,
		Coverage:    CoverageFull,
		Reason:      "/var/lib/agent/state is unreachable",
	}.Describe()

	if !strings.Contains(got, "APPLIED") {
		t.Errorf("Describe() = %q, want it to state the restriction was applied", got)
	}
	if strings.Contains(got, "not run") {
		t.Errorf("Describe() = %q, must not say the process was left untouched", got)
	}
	if !strings.Contains(got, "NOT in force as declared") {
		t.Errorf("Describe() = %q, want it to state the manifest is not in force", got)
	}
}
