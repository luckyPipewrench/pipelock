// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package guard

import (
	"errors"
	"strings"
	"testing"
)

// These cover the decisions Apply makes BEFORE it touches the kernel.
//
// They can run in-process precisely because each one returns early: Landlock is
// irreversible, so a test that reached the syscalls would restrict the test
// binary itself for the rest of the run. Every case here is chosen to stop
// before that line, which is also why the incomplete-manifest case is the one
// used to exercise coverage tiering at a supported ABI.

func TestApply_RefusesWhenLandlockUnavailable(t *testing.T) {
	sentinel := errors.New("landlock syscall missing")
	p := &PreparedManifest{complete: true}

	record, err := p.apply(func() (int, error) { return 0, sentinel })

	if !errors.Is(err, ErrLandlockUnavailable) {
		t.Fatalf("err = %v, want ErrLandlockUnavailable", err)
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want the underlying cause wrapped", err)
	}
	if record.Enforced() || record.State != EnforcementRefused {
		t.Errorf("record = %+v, want refused", record)
	}
	// No reading was taken, which must stay distinguishable from a reading of
	// zero: a nil pointer says "unknown", a zero would say "ABI 0".
	if record.ObservedABI != nil {
		t.Errorf("ObservedABI = %v, want nil when the version could not be read", *record.ObservedABI)
	}
	if record.Coverage != CoverageUnknown {
		t.Errorf("Coverage = %q, want unknown", record.Coverage)
	}
}

func TestApply_RefusesBelowThreadSyncABI(t *testing.T) {
	p := &PreparedManifest{complete: true}

	record, err := p.apply(func() (int, error) { return ThreadSyncABI - 1, nil })

	if !errors.Is(err, ErrABITooOld) {
		t.Fatalf("err = %v, want ErrABITooOld", err)
	}
	if record.Enforced() {
		t.Error("a kernel without thread-synchronised restriction must not report enforced")
	}
	// The refusal has to name the alternative, or an operator on this kernel is
	// told no with nowhere to go. Applying the same ruleset in a single-threaded
	// child before exec needs only MinimumABI.
	if !strings.Contains(record.Reason, "single-threaded child") {
		t.Errorf("Reason = %q, want it to name the pre-exec alternative", record.Reason)
	}
	if record.ObservedABI == nil || *record.ObservedABI != ThreadSyncABI-1 {
		t.Errorf("ObservedABI = %v, want %d", record.ObservedABI, ThreadSyncABI-1)
	}
}

// TestApply_ReportsPartialCoverageBeforeRefusingIncompleteManifest exercises
// the coverage tiering at a supported ABI without reaching the syscalls.
//
// The incomplete manifest is the vehicle, not the subject: it forces an early
// return AFTER capabilities have been computed, which is the only way to
// observe the tiering in-process. The assertion that matters is that a kernel
// lacking socket mediation is recorded as partial with the gap named.
func TestApply_ReportsPartialCoverageBeforeRefusingIncompleteManifest(t *testing.T) {
	p := &PreparedManifest{complete: false}

	record, err := p.apply(func() (int, error) { return ThreadSyncABI, nil })

	if !errors.Is(err, ErrManifestIncomplete) {
		t.Fatalf("err = %v, want ErrManifestIncomplete", err)
	}
	if record.Enforced() {
		t.Error("an incomplete manifest must never report enforced")
	}
	if record.Coverage != CoveragePartial {
		t.Errorf("Coverage = %q, want partial below the socket-mediation ABI", record.Coverage)
	}
	if !containsSubstring(record.Unmediated, "unix socket") {
		t.Errorf("Unmediated = %v, want the socket gap named", record.Unmediated)
	}
	if record.ManifestComplete {
		t.Error("ManifestComplete must reflect the prepared state")
	}
}

// TestApply_FullCoverageAtSocketMediationABI is the counterpart: at the ABI
// that supplies every capability, nothing is reported as unmediated.
func TestApply_FullCoverageAtSocketMediationABI(t *testing.T) {
	p := &PreparedManifest{complete: false}

	record, err := p.apply(func() (int, error) { return SocketMediationABI, nil })

	// Pin the early return. If the incomplete-manifest check ever moved after
	// ruleset construction, this test would apply a real restriction to the test
	// binary for the rest of the run, and the resulting failures would point
	// everywhere except here.
	if !errors.Is(err, ErrManifestIncomplete) {
		t.Fatalf("err = %v, want ErrManifestIncomplete", err)
	}

	if record.Coverage != CoverageFull {
		t.Errorf("Coverage = %q, want full at ABI %d", record.Coverage, SocketMediationABI)
	}
	if len(record.Unmediated) != 0 {
		t.Errorf("Unmediated = %v, want empty at full coverage", record.Unmediated)
	}
}
