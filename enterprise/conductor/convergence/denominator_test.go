// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package convergence

import (
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
)

// TestEvidenceSummary_StaleBatchIsNotHealthyEvidence covers the internal
// consistency of the denominators.
//
// Evidence coverage counted any follower with a non-nil batch as healthy, even
// one already classified stale. During an audit-delivery outage that reports a
// green evidence denominator while the convergence denominator says stale, so
// the two numbers contradict each other and the outage looks fine.
func TestEvidenceSummary_StaleBatchIsNotHealthyEvidence(t *testing.T) {
	followers := []FollowerConvergence{
		{
			InstanceID: "stale-1",
			State:      StateStale,
			LatestBatch: &AuditEvidence{
				BatchID: "b1",
			},
		},
	}

	s := evidenceSummary(followers)

	if s.Healthy != 0 {
		t.Fatalf("evidence coverage counted a stale follower as healthy (healthy=%d); "+
			"a stale follower's old batch is not healthy evidence delivery", s.Healthy)
	}
	if s.Total != 1 {
		t.Fatalf("evidence total = %d, want 1; a stale follower is still in scope", s.Total)
	}
	if s.Unknown != 1 {
		t.Fatalf("evidence unknown = %d, want 1; a stale follower must be explicitly "+
			"unvouchable rather than silently absent from both counts", s.Unknown)
	}
}

// TestBuild_DuplicateFleetStatusFailsClosed covers the second duplicate source.
//
// Build detects duplicate identity separately for intents and for fleet-status
// records. Covering only the intent path would leave the fleet-status path free
// to regress, since the two are independent maps built in different loops.
func TestBuild_DuplicateFleetStatusFailsClosed(t *testing.T) {
	now := time.Now().UTC()
	report := Build(Inputs{
		Now: now,
		FleetStatus: []controlplane.FollowerFleetStatus{
			{
				FollowerSummary: controlplane.FollowerSummary{InstanceID: "dup-fs", Active: true},
				Health:          controlplane.FleetHealthOK,
			},
			{
				FollowerSummary: controlplane.FollowerSummary{InstanceID: "dup-fs", Active: true},
				Health:          controlplane.FleetHealthOK,
			},
		},
	})

	var found *FollowerConvergence
	for i := range report.Followers {
		if report.Followers[i].InstanceID == "dup-fs" {
			found = &report.Followers[i]
		}
	}
	if found == nil {
		t.Fatal("duplicate fleet-status instance ID vanished from the report entirely")
	}
	if found.State != StateUnknown {
		t.Fatalf("duplicate fleet-status record reported as %q, want %q", found.State, StateUnknown)
	}
}

// TestBuild_DuplicateInstanceIDFailsClosed covers ambiguous identity.
//
// Intent and fleet-status maps took the last slice entry for a repeated
// instance ID, so a duplicate marked Excluded or DesiredReplicas:0 could
// suppress a real unhealthy instance purely by input ordering. Ambiguous
// identity across independent control-plane sources is a data-integrity
// condition and must be visible, not resolved by whichever record sorted last.
func TestBuild_DuplicateInstanceIDFailsClosed(t *testing.T) {
	now := time.Now().UTC()
	report := Build(Inputs{
		Now: now,
		Intents: []DeploymentIntent{
			{InstanceID: "dup-1", DesiredReplicas: 1},
			// A second record for the same ID that would silently win and
			// suppress the instance entirely.
			{InstanceID: "dup-1", Excluded: true, ExcludedReason: "suppressed"},
		},
	})

	var found *FollowerConvergence
	for i := range report.Followers {
		if report.Followers[i].InstanceID == "dup-1" {
			found = &report.Followers[i]
		}
	}
	if found == nil {
		t.Fatal("duplicate instance ID vanished from the report entirely")
	}
	if found.State == StateExcluded {
		t.Fatal("a duplicate intent record marked excluded suppressed the instance; " +
			"conflicting identity records must fail closed, not be resolved by ordering")
	}
	if found.State != StateUnknown {
		t.Fatalf("duplicate instance ID reported as %q, want unknown with a conflict reason", found.State)
	}
}

// TestClassify_InactiveFollowerIsNotConverged covers the state definition.
//
// StateFullyConverged is documented as "enrolled, active, healthy". A
// deactivated follower carrying historical OK health and a recent batch was
// still reported converged, which hides lost enforcement capacity after a
// follower is deactivated or stops serving traffic.
func TestClassify_InactiveFollowerIsNotConverged(t *testing.T) {
	now := time.Now().UTC()
	fleetStatus := &controlplane.FollowerFleetStatus{
		FollowerSummary: controlplane.FollowerSummary{Active: false},
		Health:          controlplane.FleetHealthOK,
		RuntimeStatus:   &controlplane.FollowerRuntimeStatus{ActiveBundleHash: "abc123"},
	}
	intent := &DeploymentIntent{DesiredReplicas: 1}
	batch := &controlplane.AuditBatchSummary{ReceivedAt: now.Add(-time.Minute)}

	fc := classifyFollower("inactive-1", intent, fleetStatus, batch, now, time.Minute)

	if fc.State != StateStale {
		t.Fatalf("an inactive follower was reported as %q, want %q; converged means "+
			"enrolled, active and healthy, so a deactivated follower hides lost capacity",
			fc.State, StateStale)
	}
}

// TestClassify_UnrecognizedHealthFailsClosed covers the denylist-to-allowlist
// change in health handling.
//
// The classifier rejected four specific known-bad health values, so any other
// value, including a FleetHealth constant added in a later release, fell
// straight through to the converged path. A health value this code has never
// heard of must fail closed rather than be read as fine.
func TestClassify_UnrecognizedHealthFailsClosed(t *testing.T) {
	now := time.Now().UTC()
	fleetStatus := &controlplane.FollowerFleetStatus{
		FollowerSummary: controlplane.FollowerSummary{Active: true},
		// A value this code does not know about, standing in for a constant
		// added by a future release.
		Health:        controlplane.FleetHealth("some_future_health"),
		RuntimeStatus: &controlplane.FollowerRuntimeStatus{ActiveBundleHash: "abc123"},
	}
	intent := &DeploymentIntent{DesiredReplicas: 1}
	batch := &controlplane.AuditBatchSummary{ReceivedAt: now.Add(-time.Minute)}

	fc := classifyFollower("future-1", intent, fleetStatus, batch, now, time.Minute)

	if fc.State != StateUnknown {
		t.Fatalf("a follower with unrecognized health was reported as %q, want %q; "+
			"an unknown health value must fail closed, not reach converged", fc.State, StateUnknown)
	}
}

// TestClassify_ScaledZeroButStillActiveIsNotAbsent covers the ordering of the
// scaled-zero shortcut.
//
// Scaled-zero claims a follower is intentionally absent. Deciding it before any
// runtime check meant a follower that was still enrolled and active got
// reported as intentionally gone, which hides a live enforcement point that
// nobody expects to exist.
func TestClassify_ScaledZeroButStillActiveIsNotAbsent(t *testing.T) {
	now := time.Now().UTC()
	fleetStatus := &controlplane.FollowerFleetStatus{
		FollowerSummary: controlplane.FollowerSummary{Active: true},
		Health:          controlplane.FleetHealthOK,
		RuntimeStatus:   &controlplane.FollowerRuntimeStatus{ActiveBundleHash: "abc123"},
	}
	intent := &DeploymentIntent{DesiredReplicas: 0}

	fc := classifyFollower("ghost-1", intent, fleetStatus, nil, now, time.Minute)

	if fc.State == StateScaledZero {
		t.Fatal("a follower that is still enrolled and active was reported as scaled " +
			"to zero; a live enforcement point nobody expects must not read as " +
			"intentionally absent")
	}
	if fc.State != StateUnknown {
		t.Fatalf("scaled-zero-but-active reported as %q, want %q", fc.State, StateUnknown)
	}
}
