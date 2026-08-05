//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package convergence

import (
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
)

// TestClassify_UndeclaredFollowerIsNotConverged covers the desired-state
// boundary the report exists to establish.
//
// A follower that conductor knows about but that NO deployment intent declares
// is undeclared. It may be a rogue or forgotten enforcement point. Reporting it
// as fully converged because it happens to be healthy and producing evidence
// inverts the purpose of the report: the question is not "is this thing well",
// it is "is this thing supposed to be here".
func TestClassify_UndeclaredFollowerIsNotConverged(t *testing.T) {
	now := time.Now()
	fleetStatus := &controlplane.FollowerFleetStatus{
		// Active, so the inactive guard is not what this test trips on.
		FollowerSummary: controlplane.FollowerSummary{Active: true},
		Health:          controlplane.FleetHealthOK,
		RuntimeStatus: &controlplane.FollowerRuntimeStatus{
			ActiveBundleHash: "abc123",
		},
	}
	batch := &controlplane.AuditBatchSummary{ReceivedAt: now.Add(-time.Minute)}

	fc := classifyFollower("rogue-1", nil, fleetStatus, batch, now, time.Minute)

	if fc.State != StateUndeclared {
		t.Fatalf("an undeclared follower was reported as %q, want %q; a follower no "+
			"deployment intent declares must never be counted as converged, or an "+
			"unmanaged enforcement point reads as green", fc.State, StateUndeclared)
	}
}

// TestClassify_SignedStateMustNotMaskDisagreeingRuntime covers the case where
// two sources of truth disagree about which bundle is actually running.
//
// The signed applied state is a record of what a follower reported applying.
// The runtime status is what it says it is running now. If a stale signed
// record matches the desired digest while the live runtime reports a different
// bundle, preferring the signed record reports convergence for a proxy that is
// enforcing an old, downgraded, or tampered policy.
func TestClassify_SignedStateMustNotMaskDisagreeingRuntime(t *testing.T) {
	now := time.Now()
	fleetStatus := &controlplane.FollowerFleetStatus{
		// Active, so the inactive guard is not what this test trips on.
		FollowerSummary: controlplane.FollowerSummary{Active: true},
		Health:          controlplane.FleetHealthOK,
		RuntimeStatus: &controlplane.FollowerRuntimeStatus{
			// What the proxy says it is actually running right now.
			ActiveBundleHash: "OLD-DOWNGRADED-BUNDLE",
		},
		SignedAppliedState: &controlplane.VerifiedAppliedState{
			Verified: true,
			AppliedState: conductor.FollowerAppliedState{
				// A stale record that happens to match what we wanted.
				ActiveBundleHash: "desired-digest",
			},
		},
	}
	intent := &DeploymentIntent{DesiredReplicas: 1, DesiredDigest: "desired-digest"}
	batch := &controlplane.AuditBatchSummary{ReceivedAt: now.Add(-time.Minute)}

	fc := classifyFollower("follower-1", intent, fleetStatus, batch, now, time.Minute)

	if fc.State != StateUnknown {
		t.Fatalf("a follower whose signed state and live runtime disagree was reported "+
			"as %q, want %q; the stale signed record masked a runtime on %q", fc.State,
			StateUnknown, fleetStatus.RuntimeStatus.ActiveBundleHash)
	}
}
