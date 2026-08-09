//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package convergence

import (
	"slices"
	"strings"
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
		Intents: []DeploymentIntent{
			{InstanceID: "dup-fs", DesiredReplicas: 1},
		},
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
	if report.DeliveryHealth.Expected != 1 || report.DeliveryHealth.Current != 0 ||
		!slices.Equal(report.DeliveryHealth.Alerting, []string{"dup-fs"}) {
		t.Fatalf("duplicate expected producer delivery health = %+v, want one alerting producer; "+
			"an ambiguous expected producer must not leave the exit-code gate green", report.DeliveryHealth)
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
			{InstanceID: "dup-1", Excluded: true, ExcludedOwner: "ops", ExcludedReason: "suppressed"},
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
	if report.DeliveryHealth.Expected != 1 || report.DeliveryHealth.Current != 0 ||
		!slices.Equal(report.DeliveryHealth.Alerting, []string{"dup-1"}) {
		t.Fatalf("conflicting expected producer delivery health = %+v, want one alerting producer; "+
			"an excluded duplicate must not suppress an expected producer", report.DeliveryHealth)
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

// TestClassify_UncoveredFailClosedBranches covers the four classifier branches
// the state table did not reach.
//
// The last two are fail-closed paths, which are exactly the ones whose
// regression would be silent: if either stopped firing, the follower would fall
// through to StateFullyConverged and the report would call an unprovable
// follower converged.
func TestClassify_UncoveredFailClosedBranches(t *testing.T) {
	now := time.Now().UTC()
	activeOK := func(h controlplane.FleetHealth) *controlplane.FollowerFleetStatus {
		return &controlplane.FollowerFleetStatus{
			FollowerSummary: controlplane.FollowerSummary{Active: true},
			Health:          h,
		}
	}

	tests := []struct {
		name      string
		intent    *DeploymentIntent
		status    *controlplane.FollowerFleetStatus
		batch     *controlplane.AuditBatchSummary
		wantState FollowerState
	}{
		{
			name:      "apply failed is stale",
			intent:    &DeploymentIntent{DesiredReplicas: 1},
			status:    activeOK(controlplane.FleetHealthApplyFailed),
			wantState: StateStale,
		},
		{
			name:      "unsupported runtime version is wrong digest",
			intent:    &DeploymentIntent{DesiredReplicas: 1},
			status:    activeOK(controlplane.FleetHealthUnsupported),
			wantState: StateWrongDigest,
		},
		{
			name:   "desired digest with no active bundle hash is unknown",
			intent: &DeploymentIntent{DesiredReplicas: 1, DesiredDigest: "aaaa"},
			// Healthy, but nothing reports which bundle is actually running.
			status:    activeOK(controlplane.FleetHealthOK),
			wantState: StateUnknown,
		},
		{
			name:   "batch older than the evidence window is stale",
			intent: &DeploymentIntent{DesiredReplicas: 1},
			status: activeOK(controlplane.FleetHealthOK),
			batch: &controlplane.AuditBatchSummary{
				ReceivedAt: now.Add(-(evidenceStaleWindowMultiple + 2) * time.Minute),
			},
			wantState: StateStale,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fc := classifyFollower("f-1", tc.intent, tc.status, tc.batch, now, time.Minute)
			if fc.State != tc.wantState {
				t.Fatalf("state = %q, want %q (reason: %s)", fc.State, tc.wantState, fc.Reason)
			}
			if fc.State == StateFullyConverged {
				t.Fatal("a fail-closed branch fell through to converged")
			}
		})
	}
}

// TestEvidence_RuntimeBuildIsPopulated pins the runtime_build field.
//
// The audit batch summary does not carry the emitting follower's Pipelock
// version, so it has to come from the follower's runtime status. Without this
// the report advertises a runtime_build field that is always empty, which
// overclaims what the evidence layer can tell an operator.
func TestEvidence_RuntimeBuildIsPopulated(t *testing.T) {
	now := time.Now().UTC()
	fleetStatus := &controlplane.FollowerFleetStatus{
		FollowerSummary: controlplane.FollowerSummary{Active: true},
		Health:          controlplane.FleetHealthOK,
		RuntimeStatus: &controlplane.FollowerRuntimeStatus{
			PipelockVersion: "3.4.0",
		},
	}
	intent := &DeploymentIntent{DesiredReplicas: 1}
	batch := &controlplane.AuditBatchSummary{ReceivedAt: now.Add(-time.Minute)}

	fc := classifyFollower("f-1", intent, fleetStatus, batch, now, time.Minute)

	if fc.LatestBatch == nil {
		t.Fatal("expected latest_batch to be present")
	}
	if fc.LatestBatch.RuntimeBuild != "3.4.0" {
		t.Fatalf("runtime_build = %q, want %q; the report declares this field, so "+
			"leaving it empty overclaims what the evidence layer reports",
			fc.LatestBatch.RuntimeBuild, "3.4.0")
	}
}

func TestDeliveryHealth_ExpectedCurrentAndAlerting(t *testing.T) {
	now := time.Now().UTC()
	health := deliveryHealth([]FollowerConvergence{
		{
			InstanceID: "current",
			State:      StateFullyConverged,
			LatestBatch: &AuditEvidence{
				ReceivedAt: now.Add(-time.Minute),
			},
			DeploymentIntent: &DeploymentIntent{
				InstanceID: "current", DesiredReplicas: 1,
			},
		},
		{
			InstanceID: "rolling",
			State:      StateWrongDigest,
			LatestBatch: &AuditEvidence{
				ReceivedAt: now.Add(-time.Minute),
			},
			DeploymentIntent: &DeploymentIntent{
				InstanceID: "rolling", DesiredReplicas: 1,
			},
		},
		{
			InstanceID: "stale",
			State:      StateStale,
			DeploymentIntent: &DeploymentIntent{
				InstanceID: "stale", DesiredReplicas: 1,
			},
		},
		{
			InstanceID: "missing",
			State:      StateCurrentWithoutBatch,
			DeploymentIntent: &DeploymentIntent{
				InstanceID: "missing", DesiredReplicas: 1,
			},
		},
		{
			InstanceID: "local-only",
			State:      StateExcluded,
			DeploymentIntent: &DeploymentIntent{
				InstanceID: "local-only", DesiredReplicas: 1, Excluded: true,
				ExcludedOwner: "ops", ExcludedReason: "local-only proxy",
			},
		},
		{
			InstanceID: "scaled-zero",
			State:      StateScaledZero,
			DeploymentIntent: &DeploymentIntent{
				InstanceID: "scaled-zero", DesiredReplicas: 0,
			},
		},
	}, now, time.Minute)
	if health.Expected != 4 || health.Current != 2 {
		t.Fatalf("expected/current = %d/%d, want 4/2", health.Expected, health.Current)
	}
	if got, want := strings.Join(health.Alerting, ","), "stale,missing"; got != want {
		t.Fatalf("alerting = %q, want %q", got, want)
	}
}

func TestRuntimeAndConductorSummariesDoNotVouchForUnknownState(t *testing.T) {
	healthOK := controlplane.FleetHealthOK
	followers := []FollowerConvergence{{
		InstanceID:      "unprovable",
		State:           StateUnknown,
		ConductorHealth: &healthOK,
	}}

	for name, summary := range map[string]DenominatorSummary{
		"runtime":   runtimeSummary(followers),
		"conductor": conductorSummary(followers),
	} {
		if summary.Total != 1 || summary.Healthy != 0 || summary.Unknown != 1 {
			t.Errorf("%s summary = %+v, want one unknown and no healthy followers", name, summary)
		}
	}
}

func TestDeliveryBatchCurrentBoundaries(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		name       string
		batch      *AuditEvidence
		staleAfter time.Duration
		want       bool
	}{
		{name: "missing", batch: nil, staleAfter: time.Minute},
		{name: "zero timestamp", batch: &AuditEvidence{}, staleAfter: time.Minute},
		{name: "within clock skew", batch: &AuditEvidence{ReceivedAt: now.Add(time.Second)}, staleAfter: time.Minute, want: true},
		{name: "beyond clock skew", batch: &AuditEvidence{ReceivedAt: now.Add(deliveryClockSkewAllowance + time.Nanosecond)}, staleAfter: time.Minute},
		{name: "at boundary", batch: &AuditEvidence{ReceivedAt: now.Add(-6 * time.Minute)}, staleAfter: time.Minute, want: true},
		{name: "past boundary", batch: &AuditEvidence{ReceivedAt: now.Add(-6*time.Minute - time.Nanosecond)}, staleAfter: time.Minute},
		{name: "default window", batch: &AuditEvidence{ReceivedAt: now.Add(-29 * time.Minute)}, want: true},
		{name: "overflowing direct caller window saturates", batch: &AuditEvidence{ReceivedAt: now.Add(-time.Hour)}, staleAfter: MaxEvidenceStaleAfter() + time.Nanosecond, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := deliveryBatchCurrent(tt.batch, now, tt.staleAfter); got != tt.want {
				t.Fatalf("deliveryBatchCurrent() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestClassifyFutureBatchIsUnknown(t *testing.T) {
	now := time.Now().UTC()
	status := &controlplane.FollowerFleetStatus{
		FollowerSummary: controlplane.FollowerSummary{Active: true},
		Health:          controlplane.FleetHealthOK,
	}
	intent := &DeploymentIntent{DesiredReplicas: 1}
	batch := &controlplane.AuditBatchSummary{
		ReceivedAt: now.Add(deliveryClockSkewAllowance + time.Nanosecond),
	}

	follower := classifyFollower("future", intent, status, batch, now, time.Minute)
	if follower.State != StateUnknown {
		t.Fatalf("future-dated batch state = %q, want %q", follower.State, StateUnknown)
	}
}

func TestLatestBatchMapPrefersPlausibleTimestamp(t *testing.T) {
	now := time.Now().UTC()
	batches := []controlplane.AuditBatchSummary{
		{InstanceID: "producer", BatchID: "recent", ReceivedAt: now.Add(-time.Minute)},
		{InstanceID: "producer", BatchID: "future", ReceivedAt: now.Add(time.Hour)},
	}

	latest := latestBatchMap(batches, now)["producer"]
	if latest == nil || latest.BatchID != "recent" {
		t.Fatalf("latest plausible batch = %+v, want recent", latest)
	}
}
