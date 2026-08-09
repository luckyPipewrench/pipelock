//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package convergence

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
)

func TestBuild_SixFixtureStates(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	recentBatchTime := now.Add(-1 * time.Minute)
	healthOK := controlplane.FleetHealthOK
	healthStale := controlplane.FleetHealthStale
	healthUnknown := controlplane.FleetHealthUnknown

	tests := []struct {
		name      string
		inputs    Inputs
		wantState FollowerState
		wantID    string
	}{
		{
			name: "scaled_zero",
			inputs: Inputs{
				OrgID: "org1", FleetID: "fleet1", Now: now,
				Intents: []DeploymentIntent{
					{InstanceID: "scaled-zero-1", DesiredReplicas: 0},
				},
			},
			wantState: StateScaledZero,
			wantID:    "scaled-zero-1",
		},
		{
			name: "unenrolled",
			inputs: Inputs{
				OrgID: "org1", FleetID: "fleet1", Now: now,
				Intents: []DeploymentIntent{
					{InstanceID: "unenrolled-1", DesiredReplicas: 1},
				},
				// No fleet status for this instance.
			},
			wantState: StateUnenrolled,
			wantID:    "unenrolled-1",
		},
		{
			name: "stale",
			inputs: Inputs{
				OrgID: "org1", FleetID: "fleet1", Now: now,
				Intents: []DeploymentIntent{
					{InstanceID: "stale-1", DesiredReplicas: 1},
				},
				FleetStatus: []controlplane.FollowerFleetStatus{
					{
						FollowerSummary: controlplane.FollowerSummary{InstanceID: "stale-1", Active: true},
						Health:          healthStale,
						Drift:           "status_stale",
					},
				},
			},
			wantState: StateStale,
			wantID:    "stale-1",
		},
		{
			name: "wrong_digest",
			inputs: Inputs{
				OrgID: "org1", FleetID: "fleet1", Now: now,
				Intents: []DeploymentIntent{
					{InstanceID: "wrong-1", DesiredReplicas: 1, DesiredDigest: "aaaa"},
				},
				FleetStatus: []controlplane.FollowerFleetStatus{
					{
						FollowerSummary: controlplane.FollowerSummary{InstanceID: "wrong-1", Active: true},
						Health:          healthOK,
						RuntimeStatus: &controlplane.FollowerRuntimeStatus{
							ActiveBundleHash: "bbbb",
							LastSeenAt:       now.Add(-30 * time.Second),
						},
					},
				},
			},
			wantState: StateWrongDigest,
			wantID:    "wrong-1",
		},
		{
			name: "current_without_batch",
			inputs: Inputs{
				OrgID: "org1", FleetID: "fleet1", Now: now,
				Intents: []DeploymentIntent{
					{InstanceID: "nobatch-1", DesiredReplicas: 1},
				},
				FleetStatus: []controlplane.FollowerFleetStatus{
					{
						FollowerSummary: controlplane.FollowerSummary{InstanceID: "nobatch-1", Active: true},
						Health:          healthOK,
					},
				},
				// No audit batches.
			},
			wantState: StateCurrentWithoutBatch,
			wantID:    "nobatch-1",
		},
		{
			name: "fully_converged",
			inputs: Inputs{
				OrgID: "org1", FleetID: "fleet1", Now: now,
				Intents: []DeploymentIntent{
					{InstanceID: "converged-1", DesiredReplicas: 1},
				},
				FleetStatus: []controlplane.FollowerFleetStatus{
					{
						FollowerSummary: controlplane.FollowerSummary{InstanceID: "converged-1", Active: true},
						Health:          healthOK,
					},
				},
				AuditBatches: []controlplane.AuditBatchSummary{
					{
						BatchID:    "batch-1",
						InstanceID: "converged-1",
						ReceivedAt: recentBatchTime,
						EmittedAt:  recentBatchTime.Add(-5 * time.Second),
					},
				},
			},
			wantState: StateFullyConverged,
			wantID:    "converged-1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			report := Build(tc.inputs)
			if len(report.Followers) != 1 {
				t.Fatalf("expected 1 follower, got %d", len(report.Followers))
			}
			fc := report.Followers[0]
			if fc.InstanceID != tc.wantID {
				t.Errorf("instance_id = %q, want %q", fc.InstanceID, tc.wantID)
			}
			if fc.State != tc.wantState {
				t.Errorf("state = %q, want %q (reason: %s)", fc.State, tc.wantState, fc.Reason)
			}
		})
	}

	// Verify that unknown health renders as unknown state, not converged
	// (fail-closed direction).
	t.Run("unknown_health_is_not_converged", func(t *testing.T) {
		report := Build(Inputs{
			OrgID: "org1", FleetID: "fleet1", Now: now,
			Intents: []DeploymentIntent{
				{InstanceID: "unk-1", DesiredReplicas: 1},
			},
			FleetStatus: []controlplane.FollowerFleetStatus{
				{
					FollowerSummary: controlplane.FollowerSummary{InstanceID: "unk-1", Active: true},
					Health:          healthUnknown,
					Drift:           "no_status",
				},
			},
		})
		if len(report.Followers) != 1 {
			t.Fatalf("expected 1 follower, got %d", len(report.Followers))
		}
		if report.Followers[0].State != StateUnknown {
			t.Errorf("state = %q, want %q", report.Followers[0].State, StateUnknown)
		}
	})

	// Verify excluded state.
	t.Run("excluded_is_na", func(t *testing.T) {
		report := Build(Inputs{
			OrgID: "org1", FleetID: "fleet1", Now: now,
			Intents: []DeploymentIntent{
				{InstanceID: "local-1", DesiredReplicas: 1, Excluded: true, ExcludedReason: "local-only proxy"},
			},
		})
		if len(report.Followers) != 1 {
			t.Fatalf("expected 1 follower, got %d", len(report.Followers))
		}
		fc := report.Followers[0]
		if fc.State != StateExcluded {
			t.Errorf("state = %q, want %q", fc.State, StateExcluded)
		}
		if fc.Reason != "local-only proxy" {
			t.Errorf("reason = %q, want %q", fc.Reason, "local-only proxy")
		}
	})
}

func TestBuild_FourDenominatorsNeverCollapsed(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)

	report := Build(Inputs{
		OrgID: "org1", FleetID: "fleet1", Now: now,
		Intents: []DeploymentIntent{
			{InstanceID: "a", DesiredReplicas: 1},
			{InstanceID: "b", DesiredReplicas: 1},
		},
		FleetStatus: []controlplane.FollowerFleetStatus{
			{
				FollowerSummary: controlplane.FollowerSummary{InstanceID: "a", Active: true},
				Health:          controlplane.FleetHealthOK,
			},
			// "b" has no fleet status = unenrolled.
		},
		AuditBatches: []controlplane.AuditBatchSummary{
			{
				BatchID:    "batch-a",
				InstanceID: "a",
				ReceivedAt: now.Add(-30 * time.Second),
				EmittedAt:  now.Add(-35 * time.Second),
			},
		},
	})

	// Deployment: 2 total, "a" healthy, "b" unenrolled (not healthy).
	if report.DeploymentCoverage.Total != 2 {
		t.Errorf("deployment total = %d, want 2", report.DeploymentCoverage.Total)
	}
	// Runtime: 2 total (excludes scaled_zero/excluded, both a and b count).
	if report.RuntimeCoverage.Total != 2 {
		t.Errorf("runtime total = %d, want 2", report.RuntimeCoverage.Total)
	}
	// Evidence: 2 total, only "a" has a batch.
	if report.EvidenceCoverage.Total != 2 {
		t.Errorf("evidence total = %d, want 2", report.EvidenceCoverage.Total)
	}
	if report.EvidenceCoverage.Healthy != 1 {
		t.Errorf("evidence healthy = %d, want 1", report.EvidenceCoverage.Healthy)
	}

	// The four denominators MUST be independently queryable, never one collapsed
	// number. This assertion runs unconditionally: it was previously guarded by
	// the deployment and evidence numbers happening to be equal, so a fixture
	// change that made them differ would have skipped the check entirely while
	// the test kept passing under a name claiming an unconditional invariant.
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"deployment_coverage", "runtime_coverage", "conductor_coverage", "evidence_coverage"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing top-level key %q in report JSON", key)
		}
	}
}

func TestBuild_UnknownInputFailsClosed(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)

	// A follower that appears only in audit batches (no intent, no fleet status)
	// must be unknown, not converged.
	report := Build(Inputs{
		OrgID: "org1", FleetID: "fleet1", Now: now,
		AuditBatches: []controlplane.AuditBatchSummary{
			{
				BatchID:    "batch-orphan",
				InstanceID: "orphan-1",
				ReceivedAt: now.Add(-10 * time.Second),
			},
		},
	})

	if len(report.Followers) != 1 {
		t.Fatalf("expected 1 follower, got %d", len(report.Followers))
	}
	fc := report.Followers[0]
	if fc.State != StateUnknown {
		t.Errorf("orphan state = %q, want %q", fc.State, StateUnknown)
	}
}

func TestBuild_EvidenceFields(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	emitted := now.Add(-15 * time.Second)
	received := now.Add(-10 * time.Second)

	report := Build(Inputs{
		OrgID: "org1", FleetID: "fleet1", Now: now,
		Intents: []DeploymentIntent{
			{InstanceID: "ev-1", DesiredReplicas: 1},
		},
		FleetStatus: []controlplane.FollowerFleetStatus{
			{
				FollowerSummary: controlplane.FollowerSummary{InstanceID: "ev-1", Active: true},
				Health:          controlplane.FleetHealthOK,
			},
		},
		AuditBatches: []controlplane.AuditBatchSummary{
			{
				BatchID:         "b1",
				InstanceID:      "ev-1",
				AuditSchema:     3,
				SeqStart:        100,
				SeqEnd:          200,
				DroppedCount:    2,
				SignatureKeyIDs: []string{"key-abc"},
				ReceivedAt:      received,
				EmittedAt:       emitted,
			},
		},
	})

	// Guard the index: if Build ever stops emitting this follower, an unguarded
	// report.Followers[0] panics instead of reporting which invariant broke.
	if len(report.Followers) != 1 {
		t.Fatalf("followers = %d, want 1", len(report.Followers))
	}
	fc := report.Followers[0]
	if fc.LatestBatch == nil {
		t.Fatal("expected latest_batch to be non-nil")
	}
	ev := fc.LatestBatch
	if ev.BatchID != "b1" {
		t.Errorf("batch_id = %q, want %q", ev.BatchID, "b1")
	}
	if ev.SchemaVersion != 3 {
		t.Errorf("schema_version = %d, want 3", ev.SchemaVersion)
	}
	if ev.SeqStart != 100 || ev.SeqEnd != 200 {
		t.Errorf("seq range = [%d, %d], want [100, 200]", ev.SeqStart, ev.SeqEnd)
	}
	if ev.DroppedCount != 2 {
		t.Errorf("dropped_count = %d, want 2", ev.DroppedCount)
	}
	if ev.SignerKeyID != "key-abc" {
		t.Errorf("signer_key_id = %q, want %q", ev.SignerKeyID, "key-abc")
	}
	wantLag := received.Sub(emitted).Seconds()
	if ev.DeliveryLagSecs != wantLag {
		t.Errorf("delivery_lag_secs = %f, want %f", ev.DeliveryLagSecs, wantLag)
	}
}

func TestBuild_AllStatesDistinguishable(t *testing.T) {
	// Every distinguishable state must be reachable in one mixed report, so a
	// state that silently stops being produced fails here rather than quietly
	// disappearing from operator-visible output.
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	healthOK := controlplane.FleetHealthOK
	healthStale := controlplane.FleetHealthStale

	report := Build(Inputs{
		OrgID: "org1", FleetID: "fleet1", Now: now,
		Intents: []DeploymentIntent{
			{InstanceID: "a-scaled-zero", DesiredReplicas: 0},
			{InstanceID: "b-unenrolled", DesiredReplicas: 1},
			{InstanceID: "c-stale", DesiredReplicas: 1},
			{InstanceID: "d-wrong", DesiredReplicas: 1, DesiredDigest: "aaaa"},
			{InstanceID: "e-nobatch", DesiredReplicas: 1},
			{InstanceID: "f-converged", DesiredReplicas: 1},
			{InstanceID: "g-excluded", DesiredReplicas: 1, Excluded: true, ExcludedOwner: "ops", ExcludedReason: "test only"},
			{InstanceID: "i-unknown", DesiredReplicas: 1},
		},
		FleetStatus: []controlplane.FollowerFleetStatus{
			{FollowerSummary: controlplane.FollowerSummary{InstanceID: "c-stale", Active: true}, Health: healthStale, Drift: "status_stale"},
			{FollowerSummary: controlplane.FollowerSummary{InstanceID: "d-wrong", Active: true}, Health: healthOK, RuntimeStatus: &controlplane.FollowerRuntimeStatus{ActiveBundleHash: "bbbb"}},
			{FollowerSummary: controlplane.FollowerSummary{InstanceID: "e-nobatch", Active: true}, Health: healthOK},
			{FollowerSummary: controlplane.FollowerSummary{InstanceID: "f-converged", Active: true}, Health: healthOK},
			// Enrolled and healthy but declared by no deployment intent.
			{FollowerSummary: controlplane.FollowerSummary{InstanceID: "h-undeclared", Active: true}, Health: healthOK},
			// A health value this code does not recognize must fail closed.
			{FollowerSummary: controlplane.FollowerSummary{InstanceID: "i-unknown", Active: true}, Health: controlplane.FleetHealth("some_future_health")},
		},
		AuditBatches: []controlplane.AuditBatchSummary{
			{BatchID: "b-f", InstanceID: "f-converged", ReceivedAt: now.Add(-30 * time.Second), EmittedAt: now.Add(-35 * time.Second)},
		},
	})

	stateMap := make(map[FollowerState]string)
	for _, fc := range report.Followers {
		if prev, ok := stateMap[fc.State]; ok {
			t.Errorf("state %q appears for both %q and %q", fc.State, prev, fc.InstanceID)
		}
		stateMap[fc.State] = fc.InstanceID
	}

	required := []FollowerState{
		StateScaledZero, StateUnenrolled, StateStale,
		StateWrongDigest, StateCurrentWithoutBatch, StateFullyConverged,
		StateExcluded, StateUndeclared, StateUnknown,
	}
	for _, s := range required {
		if _, ok := stateMap[s]; !ok {
			t.Errorf("missing required state %q in combined report", s)
		}
	}
}
