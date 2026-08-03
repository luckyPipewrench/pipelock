// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

// Package convergence produces a read-only fleet convergence report that joins
// four independent denominators: deployment intent, running images, conductor
// runtime status, and accepted audit evidence. Each denominator is reported
// separately; collapsing them into a single percentage is explicitly forbidden
// because deployment coverage is not evidence coverage.
package convergence

import (
	"fmt"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
)

// FollowerState enumerates the distinguishable states a follower can occupy.
// The zero value is intentionally invalid so an unset state is never silently
// treated as converged.
type FollowerState string

const (
	// StateFullyConverged means the follower is enrolled, active, healthy,
	// running the expected bundle, and has a recent accepted audit batch.
	StateFullyConverged FollowerState = "fully_converged"

	// StateCurrentWithoutBatch means runtime is healthy and on the expected
	// bundle but no accepted audit batch exists for this follower.
	StateCurrentWithoutBatch FollowerState = "current_without_batch"

	// StateStale means the follower's runtime status or signed applied state
	// is older than the staleness threshold.
	StateStale FollowerState = "stale"

	// StateWrongDigest means the follower is running a bundle hash that does
	// not match the expected bundle for its audience.
	StateWrongDigest FollowerState = "wrong_digest"

	// StateUnenrolled means the follower appears in the deployment intent
	// but has no enrollment record.
	StateUnenrolled FollowerState = "unenrolled"

	// StateScaledZero means the deployment intent declares zero desired
	// replicas; the follower is intentionally absent.
	StateScaledZero FollowerState = "scaled_zero"

	// StateUnknown means the follower's state could not be determined
	// (unreachable, unparseable, or missing data). This is the fail-closed
	// default: anything not provably healthy is unknown.
	StateUnknown FollowerState = "unknown"

	// StateExcluded means the follower is explicitly marked as not an
	// expected receipt producer (local-only proxy, test instance, etc.).
	StateExcluded FollowerState = "excluded"
)

// DeploymentIntent is the GitOps/desired declaration for one follower.
type DeploymentIntent struct {
	InstanceID      string `json:"instance_id"`
	DesiredReplicas int    `json:"desired_replicas"`
	DesiredDigest   string `json:"desired_digest,omitempty"`
	// Excluded marks this instance as intentionally not an expected receipt
	// producer. The Reason field explains why (e.g. "local-only proxy").
	Excluded       bool   `json:"excluded,omitempty"`
	ExcludedReason string `json:"excluded_reason,omitempty"`
}

// AuditEvidence is the latest accepted audit batch summary for one follower.
type AuditEvidence struct {
	InstanceID      string    `json:"instance_id"`
	BatchID         string    `json:"batch_id"`
	SchemaVersion   int       `json:"schema_version"`
	SeqStart        uint64    `json:"seq_start"`
	SeqEnd          uint64    `json:"seq_end"`
	DroppedCount    uint64    `json:"dropped_count"`
	SignerKeyID     string    `json:"signer_key_id"`
	RuntimeBuild    string    `json:"runtime_build,omitempty"`
	ReceivedAt      time.Time `json:"received_at"`
	EmittedAt       time.Time `json:"emitted_at"`
	DeliveryLagSecs float64   `json:"delivery_lag_secs"`
}

// FollowerConvergence is the per-follower convergence verdict.
type FollowerConvergence struct {
	InstanceID string        `json:"instance_id"`
	State      FollowerState `json:"state"`
	Reason     string        `json:"reason,omitempty"`

	// The four denominators, each independently present or absent.
	DeploymentIntent *DeploymentIntent                   `json:"deployment_intent,omitempty"`
	RuntimeStatus    *controlplane.FollowerRuntimeStatus `json:"runtime_status,omitempty"`
	ConductorHealth  *controlplane.FleetHealth           `json:"conductor_health,omitempty"`
	ConductorDrift   string                              `json:"conductor_drift,omitempty"`
	LatestBatch      *AuditEvidence                      `json:"latest_batch,omitempty"`
	SignedState      *controlplane.VerifiedAppliedState  `json:"signed_applied_state,omitempty"`
}

// DenominatorSummary reports a count for one denominator.
type DenominatorSummary struct {
	Total   int `json:"total"`
	Healthy int `json:"healthy"`
	Unknown int `json:"unknown"`
}

// Report is the top-level convergence report with four separate denominators.
type Report struct {
	GeneratedAt time.Time `json:"generated_at"`
	OrgID       string    `json:"org_id"`
	FleetID     string    `json:"fleet_id"`

	// Four separate denominators -- never collapsed into one number.
	DeploymentCoverage DenominatorSummary `json:"deployment_coverage"`
	RuntimeCoverage    DenominatorSummary `json:"runtime_coverage"`
	ConductorCoverage  DenominatorSummary `json:"conductor_coverage"`
	EvidenceCoverage   DenominatorSummary `json:"evidence_coverage"`

	Followers []FollowerConvergence `json:"followers"`
}

// Inputs collects the four data sources the convergence report joins.
type Inputs struct {
	OrgID   string
	FleetID string
	Now     time.Time

	// Deployment intent (GitOps desired state).
	Intents []DeploymentIntent

	// Conductor fleet status (enrolled followers + runtime health).
	FleetStatus []controlplane.FollowerFleetStatus

	// Latest accepted audit batch per follower.
	AuditBatches []controlplane.AuditBatchSummary

	// StaleAfter controls the staleness threshold for runtime status.
	// Zero means use the default (5 minutes).
	StaleAfter time.Duration
}

// Build produces a convergence report from the four input sources. Unknown,
// unreachable, or unparseable inputs render as StateUnknown, never as
// converged. This is the fail-closed direction.
func Build(in Inputs) Report {
	now := in.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	// Index fleet status and audit batches by instance ID.
	statusByID := make(map[string]*controlplane.FollowerFleetStatus, len(in.FleetStatus))
	for i := range in.FleetStatus {
		statusByID[in.FleetStatus[i].InstanceID] = &in.FleetStatus[i]
	}
	latestBatchByID := latestBatchMap(in.AuditBatches)

	// Collect all known instance IDs from all sources.
	seen := make(map[string]bool)
	for _, intent := range in.Intents {
		seen[intent.InstanceID] = true
	}
	for _, fs := range in.FleetStatus {
		seen[fs.InstanceID] = true
	}
	for _, ab := range in.AuditBatches {
		seen[ab.InstanceID] = true
	}

	intentByID := make(map[string]*DeploymentIntent, len(in.Intents))
	for i := range in.Intents {
		intentByID[in.Intents[i].InstanceID] = &in.Intents[i]
	}

	report := Report{
		GeneratedAt: now,
		OrgID:       in.OrgID,
		FleetID:     in.FleetID,
	}

	for id := range seen {
		fc := classifyFollower(id, intentByID[id], statusByID[id], latestBatchByID[id], now, in.StaleAfter)
		report.Followers = append(report.Followers, fc)
	}

	// Sort followers for deterministic output.
	sortFollowers(report.Followers)

	// Compute per-denominator summaries.
	report.DeploymentCoverage = deploymentSummary(report.Followers)
	report.RuntimeCoverage = runtimeSummary(report.Followers)
	report.ConductorCoverage = conductorSummary(report.Followers)
	report.EvidenceCoverage = evidenceSummary(report.Followers)

	return report
}

func classifyFollower(
	instanceID string,
	intent *DeploymentIntent,
	fleetStatus *controlplane.FollowerFleetStatus,
	latestBatch *controlplane.AuditBatchSummary,
	now time.Time,
	staleAfter time.Duration,
) FollowerConvergence {
	fc := FollowerConvergence{
		InstanceID: instanceID,
	}

	// Attach raw data when available.
	if intent != nil {
		fc.DeploymentIntent = intent
	}
	if fleetStatus != nil {
		fc.RuntimeStatus = fleetStatus.RuntimeStatus
		fc.SignedState = fleetStatus.SignedAppliedState
		health := fleetStatus.Health
		fc.ConductorHealth = &health
		fc.ConductorDrift = fleetStatus.Drift
	}
	if latestBatch != nil {
		fc.LatestBatch = batchToEvidence(latestBatch, instanceID)
	}

	// Classification logic. Order matters: earlier checks take priority.

	// Excluded instances are reported as N/A.
	if intent != nil && intent.Excluded {
		fc.State = StateExcluded
		fc.Reason = intent.ExcludedReason
		if fc.Reason == "" {
			fc.Reason = "explicitly excluded from receipt expectations"
		}
		return fc
	}

	// Scaled to zero: intentionally absent.
	if intent != nil && intent.DesiredReplicas == 0 {
		fc.State = StateScaledZero
		fc.Reason = "deployment intent declares zero desired replicas"
		return fc
	}

	// No fleet status at all: unenrolled if we have intent, unknown otherwise.
	if fleetStatus == nil {
		if intent != nil {
			fc.State = StateUnenrolled
			fc.Reason = "present in deployment intent but not enrolled with conductor"
		} else {
			fc.State = StateUnknown
			fc.Reason = "no deployment intent and no conductor enrollment"
		}
		return fc
	}

	// Conductor says unknown or stale.
	if fleetStatus.Health == controlplane.FleetHealthUnknown {
		fc.State = StateUnknown
		fc.Reason = fmt.Sprintf("conductor health unknown: %s", fleetStatus.Drift)
		return fc
	}
	if fleetStatus.Health == controlplane.FleetHealthStale {
		fc.State = StateStale
		fc.Reason = fmt.Sprintf("conductor reports stale: %s", fleetStatus.Drift)
		return fc
	}
	if fleetStatus.Health == controlplane.FleetHealthApplyFailed {
		fc.State = StateStale
		fc.Reason = "last policy apply failed"
		return fc
	}
	if fleetStatus.Health == controlplane.FleetHealthUnsupported {
		fc.State = StateWrongDigest
		fc.Reason = "runtime version below minimum required by bundle"
		return fc
	}

	// Check digest match if we have deployment intent with a desired digest.
	if intent != nil && intent.DesiredDigest != "" {
		actualHash := actualBundleHash(fleetStatus)
		if actualHash == "" {
			fc.State = StateUnknown
			fc.Reason = "deployment intent specifies desired digest but no active bundle hash available"
			return fc
		}
		if actualHash != intent.DesiredDigest {
			fc.State = StateWrongDigest
			fc.Reason = fmt.Sprintf("running %s, want %s", truncHash(actualHash), truncHash(intent.DesiredDigest))
			return fc
		}
	}

	// Runtime is healthy. Check evidence.
	if latestBatch == nil {
		fc.State = StateCurrentWithoutBatch
		fc.Reason = "runtime healthy but no accepted audit batch"
		return fc
	}

	// Check if the batch is stale relative to now.
	if staleAfter <= 0 {
		staleAfter = 5 * time.Minute
	}
	if now.Sub(latestBatch.ReceivedAt) > staleAfter*6 {
		// Evidence older than 6x the staleness window is suspicious.
		fc.State = StateStale
		fc.Reason = fmt.Sprintf("latest audit batch received %s ago", now.Sub(latestBatch.ReceivedAt).Truncate(time.Second))
		return fc
	}

	fc.State = StateFullyConverged
	return fc
}

func actualBundleHash(fs *controlplane.FollowerFleetStatus) string {
	if fs.SignedAppliedState != nil && fs.SignedAppliedState.AppliedState.ActiveBundleHash != "" {
		return fs.SignedAppliedState.AppliedState.ActiveBundleHash
	}
	if fs.RuntimeStatus != nil {
		return fs.RuntimeStatus.ActiveBundleHash
	}
	return ""
}

func truncHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func batchToEvidence(b *controlplane.AuditBatchSummary, instanceID string) *AuditEvidence {
	lag := float64(0)
	if !b.ReceivedAt.IsZero() && !b.EmittedAt.IsZero() {
		lag = b.ReceivedAt.Sub(b.EmittedAt).Seconds()
	}
	signerKeyID := ""
	if len(b.SignatureKeyIDs) > 0 {
		signerKeyID = b.SignatureKeyIDs[0]
	}
	return &AuditEvidence{
		InstanceID:      instanceID,
		BatchID:         b.BatchID,
		SchemaVersion:   b.AuditSchema,
		SeqStart:        b.SeqStart,
		SeqEnd:          b.SeqEnd,
		DroppedCount:    b.DroppedCount,
		SignerKeyID:     signerKeyID,
		ReceivedAt:      b.ReceivedAt,
		EmittedAt:       b.EmittedAt,
		DeliveryLagSecs: lag,
	}
}

func latestBatchMap(batches []controlplane.AuditBatchSummary) map[string]*controlplane.AuditBatchSummary {
	m := make(map[string]*controlplane.AuditBatchSummary, len(batches))
	for i := range batches {
		b := &batches[i]
		existing, ok := m[b.InstanceID]
		if !ok || b.ReceivedAt.After(existing.ReceivedAt) {
			m[b.InstanceID] = b
		}
	}
	return m
}

func sortFollowers(followers []FollowerConvergence) {
	// Stable sort by instance ID for deterministic output.
	for i := 1; i < len(followers); i++ {
		for j := i; j > 0 && followers[j].InstanceID < followers[j-1].InstanceID; j-- {
			followers[j], followers[j-1] = followers[j-1], followers[j]
		}
	}
}

func deploymentSummary(followers []FollowerConvergence) DenominatorSummary {
	var s DenominatorSummary
	for _, f := range followers {
		if f.DeploymentIntent == nil {
			continue
		}
		s.Total++
		switch f.State {
		case StateFullyConverged, StateCurrentWithoutBatch, StateExcluded, StateScaledZero:
			s.Healthy++
		case StateUnknown:
			s.Unknown++
		}
	}
	return s
}

func runtimeSummary(followers []FollowerConvergence) DenominatorSummary {
	var s DenominatorSummary
	for _, f := range followers {
		if f.State == StateExcluded || f.State == StateScaledZero {
			continue
		}
		s.Total++
		if f.ConductorHealth != nil && *f.ConductorHealth == controlplane.FleetHealthOK {
			s.Healthy++
		} else if f.State == StateUnknown || f.ConductorHealth == nil {
			s.Unknown++
		}
	}
	return s
}

func conductorSummary(followers []FollowerConvergence) DenominatorSummary {
	var s DenominatorSummary
	for _, f := range followers {
		if f.State == StateExcluded || f.State == StateScaledZero {
			continue
		}
		s.Total++
		if f.ConductorHealth != nil {
			switch *f.ConductorHealth {
			case controlplane.FleetHealthOK:
				s.Healthy++
			case controlplane.FleetHealthUnknown:
				s.Unknown++
			}
		} else {
			s.Unknown++
		}
	}
	return s
}

func evidenceSummary(followers []FollowerConvergence) DenominatorSummary {
	var s DenominatorSummary
	for _, f := range followers {
		if f.State == StateExcluded || f.State == StateScaledZero {
			continue
		}
		s.Total++
		if f.LatestBatch != nil {
			s.Healthy++
		} else if f.State == StateUnknown || f.State == StateUnenrolled {
			s.Unknown++
		}
	}
	return s
}
