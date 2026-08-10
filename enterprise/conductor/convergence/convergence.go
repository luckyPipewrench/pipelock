//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

// Package convergence produces a read-only fleet convergence report that joins
// four independent denominators: deployment intent, running images, conductor
// runtime status, and accepted audit evidence. Each denominator is reported
// separately; collapsing them into a single percentage is explicitly forbidden
// because deployment coverage is not evidence coverage.
package convergence

import (
	"fmt"
	"slices"
	"strings"
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

	// evidenceStaleWindowMultiple is how many staleness windows a follower may
	// go without delivering a batch before its evidence is treated as stale.
	//
	// It is deliberately looser than the runtime staleness window: runtime
	// status is pushed continuously, while audit batches arrive in batches, so
	// judging evidence on the runtime window would flag every follower in the
	// ordinary gap between deliveries. Loose enough not to cry wolf, tight
	// enough that a real delivery outage still surfaces.
	evidenceStaleWindowMultiple = 6
	maxDuration                 = time.Duration(1<<63 - 1)
	// deliveryClockSkewAllowance tolerates ordinary clock skew between the
	// Conductor host that stamps ReceivedAt and the operator host running this
	// report. Larger future timestamps remain unprovable and alert.
	deliveryClockSkewAllowance = 30 * time.Second

	// StateUndeclared means conductor knows about this follower but no
	// deployment intent declares it. It is distinct from StateUnknown: the
	// data is not missing, the authorization is. A rogue or forgotten
	// enforcement point lands here, and it is never counted as converged.
	StateUndeclared FollowerState = "undeclared"
)

// DeploymentIntent is the GitOps/desired declaration for one follower.
type DeploymentIntent struct {
	InstanceID      string `json:"instance_id"`
	DesiredReplicas int    `json:"desired_replicas"`
	DesiredDigest   string `json:"desired_digest,omitempty"`
	// Excluded marks this instance as intentionally not an expected receipt
	// producer. Owner and reason make the exception reviewable instead of
	// letting a delivery gap disappear behind an unexplained toggle.
	Excluded       bool   `json:"excluded,omitempty"`
	ExcludedOwner  string `json:"excluded_owner,omitempty"`
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
	// Total is every follower this denominator applies to. Followers that are
	// intentionally out of scope, meaning excluded or scaled to zero, are not
	// counted at all rather than counted as failures.
	Total int `json:"total"`

	// Healthy is the followers this denominator can positively vouch for.
	Healthy int `json:"healthy"`

	// Unknown is the followers this denominator explicitly cannot vouch for.
	//
	// Total is deliberately NOT Healthy plus Unknown. A follower can be
	// neither: definitively unhealthy in a way that is known rather than
	// unknown, such as a wrong digest. Reading the remainder as "probably
	// fine" is exactly the collapsed-percentage reasoning this report exists
	// to prevent, so the two counts are reported and neither is inferred.
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
	DeliveryHealth     DeliveryHealth     `json:"delivery_health"`

	Followers []FollowerConvergence `json:"followers"`
}

// DeliveryHealth is the explicit receipt-delivery view of the existing
// convergence report. Expected means a configured, non-excluded,
// non-scaled-zero producer. Current means that producer has a recent accepted
// signed batch.
// Local-only and scaled-zero instances remain visible in Followers but do not
// count as failures.
type DeliveryHealth struct {
	Expected int      `json:"expected"`
	Current  int      `json:"current"`
	Alerting []string `json:"alerting"`
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
	//
	// Duplicate identity across these independent control-plane sources is a
	// data-integrity condition, not something to resolve by taking whichever
	// record happened to sort last. A duplicate intent marked Excluded or
	// DesiredReplicas:0 would otherwise suppress a real unhealthy instance
	// purely through input ordering, so conflicts are recorded and the
	// affected instance is reported unknown.
	conflictingIDs := make(map[string]string)
	statusByID := make(map[string]*controlplane.FollowerFleetStatus, len(in.FleetStatus))
	for i := range in.FleetStatus {
		id := in.FleetStatus[i].InstanceID
		if _, dup := statusByID[id]; dup {
			conflictingIDs[id] = "multiple conductor fleet-status records for one instance ID"
			continue
		}
		statusByID[id] = &in.FleetStatus[i]
	}
	latestBatchByID := latestBatchMap(in.AuditBatches, now)

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
	// Keep a conservative representative for delivery accounting even when
	// duplicate intent records make normal classification impossible. If any
	// record declares the producer expected, prefer it so an excluded or
	// scaled-zero duplicate cannot make the exit-code gate report healthy.
	deliveryIntentByID := make(map[string]*DeploymentIntent, len(in.Intents))
	for i := range in.Intents {
		id := in.Intents[i].InstanceID
		candidate := &in.Intents[i]
		current := deliveryIntentByID[id]
		if current == nil || (!deliveryExpected(current) && deliveryExpected(candidate)) {
			deliveryIntentByID[id] = candidate
		}
		if _, dup := intentByID[id]; dup {
			conflictingIDs[id] = "multiple deployment-intent records for one instance ID"
			continue
		}
		intentByID[id] = &in.Intents[i]
	}

	report := Report{
		GeneratedAt: now,
		OrgID:       in.OrgID,
		FleetID:     in.FleetID,
	}

	for id := range seen {
		// An instance whose identity is ambiguous is not classified at all.
		// Running it through the normal path would let one of the conflicting
		// records decide its verdict, which is the ordering dependence this
		// guards against.
		if reason, conflicted := conflictingIDs[id]; conflicted {
			report.Followers = append(report.Followers, FollowerConvergence{
				InstanceID:       id,
				State:            StateUnknown,
				Reason:           reason,
				DeploymentIntent: deliveryIntentByID[id],
			})
			continue
		}
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
	report.DeliveryHealth = deliveryHealth(report.Followers, now, in.StaleAfter)

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
		runtimeBuild := ""
		if fleetStatus != nil && fleetStatus.RuntimeStatus != nil {
			runtimeBuild = fleetStatus.RuntimeStatus.PipelockVersion
		}
		fc.LatestBatch = batchToEvidence(latestBatch, instanceID, runtimeBuild)
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
		// Scaled-zero means intentionally absent, so it can only be claimed
		// when the follower is in fact absent. A follower that is still
		// enrolled and active while intent says zero replicas is the opposite
		// situation: a live enforcement point that nobody expects to exist.
		// Reporting that as intentionally-absent hides it.
		if fleetStatus != nil && fleetStatus.Active {
			fc.State = StateUnknown
			fc.Reason = "deployment intent declares zero desired replicas but the follower is still enrolled and active"
			return fc
		}
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

	// Enrolled but deactivated. StateFullyConverged means enrolled, active and
	// healthy, so a follower that is no longer active cannot satisfy it even
	// with historical OK health and a recent batch. Reporting it converged
	// hides enforcement capacity that has already gone away.
	if !fleetStatus.Active {
		fc.State = StateStale
		fc.Reason = "enrolled with conductor but not active"
		return fc
	}

	// Enrolled but undeclared. The report answers "is this enforcement point
	// supposed to be here", not merely "is it well", so a follower that no
	// deployment intent declares can never be converged no matter how healthy
	// it looks. Otherwise a rogue or forgotten follower reads as green and the
	// desired-state boundary this report exists to establish is inverted.
	if intent == nil {
		fc.State = StateUndeclared
		fc.Reason = "enrolled with conductor but absent from deployment intent"
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
	// Everything above rejects specific known-bad health values, which is a
	// denylist: a FleetHealth constant added later would fall straight through
	// to the converged path. Only an explicitly OK health may continue, so a
	// health value this code has never heard of fails closed. runtimeSummary
	// already counts only FleetHealthOK as healthy; this keeps the two in
	// agreement instead of letting them drift apart.
	if fleetStatus.Health != controlplane.FleetHealthOK {
		fc.State = StateUnknown
		fc.Reason = fmt.Sprintf("unrecognized conductor health %q", string(fleetStatus.Health))
		return fc
	}

	// Check digest match if we have deployment intent with a desired digest.
	if intent != nil && intent.DesiredDigest != "" {
		actualHash, hashConflict := actualBundleHash(fleetStatus)
		if hashConflict {
			fc.State = StateUnknown
			fc.Reason = fmt.Sprintf(
				"signed applied state reports %s but live runtime reports %s; running bundle is not provable",
				truncHash(actualHash), truncHash(fleetStatus.RuntimeStatus.ActiveBundleHash),
			)
			return fc
		}
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

	// Check the same bounded freshness predicate used by the delivery gate so
	// one report cannot call a future-dated batch healthy and alerting at once.
	if !batchTimestampPlausible(latestBatch.ReceivedAt, now) {
		fc.State = StateUnknown
		fc.Reason = "latest audit batch received_at is outside the allowed clock-skew window"
		return fc
	}
	if !batchReceivedAtCurrent(latestBatch.ReceivedAt, now, staleAfter) {
		fc.State = StateStale
		fc.Reason = fmt.Sprintf("latest audit batch received %s ago", now.Sub(latestBatch.ReceivedAt).Truncate(time.Second))
		return fc
	}

	fc.State = StateFullyConverged
	return fc
}

// actualBundleHash reports which bundle a follower is running, and whether its
// two sources of truth disagree.
//
// The signed applied state is a record of what the follower reported applying;
// the runtime status is what it says it is running now. Preferring the signed
// record and ignoring a contradicting runtime lets a stale signed record that
// happens to match the desired digest mask a proxy that is actually enforcing
// an old, downgraded, or tampered bundle. A disagreement is not something to
// resolve by precedence, it is evidence that the follower's state is not
// provable, so the caller must treat conflict as not-converged.
func actualBundleHash(fs *controlplane.FollowerFleetStatus) (hash string, conflict bool) {
	signed := ""
	if fs.SignedAppliedState != nil {
		signed = fs.SignedAppliedState.AppliedState.ActiveBundleHash
	}
	runtime := ""
	if fs.RuntimeStatus != nil {
		runtime = fs.RuntimeStatus.ActiveBundleHash
	}

	// Both present and disagreeing: unprovable, never silently pick one.
	if signed != "" && runtime != "" && signed != runtime {
		return signed, true
	}
	if signed != "" {
		return signed, false
	}
	return runtime, false
}

func truncHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// batchToEvidence renders one accepted batch as reportable evidence.
//
// runtimeBuild is supplied by the caller rather than read from the batch: the
// audit batch summary does not carry the emitting follower's Pipelock version,
// so it comes from the follower's runtime status. Leaving it unset would have
// the report advertise a runtime_build field that is always empty, which is an
// overclaim about what the evidence layer can actually tell an operator.
func batchToEvidence(b *controlplane.AuditBatchSummary, instanceID, runtimeBuild string) *AuditEvidence {
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
		RuntimeBuild:    runtimeBuild,
	}
}

func latestBatchMap(batches []controlplane.AuditBatchSummary, now time.Time) map[string]*controlplane.AuditBatchSummary {
	m := make(map[string]*controlplane.AuditBatchSummary, len(batches))
	for i := range batches {
		b := &batches[i]
		existing, ok := m[b.InstanceID]
		candidatePlausible := batchTimestampPlausible(b.ReceivedAt, now)
		existingPlausible := ok && batchTimestampPlausible(existing.ReceivedAt, now)
		if !ok || (candidatePlausible && !existingPlausible) ||
			(candidatePlausible == existingPlausible && b.ReceivedAt.After(existing.ReceivedAt)) {
			m[b.InstanceID] = b
		}
	}
	return m
}

// sortFollowers orders the report by instance ID so output is deterministic.
// The map iteration that builds it is not, and a report that reorders between
// runs is unusable for diffing one fleet snapshot against another.
func sortFollowers(followers []FollowerConvergence) {
	slices.SortFunc(followers, func(a, b FollowerConvergence) int {
		return strings.Compare(a.InstanceID, b.InstanceID)
	})
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
		if f.State == StateUnknown {
			s.Unknown++
			continue
		}
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
		if f.State == StateUnknown {
			s.Unknown++
			continue
		}
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

// evidenceStateIsCredible reports whether a follower's own state permits its
// latest batch to count as healthy evidence delivery. Only a follower that is
// actually converged or merely awaiting its first batch qualifies; anything
// stale, undeclared, or unprovable does not.
func evidenceStateIsCredible(state FollowerState) bool {
	switch state {
	case StateFullyConverged, StateCurrentWithoutBatch:
		return true
	default:
		return false
	}
}

func evidenceSummary(followers []FollowerConvergence) DenominatorSummary {
	var s DenominatorSummary
	for _, f := range followers {
		if f.State == StateExcluded || f.State == StateScaledZero {
			continue
		}
		s.Total++
		switch {
		// Evidence is healthy only when the follower itself is in a state
		// that makes its latest batch meaningful. A stale or unprovable
		// follower's old batch is not healthy delivery, and counting it green
		// makes this denominator contradict the convergence denominator during
		// exactly the audit-delivery outage it should surface.
		case f.LatestBatch != nil && evidenceStateIsCredible(f.State):
			s.Healthy++
		case f.State == StateUnknown || f.State == StateUnenrolled ||
			f.State == StateUndeclared || f.State == StateStale:
			s.Unknown++
		}
	}
	return s
}

func deliveryHealth(followers []FollowerConvergence, now time.Time, staleAfter time.Duration) DeliveryHealth {
	result := DeliveryHealth{Alerting: []string{}}
	for _, follower := range followers {
		if follower.State == StateExcluded || follower.State == StateScaledZero {
			continue
		}
		if !deliveryExpected(follower.DeploymentIntent) {
			continue
		}
		result.Expected++
		if deliveryBatchCurrent(follower.LatestBatch, now, staleAfter) {
			result.Current++
			continue
		}
		result.Alerting = append(result.Alerting, follower.InstanceID)
	}
	return result
}

func deliveryBatchCurrent(batch *AuditEvidence, now time.Time, staleAfter time.Duration) bool {
	if batch == nil {
		return false
	}
	return batchReceivedAtCurrent(batch.ReceivedAt, now, staleAfter)
}

func batchReceivedAtCurrent(receivedAt, now time.Time, staleAfter time.Duration) bool {
	if !batchTimestampPlausible(receivedAt, now) {
		return false
	}
	return now.Sub(receivedAt) <= evidenceStaleWindow(staleAfter)
}

// MaxEvidenceStaleAfter is the largest runtime staleness window that can be
// multiplied by the evidence window without overflowing a time.Duration.
func MaxEvidenceStaleAfter() time.Duration {
	return maxDuration / evidenceStaleWindowMultiple
}

func evidenceStaleWindow(staleAfter time.Duration) time.Duration {
	if staleAfter <= 0 {
		staleAfter = 5 * time.Minute
	}
	if staleAfter > MaxEvidenceStaleAfter() {
		return maxDuration
	}
	return staleAfter * evidenceStaleWindowMultiple
}

func batchTimestampPlausible(receivedAt, now time.Time) bool {
	return !receivedAt.IsZero() && !receivedAt.After(now.Add(deliveryClockSkewAllowance))
}

func deliveryExpected(intent *DeploymentIntent) bool {
	return intent != nil && !intent.Excluded && intent.DesiredReplicas > 0
}
