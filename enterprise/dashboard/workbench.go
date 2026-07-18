//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// artifactHashPattern bounds the operator-supplied artifact hash to a canonical
// hash shape (hex/base32/base64url plus the "sha256:" style prefix). It rejects
// path traversal, whitespace, and control characters before the value reaches
// any source.
var artifactHashPattern = regexp.MustCompile(`^[A-Za-z0-9:_-]{1,128}$`)

// Signed Action Workbench and Incident Cockpit are PREPARE / VERIFY / REPLAY
// surfaces only. They hold no control authority: the dashboard exposes no route
// that publishes a policy, kills or resumes a fleet, rolls back a stream, or
// otherwise mutates conductor state. Every route in this package is GET-only and
// the only conductor seam it consumes (ConductorDecisionSource) is read-only.
// An operator PREPARES and SUBMITS an action with the shipped conductor CLI
// OUTSIDE the dashboard; the workbench's job ends at "here is the predicted
// effect and the exact command to run".

const (
	// Bounded conductor action kinds. A replay whose kind is none of these is
	// rendered as "unknown" rather than echoed back.
	actionKindPublish    = "publish"
	actionKindRemoteKill = "remote_kill"
	actionKindRollback   = "rollback"
	actionKindUnknown    = "unknown"

	replayConflictIDConflict            = "conflict"
	replayConflictStaleCounter          = "stale_counter"
	replayConflictRollbackAttempt       = "rollback_attempt"
	replayConflictVersionBelowStreamMax = "version_below_stream_max"
	replayConflictPreviousHashMismatch  = "previous_hash_mismatch"
	replayConflictFleetSkew             = "fleet_skew"
	replayConflictUnknown               = "unknown"

	workbenchNeverAuthority = "This dashboard never publishes, kills, resumes, or rolls back a fleet. " +
		"It prepares and verifies an action and shows its predicted effect; you submit it with the shipped " +
		"conductor CLI outside the dashboard."

	workbenchReplayClaim = "Replay re-derives the conductor authorization and effect decision for a past " +
		"signed action under current fleet and policy state."
	workbenchReplayNonClaim = "does not re-derive proxy content-scan verdicts, and does not prove any action " +
		"executed or was prevented outside the conductor decision"

	incidentClaim = "Correlates one conductor decision with its replay divergence and the mediated applied " +
		"state reported by enrolled followers."
	incidentNonClaim = "does not prove no bypass occurred outside Pipelock, outside enrolled followers, or " +
		"outside the report window"

	workbenchArtifactHashLimit = 128
)

// PrepareStep is one row of static, honest guidance: the shipped conductor CLI
// command an operator runs OUTSIDE the dashboard to prepare and submit an
// action, plus the read-only dry-run they can run first. It carries no operator
// input and no fleet state, so it is identical for every request.
type PrepareStep struct {
	Kind        string
	Title       string
	Description string
	Command     string
}

// prepareSteps is the fixed set of shipped conductor commands surfaced as
// prepare/submit guidance. The dashboard never runs these; it only shows them.
func prepareSteps() []PrepareStep {
	return []PrepareStep{
		{
			Kind:        actionKindPublish,
			Title:       "Publish a policy bundle",
			Description: "Sign a config as a policy bundle and publish it to the fleet's stream head.",
			Command: "pipelock conductor publish --conductor-url <url> --org <org> --fleet <fleet> --audience '*' " +
				"--config <policy.yaml> --version <n> --signing-key <policy-bundle-signing.key> " +
				"--publisher-token-file <publisher-token> --tls-cert <client.crt> --tls-key <client.key> --server-ca <server-ca.crt>",
		},
		{
			Kind:        actionKindRemoteKill,
			Title:       "Remote kill / resume",
			Description: "Publish a signed remote-kill (or resume) message that halts or restores follower egress.",
			Command: "pipelock conductor kill --conductor-url <url> --org <org> --fleet <fleet> --instance '*' " +
				"--counter <n> --signing-key <remote-kill-signing.key> --admin-token-file <admin-token> " +
				"--tls-cert <client.crt> --tls-key <client.key> --server-ca <server-ca.crt>",
		},
		{
			Kind:        actionKindRollback,
			Title:       "Roll back the stream head",
			Description: "Publish a signed rollback authorization that moves the effective head to a prior bundle.",
			Command: "pipelock conductor rollback --conductor-url <url> --org <org> --fleet <fleet> " +
				"--current-bundle-id <id> --current-version <n> --target-bundle-id <id> --target-version <n> " +
				"--counter <n> --signing-key <policy-bundle-rollback.key> --admin-token-file <admin-token> " +
				"--tls-cert <client.crt> --tls-key <client.key> --server-ca <server-ca.crt>",
		},
	}
}

// DecisionScope identifies one past decision to replay. All fields are operator
// input and are validated before use; ArtifactHash is the canonical hash of the
// signed action as printed by the conductor CLI when the action was submitted.
type DecisionScope struct {
	OrgID        string
	FleetID      string
	ArtifactHash string
}

// ConductorDecisionSource is the dashboard-local read seam for the conductor's
// read-only decision dry-run/replay surface (BE-2). Implementations MUST be
// read-only: replaying a decision mutates no store. This is the ONLY conductor
// seam the workbench and cockpit consume, and it deliberately exposes no
// publish/kill/rollback method, so no write path to fleet state is reachable
// from the dashboard.
type ConductorDecisionSource interface {
	// ReplayDecision re-derives the conductor decision for the signed action
	// identified by scope.ArtifactHash under current fleet/policy state and
	// reports whether that decision diverges from what was recorded. It returns
	// found=false when no such recorded decision exists. Read-only.
	ReplayDecision(ctx context.Context, scope DecisionScope) (DecisionReplayView, bool, error)
}

// DecisionReplayView is the dashboard-local projection of a replay result. It
// carries NO bundle payload, signature bytes, or signing material: only the
// re-derived verdict, the loud divergence flag, and identifiers/versions that
// the RBAC redaction step strips for metadata-token holders.
type DecisionReplayView struct {
	ActionKind        string
	ArtifactHash      string // redacted in metadata view
	ResultVersion     uint64 // redacted in metadata view (0 = hidden)
	ResultHash        string // redacted in metadata view
	UsedStateSnapshot bool
	ReplayedAt        time.Time

	// Computed status: kept in the metadata view.
	Valid            bool
	Conflict         string // bounded conflict code (e.g. "stale_counter"), or ""
	Divergence       bool
	DivergenceReason string // redacted in metadata view (may carry identifiers)

	RecordedPresent  bool
	RecordedAccepted bool
	RecordedHash     string // redacted in metadata view
	RecordedAt       time.Time
}

// WorkbenchPage is the rendered workbench view.
type WorkbenchPage struct {
	Nav              NavContext
	NeverAuthority   string
	PrepareSteps     []PrepareStep
	ReplayClaim      string
	ReplayNonClaim   string
	SourceConfigured bool
	RawAllowed       bool

	// Replay panel: populated only when an artifact hash was supplied AND a
	// conductor source is wired AND the decision was found.
	ScopeProvided  bool
	OrgID          string
	FleetID        string
	HasReplay      bool
	Replay         DecisionReplayView
	ReplayNotFound bool
}

// Workbench builds the read-only workbench view. When no conductor source is
// wired it renders the prepare guidance plus an explicit unconfigured-replay
// state, exactly like the fleet overview's unconfigured-source state.
func (m *ReadModel) Workbench(ctx context.Context, scope DecisionScope, rawAllowed bool) (WorkbenchPage, error) {
	scope = normalizeDecisionScope(scope)
	page := WorkbenchPage{
		NeverAuthority:   workbenchNeverAuthority,
		PrepareSteps:     prepareSteps(),
		ReplayClaim:      workbenchReplayClaim,
		ReplayNonClaim:   workbenchReplayNonClaim,
		SourceConfigured: m.conductorSource != nil,
		RawAllowed:       rawAllowed,
		OrgID:            metadataScopeDisplay(scope.OrgID, rawAllowed),
		FleetID:          metadataScopeDisplay(scope.FleetID, rawAllowed),
		ScopeProvided:    scope.ArtifactHash != "",
	}
	if scope.ArtifactHash == "" || m.conductorSource == nil {
		return page, nil
	}
	view, found, err := m.conductorSource.ReplayDecision(ctx, scope)
	if err != nil {
		return WorkbenchPage{}, fmt.Errorf("replay decision: %w", err)
	}
	if !found {
		page.ReplayNotFound = true
		return page, nil
	}
	page.HasReplay = true
	page.Replay = normalizeReplayView(view)
	if !rawAllowed {
		page.Replay = redactReplayView(page.Replay)
	}
	return page, nil
}

func normalizeDecisionScope(scope DecisionScope) DecisionScope {
	scope.OrgID = strings.TrimSpace(scope.OrgID)
	scope.FleetID = strings.TrimSpace(scope.FleetID)
	scope.ArtifactHash = strings.TrimSpace(scope.ArtifactHash)
	return scope
}

// validateDecisionScope requires a well-formed org/fleet scope and artifact hash
// whenever an artifact hash is supplied. An empty artifact hash is valid (the
// workbench renders prepare guidance only); a supplied hash requires org+fleet.
func validateDecisionScope(scope DecisionScope) error {
	scope = normalizeDecisionScope(scope)
	if scope.ArtifactHash == "" {
		if scope.OrgID != "" || scope.FleetID != "" {
			return fmt.Errorf("%w: org_id and fleet_id require an artifact_hash", errInvalidFleetScope)
		}
		return nil
	}
	if scope.OrgID == "" || scope.FleetID == "" {
		return fmt.Errorf("%w: org_id and fleet_id are required with an artifact_hash", errInvalidFleetScope)
	}
	if !fleetScopePattern.MatchString(scope.OrgID) || !fleetScopePattern.MatchString(scope.FleetID) {
		return fmt.Errorf("%w: org_id and fleet_id must match [A-Za-z0-9._:-]{1,128}", errInvalidFleetScope)
	}
	if len(scope.ArtifactHash) > workbenchArtifactHashLimit || !artifactHashPattern.MatchString(scope.ArtifactHash) {
		return fmt.Errorf("%w: artifact_hash must match [A-Za-z0-9:_-]{1,128}", errInvalidFleetScope)
	}
	return nil
}

func normalizeReplayView(v DecisionReplayView) DecisionReplayView {
	switch v.ActionKind {
	case actionKindPublish, actionKindRemoteKill, actionKindRollback:
		// kept
	default:
		v.ActionKind = actionKindUnknown
	}
	v.Conflict = normalizeReplayConflict(v.Conflict)
	return v
}

func normalizeReplayConflict(conflict string) string {
	conflict = strings.TrimSpace(conflict)
	switch conflict {
	case "", replayConflictIDConflict, replayConflictStaleCounter, replayConflictRollbackAttempt,
		replayConflictVersionBelowStreamMax, replayConflictPreviousHashMismatch, replayConflictFleetSkew:
		return conflict
	default:
		return replayConflictUnknown
	}
}

func metadataScopeDisplay(value string, rawAllowed bool) string {
	if rawAllowed {
		return value
	}
	return redactedFleetString(value)
}

// redactReplayView strips identifiers, versions, hashes, and the free-text
// divergence reason for the metadata view, keeping only computed status
// (validity, the bounded conflict code, and the loud divergence flag).
func redactReplayView(v DecisionReplayView) DecisionReplayView {
	v.ArtifactHash = redactedFleetString(v.ArtifactHash)
	v.ResultHash = redactedFleetString(v.ResultHash)
	v.RecordedHash = redactedFleetString(v.RecordedHash)
	v.ResultVersion = 0
	if strings.TrimSpace(v.DivergenceReason) != "" {
		v.DivergenceReason = fleetRedacted
	}
	return v
}

// Kind returns a stable human label for the bounded action kind.
func (v DecisionReplayView) KindLabel() string {
	switch v.ActionKind {
	case actionKindPublish:
		return "Policy publish"
	case actionKindRemoteKill:
		return "Remote kill / resume"
	case actionKindRollback:
		return "Rollback"
	default:
		return "Unknown action"
	}
}

// VerdictLabel is a bounded, never-green status phrase for the re-derived
// decision. Divergence is surfaced loudly and separately.
func (v DecisionReplayView) VerdictLabel() string {
	if v.Valid {
		return "Would be accepted"
	}
	if strings.TrimSpace(v.Conflict) != "" {
		return "Would be rejected: " + v.Conflict
	}
	return "Would be rejected"
}

func (v DecisionReplayView) VerdictClass() string {
	if v.Valid {
		return "signed-unverified"
	}
	return "missing"
}

func (v DecisionReplayView) DivergenceLabel() string {
	if v.Divergence {
		return "Divergence"
	}
	return "No divergence"
}

func (v DecisionReplayView) DivergenceClass() string {
	if v.Divergence {
		return "missing"
	}
	return "verified"
}

func (v DecisionReplayView) ArtifactHashDisplay() string { return displayFleetString(v.ArtifactHash) }
func (v DecisionReplayView) ResultHashDisplay() string   { return displayFleetString(v.ResultHash) }
func (v DecisionReplayView) RecordedHashDisplay() string { return displayFleetString(v.RecordedHash) }
func (v DecisionReplayView) DivergenceReasonDisplay() string {
	return displayFleetString(v.DivergenceReason)
}
func (v DecisionReplayView) ConflictDisplay() string   { return displayFleetString(v.Conflict) }
func (v DecisionReplayView) ReplayedAtDisplay() string { return displayFleetTime(v.ReplayedAt) }
func (v DecisionReplayView) RecordedAtDisplay() string { return displayFleetTime(v.RecordedAt) }

func (v DecisionReplayView) ResultVersionDisplay() string {
	if v.ResultVersion == 0 {
		return fleetEmptyDash
	}
	return fmt.Sprintf("%d", v.ResultVersion)
}

func (v DecisionReplayView) RecordedLabel() string {
	if v.RecordedPresent && v.RecordedAccepted {
		return "recorded (accepted)"
	}
	if v.RecordedPresent {
		return "recorded (not accepted)"
	}
	return "no recorded decision"
}
