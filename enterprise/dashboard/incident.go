//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"context"
	"fmt"
)

// The Incident Cockpit is a READ-ONLY correlation lens. It joins one conductor
// decision (re-derived by the read-only replay seam) with the mediated applied
// state reported by enrolled followers. It embeds no agent-kill, no publish, and
// no authority: like every other page in this package it is GET-only and reaches
// no write path.

// IncidentPage is the rendered incident cockpit view.
type IncidentPage struct {
	Claim    string
	NonClaim string

	DecisionSourceConfigured bool
	FleetSourceConfigured    bool
	RawAllowed               bool

	ScopeProvided bool
	OrgID         string
	FleetID       string

	HasDecision     bool
	DecisionMissing bool
	Decision        DecisionReplayView

	HasFleet bool
	Applied  FleetAppliedSummary
}

// FleetAppliedSummary is a bounded, non-identifying rollup of follower applied
// state for the scoped fleet. It carries only counts (never instance ids,
// hostnames, hashes, or versions), so it is safe in the metadata view without
// per-field redaction.
type FleetAppliedSummary struct {
	Total            int
	Verified         int
	SignedUnverified int
	Unsigned         int
	NoReport         int
	Drift            int
	ApplyFailed      int
	Truncated        bool
}

// Incident builds the read-only incident cockpit view. Each correlated source is
// independent: a missing conductor decision source or fleet source renders an
// explicit unconfigured state without failing the other half, mirroring the
// fleet overview's per-source absence handling.
func (m *ReadModel) Incident(ctx context.Context, scope DecisionScope, rawAllowed bool) (IncidentPage, error) {
	scope = normalizeDecisionScope(scope)
	page := IncidentPage{
		Claim:                    incidentClaim,
		NonClaim:                 incidentNonClaim,
		DecisionSourceConfigured: m.conductorSource != nil,
		FleetSourceConfigured:    m.fleetSource != nil,
		RawAllowed:               rawAllowed,
		OrgID:                    metadataScopeDisplay(scope.OrgID, rawAllowed),
		FleetID:                  metadataScopeDisplay(scope.FleetID, rawAllowed),
		ScopeProvided:            scope.ArtifactHash != "",
	}
	if scope.ArtifactHash == "" {
		return page, nil
	}
	if m.conductorSource != nil {
		view, found, err := m.conductorSource.ReplayDecision(ctx, scope)
		if err != nil {
			return IncidentPage{}, fmt.Errorf("replay decision: %w", err)
		}
		if !found {
			page.DecisionMissing = true
		} else {
			page.HasDecision = true
			page.Decision = normalizeReplayView(view)
			if !rawAllowed {
				page.Decision = redactReplayView(page.Decision)
			}
		}
	}
	if m.fleetSource != nil {
		summary, err := m.fleetAppliedSummary(ctx, scope.OrgID, scope.FleetID)
		if err != nil {
			return IncidentPage{}, err
		}
		page.HasFleet = true
		page.Applied = summary
	}
	return page, nil
}

// fleetAppliedSummary reads the scoped followers and reduces them to bounded
// counts. It reuses the fleet overview's read seam and its follower limit, and
// it normalizes health/drift through the same bounded classifier.
func (m *ReadModel) fleetAppliedSummary(ctx context.Context, orgID, fleetID string) (FleetAppliedSummary, error) {
	followers, err := m.fleetSource.ListFleetFollowers(ctx, orgID, fleetID, fleetOverviewFollowerLimit+1)
	if err != nil {
		return FleetAppliedSummary{}, fmt.Errorf("list fleet followers: %w", err)
	}
	var summary FleetAppliedSummary
	if len(followers) > fleetOverviewFollowerLimit {
		followers = followers[:fleetOverviewFollowerLimit]
		summary.Truncated = true
	}
	followers = normalizeFleetFollowers(followers)
	summary.Total = len(followers)
	for _, f := range followers {
		switch f.SourceClass() {
		case "verified":
			summary.Verified++
		case "signed-unverified":
			summary.SignedUnverified++
		case "unsigned":
			summary.Unsigned++
		default:
			summary.NoReport++
		}
		if f.Drift == "drift" {
			summary.Drift++
		}
		if f.FleetHealth == "apply_failed" {
			summary.ApplyFailed++
		}
	}
	return summary, nil
}
