// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package guard

import (
	"github.com/luckyPipewrench/pipelock/internal/config"
)

// PreparedManifest exists on every platform so callers compile everywhere, but
// off Linux it can never carry a grant.
type PreparedManifest struct {
	outcomes []PathOutcome
}

// Outcomes returns the per-path dispositions.
func (p *PreparedManifest) Outcomes() []PathOutcome {
	out := make([]PathOutcome, len(p.outcomes))
	copy(out, p.outcomes)
	return out
}

// Complete always reports false off Linux: nothing was granted, so nothing is
// complete. Reporting true for an empty grant set would let a caller that
// checks completeness before enforcement conclude all was well.
func (p *PreparedManifest) Complete() bool { return false }

// Close is a no-op; no descriptors are held.
func (p *PreparedManifest) Close() error { return nil }

// Prepare records every declared path as withheld.
//
// It deliberately still runs the planner, so a manifest that is malformed or
// floor-refused is reported as such on macOS too. An operator authoring policy
// on a laptop should see the same refusals they will see in production, rather
// than a single flat "unsupported" that hides real errors until deploy.
func Prepare(cfg *config.Config, profileName string, _ int) (*PreparedManifest, error) {
	grants, err := planManifests(cfg, profileName)
	if err != nil {
		return nil, err
	}
	return prepareGrants(grants, 0, config.ExplainGuardPathFloor)
}

func prepareGrants(grants []grant, _ int, _ floorEvaluator) (*PreparedManifest, error) {
	prepared := &PreparedManifest{outcomes: make([]PathOutcome, 0, len(grants))}
	for _, g := range grants {
		outcome := PathOutcome{DeclaredPath: g.declared, Access: g.access, State: StateWithheld}
		outcome.Reason = "guard enforcement is not implemented on this platform"
		if g.refusal != "" {
			outcome.State = StateRefused
			outcome.Reason = g.refusal
		}
		prepared.outcomes = append(prepared.outcomes, outcome)
	}
	return prepared, nil
}

// Apply always refuses off Linux.
func (p *PreparedManifest) Apply() (EnforcementRecord, error) {
	record := EnforcementRecord{
		State:            EnforcementRefused,
		Mechanism:        "landlock",
		RequiredABI:      MinimumABI,
		ManifestComplete: false,
		Coverage:         CoverageUnknown,
		Reason:           "guard enforcement requires Linux landlock; this platform has no equivalent path-grant mechanism",
		Outcomes:         p.Outcomes(),
	}
	return record, ErrUnsupportedPlatform
}

// ApplyForExec always refuses off Linux, like Apply.
func (p *PreparedManifest) ApplyForExec() (EnforcementRecord, error) {
	return p.Apply()
}
