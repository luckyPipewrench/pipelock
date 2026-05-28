//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package applycache

import (
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

type StaleState string

const (
	StaleStateActive             StaleState = "active"
	StaleStateLastKnownGood      StaleState = "last_known_good"
	StaleStateStrictDenyNoBundle StaleState = "strict_deny_no_valid_bundle"
)

type StaleDecision struct {
	State      StaleState
	BundleID   string
	Version    uint64
	ExpiresAt  time.Time
	GraceUntil time.Time
}

func DecideStale(active *VerifiedBundle, policy config.ConductorStalePolicy, now time.Time) StaleDecision {
	if active == nil || active.Bundle.BundleID == "" {
		return StaleDecision{State: StaleStateStrictDenyNoBundle}
	}
	bundle := active.Bundle
	decision := StaleDecision{
		State:     StaleStateActive,
		BundleID:  bundle.BundleID,
		Version:   bundle.Version,
		ExpiresAt: bundle.ExpiresAt.UTC(),
	}
	if !now.UTC().After(bundle.ExpiresAt.UTC()) {
		return decision
	}
	graceMultiplier := policy.GraceMultiplier
	if graceMultiplier <= 0 {
		graceMultiplier = 1
	}
	validity := bundle.ExpiresAt.Sub(bundle.NotBefore)
	if validity < 0 {
		validity = 0
	}
	decision.GraceUntil = bundle.ExpiresAt.UTC().Add(time.Duration(graceMultiplier) * validity)
	if !now.UTC().After(decision.GraceUntil) {
		decision.State = StaleStateLastKnownGood
		return decision
	}
	if policy.AfterGrace == config.ConductorStaleContinueLastKnownGood {
		decision.State = StaleStateLastKnownGood
		return decision
	}
	decision.State = StaleStateStrictDenyNoBundle
	return decision
}
