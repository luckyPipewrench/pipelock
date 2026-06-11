//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package applycache

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// StaleKillSwitch is the subset of the kill-switch controller the stale enforcer
// drives. It mirrors emergency.KillSwitchSetter but with a stale-specific setter
// so the stale source is independent of the operator remote-kill source:
// clearing one must never clear the other.
type StaleKillSwitch interface {
	SetConductorStale(active bool, message string)
}

// activeBundleSource is the subset of *Cache the enforcer reads. Defined as an
// interface so tests can supply a stub that returns a corrupt-bundle error
// without constructing a real on-disk cache.
type activeBundleSource interface {
	Active() (VerifiedBundle, error)
}

var (
	// ErrStaleEnforcerCacheRequired is returned when the enforcer is built
	// without an active-bundle source.
	ErrStaleEnforcerCacheRequired = errors.New("conductor stale enforcer cache required")
	// ErrStaleEnforcerKillSwitchRequired is returned when the enforcer is built
	// without a kill switch to drive.
	ErrStaleEnforcerKillSwitchRequired = errors.New("conductor stale enforcer kill switch required")
)

// minStaleCheckInterval bounds the tick cadence. The enforcer reuses the
// follower's poll interval, which NewPoller already floors at 1s, but the
// enforcer is constructed independently so it floors again here.
const minStaleCheckInterval = time.Second

// StaleEnforcerConfig wires the stale enforcer. CheckInterval defaults to the
// follower poll interval; the runtime passes that through.
type StaleEnforcerConfig struct {
	Cache         activeBundleSource
	KillSwitch    StaleKillSwitch
	Policy        config.ConductorStalePolicy
	CheckInterval time.Duration
	// Now injects the clock. nil uses time.Now; tests pass a controlled clock so
	// the staleness decision is never gated on the wall clock (time-bomb rule).
	Now    func() time.Time
	Logger *slog.Logger
}

// StaleEnforcer periodically re-evaluates whether the follower's active policy
// bundle has aged past its grace window and, under a strict_deny_all policy,
// engages the kill switch's conductor_stale source to fail closed (deny ALL
// traffic) until a fresh in-grace bundle is applied. It is the runtime consumer
// that makes DecideStale actually act: without it, a follower whose leader goes
// dark serves the stale bundle forever.
type StaleEnforcer struct {
	cache      activeBundleSource
	killSwitch StaleKillSwitch
	policy     config.ConductorStalePolicy
	interval   time.Duration
	now        func() time.Time
	logger     *slog.Logger
}

// NewStaleEnforcer validates the wiring and returns a ready enforcer.
func NewStaleEnforcer(cfg StaleEnforcerConfig) (*StaleEnforcer, error) {
	if isNilInterface(cfg.Cache) {
		return nil, ErrStaleEnforcerCacheRequired
	}
	if isNilInterface(cfg.KillSwitch) {
		return nil, ErrStaleEnforcerKillSwitchRequired
	}
	interval := cfg.CheckInterval
	if interval < minStaleCheckInterval {
		interval = minStaleCheckInterval
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &StaleEnforcer{
		cache:      cfg.Cache,
		killSwitch: cfg.KillSwitch,
		policy:     cfg.Policy,
		interval:   interval,
		now:        now,
		logger:     cfg.Logger,
	}, nil
}

func isNilInterface(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}

// Run ticks on the check interval until ctx is cancelled, evaluating staleness
// each tick. It evaluates once immediately on entry so a follower that starts
// up already holding a stale bundle fails closed without waiting a full
// interval. Returns ctx.Err() on cancellation, matching the poller contract so
// the lifecycle treats a clean shutdown the same way.
func (e *StaleEnforcer) Run(ctx context.Context) error {
	if e == nil {
		return ErrStaleEnforcerCacheRequired
	}
	e.evaluate()
	timer := time.NewTimer(e.interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			e.evaluate()
			timer.Reset(e.interval)
		}
	}
}

// evaluate reads the active bundle, decides staleness, and drives the kill
// switch. It fails closed on every error edge: a missing or corrupt active
// bundle is treated as "no valid bundle" (DecideStale(nil, ...) =>
// StrictDenyNoBundle), so a follower can never serve traffic on the strength of
// a bundle it cannot read.
func (e *StaleEnforcer) evaluate() {
	now := e.now().UTC()
	active, err := e.cache.Active()
	var decision StaleDecision
	if err != nil {
		// No valid active bundle (none applied yet, or corrupt/unreadable
		// record). DecideStale(nil) returns StrictDenyNoBundle regardless of
		// after_grace policy: a follower with Conductor enabled but no readable
		// policy must fail closed, NOT serve unfiltered traffic. This is the
		// "missing/corrupt active bundle => deny" edge. It also means a freshly
		// started follower denies until its first bundle lands, which is the
		// correct fail-closed posture for a fleet-managed follower.
		decision = DecideStale(nil, e.policy, now)
		e.applyDecision(decision, err)
		return
	}
	decision = DecideStale(&active, e.policy, now)
	e.applyDecision(decision, nil)
}

// applyDecision maps a StaleDecision onto the kill switch. StrictDenyNoBundle =>
// engage (deny all). Active / LastKnownGood => clear (serve). The clear path is
// idempotent: SetConductorStale(false, ...) on an already-clear source is a
// no-op, so steady-state in-grace ticks do not churn the kill switch.
func (e *StaleEnforcer) applyDecision(decision StaleDecision, readErr error) {
	switch decision.State {
	case StaleStateStrictDenyNoBundle:
		e.killSwitch.SetConductorStale(true, staleKillMessage(decision, readErr))
		e.logDeny(decision, readErr)
	case StaleStateActive:
		e.killSwitch.SetConductorStale(false, "")
	case StaleStateLastKnownGood:
		// Within grace, OR past grace under continue_last_known_good. Either way
		// we serve, but a past-grace continue is a weakened-posture event worth a
		// warning so operators can see they are running on an expired bundle.
		e.killSwitch.SetConductorStale(false, "")
		e.logLastKnownGood(decision)
	default:
		// Unknown state: fail closed rather than silently serving.
		e.killSwitch.SetConductorStale(true, "conductor policy bundle staleness state unknown")
		e.logDeny(decision, readErr)
	}
}

func staleKillMessage(decision StaleDecision, readErr error) string {
	if readErr != nil {
		return "conductor policy bundle unavailable or unreadable; denying all traffic (fail-closed)"
	}
	if decision.BundleID == "" {
		return "no valid conductor policy bundle; denying all traffic (fail-closed)"
	}
	return fmt.Sprintf("conductor policy bundle %s v%d expired past grace; denying all traffic (fail-closed)",
		decision.BundleID, decision.Version)
}

func (e *StaleEnforcer) logDeny(decision StaleDecision, readErr error) {
	if e.logger == nil {
		return
	}
	attrs := []any{
		slog.String("event", "conductor_stale_bundle_deny"),
		slog.String("state", string(decision.State)),
		slog.String("after_grace", e.policy.AfterGrace),
	}
	if decision.BundleID != "" {
		attrs = append(attrs, slog.String("bundle_id", decision.BundleID), slog.Uint64("version", decision.Version))
	}
	if readErr != nil {
		attrs = append(attrs, slog.String("error", readErr.Error()))
	}
	e.logger.Warn("conductor_stale_bundle_deny", attrs...)
}

func (e *StaleEnforcer) logLastKnownGood(decision StaleDecision) {
	if e.logger == nil {
		return
	}
	// Only the past-grace case (GraceUntil set and now past it) is a weakened
	// posture; an in-grace bundle has a zero GraceUntil and is unremarkable.
	if decision.GraceUntil.IsZero() {
		return
	}
	e.logger.Warn("conductor_stale_bundle_continue_last_known_good",
		slog.String("event", "conductor_stale_bundle_continue_last_known_good"),
		slog.String("bundle_id", decision.BundleID),
		slog.Uint64("version", decision.Version),
		slog.Time("grace_until", decision.GraceUntil),
	)
}
