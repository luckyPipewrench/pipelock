//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package applycache

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

// fakeStaleKillSwitch records the last SetConductorStale call and counts calls
// per state so tests can assert engage/clear and idempotency.
type fakeStaleKillSwitch struct {
	mu          sync.Mutex
	active      bool
	message     string
	engageCount int
	clearCount  int
}

func (f *fakeStaleKillSwitch) SetConductorStale(active bool, message string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.active = active
	f.message = message
	if active {
		f.engageCount++
	} else {
		f.clearCount++
	}
}

func (f *fakeStaleKillSwitch) state() (bool, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.active, f.message
}

// fakeActiveSource returns a fixed bundle or error for the enforcer's
// Cache.Active() call, without an on-disk cache.
type fakeActiveSource struct {
	bundle VerifiedBundle
	err    error
}

func (f fakeActiveSource) Active() (VerifiedBundle, error) {
	if f.err != nil {
		return VerifiedBundle{}, f.err
	}
	return f.bundle, nil
}

func strictPolicy() config.ConductorStalePolicy {
	return config.ConductorStalePolicy{GraceMultiplier: 1, AfterGrace: config.ConductorStaleStrictDenyAll}
}

func continuePolicy() config.ConductorStalePolicy {
	return config.ConductorStalePolicy{GraceMultiplier: 1, AfterGrace: config.ConductorStaleContinueLastKnownGood}
}

// newEnforcerAt builds an enforcer whose clock is pinned to `now`, against the
// given source and policy, returning the enforcer and the fake kill switch.
func newEnforcerAt(t *testing.T, src activeBundleSource, policy config.ConductorStalePolicy, now time.Time) (*StaleEnforcer, *fakeStaleKillSwitch) {
	t.Helper()
	ks := &fakeStaleKillSwitch{}
	e, err := NewStaleEnforcer(StaleEnforcerConfig{
		Cache:         src,
		KillSwitch:    ks,
		Policy:        policy,
		CheckInterval: time.Second,
		Now:           func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewStaleEnforcer error = %v", err)
	}
	return e, ks
}

// enforcerBundle builds a minimal VerifiedBundle for the enforcer tests. The
// enforcer drives DecideStale, which reads only BundleID, Version, NotBefore,
// and ExpiresAt - it does NOT re-verify signatures - so a plain unsigned bundle
// with the right time window is sufficient and keeps these tests free of the
// signing helpers. Validity window is NotBefore..ExpiresAt; grace (multiplier 1)
// extends one window-length past ExpiresAt.
func enforcerBundle(id string, version uint64, notBefore, expiresAt time.Time) VerifiedBundle {
	return VerifiedBundle{Bundle: conductor.PolicyBundle{
		BundleID:  id,
		Version:   version,
		NotBefore: notBefore,
		ExpiresAt: expiresAt,
	}}
}

func activeBundleSrc(t *testing.T) fakeActiveSource {
	t.Helper()
	// Validity testNow-1m .. testNow+1h; grace extends ~1h past expiry.
	return fakeActiveSource{bundle: enforcerBundle("bundle-1", 1, testNow.Add(-time.Minute), testNow.Add(time.Hour))}
}

func TestStaleEnforcer_WithinGraceServes(t *testing.T) {
	// testNow+30m: bundle not yet expired (expires at testNow+1h).
	e, ks := newEnforcerAt(t, activeBundleSrc(t), strictPolicy(), testNow.Add(30*time.Minute))
	e.evaluate()
	if active, _ := ks.state(); active {
		t.Fatal("within grace: kill switch engaged, want cleared (serve)")
	}
}

func TestStaleEnforcer_ExactlyAtExpiryEdgeServes(t *testing.T) {
	// At exactly ExpiresAt (testNow+1h): DecideStale uses `!now.After(expiresAt)`
	// so == expiry is still ACTIVE (serve). Boundary case.
	e, ks := newEnforcerAt(t, activeBundleSrc(t), strictPolicy(), testNow.Add(time.Hour))
	e.evaluate()
	if active, _ := ks.state(); active {
		t.Fatal("at expiry edge: kill switch engaged, want cleared (still active/serve)")
	}
}

func TestStaleEnforcer_WithinGraceWindowServes(t *testing.T) {
	// testNow+90m: past expiry but within grace (grace ~= validity ~1h past
	// expiry). last_known_good => serve.
	e, ks := newEnforcerAt(t, activeBundleSrc(t), strictPolicy(), testNow.Add(90*time.Minute))
	e.evaluate()
	if active, _ := ks.state(); active {
		t.Fatal("within grace window: kill switch engaged, want cleared (serve)")
	}
}

func TestStaleEnforcer_PastGraceStrictDeniesAll(t *testing.T) {
	// testNow+3h: well past grace. strict_deny_all => ENGAGE (deny all).
	e, ks := newEnforcerAt(t, activeBundleSrc(t), strictPolicy(), testNow.Add(3*time.Hour))
	e.evaluate()
	active, msg := ks.state()
	if !active {
		t.Fatal("past grace strict: kill switch cleared, want engaged (deny all)")
	}
	if msg == "" {
		t.Fatal("past grace strict: empty deny message, want a reason")
	}
}

func TestStaleEnforcer_PastGraceContinueServesAndWarns(t *testing.T) {
	// testNow+3h past grace, but continue_last_known_good => SERVE (cleared).
	e, ks := newEnforcerAt(t, activeBundleSrc(t), continuePolicy(), testNow.Add(3*time.Hour))
	e.evaluate()
	if active, _ := ks.state(); active {
		t.Fatal("past grace continue: kill switch engaged, want cleared (serve)")
	}
}

func TestStaleEnforcer_MissingBundleDeniesAll(t *testing.T) {
	// Cache.Active() returns ErrNoValidBundle (no bundle applied yet). Must fail
	// closed: deny all. Holds even under continue_last_known_good, because
	// DecideStale(nil) is StrictDenyNoBundle regardless of policy.
	for name, policy := range map[string]config.ConductorStalePolicy{
		"strict":   strictPolicy(),
		"continue": continuePolicy(),
	} {
		t.Run(name, func(t *testing.T) {
			src := fakeActiveSource{err: ErrNoValidBundle}
			e, ks := newEnforcerAt(t, src, policy, testNow)
			e.evaluate()
			if active, _ := ks.state(); !active {
				t.Fatal("missing bundle: kill switch cleared, want engaged (fail closed)")
			}
		})
	}
}

func TestStaleEnforcer_CorruptBundleDeniesAll(t *testing.T) {
	// Cache.Active() returns a corrupt-record error. Must fail closed.
	src := fakeActiveSource{err: ErrInvalidActiveRecord}
	e, ks := newEnforcerAt(t, src, strictPolicy(), testNow)
	e.evaluate()
	active, msg := ks.state()
	if !active {
		t.Fatal("corrupt bundle: kill switch cleared, want engaged (fail closed)")
	}
	if msg == "" {
		t.Fatal("corrupt bundle: empty deny message, want a reason")
	}
}

// TestStaleEnforcer_RecoversAfterFreshBundle proves the deny clears when a fresh
// in-grace bundle replaces a stale one: stale -> deny, then serve.
func TestStaleEnforcer_RecoversAfterFreshBundle(t *testing.T) {
	staleNow := testNow.Add(3 * time.Hour)

	// Mutable source: starts stale (validity testNow-1m..testNow+1h, so 3h later
	// is well past grace), then swaps to a fresh bundle.
	src := &swappableSource{bundle: enforcerBundle("bundle-1", 1, testNow.Add(-time.Minute), testNow.Add(time.Hour))}
	ks := &fakeStaleKillSwitch{}
	e, err := NewStaleEnforcer(StaleEnforcerConfig{
		Cache:         src,
		KillSwitch:    ks,
		Policy:        strictPolicy(),
		CheckInterval: time.Second,
		Now:           func() time.Time { return staleNow },
	})
	if err != nil {
		t.Fatalf("NewStaleEnforcer error = %v", err)
	}

	// First evaluation: bundle is stale (3h past a 1h-valid bundle) -> deny.
	e.evaluate()
	if active, _ := ks.state(); !active {
		t.Fatal("stale: kill switch cleared, want engaged")
	}

	// Operator publishes a fresh bundle whose validity covers staleNow.
	src.set(enforcerBundle("bundle-2", 2, staleNow.Add(-time.Minute), staleNow.Add(time.Hour)))
	e.evaluate()
	if active, _ := ks.state(); active {
		t.Fatal("after fresh bundle: kill switch engaged, want cleared (recovered)")
	}
}

// TestStaleEnforcer_RunEvaluatesImmediatelyAndStopsOnCancel proves Run does a
// fail-closed evaluation on entry (before the first tick) and returns
// context.Canceled cleanly on shutdown.
func TestStaleEnforcer_RunEvaluatesImmediatelyAndStopsOnCancel(t *testing.T) {
	src := fakeActiveSource{err: ErrNoValidBundle}
	e, ks := newEnforcerAt(t, src, strictPolicy(), testNow)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()

	// Run evaluates once immediately on entry; poll for the engage to land.
	deadline := time.After(2 * time.Second)
	for {
		if active, _ := ks.state(); active {
			break
		}
		select {
		case <-deadline:
			t.Fatal("Run did not engage kill switch on immediate evaluation")
		case <-time.After(5 * time.Millisecond):
		}
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func TestStaleEnforcer_RequiresCacheAndKillSwitch(t *testing.T) {
	if _, err := NewStaleEnforcer(StaleEnforcerConfig{KillSwitch: &fakeStaleKillSwitch{}}); !errors.Is(err, ErrStaleEnforcerCacheRequired) {
		t.Fatalf("nil cache: err = %v, want ErrStaleEnforcerCacheRequired", err)
	}
	if _, err := NewStaleEnforcer(StaleEnforcerConfig{Cache: fakeActiveSource{}}); !errors.Is(err, ErrStaleEnforcerKillSwitchRequired) {
		t.Fatalf("nil kill switch: err = %v, want ErrStaleEnforcerKillSwitchRequired", err)
	}
	var typedNilCache *swappableSource
	if _, err := NewStaleEnforcer(StaleEnforcerConfig{Cache: typedNilCache, KillSwitch: &fakeStaleKillSwitch{}}); !errors.Is(err, ErrStaleEnforcerCacheRequired) {
		t.Fatalf("typed-nil cache: err = %v, want ErrStaleEnforcerCacheRequired", err)
	}
	var typedNilKillSwitch *fakeStaleKillSwitch
	if _, err := NewStaleEnforcer(StaleEnforcerConfig{Cache: fakeActiveSource{}, KillSwitch: typedNilKillSwitch}); !errors.Is(err, ErrStaleEnforcerKillSwitchRequired) {
		t.Fatalf("typed-nil kill switch: err = %v, want ErrStaleEnforcerKillSwitchRequired", err)
	}
}

func TestStaleEnforcer_IntervalFlooredToMinimum(t *testing.T) {
	e, err := NewStaleEnforcer(StaleEnforcerConfig{
		Cache:         fakeActiveSource{},
		KillSwitch:    &fakeStaleKillSwitch{},
		CheckInterval: time.Millisecond, // below the 1s floor
	})
	if err != nil {
		t.Fatalf("NewStaleEnforcer error = %v", err)
	}
	if e.interval != minStaleCheckInterval {
		t.Fatalf("interval = %s, want floored to %s", e.interval, minStaleCheckInterval)
	}
}

// TestStaleEnforcer_LogsDenyAndContinueWarnings exercises the logger paths: a
// past-grace strict deny logs a deny event, and a past-grace continue logs the
// weakened-posture warning. Uses a real slog logger writing to a buffer so the
// log helpers actually run (the fake-kill-switch tests pass a nil logger).
func TestStaleEnforcer_LogsDenyAndContinueWarnings(t *testing.T) {
	t.Run("deny logs", func(t *testing.T) {
		var buf syncBuffer
		ks := &fakeStaleKillSwitch{}
		e, err := NewStaleEnforcer(StaleEnforcerConfig{
			Cache:         activeBundleSrc(t),
			KillSwitch:    ks,
			Policy:        strictPolicy(),
			CheckInterval: time.Second,
			Now:           func() time.Time { return testNow.Add(3 * time.Hour) },
			Logger:        slog.New(slog.NewJSONHandler(&buf, nil)),
		})
		if err != nil {
			t.Fatalf("NewStaleEnforcer: %v", err)
		}
		e.evaluate()
		if active, _ := ks.state(); !active {
			t.Fatal("past grace strict: want engaged")
		}
		if !bytes.Contains(buf.bytes(), []byte("conductor_stale_bundle_deny")) {
			t.Fatalf("log missing deny event: %s", buf.bytes())
		}
	})
	t.Run("continue warns", func(t *testing.T) {
		var buf syncBuffer
		ks := &fakeStaleKillSwitch{}
		e, err := NewStaleEnforcer(StaleEnforcerConfig{
			Cache:         activeBundleSrc(t),
			KillSwitch:    ks,
			Policy:        continuePolicy(),
			CheckInterval: time.Second,
			Now:           func() time.Time { return testNow.Add(3 * time.Hour) },
			Logger:        slog.New(slog.NewJSONHandler(&buf, nil)),
		})
		if err != nil {
			t.Fatalf("NewStaleEnforcer: %v", err)
		}
		e.evaluate()
		if active, _ := ks.state(); active {
			t.Fatal("past grace continue: want cleared (serve)")
		}
		if !bytes.Contains(buf.bytes(), []byte("conductor_stale_bundle_continue_last_known_good")) {
			t.Fatalf("log missing continue warning: %s", buf.bytes())
		}
	})
	t.Run("within grace does not warn", func(t *testing.T) {
		var buf syncBuffer
		ks := &fakeStaleKillSwitch{}
		e, err := NewStaleEnforcer(StaleEnforcerConfig{
			Cache:         activeBundleSrc(t),
			KillSwitch:    ks,
			Policy:        continuePolicy(),
			CheckInterval: time.Second,
			// testNow+30m: within validity, last_known_good with zero GraceUntil.
			Now:    func() time.Time { return testNow.Add(30 * time.Minute) },
			Logger: slog.New(slog.NewJSONHandler(&buf, nil)),
		})
		if err != nil {
			t.Fatalf("NewStaleEnforcer: %v", err)
		}
		e.evaluate()
		if bytes.Contains(buf.bytes(), []byte("continue_last_known_good")) {
			t.Fatalf("within-grace should not warn, got: %s", buf.bytes())
		}
	})
}

// syncBuffer is a minimal goroutine-safe buffer for capturing slog output.
type syncBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *syncBuffer) bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]byte, len(b.buf))
	copy(out, b.buf)
	return out
}

// swappableSource is a mutable activeBundleSource for the recovery test.
type swappableSource struct {
	mu     sync.Mutex
	bundle VerifiedBundle
	err    error
}

func (s *swappableSource) Active() (VerifiedBundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return VerifiedBundle{}, s.err
	}
	return s.bundle, nil
}

func (s *swappableSource) set(b VerifiedBundle) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bundle = b
	s.err = nil
}
