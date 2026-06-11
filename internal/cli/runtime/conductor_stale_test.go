//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/applycache"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
)

func staleEnforcerBaseConfig(dir string) config.Conductor {
	return config.Conductor{
		Enabled:        true,
		ConductorURL:   "https://conductor.example",
		OrgID:          "org-main",
		FleetID:        "prod",
		InstanceID:     "pl-prod-1",
		BundleCacheDir: filepath.Join(dir, "bundles"),
		PollInterval:   "30s",
		StalePolicy: config.ConductorStalePolicy{
			GraceMultiplier: 1,
			AfterGrace:      config.ConductorStaleStrictDenyAll,
		},
	}
}

func TestBuildConductorStaleEnforcerDisabled(t *testing.T) {
	s := &Server{}
	enforcer, err := s.buildConductorStaleEnforcer(&config.Config{Conductor: config.Conductor{Enabled: false}}, killswitch.New(config.Defaults()), io.Discard)
	if err != nil {
		t.Fatalf("disabled buildConductorStaleEnforcer() error = %v", err)
	}
	if enforcer != nil {
		t.Fatal("disabled buildConductorStaleEnforcer() enforcer = non-nil, want nil")
	}
}

func TestBuildConductorStaleEnforcerRequiresApplyCache(t *testing.T) {
	// conductor.enabled but conductorApply unset (initConductorApplyAndAudit
	// did not run): must fail closed, not launch an enforcer with no bundle src.
	s := &Server{}
	cfg := staleEnforcerBaseConfig(t.TempDir())
	_, err := s.buildConductorStaleEnforcer(&config.Config{Conductor: cfg}, killswitch.New(config.Defaults()), io.Discard)
	if !errors.Is(err, applycache.ErrCacheRequired) {
		t.Fatalf("error = %v, want ErrCacheRequired", err)
	}
}

func TestBuildConductorStaleEnforcerBadPollInterval(t *testing.T) {
	dir := t.TempDir()
	cache, err := applycache.Open(applycache.Config{Dir: filepath.Join(dir, "cache")})
	if err != nil {
		t.Fatalf("applycache.Open: %v", err)
	}
	s := &Server{conductorApply: cache}
	cfg := staleEnforcerBaseConfig(dir)
	cfg.PollInterval = "not-a-duration"
	_, err = s.buildConductorStaleEnforcer(&config.Config{Conductor: cfg}, killswitch.New(config.Defaults()), io.Discard)
	if err == nil {
		t.Fatal("bad poll interval: want error, got nil")
	}
}

func TestBuildConductorStaleEnforcerValid(t *testing.T) {
	dir := t.TempDir()
	cache, err := applycache.Open(applycache.Config{Dir: filepath.Join(dir, "cache")})
	if err != nil {
		t.Fatalf("applycache.Open: %v", err)
	}
	s := &Server{conductorApply: cache}
	cfg := staleEnforcerBaseConfig(dir)
	enforcer, err := s.buildConductorStaleEnforcer(&config.Config{Conductor: cfg}, killswitch.New(config.Defaults()), nil)
	if err != nil {
		t.Fatalf("valid buildConductorStaleEnforcer() error = %v", err)
	}
	if enforcer == nil {
		t.Fatal("valid buildConductorStaleEnforcer() enforcer = nil, want non-nil")
	}
}

// TestInitConductorStaleEnforcerSetsStrictDenyFlag proves the production init
// path records the strict_deny_all posture on the Server so teardownConductor
// can fail closed. Strict -> flag set; continue -> flag NOT set.
func TestInitConductorStaleEnforcerSetsStrictDenyFlag(t *testing.T) {
	t.Run("strict sets flag", func(t *testing.T) {
		dir := t.TempDir()
		cache, err := applycache.Open(applycache.Config{Dir: filepath.Join(dir, "cache")})
		if err != nil {
			t.Fatalf("applycache.Open: %v", err)
		}
		s := &Server{conductorApply: cache}
		cfg := staleEnforcerBaseConfig(dir) // defaults to strict_deny_all
		if err := s.initConductorStaleEnforcer(&config.Config{Conductor: cfg}, killswitch.New(config.Defaults()), io.Discard); err != nil {
			t.Fatalf("initConductorStaleEnforcer: %v", err)
		}
		if !s.conductorStaleStrictDeny.Load() {
			t.Fatal("strict policy did not set conductorStaleStrictDeny")
		}
	})
	t.Run("continue does not set flag", func(t *testing.T) {
		dir := t.TempDir()
		cache, err := applycache.Open(applycache.Config{Dir: filepath.Join(dir, "cache")})
		if err != nil {
			t.Fatalf("applycache.Open: %v", err)
		}
		s := &Server{conductorApply: cache}
		cfg := staleEnforcerBaseConfig(dir)
		cfg.StalePolicy.AfterGrace = config.ConductorStaleContinueLastKnownGood
		if err := s.initConductorStaleEnforcer(&config.Config{Conductor: cfg}, killswitch.New(config.Defaults()), io.Discard); err != nil {
			t.Fatalf("initConductorStaleEnforcer: %v", err)
		}
		if s.conductorStaleStrictDeny.Load() {
			t.Fatal("continue policy set conductorStaleStrictDeny, want false")
		}
	})
	t.Run("disabled does not set flag", func(t *testing.T) {
		s := &Server{}
		if err := s.initConductorStaleEnforcer(&config.Config{Conductor: config.Conductor{Enabled: false}}, killswitch.New(config.Defaults()), io.Discard); err != nil {
			t.Fatalf("initConductorStaleEnforcer: %v", err)
		}
		if s.conductorStaleStrictDeny.Load() {
			t.Fatal("disabled conductor set conductorStaleStrictDeny, want false")
		}
	})
}

// TestStaleEnforcerEndToEndDeniesAllThroughRealKillSwitch wires a real apply
// cache (empty -> no valid bundle), a real kill-switch controller, and the real
// enforcer, then runs the enforcer and asserts it engages a TOTAL deny on the
// kill switch. An empty cache is the "missing bundle" fail-closed edge: the
// enforcer must deny all traffic across every transport surface.
func TestStaleEnforcerEndToEndDeniesAllThroughRealKillSwitch(t *testing.T) {
	dir := t.TempDir()
	cache, err := applycache.Open(applycache.Config{Dir: filepath.Join(dir, "cache")})
	if err != nil {
		t.Fatalf("applycache.Open: %v", err)
	}
	ks := killswitch.New(config.Defaults())
	s := &Server{conductorApply: cache}
	cfg := staleEnforcerBaseConfig(dir)
	// Sub-second interval is floored to 1s internally; the immediate on-entry
	// evaluation drives the deny without waiting for a tick.
	cfg.PollInterval = "1s"
	enforcer, err := s.buildConductorStaleEnforcer(&config.Config{Conductor: cfg}, ks, io.Discard)
	if err != nil {
		t.Fatalf("buildConductorStaleEnforcer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- enforcer.Run(ctx) }()

	// Poll for the immediate on-entry evaluation to engage the kill switch.
	deadline := time.After(2 * time.Second)
	for !ks.IsActive() {
		select {
		case <-deadline:
			t.Fatal("enforcer did not engage kill switch for empty (missing-bundle) cache")
		case <-time.After(5 * time.Millisecond):
		}
	}

	// Prove the deny is TOTAL through the real controller: HTTP, IP, and MCP.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/fetch?url=http://example.com", nil)
	req.RemoteAddr = "203.0.113.9:6666"
	if d := ks.IsActiveHTTP(req); !d.Active || d.Source != "conductor_stale" {
		t.Fatalf("HTTP decision = %+v, want active conductor_stale", d)
	}
	if d := ks.IsActiveForIP("203.0.113.9"); !d.Active || d.Source != "conductor_stale" {
		t.Fatalf("IP decision = %+v, want active conductor_stale", d)
	}
	if d := ks.IsActiveMCP([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`)); !d.Active {
		t.Fatalf("MCP decision = %+v, want active", d)
	}
	if !ks.Sources()["conductor_stale"] {
		t.Fatal("Sources()[conductor_stale] = false, want true")
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
