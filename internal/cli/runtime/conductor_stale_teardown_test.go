// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
)

// TestTeardownConductor_StrictStaleEngagesDenyAll proves the teardown fail-open
// fix: when the follower's stale policy is strict_deny_all, losing the fleet
// entitlement (teardown) ENGAGES the conductor_stale kill-switch source so the
// follower denies ALL traffic — because the stale enforcer's ticker is
// cancelled by teardown and can never re-engage once coordination is gone.
func TestTeardownConductor_StrictStaleEngagesDenyAll(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ks := killswitch.New(config.Defaults())
	s := &Server{killswitch: ks}
	s.conductorStaleStrictDeny.Store(true)
	s.setConductorCancel(cancel)

	// Before teardown: nothing engaged, follower serves.
	if ks.IsActive() {
		t.Fatal("kill switch active before teardown, want inactive")
	}

	s.teardownConductor("test revoke under strict stale")

	if ctx.Err() == nil {
		t.Fatal("teardown must cancel the conductor sub-context")
	}
	// After teardown: conductor_stale engaged, deny is TOTAL across transports.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/fetch?url=http://example.com", nil)
	req.RemoteAddr = "203.0.113.7:5555"
	if d := ks.IsActiveHTTP(req); !d.Active || d.Source != "conductor_stale" {
		t.Fatalf("HTTP decision = %+v, want active conductor_stale", d)
	}
	if d := ks.IsActiveForIP("203.0.113.7"); !d.Active || d.Source != "conductor_stale" {
		t.Fatalf("IP decision = %+v, want active conductor_stale", d)
	}
	if d := ks.IsActiveMCP([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`)); !d.Active {
		t.Fatalf("MCP decision = %+v, want active", d)
	}
	if !ks.Sources()["conductor_stale"] {
		t.Fatal("Sources()[conductor_stale] = false after strict teardown, want true")
	}
}

// TestTeardownConductor_ContinueStaleDoesNotEngage proves that under
// continue_last_known_good, teardown does NOT engage conductor_stale: the
// existing serve-last-config semantics are preserved (detection continues, the
// follower keeps running the last applied policy).
func TestTeardownConductor_ContinueStaleDoesNotEngage(t *testing.T) {
	_, cancel := context.WithCancel(context.Background())
	ks := killswitch.New(config.Defaults())
	s := &Server{killswitch: ks}
	// conductorStaleStrictDeny left false (continue_last_known_good or disabled).
	s.setConductorCancel(cancel)

	s.teardownConductor("test revoke under continue stale")

	if ks.IsActive() {
		t.Fatal("kill switch active after continue-policy teardown, want inactive (serve last config)")
	}
	if ks.Sources()["conductor_stale"] {
		t.Fatal("Sources()[conductor_stale] = true under continue policy, want false")
	}
}

// TestTeardownConductor_StaleEngagedSurvivesRemoteClear proves the engaged
// conductor_stale source is INDEPENDENT of conductor_remote: an operator (or a
// stale remote-kill message) clearing conductor_remote after teardown must NOT
// lift the stale deny. OR-composition + independent sources.
func TestTeardownConductor_StaleEngagedSurvivesRemoteClear(t *testing.T) {
	_, cancel := context.WithCancel(context.Background())
	ks := killswitch.New(config.Defaults())
	s := &Server{killswitch: ks}
	s.conductorStaleStrictDeny.Store(true)
	s.setConductorCancel(cancel)

	// Simulate an operator remote-kill also being active at teardown time.
	ks.SetConductorRemote(true, "operator kill")

	s.teardownConductor("test revoke")

	// Clear the remote-kill source: the stale deny must remain.
	ks.SetConductorRemote(false, "")

	d := ks.IsActiveForIP("10.9.9.9")
	if !d.Active || d.Source != "conductor_stale" {
		t.Fatalf("after clearing remote: decision = %+v, want active conductor_stale", d)
	}
}
