// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package killswitch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestController_ConductorStaleSource(t *testing.T) {
	cfg := config.Defaults()
	ks := New(cfg)
	ks.SetConductorStale(true, "stale deny")

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/fetch", nil)
	req.RemoteAddr = "10.0.0.1:4321"
	d := ks.IsActiveHTTP(req)
	if !d.Active || d.Source != "conductor_stale" || d.Message != "stale deny" {
		t.Fatalf("decision = %+v, want active conductor_stale stale deny", d)
	}
	if !ks.Sources()["conductor_stale"] {
		t.Fatalf("Sources()[conductor_stale] = false, want true")
	}

	ks.SetConductorStale(false, "")
	if d := ks.IsActiveHTTP(req); d.Active {
		t.Fatalf("decision after clear = %+v, want inactive", d)
	}
	if ks.Sources()["conductor_stale"] {
		t.Fatalf("Sources()[conductor_stale] = true after clear, want false")
	}
}

// TestController_ConductorStaleDeniesAllTransports proves the stale source
// engages a TOTAL deny: HTTP, IP-only (intercepted CONNECT), and MCP all deny
// when the stale source is active. A bundle that ages out must close every
// surface, not just the HTTP path.
func TestController_ConductorStaleDeniesAllTransports(t *testing.T) {
	cfg := config.Defaults()
	ks := New(cfg)
	ks.SetConductorStale(true, "stale deny")

	// HTTP surface.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/fetch?url=http://example.com", nil)
	req.RemoteAddr = "203.0.113.5:5555"
	if d := ks.IsActiveHTTP(req); !d.Active {
		t.Fatalf("HTTP decision = %+v, want active", d)
	}
	// IP-only surface (CONNECT tunnel).
	if d := ks.IsActiveForIP("203.0.113.5"); !d.Active {
		t.Fatalf("IP decision = %+v, want active", d)
	}
	// MCP surface.
	if d := ks.IsActiveMCP([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`)); !d.Active {
		t.Fatalf("MCP decision = %+v, want active", d)
	}
	// Source-agnostic IsActive.
	if !ks.IsActive() {
		t.Fatal("IsActive() = false, want true")
	}
}

// TestController_ConductorStaleIndependentOfRemote proves the two conductor
// sources are independent: clearing stale must not lift an operator remote kill,
// and clearing remote must not lift a stale deny.
func TestController_ConductorStaleIndependentOfRemote(t *testing.T) {
	cfg := config.Defaults()
	ks := New(cfg)

	// Both engaged.
	ks.SetConductorRemote(true, "operator kill")
	ks.SetConductorStale(true, "stale deny")
	if !ks.IsActive() {
		t.Fatal("both engaged: IsActive() = false, want true")
	}

	// Clearing stale leaves remote active. Priority puts conductor_remote first.
	ks.SetConductorStale(false, "")
	d := ks.IsActiveForIP("10.1.1.1")
	if !d.Active || d.Source != "conductor_remote" {
		t.Fatalf("after clearing stale: decision = %+v, want active conductor_remote", d)
	}

	// Re-engage stale, clear remote: stale keeps it closed.
	ks.SetConductorStale(true, "stale deny")
	ks.SetConductorRemote(false, "")
	d = ks.IsActiveForIP("10.1.1.1")
	if !d.Active || d.Source != "conductor_stale" {
		t.Fatalf("after clearing remote: decision = %+v, want active conductor_stale", d)
	}

	// Clear both: inactive.
	ks.SetConductorStale(false, "")
	if d := ks.IsActiveForIP("10.1.1.1"); d.Active {
		t.Fatalf("after clearing both: decision = %+v, want inactive", d)
	}
}

// TestController_ConductorStaleEmptyMessageFallsBackToConfig proves an empty
// stale message falls back to the configured kill-switch message, matching the
// conductor_remote source behavior.
func TestController_ConductorStaleEmptyMessageFallsBackToConfig(t *testing.T) {
	cfg := config.Defaults()
	cfg.KillSwitch.Message = "configured deny message"
	ks := New(cfg)
	ks.SetConductorStale(true, "")

	d := ks.IsActiveForIP("10.2.2.2")
	if !d.Active || d.Source != "conductor_stale" {
		t.Fatalf("decision = %+v, want active conductor_stale", d)
	}
	if d.Message != "configured deny message" {
		t.Fatalf("message = %q, want fallback to configured message", d.Message)
	}
}
