//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/applycache"
)

func TestConductorApplyTeardownSurvivesLateStaleCheck(t *testing.T) {
	s, signer := newConductorApplyTestServer(t)
	bundle := signedRuntimePolicyBundle(t, signer, "first", 1, "", "mode: strict\napi_allowlist:\n  - api.vendor.example\n")
	if _, err := s.ApplyConductorPolicyBundle(bundle, ConductorApplyOptions{Resolver: signer.resolver()}); err != nil {
		t.Fatal(err)
	}
	requestStatus := func() int {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url=https%3A%2F%2Funapproved.vendor.example", nil)
		req.RemoteAddr = "203.0.113.7:4040"
		rec := httptest.NewRecorder()
		s.proxy.Handler().ServeHTTP(rec, req)
		return rec.Code
	}
	if got := requestStatus(); got != http.StatusForbidden {
		t.Fatalf("healthy policy status=%d, want 403", got)
	}
	if !s.conductorStaleStrictDeny.Load() || s.killswitch.ConductorApplyFailure() {
		t.Fatal("fixture requires strict stale policy and a completed healthy apply")
	}
	// Teardown can cancel the poller after its tick has begun. Complete that
	// real stale evaluation against a still-fresh cache after teardown returns.
	enforcer, err := applycache.NewStaleEnforcer(applycache.StaleEnforcerConfig{
		Cache: s.applyCache(), KillSwitch: s.killswitch,
		Policy: s.currentConfig().Conductor.StalePolicy,
		Now: func() time.Time {
			s.teardownConductor("synthetic entitlement loss during stale check")
			return time.Now()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	enforcer.CheckNow()
	if !s.conductorDown.Load() {
		t.Fatal("fixture did not tear down Conductor")
	}
	assertApplyDenial := func(phase string) {
		t.Helper()
		decision := s.killswitch.IsActiveForIP("203.0.113.7")
		if !decision.Active || decision.Source != "conductor_apply_failure" {
			t.Fatalf("%s: decision=%+v, want independent policy-application denial", phase, decision)
		}
	}
	assertApplyDenial("late stale check")
	if got := requestStatus(); got != http.StatusServiceUnavailable {
		t.Fatalf("late stale check cleared strict entitlement denial: status=%d, want 503", got)
	}
	s.setConductorApplyConsistency(nil)
	assertApplyDenial("consistency completion")
	if got := requestStatus(); got != http.StatusServiceUnavailable {
		t.Fatalf("consistency completion cleared strict entitlement denial: status=%d, want 503", got)
	}
}
