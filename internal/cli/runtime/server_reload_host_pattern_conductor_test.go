//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
	"context"
	"strings"
	"testing"
)

// TestReload_HostPatternRejectionPrecedesConductorTeardown pins the ORDERING
// that the host-pattern check actually buys.
//
// With the check removed the reload is still refused, because scanner
// construction rejects the pattern further down. What the check adds is that
// the refusal happens BEFORE teardownConductor runs. Without it, a reload
// carrying both a revoked fleet entitlement and a bad host pattern tears the
// follower down and only then rejects, so an operator loses a running
// Conductor to a config that was never applied.
//
// A plain rejection test cannot see this: it has no live Conductor to lose.
func TestReload_HostPatternRejectionPrecedesConductorTeardown(t *testing.T) {
	s, _ := newConductorApplyTestServer(t)
	_, cancel := context.WithCancel(context.Background())
	s.setConductorCancel(cancel)

	// Both conditions at once: the license loses the fleet entitlement (which
	// alone tears the follower down, proven by
	// TestReload_FleetDowngradeTearsDownConductor) AND the config carries an
	// invalid host pattern.
	proTok, proPubHex := agentsOnlyLicenseFixture(t)
	newCfg := s.proxy.CurrentConfig().Clone()
	newCfg.LicenseKey = proTok
	newCfg.LicensePublicKey = proPubHex
	newCfg.TrustedDomains = []string{"*"}

	err := s.Reload(newCfg)
	if err == nil {
		t.Fatal("Reload accepted an invalid host pattern")
	}
	if !strings.Contains(err.Error(), "invalid host pattern") {
		t.Fatalf("Reload error = %q, want the host-pattern rejection to be the reason", err)
	}
	if s.conductorDown.Load() {
		t.Fatal("a rejected reload tore down the Conductor follower; validation must precede teardown, or an operator loses a running fleet to a config that was never applied")
	}
}
