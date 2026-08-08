// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// TestReloadDowngradeRejectReason_RequiredTeardownWithoutWarnings is the whole
// point of requiredModeTeardowns. Before it existed, the rejection was reachable
// ONLY through a ReloadWarning emitted by config.ValidateReload in another
// package. reloadDowngradeRejectReason returned "" on an empty warning list
// before it ever looked at the required contracts, so a required contract could
// be torn down with no rejection at all if nobody had written the matching
// warning. That is exactly how a reload silently cleared an active
// flight_recorder.require_receipts.
//
// Passing a nil warning list is therefore not an artificial case: it is the
// precise shape of the original defect. Every required contract must now reject
// on its own transition, with no warning in play.
func TestReloadDowngradeRejectReason_RequiredTeardownWithoutWarnings(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		on     func(*config.Config)
		wantIn string
	}{
		{
			name:   "require_receipts",
			on:     func(c *config.Config) { c.FlightRecorder.RequireReceipts = true },
			wantIn: "flight_recorder.require_receipts",
		},
		{
			name:   "license_require_intermediate",
			on:     func(c *config.Config) { c.LicenseRequireIntermediateResolved = true },
			wantIn: "license_require_intermediate",
		},
		{
			name: "a2a_require_signed_agent_cards",
			on: func(c *config.Config) {
				c.A2AScanning.Enabled = true
				c.A2AScanning.RequireSignedAgentCards = true
			},
			wantIn: "a2a_scanning.require_signed_agent_cards",
		},
		{
			name: "mcp_binary_integrity_require_signature",
			on: func(c *config.Config) {
				c.MCPBinaryIntegrity.Enabled = true
				c.MCPBinaryIntegrity.RequireSignature = true
			},
			wantIn: "mcp_binary_integrity.require_signature",
		},
		{
			name:   "mediation_envelope_verify_inbound",
			on:     func(c *config.Config) { c.MediationEnvelope.VerifyInbound.Enabled = true },
			wantIn: "mediation_envelope.verify_inbound.enabled",
		},
		{
			// sni_require_tls refuses to splice an opaque CONNECT tunnel: a
			// non-TLS payload or a ClientHello with no SNI extension bypasses
			// DLP entirely, which is a one-tunnel exfiltration channel. Turning
			// it off is therefore a required-contract teardown, and it silently
			// applied on a balanced reload before it was listed here.
			name: "forward_proxy_sni_require_tls",
			on: func(c *config.Config) {
				enabled := true
				c.ForwardProxy.SNIVerification = &enabled
				c.ForwardProxy.SNIRequireTLS = &enabled
			},
			wantIn: "forward_proxy.sni_require_tls",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			oldCfg := config.Defaults()
			tc.on(oldCfg)
			newCfg := config.Defaults() // contract absent: this is the teardown

			got := reloadDowngradeRejectReason(oldCfg, newCfg, nil)
			if !strings.Contains(got, tc.wantIn) {
				t.Fatalf("reject reason = %q, want it to name %s", got, tc.wantIn)
			}

			// Direction check: turning the contract ON must never be read as a
			// teardown, or an operator hardening their config would be blocked
			// from doing it.
			if reason := reloadDowngradeRejectReason(newCfg, oldCfg, nil); reason != "" {
				t.Fatalf("enabling %s rejected as a downgrade: %q", tc.wantIn, reason)
			}
			// Unchanged in either state must stay quiet, so an unrelated reload
			// is not rejected merely because a required contract is in force.
			if reason := reloadDowngradeRejectReason(oldCfg, oldCfg, nil); reason != "" {
				t.Fatalf("unchanged %s rejected: %q", tc.wantIn, reason)
			}
			if reason := reloadDowngradeRejectReason(newCfg, newCfg, nil); reason != "" {
				t.Fatalf("contract-absent reload rejected: %q", reason)
			}
		})
	}
}

// TestRequiredModeTeardowns_ParentDisableCountsAsTeardown covers the shape that
// makes a naive field-by-field comparison wrong. A2A card signatures and MCP
// binary signatures are only in force while their parent is enabled, so
// switching the PARENT off tears the contract down just as surely as clearing
// the flag, while leaving the flag itself set to true. Comparing the flag alone
// would miss it. flight_recorder.require_receipts also requires its parent, but
// that parent is restart-only and has already been preserved before this helper
// runs, so its direct flag comparison is against equal effective parents.
func TestRequiredModeTeardowns_ParentDisableCountsAsTeardown(t *testing.T) {
	t.Parallel()
	oldCfg := config.Defaults()
	oldCfg.A2AScanning.Enabled = true
	oldCfg.A2AScanning.RequireSignedAgentCards = true
	oldCfg.MCPBinaryIntegrity.Enabled = true
	oldCfg.MCPBinaryIntegrity.RequireSignature = true

	newCfg := oldCfg.Clone()
	newCfg.A2AScanning.Enabled = false        // flag stays true
	newCfg.MCPBinaryIntegrity.Enabled = false // flag stays true

	torn := requiredModeTeardowns(oldCfg, newCfg)
	joined := strings.Join(torn, ", ")
	for _, want := range []string{
		"a2a_scanning.require_signed_agent_cards",
		"mcp_binary_integrity.require_signature",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("teardowns = %v, want %s (parent disabled while the flag stayed true)", torn, want)
		}
	}

	// The mirror case must NOT fire: a parent that was already off means the
	// stale require flag was never in force, so clearing it tears nothing down.
	staleOld := config.Defaults()
	staleOld.A2AScanning.Enabled = false
	staleOld.A2AScanning.RequireSignedAgentCards = true
	staleNew := staleOld.Clone()
	staleNew.A2AScanning.RequireSignedAgentCards = false
	if torn := requiredModeTeardowns(staleOld, staleNew); len(torn) > 0 {
		t.Fatalf("clearing a stale require flag under a disabled parent reported a teardown: %v", torn)
	}
}

// TestRequiredModeTeardowns_SNIRequireTLSParentGating covers the same
// parent-gated shape for sni_require_tls, whose parent is SNI verification
// rather than an `enabled` field: forward.go consults sni_require_tls only
// inside the verification branch, so with verification off the flag was never
// in force and clearing it tears nothing down, while turning verification off
// while both were on IS a teardown.
func TestRequiredModeTeardowns_SNIRequireTLSParentGating(t *testing.T) {
	t.Parallel()
	yes, no := true, false

	inForce := config.Defaults()
	inForce.ForwardProxy.SNIVerification = &yes
	inForce.ForwardProxy.SNIRequireTLS = &yes

	// The direct teardown, and the shape an operator is most likely to write:
	// SNI verification stays on and only sni_require_tls is switched off. This
	// is the transition that was silently applying before the contract was
	// listed, so it is the one that most needs pinning.
	flagOff := inForce.Clone()
	flagOff.ForwardProxy.SNIRequireTLS = &no
	torn := requiredModeTeardowns(inForce, flagOff)
	if len(torn) != 1 || torn[0] != "forward_proxy.sni_require_tls" {
		t.Fatalf("clearing sni_require_tls under live verification reported %v, want exactly forward_proxy.sni_require_tls", torn)
	}

	// Parent off while the flag stays true: still a teardown.
	parentOff := inForce.Clone()
	parentOff.ForwardProxy.SNIVerification = &no
	if torn := requiredModeTeardowns(inForce, parentOff); len(torn) == 0 {
		t.Fatal("disabling SNI verification while sni_require_tls stayed true reported no teardown")
	}

	// Never in force: parent already off, clearing the flag changes nothing.
	staleOld := config.Defaults()
	staleOld.ForwardProxy.SNIVerification = &no
	staleOld.ForwardProxy.SNIRequireTLS = &yes
	staleNew := staleOld.Clone()
	staleNew.ForwardProxy.SNIRequireTLS = &no
	if torn := requiredModeTeardowns(staleOld, staleNew); len(torn) > 0 {
		t.Fatalf("clearing sni_require_tls under disabled verification reported a teardown: %v", torn)
	}
}
