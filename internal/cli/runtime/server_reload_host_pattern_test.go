// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// The reload activation seam is an ingest boundary, not only the tail of the
// file reloader: the Conductor apply path calls reloadLocked directly. A host
// pattern that reaches the live scanner unchecked can match a host the operator
// never wrote, so this seam refuses it the same way it already refuses reserved
// day-of-week limits, malformed suppressions and an unenforceable file sentry.
//
// WHAT THE MESSAGE ASSERTION IS FOR, since the reload would be refused either
// way. Scanner construction later in this function rejects the same pattern, so
// removing the preamble check does not make a bad reload land. What it changes
// is WHEN. The preamble runs before the license block can call teardownConductor
// and before restart-only fields are preserved; scanner construction runs after
// both. A reload carrying an invalid host pattern AND a revoked fleet
// entitlement would therefore tear the conductor down and only then reject,
// leaving the follower down on the strength of a reload that never applied.
// Asserting the preamble's message rather than the constructor's is how this
// test pins the ordering.
func TestServer_ReloadRejectsInvalidHostPattern(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*config.Config)
		wantField string
	}{
		{
			name:      "api_allowlist wildcard over a public suffix",
			mutate:    func(c *config.Config) { c.APIAllowlist = append(c.APIAllowlist, "*.co.uk") },
			wantField: "api_allowlist",
		},
		{
			// Validates as one host and matches as another, so this blocklist
			// entry would never block.
			name:      "blocklist entry the matcher reads differently",
			mutate:    func(c *config.Config) { c.FetchProxy.Monitoring.Blocklist = []string{"vendor.example.."} },
			wantField: "fetch_proxy.monitoring.blocklist",
		},
		{
			name:      "trusted_domains bare wildcard",
			mutate:    func(c *config.Config) { c.TrustedDomains = []string{"*"} },
			wantField: "trusted_domains",
		},
		{
			name: "request_policy route host with an interior wildcard",
			mutate: func(c *config.Config) {
				c.RequestPolicy.Rules = []config.RequestPolicyRule{{
					Name:   "deny-uploads",
					Action: config.ActionBlock,
					Route:  config.RequestPolicyRoute{Hosts: []string{"*.vendor*.example"}},
				}}
			},
			wantField: "request_policy.rules",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, _ := newTestServer(t, nil)
			oldCfg := s.proxy.CurrentConfig()

			newCfg := oldCfg.Clone()
			tt.mutate(newCfg)

			err := s.Reload(newCfg)
			if err == nil {
				t.Fatal("Reload accepted an invalid host pattern; this seam must stay fail-closed for every caller")
			}
			if !strings.Contains(err.Error(), "rejected: invalid config reload: invalid host pattern") {
				t.Errorf("Reload error = %q, want a host-pattern rejection", err)
			}
			if !strings.Contains(err.Error(), tt.wantField) {
				t.Errorf("Reload error = %q, does not name %q; the operator cannot act on a message that omits the field", err, tt.wantField)
			}
			if live := s.proxy.CurrentConfig(); live != oldCfg {
				t.Error("a rejected reload changed the live config; the refusal must be atomic")
			}
		})
	}
}

// Control for the rejections above: an ordinary reload carrying a well-formed
// host pattern still lands. Without this the rejection test would pass against
// a seam that refuses everything.
func TestServer_ReloadAcceptsValidHostPattern(t *testing.T) {
	s, _ := newTestServer(t, nil)
	oldCfg := s.proxy.CurrentConfig()

	newCfg := oldCfg.Clone()
	newCfg.TrustedDomains = []string{"*.internal.vendor.example", "api.vendor.example"}

	if err := s.Reload(newCfg); err != nil {
		t.Fatalf("Reload(valid host patterns) = %v, want nil; the guard must not refuse working configuration", err)
	}
	live := s.proxy.CurrentConfig()
	if live == oldCfg {
		t.Fatal("a valid reload did not replace the live config, so this control proves nothing")
	}
	if len(live.TrustedDomains) != 2 {
		t.Errorf("live trusted_domains = %q, want the two patterns the reload carried", live.TrustedDomains)
	}
}
