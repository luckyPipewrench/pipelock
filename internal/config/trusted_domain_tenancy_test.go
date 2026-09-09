// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// trusted_domains exempts a hostname from the internal-IP check, and several
// public-suffix-list PRIVATE boundaries are dynamic-DNS services where a third
// party sets the address behind their own name. So "*.duckdns.org" on this list
// exempts every name a stranger can point inward.
//
// This WARNS instead of refusing, and the test pins that choice as much as the
// behaviour: the identical pattern shape is legitimate and effective for an
// Azure private endpoint, where the public hostname resolves to a private
// address and this list is the documented remedy. Refusing it would break that
// deployment, and the list itself records who administers a boundary rather
// than who controls the addresses below it, so no predicate can separate the
// two cases. A human has to.
func TestTrustedDomainTenancyWarning(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		hosts   []string
		wantHit string // the pattern the warning must name, or "" for no warning
	}{
		{
			name:    "a dynamic-DNS boundary is the case this exists for",
			hosts:   []string{"*.duckdns.org"},
			wantHit: "*.duckdns.org",
		},
		{
			name:    "a cloud-service boundary gets the same advisory, not a refusal",
			hosts:   []string{"*.blob.core.windows.net"},
			wantHit: "*.blob.core.windows.net",
		},
		{
			name:    "an ordinary registrable domain is not a shared boundary",
			hosts:   []string{"*.vendor.example"},
			wantHit: "",
		},
		{
			name:    "a pattern BELOW the boundary is the narrower form being recommended",
			hosts:   []string{"*.myaccount.blob.core.windows.net"},
			wantHit: "",
		},
		{
			name:    "an exact host names one thing and needs no advisory",
			hosts:   []string{"myaccount.blob.core.windows.net"},
			wantHit: "",
		},
		{
			name:    "an internal name is the ordinary use of this list",
			hosts:   []string{"*.internal.corp", "upstream", "localhost"},
			wantHit: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := Defaults()
			cfg.TrustedDomains = tt.hosts
			warnings, err := cfg.ValidateWithWarnings()
			if err != nil {
				t.Fatalf("these hosts must all VALIDATE; the point is that they are accepted: %v", err)
			}

			var got string
			for _, w := range warnings {
				if w.Field == "trusted_domains" {
					got = w.Message
				}
			}
			switch {
			case tt.wantHit == "" && got != "":
				t.Errorf("unexpected advisory for %v, which would be noise on a legitimate config: %s", tt.hosts, got)
			case tt.wantHit != "" && got == "":
				t.Errorf("no advisory for %v; this list exempts a hostname from the internal-IP check and the pattern spans a shared boundary", tt.hosts)
			case tt.wantHit != "" && !strings.Contains(got, tt.wantHit):
				t.Errorf("advisory does not name %q, so the operator cannot tell which entry it means: %s", tt.wantHit, got)
			}
		})
	}
}

// The advisory must not fire on anything this repository ships, or it teaches
// operators that warnings are background noise. Presets are loaded from disk by
// a sibling test; this covers the compiled-in defaults.
func TestTrustedDomainTenancyWarningSilentOnDefaults(t *testing.T) {
	t.Parallel()

	cfg := Defaults()
	warnings, err := cfg.ValidateWithWarnings()
	if err != nil {
		t.Fatalf("defaults must validate: %v", err)
	}
	for _, w := range warnings {
		if w.Field == "trusted_domains" {
			t.Errorf("the shipped defaults emit this advisory, which makes it noise: %s", w.Message)
		}
	}
}
