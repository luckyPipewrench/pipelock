// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// Scanner construction is an ingest boundary. Several callers reach it with a
// Config that never passed through config.Validate: the enterprise per-agent
// merge builds one, and the assess and sandbox paths assemble one in code. A
// host pattern that arrives that way would otherwise be installed verbatim and
// matched against live traffic.
func TestNew_RefusesInvalidHostPattern(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		mutate    func(*config.Config)
		wantField string
		why       string
	}{
		{
			name:      "api_allowlist wildcard over a public suffix",
			mutate:    func(c *config.Config) { c.APIAllowlist = []string{"*.co.uk"} },
			wantField: "api_allowlist",
			why:       "in strict mode this grants every domain under an entire registry, which is strict mode spelled as if it were enabled",
		},
		{
			name:      "blocklist entry the matcher reads differently",
			mutate:    func(c *config.Config) { c.FetchProxy.Monitoring.Blocklist = []string{"vendor.example.."} },
			wantField: "fetch_proxy.monitoring.blocklist",
			why:       "the matcher trims one trailing dot, so this deny rule would compare two strings that never agree and would never deny",
		},
		{
			name:      "trusted_domains bare wildcard",
			mutate:    func(c *config.Config) { c.TrustedDomains = []string{"*"} },
			wantField: "trusted_domains",
			why:       "a bare wildcard exempts every host from the SSRF internal-IP check",
		},
		{
			name: "subdomain_entropy_exclusions host that folds into a different ASCII host",
			mutate: func(c *config.Config) {
				c.FetchProxy.Monitoring.SubdomainEntropyExclusions = []string{"Kexample.com"}
			},
			wantField: "fetch_proxy.monitoring.subdomain_entropy_exclusions",
			why:       "U+212A folds to ASCII k, so this would exempt kexample.com, a host the operator never wrote",
		},
		{
			name: "query_entropy_param_exclusions host carrying a wildcard",
			mutate: func(c *config.Config) {
				c.FetchProxy.Monitoring.QueryEntropyParamExclusions = []config.QueryEntropyParamExclusion{
					{Scheme: "https", Host: "*.vendor.example", Path: "/v1", Param: "sig"},
				}
			},
			wantField: "fetch_proxy.monitoring.query_entropy_param_exclusions[0].host",
			why:       "this list is matched literally, so a wildcard here is an exemption that can never fire",
		},
		{
			name: "dlp pattern exempt_domains carrying a URL",
			mutate: func(c *config.Config) {
				c.DLP.Patterns = append(c.DLP.Patterns, config.DLPPattern{
					Name:          "custom-token",
					Regex:         "tok_[a-z]+",
					ExemptDomains: []string{"https://vendor.example"},
				})
			},
			wantField: `dlp.patterns["custom-token"].exempt_domains`,
			why:       "a URL is not a hostname pattern, so this exemption would never match and the operator would think it had",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Control: the same config without the mutation builds, so a
			// failure below is attributable to the pattern and not to the
			// fixture.
			base := config.Defaults()
			base.Internal = nil
			control, err := New(base)
			if err != nil {
				t.Fatalf("control failed: an unmutated Defaults() config did not build: %v", err)
			}
			control.Close()

			cfg := config.Defaults()
			cfg.Internal = nil
			tt.mutate(cfg)

			s, err := New(cfg)
			if err == nil {
				s.Close()
				t.Fatalf("New accepted the config; %s", tt.why)
			}
			if !strings.Contains(err.Error(), "invalid host pattern") {
				t.Errorf("New error = %q, want it prefixed as a host-pattern refusal", err)
			}
			if !strings.Contains(err.Error(), tt.wantField) {
				t.Errorf("New error = %q, does not name %q; the operator cannot fix a field the message never mentions", err, tt.wantField)
			}
		})
	}
}

// The refusal must not cost a working configuration. Defaults plus ordinary
// operator patterns, including the wildcard shapes this repository ships, still
// build.
func TestNew_AcceptsWorkingHostPatterns(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.APIAllowlist = []string{"api.anthropic.com", "*.googleapis.com", "*.vendor.example"}
	cfg.TrustedDomains = []string{"internal.vendor.example", "*.internal.vendor.example"}
	cfg.FetchProxy.Monitoring.Blocklist = []string{"blocked.vendor.example", "*.co.uk", "10.0.0.1"}
	cfg.FetchProxy.Monitoring.SubdomainEntropyExclusions = []string{"*.cdn.vendor.example"}
	cfg.FetchProxy.Monitoring.QueryEntropyExclusions = []string{"s3.vendor.example"}

	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New refused a working configuration: %v", err)
	}
	defer s.Close()

	// A broad wildcard on the DENY list is policy, not a mistake, and the two
	// directions must stay distinguishable: the same pattern is refused on the
	// allowlist above and accepted here.
	if s.checkBlocklist("anything.co.uk").Allowed {
		t.Error("the *.co.uk block rule did not survive construction; breadth on a deny list is policy and must stay expressible")
	}
	if !s.checkBlocklist("allowed.vendor.example").Allowed {
		t.Error("an unrelated host was blocked, so the assertion above proves nothing about the rule")
	}
}
