// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// Every host-pattern list that can reach a Scanner is refused when it carries a
// pattern Validate would reject. One case per list, so a list that loses its
// row in the table fails here rather than going quietly uncovered.
func TestValidateHostPatternsRefusesEveryList(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*Config)
		wantField string
		wantRaw   string
		wantNorm  string
		wantWhy   string
	}{
		{
			name:      "api_allowlist wildcard over a public suffix",
			mutate:    func(c *Config) { c.APIAllowlist = []string{"api.vendor.example", "*.co.uk"} },
			wantField: "api_allowlist[1]",
			wantRaw:   `"*.co.uk"`,
			wantNorm:  `"*.co.uk"`,
			wantWhy:   "public suffix",
		},
		{
			// Validates as one host and matches as another: the matcher trims a
			// single trailing dot, so a deny rule written this way never denies.
			name:      "blocklist entry the matcher reads differently",
			mutate:    func(c *Config) { c.FetchProxy.Monitoring.Blocklist = []string{"vendor.example.."} },
			wantField: "fetch_proxy.monitoring.blocklist[0]",
			wantRaw:   `"vendor.example.."`,
			wantNorm:  `"vendor.example"`,
			wantWhy:   "never agree with the validated form",
		},
		{
			name:      "trusted_domains bare wildcard",
			mutate:    func(c *Config) { c.TrustedDomains = []string{"*"} },
			wantField: "trusted_domains[0]",
			wantRaw:   `"*"`,
			wantNorm:  `"*"`,
			wantWhy:   "disables all SSRF protection",
		},
		{
			// U+212A KELVIN SIGN folds to ASCII "k", so this exempts a host the
			// operator never wrote. The normalized value in the message is what
			// makes that visible.
			name: "subdomain_entropy_exclusions host that folds into a different ASCII host",
			mutate: func(c *Config) {
				c.FetchProxy.Monitoring.SubdomainEntropyExclusions = []string{"Kexample.com"}
			},
			wantField: "fetch_proxy.monitoring.subdomain_entropy_exclusions[0]",
			wantNorm:  `"kexample.com"`,
			wantWhy:   "must be ASCII",
		},
		{
			name:      "query_entropy_exclusions blank entry",
			mutate:    func(c *Config) { c.FetchProxy.Monitoring.QueryEntropyExclusions = []string{"  "} },
			wantField: "fetch_proxy.monitoring.query_entropy_exclusions[0]",
			wantNorm:  `""`,
			wantWhy:   "empty",
		},
		{
			name: "path_entropy_exclusions host wildcard over a registry",
			mutate: func(c *Config) {
				c.FetchProxy.Monitoring.PathEntropyExclusions = []PathEntropyExclusion{
					{Scheme: "https", Host: "*.co.uk", PathPrefix: "/document/d/"},
				}
			},
			wantField: "fetch_proxy.monitoring.path_entropy_exclusions[0].host",
			wantRaw:   `"*.co.uk"`,
			wantWhy:   "public suffix",
		},
		{
			name: "query_entropy_param_exclusions host carrying a wildcard",
			mutate: func(c *Config) {
				c.FetchProxy.Monitoring.QueryEntropyParamExclusions = []QueryEntropyParamExclusion{
					{Scheme: "https", Host: "*.vendor.example", Path: "/v1", Param: "sig"},
				}
			},
			wantField: "fetch_proxy.monitoring.query_entropy_param_exclusions[0].host",
			wantRaw:   `"*.vendor.example"`,
			wantWhy:   "without URL syntax, port, or wildcard",
		},
		{
			// An interior wildcard matches no legal hostname, so a block rule
			// carrying it denies nothing.
			name: "request_policy rule route host with an interior wildcard",
			mutate: func(c *Config) {
				c.RequestPolicy.Rules = []RequestPolicyRule{
					{Name: "deny-uploads", Route: RequestPolicyRoute{Hosts: []string{"*.vendor*.example"}}},
				}
			},
			wantField: `request_policy.rules["deny-uploads"].route.hosts[0]`,
			wantRaw:   `"*.vendor*.example"`,
			wantWhy:   "only as the leading",
		},
		{
			name: "request_policy batch route host with an interior wildcard",
			mutate: func(c *Config) {
				c.RequestPolicy.Batch = []RequestPolicyBatch{
					{Route: RequestPolicyRoute{Hosts: []string{"*.vendor*.example"}}},
				}
			},
			wantField: "request_policy.batch[0].route.hosts[0]",
			wantRaw:   `"*.vendor*.example"`,
			wantWhy:   "only as the leading",
		},
		{
			name: "dlp pattern exempt_domains carrying a URL",
			mutate: func(c *Config) {
				c.DLP.Patterns = append(c.DLP.Patterns, DLPPattern{
					Name:          "custom-token",
					Regex:         "tok_[a-z]+",
					ExemptDomains: []string{"https://vendor.example"},
				})
			},
			wantField: `dlp.patterns["custom-token"].exempt_domains[0]`,
			wantRaw:   `"https://vendor.example"`,
			wantWhy:   "not a URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			tt.mutate(cfg)
			err := cfg.ValidateHostPatterns()
			if err == nil {
				t.Fatalf("ValidateHostPatterns() = nil, want a refusal; this list reaches the Scanner unchecked")
			}
			msg := err.Error()
			for _, want := range []string{tt.wantField, tt.wantRaw, tt.wantNorm, tt.wantWhy} {
				if want == "" {
					continue
				}
				if !strings.Contains(msg, want) {
					t.Errorf("error %q does not name %q; the operator cannot act on a message that omits it", msg, want)
				}
			}
		})
	}
}

// The invariant must refuse nothing that works today. It reuses Validate's own
// validators rather than a second copy of the rules, so this holds by
// construction; the test is here because the construction is the security
// property and a future row could quietly break it.
func TestValidateHostPatternsAcceptsEveryShippedConfig(t *testing.T) {
	if err := Defaults().ValidateHostPatterns(); err != nil {
		t.Fatalf("Defaults() is refused by the invariant: %v", err)
	}

	// Collect first, load second. A walk callback that swallows its own error
	// to keep going is the shape that hides a broken tree, so the walk
	// propagates and only the LOAD is allowed to skip.
	var paths []string
	for _, root := range []string{"../../configs", "../../examples", "../../charts", "../../docs"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				return nil
			}
			if ext := filepath.Ext(path); ext == ".yaml" || ext == ".yml" {
				paths = append(paths, path)
			}
			return nil
		})
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("walking %s: %v", root, err)
		}
	}

	var checked int
	for _, path := range paths {
		// Anything that does not load is not a pipelock config, or is already
		// refused for an unrelated reason. Only configs Validate accepts are in
		// scope: those are what "works today" means.
		cfg, loadErr := Load(path)
		if loadErr != nil || cfg == nil {
			continue
		}
		checked++
		if invErr := cfg.ValidateHostPatterns(); invErr != nil {
			t.Errorf("%s passes config.Load but the invariant refuses it: %v", path, invErr)
		}
	}
	if checked == 0 {
		t.Fatal("no shipped config was checked; this test would pass without exercising anything")
	}
	t.Logf("checked %d shipped configs that load through config.Load", checked)
}

// Two of the shared validators normalize their input in place. The invariant
// runs where the Config may already be serving live traffic, so it must leave
// every list exactly as it found it.
func TestValidateHostPatternsDoesNotMutateConfig(t *testing.T) {
	cfg := Defaults()
	// Values that all four normalizers WOULD rewrite: mixed case, surrounding
	// space, a trailing dot. Each is accepted, so the walk runs to completion
	// and any in-place write would land.
	cfg.APIAllowlist = []string{"API.Vendor.Example"}
	cfg.TrustedDomains = []string{" internal.Vendor.example "}
	cfg.FetchProxy.Monitoring.Blocklist = []string{"blocked.vendor.example"}
	cfg.FetchProxy.Monitoring.SubdomainEntropyExclusions = []string{"Entropy.Vendor.Example"}
	cfg.FetchProxy.Monitoring.QueryEntropyExclusions = []string{" Query.Vendor.Example "}

	want := map[string][]string{
		"api_allowlist":               {"API.Vendor.Example"},
		"trusted_domains":             {" internal.Vendor.example "},
		"blocklist":                   {"blocked.vendor.example"},
		"subdomain_entropy_exclusion": {"Entropy.Vendor.Example"},
		"query_entropy_exclusion":     {" Query.Vendor.Example "},
	}

	if err := cfg.ValidateHostPatterns(); err != nil {
		t.Fatalf("ValidateHostPatterns() = %v, want nil; these are legitimate operator values", err)
	}

	got := map[string][]string{
		"api_allowlist":               cfg.APIAllowlist,
		"trusted_domains":             cfg.TrustedDomains,
		"blocklist":                   cfg.FetchProxy.Monitoring.Blocklist,
		"subdomain_entropy_exclusion": cfg.FetchProxy.Monitoring.SubdomainEntropyExclusions,
		"query_entropy_exclusion":     cfg.FetchProxy.Monitoring.QueryEntropyExclusions,
	}
	for field, wantVals := range want {
		gotVals := got[field]
		if len(gotVals) != len(wantVals) || gotVals[0] != wantVals[0] {
			t.Errorf("%s = %q after the invariant, want %q unchanged; a check that rewrites a live Config is not a check",
				field, gotVals, wantVals)
		}
	}
}

// A list that reaches the Scanner without a row in the table is invisible to
// the invariant, which is the exact failure a single walk exists to prevent.
// This pins the covered set so adding a list without covering it is a visible
// test change rather than a silent gap.
func TestHostPatternListsCoversTheKnownSet(t *testing.T) {
	cfg := Defaults()
	cfg.APIAllowlist = []string{"a.vendor.example"}
	cfg.TrustedDomains = []string{"b.vendor.example"}
	cfg.FetchProxy.Monitoring.Blocklist = []string{"c.vendor.example"}
	cfg.FetchProxy.Monitoring.SubdomainEntropyExclusions = []string{"d.vendor.example"}
	cfg.FetchProxy.Monitoring.QueryEntropyExclusions = []string{"e.vendor.example"}
	cfg.FetchProxy.Monitoring.PathEntropyExclusions = []PathEntropyExclusion{
		{Scheme: "https", Host: "f.vendor.example", PathPrefix: "/d/"},
	}
	cfg.FetchProxy.Monitoring.QueryEntropyParamExclusions = []QueryEntropyParamExclusion{
		{Scheme: "https", Host: "g.vendor.example", Path: "/v1", Param: "sig"},
	}
	cfg.RequestPolicy.Rules = []RequestPolicyRule{
		{Name: "r", Route: RequestPolicyRoute{Hosts: []string{"h.vendor.example"}}},
	}
	cfg.RequestPolicy.Batch = []RequestPolicyBatch{
		{Route: RequestPolicyRoute{Hosts: []string{"i.vendor.example"}}},
	}
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, DLPPattern{
		Name: "custom", Regex: "x", ExemptDomains: []string{"j.vendor.example"},
	})

	want := []string{
		"api_allowlist",
		"trusted_domains",
		"fetch_proxy.monitoring.blocklist",
		"fetch_proxy.monitoring.subdomain_entropy_exclusions",
		"fetch_proxy.monitoring.query_entropy_exclusions",
		"fetch_proxy.monitoring.path_entropy_exclusions[0].host",
		"fetch_proxy.monitoring.query_entropy_param_exclusions[0].host",
		`request_policy.rules["r"].route.hosts`,
		"request_policy.batch[0].route.hosts",
		`dlp.patterns["custom"].exempt_domains`,
	}

	got := make(map[string]bool)
	for _, list := range cfg.hostPatternLists() {
		got[list.field] = true
	}
	for _, field := range want {
		if !got[field] {
			t.Errorf("hostPatternLists() omits %q, so that list reaches the Scanner unchecked", field)
		}
	}
}
