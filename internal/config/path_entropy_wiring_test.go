// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// The validation matrix elsewhere calls validatePathEntropyExclusions directly,
// which proves the rules but NOT that anything runs them. This drives the real
// Validate() entry point, so a refactor that drops the call site fails here
// rather than shipping a validator with no consumer.
func TestValidateRejectsBadPathEntropyExclusion(t *testing.T) {
	t.Parallel()

	cfg := Defaults()
	cfg.Internal = nil
	if err := cfg.Validate(); err != nil {
		t.Fatalf("control: Defaults() must validate cleanly, got %v", err)
	}

	cfg.FetchProxy.Monitoring.PathEntropyExclusions = []PathEntropyExclusion{{
		Host:       "docs.vendor.example",
		PathPrefix: "/",
	}}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() accepted a root path_prefix that exempts every path on the host; the validator is not wired into Validate")
	}
	if !strings.Contains(err.Error(), "exempts every path on the host") {
		t.Fatalf("Validate() rejected for the wrong reason: %v", err)
	}
}

// Canonical ordering has a scheme tiebreak that validation makes unreachable
// at runtime, since a non-https entry is refused. Canonicalization runs on the
// raw struct though, and hot reload and the dashboard snapshot both call it, so
// the ordering must be total rather than dependent on validation having run.
func TestCanonicalPathEntropyExclusionsOrderIsTotal(t *testing.T) {
	t.Parallel()

	http := PathEntropyExclusion{Scheme: "http", Host: "docs.vendor.example", PathPrefix: "/document/d/"}
	https := PathEntropyExclusion{Scheme: "https", Host: "docs.vendor.example", PathPrefix: "/document/d/"}

	forward := canonicalPathEntropyExclusions([]PathEntropyExclusion{http, https})
	reversed := canonicalPathEntropyExclusions([]PathEntropyExclusion{https, http})
	if len(forward) != 2 || len(reversed) != 2 {
		t.Fatalf("expected both entries retained, got %d and %d", len(forward), len(reversed))
	}
	for i := range forward {
		if forward[i] != reversed[i] {
			t.Fatalf("entries differing only in scheme did not sort deterministically:\n  %+v\n  %+v", forward, reversed)
		}
	}
	if forward[0].Scheme != "http" {
		t.Errorf("scheme ordering is not ascending: got %q first", forward[0].Scheme)
	}
}

// The explicit-threshold guard parses the raw YAML a second time. Its parse
// error path is unreachable through Load, which rejects malformed YAML first,
// so it is exercised here directly rather than left as an untested branch.
func TestValidateExplicitEntropyThresholdRejectsUnparseableYAML(t *testing.T) {
	t.Parallel()

	cfg := Defaults()
	err := validateExplicitEntropyThreshold([]byte("fetch_proxy: [this is not a mapping"), cfg)
	if err == nil {
		t.Fatal("expected a parse error for malformed YAML")
	}
	if !strings.Contains(err.Error(), "entropy threshold validation") {
		t.Fatalf("error did not identify its own stage: %v", err)
	}
}
