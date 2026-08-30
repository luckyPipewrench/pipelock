// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func TestAuthenticatedArtifactsConfigContract(t *testing.T) {
	valid := AuthenticatedArtifactEntry{Host: "rules.example", Path: "/rules/pipelock-community/bundle.yaml", BundleName: "pipelock-community"}
	for _, tc := range []struct {
		name    string
		entries []AuthenticatedArtifactEntry
		want    string
	}{
		{"omitted", nil, ""},
		{"valid", []AuthenticatedArtifactEntry{valid}, ""},
		{"duplicate", []AuthenticatedArtifactEntry{valid, valid}, "duplicates"},
		{"wildcard host", []AuthenticatedArtifactEntry{{Host: "*.example", Path: valid.Path, BundleName: valid.BundleName}}, "exact DNS"},
		{"bad DNS label", []AuthenticatedArtifactEntry{{Host: "-rules.example", Path: valid.Path, BundleName: valid.BundleName}}, "host"},
		{"non ASCII host", []AuthenticatedArtifactEntry{{Host: "rulés.example", Path: valid.Path, BundleName: valid.BundleName}}, "host"},
		{"trailing DNS dot normalizes", []AuthenticatedArtifactEntry{{Host: "RULES.EXAMPLE.", Path: valid.Path, BundleName: valid.BundleName}}, ""},
		{"root path", []AuthenticatedArtifactEntry{{Host: valid.Host, Path: "/", BundleName: valid.BundleName}}, "canonical non-root"},
		{"encoded topology", []AuthenticatedArtifactEntry{{Host: valid.Host, Path: "/rules/%2e%2e/x", BundleName: valid.BundleName}}, "canonical non-root"},
		{"encoded slash", []AuthenticatedArtifactEntry{{Host: valid.Host, Path: "/rules%2fbundle.yaml", BundleName: valid.BundleName}}, "canonical non-root"},
		{"missing name", []AuthenticatedArtifactEntry{{Host: valid.Host, Path: valid.Path}}, "bundle_name"},
		{"invalid name uppercase", []AuthenticatedArtifactEntry{{Host: valid.Host, Path: valid.Path, BundleName: "Pipelock-Community"}}, "bundle_name"},
		{"invalid name edge hyphen", []AuthenticatedArtifactEntry{{Host: valid.Host, Path: valid.Path, BundleName: "-pipelock"}}, "bundle_name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.ResponseScanning.AuthenticatedArtifacts = tc.entries
			err := cfg.Validate()
			if tc.want == "" && err != nil {
				t.Fatal(err)
			}
			if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("err=%v want %q", err, tc.want)
			}
		})
	}
}

func TestAuthenticatedArtifactsCloneAndCanonicalOrder(t *testing.T) {
	a := AuthenticatedArtifactEntry{Host: "a.example", Path: "/rules/a/bundle.yaml", BundleName: "a"}
	b := AuthenticatedArtifactEntry{Host: "b.example", Path: "/rules/b/bundle.yaml", BundleName: "b"}
	cfg := Defaults()
	cfg.ResponseScanning.AuthenticatedArtifacts = []AuthenticatedArtifactEntry{b, a}
	clone := cfg.Clone()
	clone.ResponseScanning.AuthenticatedArtifacts[0].Host = "changed.example"
	if cfg.ResponseScanning.AuthenticatedArtifacts[0].Host != "b.example" {
		t.Fatal("Clone aliased authenticated artifacts")
	}
	other := Defaults()
	other.ResponseScanning.AuthenticatedArtifacts = []AuthenticatedArtifactEntry{a, b}
	if cfg.CanonicalPolicyHash() != other.CanonicalPolicyHash() {
		t.Fatal("entry order changed canonical policy hash")
	}
}
