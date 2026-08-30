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
		{"invalid name one character", []AuthenticatedArtifactEntry{{Host: valid.Host, Path: valid.Path, BundleName: "a"}}, "bundle_name"},
		{"invalid name two characters", []AuthenticatedArtifactEntry{{Host: valid.Host, Path: valid.Path, BundleName: "ab"}}, "bundle_name"},
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

func TestAuthenticatedArtifactsConfigNormalizesHost(t *testing.T) {
	cfg := Defaults()
	cfg.ResponseScanning.AuthenticatedArtifacts = []AuthenticatedArtifactEntry{{
		Host:       "RULES.EXAMPLE.",
		Path:       "/rules/pipelock-community/bundle.yaml",
		BundleName: "pipelock-community",
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := cfg.ResponseScanning.AuthenticatedArtifacts[0].Host; got != "rules.example" {
		t.Fatalf("normalized host=%q want %q", got, "rules.example")
	}
}

func TestAuthenticatedArtifactsCloneAndCanonicalOrder(t *testing.T) {
	a := AuthenticatedArtifactEntry{Host: "a.example", Path: "/rules/a/bundle.yaml", BundleName: "aaa"}
	b := AuthenticatedArtifactEntry{Host: "b.example", Path: "/rules/b/bundle.yaml", BundleName: "bbb"}
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
	pathA := AuthenticatedArtifactEntry{Host: "rules.example", Path: "/rules/a/bundle.yaml", BundleName: "bundle-a"}
	pathB := AuthenticatedArtifactEntry{Host: "rules.example", Path: "/rules/b/bundle.yaml", BundleName: "bundle-b"}
	nameA := AuthenticatedArtifactEntry{Host: "same.example", Path: "/rules/bundle.yaml", BundleName: "bundle-a"}
	nameB := AuthenticatedArtifactEntry{Host: "same.example", Path: "/rules/bundle.yaml", BundleName: "bundle-b"}
	for _, tc := range []struct {
		name    string
		entries []AuthenticatedArtifactEntry
		want    []AuthenticatedArtifactEntry
	}{
		{name: "path", entries: []AuthenticatedArtifactEntry{pathB, pathA}, want: []AuthenticatedArtifactEntry{pathA, pathB}},
		{name: "bundle name", entries: []AuthenticatedArtifactEntry{nameB, nameA}, want: []AuthenticatedArtifactEntry{nameA, nameB}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := canonicalAuthenticatedArtifacts(tc.entries)
			if got[0] != tc.want[0] || got[1] != tc.want[1] {
				t.Fatalf("canonical order=%v want=%v", got, tc.want)
			}
		})
	}
}
