// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func TestValidate_DeclaredCredentialHosts(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.DLP.GitHubEnterpriseHosts = []string{"GHE.Example.COM."}
	cfg.DLP.GitLabHosts = []string{"gitlab.example.com"}
	warnings, err := cfg.ValidateWithWarnings()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DLP.GitHubEnterpriseHosts[0] != "ghe.example.com" {
		t.Fatalf("normalized github host = %#v", cfg.DLP.GitHubEnterpriseHosts)
	}
	var githubWarn, gitlabWarn bool
	for _, warning := range warnings {
		if warning.Field == "dlp.github_enterprise_hosts" && strings.Contains(warning.Message, "by design") {
			githubWarn = true
		}
		if warning.Field == "dlp.gitlab_hosts" && strings.Contains(warning.Message, "by design") {
			gitlabWarn = true
		}
	}
	if !githubWarn || !gitlabWarn {
		t.Fatalf("load warnings = %#v", warnings)
	}

	rejects := []struct {
		name   string
		github []string
		gitlab []string
	}{
		{"wildcard", []string{"*.ghe.example.com"}, nil},
		{"ip", []string{"192.0.2.10"}, nil},
		{"url", nil, []string{"https://gitlab.example.com"}},
		{"port", nil, []string{"gitlab.example.com:8443"}},
	}
	for _, tc := range rejects {
		t.Run(tc.name, func(t *testing.T) {
			bad := Defaults()
			bad.DLP.GitHubEnterpriseHosts = tc.github
			bad.DLP.GitLabHosts = tc.gitlab
			if err := bad.Validate(); err == nil {
				t.Fatal("invalid declared host was accepted")
			}
		})
	}
}

func TestValidate_DeclaredCredentialHostEdges(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		host string
		ok   bool
	}{
		{"empty", "", false},
		{"blank", "  ", false},
		{"ipv6", "2001:db8::1", false},
		{"bracketed ipv6", "[2001:db8::1]", false},
		{"path", "gitlab.example.com/api", false},
		{"userinfo", "user@gitlab.example.com", false},
		{"bare wildcard", "*", false},
		{"trailing dot", "gitlab.example.com.", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.DLP.GitLabHosts = []string{tc.host}
			err := cfg.Validate()
			if (err == nil) != tc.ok {
				t.Fatalf("host %q: err=%v want ok=%t", tc.host, err, tc.ok)
			}
		})
	}
	dup := Defaults()
	dup.DLP.GitHubEnterpriseHosts = []string{"ghe.example.com", "GHE.example.com."}
	if err := dup.Validate(); err == nil {
		t.Fatal("duplicate declared host after normalization was accepted")
	}
}

func TestCanonicalPolicyHash_DeclaredCredentialHosts(t *testing.T) {
	t.Parallel()
	base := Defaults()
	a := Defaults()
	a.DLP.GitHubEnterpriseHosts = []string{"a.example.com", "b.example.com"}
	b := Defaults()
	b.DLP.GitHubEnterpriseHosts = []string{"b.example.com", "a.example.com"}
	gl := Defaults()
	gl.DLP.GitLabHosts = []string{"a.example.com", "b.example.com"}
	if a.CanonicalPolicyHash() == base.CanonicalPolicyHash() {
		t.Fatal("declaring a GitHub enterprise host did not change policy identity")
	}
	if a.CanonicalPolicyHash() != b.CanonicalPolicyHash() {
		t.Fatal("declared host order changed policy identity")
	}
	if gl.CanonicalPolicyHash() == a.CanonicalPolicyHash() {
		t.Fatal("GitHub and GitLab declarations share a policy identity")
	}
}

func TestValidate_CoreGitHubGitLabFloorStillRefusesControls(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"GitHub Token", "GitHub Fine-Grained PAT", "GitLab PAT"} {
		cfg := Defaults()
		cfg.Suppress = []SuppressEntry{{Rule: name, Path: "*", Reason: "no"}}
		if err := cfg.Validate(); err == nil {
			t.Fatalf("%s suppress accepted", name)
		}
		cfg = Defaults()
		cfg.RequestBodyScanning.DisablePatterns = []string{name}
		if err := cfg.Validate(); err == nil {
			t.Fatalf("%s disable accepted", name)
		}
		cfg = Defaults()
		cfg.RequestBodyScanning.PatternActions = map[string]string{name: ActionWarn}
		if err := cfg.Validate(); err == nil {
			t.Fatalf("%s warn accepted", name)
		}
	}
}

func TestReload_DeclaredCredentialHostWidening(t *testing.T) {
	t.Parallel()
	old := Defaults()
	added := old.Clone()
	added.DLP.GitHubEnterpriseHosts = []string{"ghe.example.com"}
	added.DLP.GitLabHosts = []string{"gitlab.example.com"}
	warnings := ValidateReload(old, added)
	var github, gitlab bool
	for _, warning := range warnings {
		if warning.Disposition != "" {
			t.Fatalf("widening disposition = %q, want rejectable zero value", warning.Disposition)
		}
		switch warning.Field {
		case "dlp.github_enterprise_hosts":
			github = true
		case "dlp.gitlab_hosts":
			gitlab = true
		}
	}
	if !github || !gitlab {
		t.Fatalf("widening warnings = %#v", warnings)
	}
	removed := Defaults()
	if got := ValidateReload(added, removed); len(got) != 0 {
		t.Fatalf("removing a declared host warned: %#v", got)
	}
	same := added.Clone()
	if got := ValidateReload(added, same); len(got) != 0 {
		t.Fatalf("unchanged declared hosts warned: %#v", got)
	}
}
