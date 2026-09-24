// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestGitHubGitLabCredentialAudience_Surfaces(t *testing.T) {
	t.Parallel()
	s := MustNew(credentialAudienceTestConfig())
	gh := "ghp_" + strings.Repeat("a", 36)
	pat := "github_pat_" + strings.Repeat("b", 36)
	gl := "glpat-" + strings.Repeat("c", 20)
	job := "glcbt-" + strings.Repeat("d", 20)
	cases := []struct {
		name    string
		token   string
		pattern string
		target  string
		surface string
		allow   bool
		host    string
	}{
		{"github bearer api", gh, "GitHub Token", "https://api.github.com/user", CredentialAudienceAuthorizationHeaderSurface, true, "api.github.com"},
		{"github token-scheme uploads", gh, "GitHub Token", "https://uploads.github.com/repos/o/r/releases/1/assets", credentialAudienceAuthorizationTokenSurface, true, "uploads.github.com"},
		{"github fine-grained bearer", pat, "GitHub Fine-Grained PAT", "https://API.GITHUB.COM./user", CredentialAudienceAuthorizationHeaderSurface, true, "api.github.com"},
		{"github url blocked", gh, "GitHub Token", "https://api.github.com/user?access_token=" + gh, "url", false, ""},
		{"github body blocked", gh, "GitHub Token", "https://api.github.com/user", "body", false, ""},
		{"github other header blocked", gh, "GitHub Token", "https://api.github.com/user", "header", false, ""},
		{"github websocket blocked", gh, "GitHub Token", "wss://api.github.com/user", "websocket_frame", false, ""},
		{"github private-token blocked", gh, "GitHub Token", "https://api.github.com/user", credentialAudiencePrivateTokenSurface, false, ""},
		{"github cleartext blocked", gh, "GitHub Token", "http://api.github.com/user", CredentialAudienceAuthorizationHeaderSurface, false, ""},
		{"github lookalike blocked", gh, "GitHub Token", "https://api.github.com.evil.example/user", CredentialAudienceAuthorizationHeaderSurface, false, ""},
		{"github subdomain blocked", gh, "GitHub Token", "https://evil.api.github.com/user", CredentialAudienceAuthorizationHeaderSurface, false, ""},
		{"github other host blocked", gh, "GitHub Token", "https://github.com/user", CredentialAudienceAuthorizationHeaderSurface, false, ""},
		{"undeclared ghes blocked", gh, "GitHub Token", "https://ghe.example.com/api/v3/user", CredentialAudienceAuthorizationHeaderSurface, false, ""},
		{"gitlab private-token", gl, "GitLab PAT", "https://gitlab.com/api/v4/projects", credentialAudiencePrivateTokenSurface, true, "gitlab.com"},
		{"gitlab bearer", gl, "GitLab PAT", "https://gitlab.com./api/v4/user", CredentialAudienceAuthorizationHeaderSurface, true, "gitlab.com"},
		{"gitlab job token", job, "GitLab CI Job Token", "wss://gitlab.com/api/v4", credentialAudienceJobTokenSurface, true, "gitlab.com"},
		{"gitlab job on private-token blocked", job, "GitLab CI Job Token", "https://gitlab.com/api/v4", credentialAudiencePrivateTokenSurface, false, ""},
		{"gitlab url blocked", gl, "GitLab PAT", "https://gitlab.com/api/v4/projects?private_token=" + gl, "url", false, ""},
		{"gitlab body blocked", gl, "GitLab PAT", "https://gitlab.com/api/v4/projects", "body", false, ""},
		{"gitlab lookalike blocked", gl, "GitLab PAT", "https://gitlab.com.evil.example/api/v4", credentialAudiencePrivateTokenSurface, false, ""},
		{"gitlab subdomain blocked", gl, "GitLab PAT", "https://registry.gitlab.com/v2/", credentialAudiencePrivateTokenSurface, false, ""},
		{"github basic at api blocked", gh, "GitHub Token", "https://api.github.com/user", credentialAudienceAuthorizationBasicSurface, false, ""},
		{"github other scheme blocked", gh, "GitHub Token", "https://api.github.com/user", credentialAudienceAuthorizationOtherSurface, false, ""},
		{"gitlab basic", gl, "GitLab PAT", "https://gitlab.com/g/r.git/info/refs", credentialAudienceAuthorizationBasicSurface, true, "gitlab.com"},
		{"gitlab token-scheme blocked", gl, "GitLab PAT", "https://gitlab.com/api/v4/user", credentialAudienceAuthorizationTokenSurface, false, ""},
		{"gitlab other scheme blocked", gl, "GitLab PAT", "https://gitlab.com/api/v4/user", credentialAudienceAuthorizationOtherSurface, false, ""},
		{"google bearer-only rejects basic", "ya29." + strings.Repeat("g", 40), "Google OAuth Token", "https://www.googleapis.com/drive/v3/files", credentialAudienceAuthorizationBasicSurface, false, ""},
		{"aws secret at github blocked", "aws_secret_access_key = " + strings.Repeat("A", 40), "AWS Secret Key", "https://api.github.com/", CredentialAudienceAuthorizationHeaderSurface, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matches := s.ScanTextForDLP(context.Background(), tc.token).Matches
			retained, allows := s.FilterTextDLPMatchesForDestination(matches, tc.target, tc.surface)
			if tc.allow {
				if matchRetained(retained, tc.pattern) || !audienceAllowFor(allows, tc.pattern) {
					t.Fatalf("retained=%v allows=%#v", matchRetained(retained, tc.pattern), allows)
				}
				if allows[0].Destination != tc.host || allows[0].Surface != "header" {
					t.Fatalf("allow record = %#v", allows[0])
				}
				return
			}
			if !matchRetained(retained, tc.pattern) || audienceAllowFor(allows, tc.pattern) {
				t.Fatalf("pattern %s was allowed: retained=%v allows=%#v", tc.pattern, matchRetained(retained, tc.pattern), allows)
			}
		})
	}

	urlBlocked := s.Scan(context.Background(), "https://api.github.com/user?token="+gh)
	if urlBlocked.Allowed || audienceAllowFor(urlBlocked.CredentialAudienceAllows, "GitHub Token") {
		t.Fatalf("core URL floor allowed a GitHub token: allowed=%v allows=%#v", urlBlocked.Allowed, urlBlocked.CredentialAudienceAllows)
	}
}

func TestGitHubGitLabCredentialAudience_DeclaredHosts(t *testing.T) {
	t.Parallel()
	cfg := credentialAudienceTestConfig()
	cfg.DLP.GitHubEnterpriseHosts = []string{"ghe.example.com"}
	cfg.DLP.GitLabHosts = []string{"gitlab.example.com"}
	s := MustNew(cfg)
	gh := "ghp_" + strings.Repeat("a", 36)
	gl := "glpat-" + strings.Repeat("c", 20)
	matches := s.ScanTextForDLP(context.Background(), gh).Matches
	retained, allows := s.FilterTextDLPMatchesForDestination(matches, "https://ghe.example.com/api/v3/user", CredentialAudienceAuthorizationHeaderSurface)
	if matchRetained(retained, "GitHub Token") || !audienceAllowFor(allows, "GitHub Token") || allows[0].Destination != "ghe.example.com" {
		t.Fatalf("declared GHES allow = retained %v %#v", matchRetained(retained, "GitHub Token"), allows)
	}
	glMatches := s.ScanTextForDLP(context.Background(), gl).Matches
	retained, allows = s.FilterTextDLPMatchesForDestination(glMatches, "https://gitlab.example.com/api/v4/user", credentialAudiencePrivateTokenSurface)
	if matchRetained(retained, "GitLab PAT") || !audienceAllowFor(allows, "GitLab PAT") {
		t.Fatalf("declared GitLab allow = %#v retained %v", allows, matchRetained(retained, "GitLab PAT"))
	}
	retained, _ = s.FilterTextDLPMatchesForDestination(matches, "https://gitlab.example.com/api/v4/user", CredentialAudienceAuthorizationHeaderSurface)
	if !matchRetained(retained, "GitHub Token") {
		t.Fatal("GitHub token was allowed at a GitLab host")
	}
}

func TestGitLabAudience_WarnRedefinitionDoesNotRegainAudience(t *testing.T) {
	t.Parallel()
	raw := []byte("version: 1\nmode: balanced\ndlp:\n  patterns:\n    - name: GitLab CI Job Token\n      regex: 'glcbt-[a-zA-Z0-9\\-_]{20,}'\n      severity: critical\n      action: warn\n")
	cfg, err := config.LoadBytes(raw)
	if err != nil {
		t.Fatalf("load warn redefinition: %v", err)
	}
	s := MustNew(cfg)
	token := "glcbt-" + strings.Repeat("e", 20)
	for _, target := range []string{"https://gitlab.com/api/v4/projects", "https://evil.example/api"} {
		result := s.ScanTextForDLP(context.Background(), token)
		if matchRetained(result.Matches, "GitLab CI Job Token") {
			t.Fatalf("%s still enforced the warned pattern: %#v", target, result.Matches)
		}
		retained, allows := s.FilterTextDLPMatchesForDestination(result.Matches, target, credentialAudienceJobTokenSurface)
		if audienceAllowFor(allows, "GitLab CI Job Token") || matchRetained(retained, "GitLab CI Job Token") {
			t.Fatalf("%s regained an audience allow: %#v", target, allows)
		}
	}
}
