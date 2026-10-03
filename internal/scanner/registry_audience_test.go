// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func registryBasic(user, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
}

func registryJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + "." + strings.Repeat("a", 16)
}

func TestRegistryCredentialAudience(t *testing.T) {
	t.Parallel()
	s := MustNew(credentialAudienceTestConfig())
	gh := "ghp_" + strings.Repeat("a", 36)
	pat := "github_pat_" + strings.Repeat("b", 36)
	ghs := "ghs_" + strings.Repeat("c", 36)
	registryJWTValue := registryJWT(t, map[string]any{
		"aud":    "ghcr.io",
		"access": []any{map[string]any{"type": "repository", "name": "o/r", "actions": []string{"pull"}}},
	})
	otherAud := registryJWT(t, map[string]any{
		"aud":    "registry.vendor.example",
		"access": []any{map[string]any{"type": "repository"}},
	})
	noAccess := registryJWT(t, map[string]any{"aud": "ghcr.io"})

	type tc struct {
		name    string
		token   string
		pattern string
		header  string
		value   string
		target  string
		allow   bool
		host    string
	}
	cases := []tc{
		{"ghcr basic token", gh, "GitHub Token", "Authorization", registryBasic("octocat", gh), "https://ghcr.io/token?service=ghcr.io&scope=repository:o/r:pull", true, "ghcr.io"},
		{"ghcr basic fine-grained", pat, "GitHub Fine-Grained PAT", "Authorization", registryBasic("octocat", pat), "https://ghcr.io/v2/o/r/manifests/latest", true, "ghcr.io"},
		{"ghcr basic server token", ghs, "GitHub Token", "Authorization", registryBasic("mona-cat_octo", ghs), "https://GHCR.IO./token", true, "ghcr.io"},
		{"maven basic", gh, "GitHub Token", "Authorization", registryBasic("octocat", gh), "https://maven.pkg.github.com/octocat/repo/pkg.jar", true, "maven.pkg.github.com"},
		{"nuget basic", pat, "GitHub Fine-Grained PAT", "Authorization", registryBasic("octocat", pat), "https://nuget.pkg.github.com/octocat/index.json", true, "nuget.pkg.github.com"},
		{"rubygems bearer", gh, "GitHub Token", "Authorization", "Bearer " + gh, "https://rubygems.pkg.github.com/octocat/gems", true, "rubygems.pkg.github.com"},
		{"rubygems basic blocked", gh, "GitHub Token", "Authorization", registryBasic("octocat", gh), "https://rubygems.pkg.github.com/octocat/gems", false, ""},
		{"other host blocked", gh, "GitHub Token", "Authorization", registryBasic("octocat", gh), "https://registry.vendor.example/token", false, ""},
		{"lookalike blocked", gh, "GitHub Token", "Authorization", registryBasic("octocat", gh), "https://ghcr.io.evil.example/token", false, ""},
		{"subdomain blocked", gh, "GitHub Token", "Authorization", registryBasic("octocat", gh), "https://evil.ghcr.io/token", false, ""},
		{"cleartext blocked", gh, "GitHub Token", "Authorization", registryBasic("octocat", gh), "http://ghcr.io/token", false, ""},
		{"bearer token at ghcr blocked", gh, "GitHub Token", "Authorization", "Bearer " + gh, "https://ghcr.io/v2/", false, ""},
		{"token in username blocked", gh, "GitHub Token", "Authorization", registryBasic(gh, "not-a-token"), "https://ghcr.io/token", false, ""},
		{"empty user blocked", gh, "GitHub Token", "Authorization", registryBasic("", gh), "https://ghcr.io/token", false, ""},
		{"dotted user blocked", gh, "GitHub Token", "Authorization", registryBasic("octo.cat", gh), "https://ghcr.io/token", false, ""},
		{"password suffix blocked", gh, "GitHub Token", "Authorization", registryBasic("octocat", gh+"!"), "https://ghcr.io/token", false, ""},
		{"api basic still blocked", gh, "GitHub Token", "Authorization", registryBasic("octocat", gh), "https://api.github.com/user", false, ""},
		{"registry jwt bearer", registryJWTValue, "JWT Token", "Authorization", "Bearer " + registryJWTValue, "https://ghcr.io/v2/o/r/manifests/latest", true, "ghcr.io"},
		{"registry jwt other aud blocked", otherAud, "JWT Token", "Authorization", "Bearer " + otherAud, "https://ghcr.io/v2/", false, ""},
		{"registry jwt no access blocked", noAccess, "JWT Token", "Authorization", "Bearer " + noAccess, "https://ghcr.io/v2/", false, ""},
		{"registry jwt at maven blocked", registryJWTValue, "JWT Token", "Authorization", "Bearer " + registryJWTValue, "https://maven.pkg.github.com/o/r", false, ""},
		{"registry jwt other host blocked", registryJWTValue, "JWT Token", "Authorization", "Bearer " + registryJWTValue, "https://registry.vendor.example/v2/", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matches := s.ScanTextForDLP(context.Background(), tc.token).Matches
			retained, allows := s.FilterHeaderDLPMatches(matches, tc.target, tc.header, tc.value)
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
}
