// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
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
	mavenAud := registryJWT(t, map[string]any{
		"aud":    "maven.pkg.github.com",
		"access": []any{map[string]any{"type": "repository"}},
	})

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
		{"registry jwt naming maven blocked", mavenAud, "JWT Token", "Authorization", "Bearer " + mavenAud, "https://maven.pkg.github.com/o/r", false, ""},
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

func TestBasicUserPassword(t *testing.T) {
	t.Parallel()
	enc := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	raw := func(s string) string { return base64.RawStdEncoding.EncodeToString([]byte(s)) }
	cases := []struct {
		name, value, user, password string
		ok                          bool
	}{
		{"scheme and value", "Basic " + enc("octocat:pw"), "octocat", "pw", true},
		{"scheme case-insensitive", "basic " + enc("octocat:pw"), "octocat", "pw", true},
		{"bare field", enc("octocat:pw"), "octocat", "pw", true},
		{"unpadded base64", "Basic " + raw("octocat:p"), "octocat", "p", true},
		{"password keeps later colons", "Basic " + enc("octocat:a:b"), "octocat", "a:b", true},
		{"wrong scheme", "Bearer " + enc("octocat:pw"), "", "", false},
		{"empty", "", "", "", false},
		{"three fields", "Basic " + enc("octocat:pw") + " extra", "", "", false},
		{"not base64", "Basic !!!", "", "", false},
		{"no colon", "Basic " + enc("octocat"), "", "", false},
		{"empty password", "Basic " + enc("octocat:"), "", "", false},
		{"empty user", "Basic " + enc(":pw"), "", "", false},
		{"crlf in decoded value", "Basic " + enc("octocat:pw\r\nX-Injected: 1"), "", "", false},
		{"lf in decoded value", "Basic " + enc("octo\ncat:pw"), "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			user, password, ok := basicUserPassword(tc.value)
			if ok != tc.ok || user != tc.user || password != tc.password {
				t.Fatalf("basicUserPassword(%q) = %q, %q, %v; want %q, %q, %v", tc.value, user, password, ok, tc.user, tc.password, tc.ok)
			}
		})
	}
}

func TestRegistryJWTAudienceMatches(t *testing.T) {
	t.Parallel()
	access := []any{map[string]any{"type": "repository"}}
	seg := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	head := seg(map[string]any{"alg": "none"})
	cases := []struct {
		name  string
		token string
		want  bool
	}{
		{"string aud", registryJWT(t, map[string]any{"aud": "ghcr.io", "access": access}), true},
		{"array aud with host", registryJWT(t, map[string]any{"aud": []string{"other.example", "ghcr.io"}, "access": access}), true},
		{"array aud without host", registryJWT(t, map[string]any{"aud": []string{"other.example"}, "access": access}), false},
		{"empty array aud", registryJWT(t, map[string]any{"aud": []string{}, "access": access}), false},
		{"numeric aud", registryJWT(t, map[string]any{"aud": 7, "access": access}), false},
		{"missing aud", registryJWT(t, map[string]any{"access": access}), false},
		{"empty access", registryJWT(t, map[string]any{"aud": "ghcr.io", "access": []any{}}), false},
		{"access not array", registryJWT(t, map[string]any{"aud": "ghcr.io", "access": "pull"}), false},
		{"two segments", head + "." + seg(map[string]any{"aud": "ghcr.io"}), false},
		{"payload not base64", head + ".!!!.sig", false},
		{"payload not json", head + "." + base64.RawURLEncoding.EncodeToString([]byte("nope")) + ".sig", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := registryJWTAudienceMatches(tc.token, "ghcr.io"); got != tc.want {
				t.Fatalf("registryJWTAudienceMatches = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRegistryBearerRejectsMalformedRequests(t *testing.T) {
	t.Parallel()
	s := MustNew(credentialAudienceTestConfig())
	jwt := registryJWT(t, map[string]any{"aud": "ghcr.io", "access": []any{map[string]any{"type": "repository"}}})
	matches := s.ScanTextForDLP(context.Background(), jwt).Matches
	cases := []struct{ name, target, value string }{
		{"cleartext target", "http://ghcr.io/v2/", "Bearer " + jwt},
		{"unparseable target", "https://ghcr.io/%zz", "Bearer " + jwt},
		{"basic scheme", "https://ghcr.io/v2/", "Basic " + jwt},
		{"extra field", "https://ghcr.io/v2/", "Bearer " + jwt + " x"},
		{"missing value", "https://ghcr.io/v2/", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			retained, allows := s.FilterHeaderDLPMatches(matches, tc.target, "Authorization", tc.value)
			if !matchRetained(retained, "JWT Token") || audienceAllowFor(allows, "JWT Token") {
				t.Fatalf("registry bearer allowed: allows=%#v", allows)
			}
		})
	}
	gh := "ghp_" + strings.Repeat("a", 36)
	ghMatches := s.ScanTextForDLP(context.Background(), gh).Matches
	retained, allows := s.FilterHeaderDLPMatches(ghMatches, "https://ghcr.io/%zz", "Authorization", registryBasic("octocat", gh))
	if !matchRetained(retained, "GitHub Token") || audienceAllowFor(allows, "GitHub Token") {
		t.Fatalf("registry basic allowed on unparseable target: allows=%#v", allows)
	}
}

func TestRegistryAllowGuardsDirect(t *testing.T) {
	t.Parallel()
	gh := "ghp_" + strings.Repeat("a", 36)
	jwt := registryJWT(t, map[string]any{"aud": "ghcr.io", "access": []any{map[string]any{"type": "repository"}}})
	basic := credentialAudienceCandidate{
		carrierMask:   config.CredentialAudienceCarrierRegistryBasic,
		registryHosts: []string{"ghcr.io"},
		headerValue:   registryBasic("octocat", gh),
	}
	bearer := credentialAudienceCandidate{
		carrierMask:   config.CredentialAudienceCarrierRegistryBearer,
		registryHosts: []string{"ghcr.io"},
		headerValue:   "Bearer " + jwt,
	}
	if !registryBasicAllowed(basic, "ghcr.io", "https://ghcr.io/token", credentialAudienceAuthorizationBasicSurface) {
		t.Fatal("positive basic control refused")
	}
	if !registryBearerAllowed(bearer, "ghcr.io", "https://ghcr.io/v2/", CredentialAudienceAuthorizationHeaderSurface) {
		t.Fatal("positive bearer control refused")
	}
	for _, target := range []string{"http://ghcr.io/token", "https://ghcr.io/%zz"} {
		if registryBasicAllowed(basic, "ghcr.io", target, credentialAudienceAuthorizationBasicSurface) {
			t.Fatalf("basic allowed for %q", target)
		}
		if registryBearerAllowed(bearer, "ghcr.io", target, CredentialAudienceAuthorizationHeaderSurface) {
			t.Fatalf("bearer allowed for %q", target)
		}
	}
	bad := bearer
	bad.headerValue = "Basic " + jwt
	if registryBearerAllowed(bad, "ghcr.io", "https://ghcr.io/v2/", CredentialAudienceAuthorizationHeaderSurface) {
		t.Fatal("bearer allowed with Basic scheme")
	}
}

// GitHub's stateless installation token is a ghs_-prefixed JWT, so the JWT
// pattern also matches inside it. A validated Basic login must clear both.
func TestRegistryBasicStatelessInstallationToken(t *testing.T) {
	t.Parallel()
	s := MustNew(credentialAudienceTestConfig())
	seg := func(v string) string { return base64.RawURLEncoding.EncodeToString([]byte(v)) }
	stateless := "ghs_" + seg(`{"alg":"ES256","typ":"JWT"}`) + "." +
		seg(`{"iss":"github","sub":"installation","pad":"`+strings.Repeat("x", 120)+`"}`) + "." +
		strings.Repeat("B", 86)
	matches := s.ScanTextForDLP(context.Background(), stateless).Matches
	if !hasTextDLPMatch(matches, "JWT Token", "") || !hasTextDLPMatch(matches, "GitHub Token", "") {
		t.Fatalf("fixture must match both patterns: %v", matches)
	}
	for _, target := range []string{"https://ghcr.io/token", "https://maven.pkg.github.com/o/r/p.jar", "https://nuget.pkg.github.com/o/index.json"} {
		retained, _ := s.FilterHeaderDLPMatches(matches, target, "Authorization", registryBasic("octocat", stateless))
		if len(retained) != 0 {
			t.Fatalf("%s: stateless token login retained %v", target, retained)
		}
	}
	for _, tc := range []struct{ target, value string }{
		{"https://registry.vendor.example/token", registryBasic("octocat", stateless)},
		{"https://ghcr.io/token", registryBasic(stateless, "pw")},
		{"https://maven.pkg.github.com/o/r", "Bearer " + stateless},
	} {
		retained, _ := s.FilterHeaderDLPMatches(matches, tc.target, "Authorization", tc.value)
		if !matchRetained(retained, "JWT Token") {
			t.Fatalf("%s %q: JWT match dropped", tc.target, tc.value[:12])
		}
	}
}
