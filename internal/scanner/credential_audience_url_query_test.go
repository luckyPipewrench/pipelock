// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	githubReleaseAssetsHost = "release-assets.githubusercontent.com"
	githubReleaseAssetsBase = "https://" + githubReleaseAssetsHost + "/github-production-release-asset/1/asset"
	jwtPatternName          = "JWT Token"
)

// fakeAudienceJWT builds a structurally valid, unsigned-looking JWT at runtime
// so no token literal sits in source.
func fakeAudienceJWT() string {
	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := enc.EncodeToString([]byte(`{"aud":"release-assets.example","sub":"grant"}`))
	sum := sha256.Sum256([]byte("audience-fixture"))
	return header + "." + payload + "." + enc.EncodeToString(sum[:])
}

func TestScan_GitHubReleaseGrantJWT_QueryCarriage(t *testing.T) {
	t.Parallel()
	s := MustNew(credentialAudienceTestConfig())
	defer s.Close()
	jwt := fakeAudienceJWT()

	for _, tc := range []struct {
		name      string
		target    string
		wantAllow bool
	}{
		{"exact host, query", githubReleaseAssetsBase + "?jwt=" + jwt, true},
		{"other query name", githubReleaseAssetsBase + "?grant=" + jwt + "&x=1", true},
		{"uppercase host", "https://RELEASE-ASSETS.GITHUBUSERCONTENT.COM/a/b?jwt=" + jwt, true},
		{"trailing dot host", "https://" + githubReleaseAssetsHost + "./a/b?jwt=" + jwt, true},
		{"explicit default port", "https://" + githubReleaseAssetsHost + ":443/a/b?jwt=" + jwt, true},
		{"percent-encoded value", githubReleaseAssetsBase + "?jwt=" + url.QueryEscape(jwt), true},
		{"split across query values", githubReleaseAssetsBase + "?a=" + jwt[:40] + "&b=" + jwt[40:] + "&c=1", true},

		{"other host", "https://api.vendor.example/a?jwt=" + jwt, false},
		{"suffix lookalike", "https://" + githubReleaseAssetsHost + ".evil.example/a?jwt=" + jwt, false},
		{"prefix lookalike", "https://evilrelease-assets.githubusercontent.com/a?jwt=" + jwt, false},
		{"tld lookalike", "https://release-assets.githubusercontent.co/a?jwt=" + jwt, false},
		{"subdomain of audience host", "https://sub." + githubReleaseAssetsHost + "/a?jwt=" + jwt, false},
		{"sibling storage host", "https://objects.githubusercontent.com/a?jwt=" + jwt, false},
		{"userinfo trick", "https://" + githubReleaseAssetsHost + "@evil.example/a?jwt=" + jwt, false},
		{"cleartext scheme", "http://" + githubReleaseAssetsHost + "/a?jwt=" + jwt, false},
		{"path carriage", githubReleaseAssetsBase + "/" + jwt, false},
		{"path carriage with clean query", githubReleaseAssetsBase + "/" + jwt + "?x=1", false},
		{"path and query both", githubReleaseAssetsBase + "/" + jwt + "?jwt=" + jwt, false},
		{"fragment carriage", githubReleaseAssetsBase + "?x=1#" + jwt, false},
		{"host carriage", "https://" + jwt + ".evil.example/a?x=1", false},
		{"host carriage under the audience host", "https://" + jwt + "." + githubReleaseAssetsHost + "/a?x=1", false},
		{"cyrillic homoglyph host", "https://r\u0435lease-assets.githubusercontent.com/a?jwt=" + jwt, false},
		{"punycode homoglyph host", "https://xn--rlease-assets-yxj.githubusercontent.com/a?jwt=" + jwt, false},
		{"ipv4 literal", "https://192.0.2.10/a?jwt=" + jwt, false},
		{"ipv6 literal", "https://[2001:db8::1]/a?jwt=" + jwt, false},
		{"backslash authority trick", "https://evil.example\\@" + githubReleaseAssetsHost + "/a?jwt=" + jwt, false},
		{"percent-encoded dot host", "https://release-assets%2Egithubusercontent.com/a?jwt=" + jwt, false},
		{"lookalike with trailing dot", "https://" + githubReleaseAssetsHost + ".evil.example./a?jwt=" + jwt, false},
		{"second credential beside the grant", githubReleaseAssetsBase + "?jwt=" + jwt + "&k=" + "AKIA" + "IOSFODNN7" + "EXAMPLE", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := s.Scan(context.Background(), tc.target)
			if result.Allowed != tc.wantAllow {
				t.Fatalf("Allowed = %v (reason %q), want %v", result.Allowed, result.Reason, tc.wantAllow)
			}
			if !tc.wantAllow {
				if len(result.CredentialAudienceAllows) != 0 {
					t.Fatalf("blocked URL emitted allow records: %#v", result.CredentialAudienceAllows)
				}
				return
			}
			assertCredentialAudienceAllow(t, result, jwtPatternName, githubReleaseAssetsHost)
			blob, err := marshalAllows(result.CredentialAudienceAllows)
			if err != nil || strings.Contains(blob, jwt[:20]) {
				t.Fatalf("allow record carries credential bytes: %s (err %v)", blob, err)
			}
		})
	}
}

// The real redirect shape: a long signed query with a base64 signature beside
// the grant. Default entropy thresholds stay on, so this fails if the query
// entropy check blocks the grant or the signature.
func TestScan_GitHubReleaseGrantJWT_RealRedirectShapeDefaultEntropy(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	cfg.Internal = nil
	s := MustNew(cfg)
	defer s.Close()
	sig := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 8) + "K7q2Zp9XwL4mB1vN6tR3yH5jD0cF8gA"))
	query := "sp=r&sv=2018-11-09&sr=b&spr=https&se=2026-09-30T00%3A37%3A09Z" +
		"&rscd=attachment%3B+filename%3Dtool_1.0_checksums.txt&rsct=application%2Foctet-stream" +
		"&skoid=00000000-0000-4000-8000-000000000001&sktid=00000000-0000-4000-8000-000000000002" +
		"&skt=2026-09-29T23%3A36%3A42Z&ske=2026-09-30T00%3A37%3A09Z&sks=b&skv=2018-11-09" +
		"&sig=" + url.QueryEscape(sig) + "&jwt=" + fakeAudienceJWT() +
		"&response-content-disposition=attachment%3B%20filename%3Dtool_1.0_checksums.txt" +
		"&response-content-type=application%2Foctet-stream"
	target := "https://" + githubReleaseAssetsHost + "/github-production-release-asset/212613049/00000000-0000-4000-8000-000000000003?" + query

	result := s.Scan(context.Background(), target)
	if !result.Allowed {
		t.Fatalf("release redirect blocked: scanner=%s reason=%s", result.Scanner, result.Reason)
	}
	assertCredentialAudienceAllow(t, result, jwtPatternName, githubReleaseAssetsHost)

	other := s.Scan(context.Background(), strings.Replace(target, githubReleaseAssetsHost, "api.vendor.example", 1))
	if other.Allowed {
		t.Fatal("same redirect shape allowed at a non-audience host")
	}
}

// Only the JWT pattern is bound to the release host. Every other credential
// class stays blocked in the query there, and next to a JWT.
func TestScan_GitHubReleaseGrantJWT_OtherCredentialsStayBlocked(t *testing.T) {
	t.Parallel()
	s := MustNew(credentialAudienceTestConfig())
	defer s.Close()
	jwt := fakeAudienceJWT()
	for name, credential := range map[string]string{
		"AWS access key":      "AKIA" + "IOSFODNN7EXAMPLE",
		"GitHub token":        "ghp_" + strings.Repeat("a", 36),
		"GitHub fine-grained": "github_pat_" + strings.Repeat("a", 40),
		"Anthropic key":       "sk-" + "ant-" + strings.Repeat("a", 24),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			alone := s.Scan(context.Background(), githubReleaseAssetsBase+"?k="+credential)
			if alone.Allowed {
				t.Fatalf("%s allowed in query at the release host", name)
			}
			beside := s.Scan(context.Background(), githubReleaseAssetsBase+"?jwt="+jwt+"&k="+credential)
			if beside.Allowed {
				t.Fatalf("%s beside a JWT allowed at the release host", name)
			}
		})
	}
}

// Header, body and WebSocket-frame text do not carry the URL-query surface, so
// the grant is refused there even at the release host.
func TestFilterTextDLPMatchesForDestination_GitHubReleaseGrantJWTOnlyInQuery(t *testing.T) {
	t.Parallel()
	s := MustNew(credentialAudienceTestConfig())
	defer s.Close()
	matches := s.ScanTextForDLPQuiet(context.Background(), fakeAudienceJWT()).Matches
	if !matchRetained(matches, jwtPatternName) {
		t.Fatal("control: JWT text did not match the JWT pattern")
	}
	for _, surface := range []string{
		"header", CredentialAudienceAuthorizationHeaderSurface, credentialAudienceAuthorizationTokenSurface,
		credentialAudienceAuthorizationBasicSurface, credentialAudiencePrivateTokenSurface,
		credentialAudienceJobTokenSurface, "body", "websocket", "url",
	} {
		kept, allows := s.FilterTextDLPMatchesForDestination(matches, githubReleaseAssetsBase, surface)
		if !matchRetained(kept, jwtPatternName) || len(allows) != 0 {
			t.Errorf("surface %q at the release host: kept=%d allows=%#v", surface, len(kept), allows)
		}
	}
	kept, allows := s.FilterTextDLPMatchesForDestination(matches, githubReleaseAssetsBase, credentialAudienceURLQuerySurface)
	if matchRetained(kept, jwtPatternName) || !audienceAllowFor(allows, jwtPatternName) {
		t.Errorf("control: url_query surface at the release host: kept=%d allows=%#v", len(kept), allows)
	}
	if allows[0].Surface != "url" {
		t.Errorf("allow surface = %q, want url", allows[0].Surface)
	}
}

// No other built-in audience gained query carriage, and the JWT built-in is
// query-only.
func TestBuiltInAudiencesQueryCarriageIsJWTOnly(t *testing.T) {
	t.Parallel()
	for _, p := range config.DefaultDLPPatterns() {
		hasQuery := p.CredentialAudienceCarrierMask&config.CredentialAudienceCarrierURLQuery != 0
		if p.Name == jwtPatternName {
			if !hasQuery || p.CredentialAudienceCarrierMask != config.CredentialAudienceCarrierURLQuery ||
				len(p.CredentialAudienceHosts) != 1 || p.CredentialAudienceHosts[0] != githubReleaseAssetsHost {
				t.Errorf("JWT audience = hosts %v mask %d", p.CredentialAudienceHosts, p.CredentialAudienceCarrierMask)
			}
			continue
		}
		if hasQuery {
			t.Errorf("%s gained URL-query carriage", p.Name)
		}
	}
}

func TestUrlDLPAudienceSurface_Edges(t *testing.T) {
	t.Parallel()
	s := MustNew(credentialAudienceTestConfig())
	defer s.Close()
	var jwtPattern, plainPattern *compiledPattern
	for _, p := range s.dlpPatterns {
		switch p.name {
		case jwtPatternName:
			jwtPattern = p
		case "Anthropic API Key":
			plainPattern = p
		}
	}
	if jwtPattern == nil || plainPattern == nil {
		t.Fatal("expected patterns not compiled")
	}
	parse := func(raw string) *url.URL {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	jwt := fakeAudienceJWT()
	for _, tc := range []struct {
		name    string
		pattern *compiledPattern
		target  *url.URL
		want    string
	}{
		{"nil pattern", nil, parse(githubReleaseAssetsBase + "?j=" + jwt), "url"},
		{"nil url", jwtPattern, nil, "url"},
		{"pattern without query carrier", plainPattern, parse(githubReleaseAssetsBase + "?j=" + jwt), "url"},
		{"no query", jwtPattern, parse(githubReleaseAssetsBase), "url"},
		{"query without the credential", jwtPattern, parse(githubReleaseAssetsBase + "?j=1"), "url"},
		{"query with an empty value", jwtPattern, parse(githubReleaseAssetsBase + "?j="), "url"},
		{"query carriage", jwtPattern, parse(githubReleaseAssetsBase + "?j=" + jwt), credentialAudienceURLQuerySurface},
		{"path carriage", jwtPattern, parse(githubReleaseAssetsBase + "/" + jwt + "?j=" + jwt), "url"},
	} {
		if got := s.urlDLPAudienceSurface(tc.pattern, tc.target); got != tc.want {
			t.Errorf("%s: surface = %q, want %q", tc.name, got, tc.want)
		}
	}

	if got := s.urlDLPAudienceSurfaceForTarget(jwtPattern, "https://%zz/a?j="+jwt); got != "url" {
		t.Errorf("malformed target surface = %q, want url", got)
	}
	if got := s.urlDLPAudienceSurfaceForTarget(jwtPattern, githubReleaseAssetsBase+"?j="+jwt); got != credentialAudienceURLQuerySurface {
		t.Errorf("valid target surface = %q, want url_query", got)
	}

	// A bare "url" surface must not earn the allow through the subsequence path.
	kept, allows := s.credentialAudienceAllows(jwtPattern, "https://"+githubReleaseAssetsHost+"/a?j="+jwt, "url")
	if allows || kept.PatternName != "" {
		t.Errorf("bare url surface earned the query grant: %#v", kept)
	}
}

func marshalAllows(allows []CredentialAudienceAllow) (string, error) {
	out, err := json.Marshal(allows)
	return string(out), err
}

func TestCredentialAudienceURLQueryRequiresHTTPS(t *testing.T) {
	t.Parallel()
	candidates := []credentialAudienceCandidate{{
		patternName: jwtPatternName,
		hosts:       []string{githubReleaseAssetsHost},
		carrierMask: config.CredentialAudienceCarrierURLQuery,
	}}
	for _, scheme := range []string{"https", "wss", "http", "ws"} {
		t.Run(scheme, func(t *testing.T) {
			keep, allows := filterCredentialAudience(candidates, scheme+"://"+githubReleaseAssetsHost+"/asset", credentialAudienceURLQuerySurface)
			wantAllow := scheme == "https"
			if keep[0] == wantAllow || (len(allows) != 0) != wantAllow {
				t.Fatalf("scheme %s: keep=%v allows=%v, want allowance=%v", scheme, keep, allows, wantAllow)
			}
		})
	}
}
