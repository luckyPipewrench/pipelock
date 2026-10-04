// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	payload := enc.EncodeToString([]byte(`{"aud":"release-assets.githubusercontent.com","iss":"github.com","path":"/asset","nbf":1000,"exp":1300}`))
	sum := sha256.Sum256([]byte("audience-fixture"))
	return header + "." + payload + "." + enc.EncodeToString(sum[:])
}

// claimJWT builds a JWT-shaped token with the given payload JSON.
func claimJWT(payload string) string {
	enc := base64.RawURLEncoding
	sum := sha256.Sum256([]byte(payload))
	return enc.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + enc.EncodeToString([]byte(payload)) + "." + enc.EncodeToString(sum[:])
}

// oddHeaderJWT is a grant-shaped token whose header carries an extra field.
func oddHeaderJWT() string {
	enc := base64.RawURLEncoding
	sum := sha256.Sum256([]byte("odd"))
	return enc.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT","kid":"x"}`)) + "." +
		enc.EncodeToString([]byte(`{"aud":"release-assets.githubusercontent.com","iss":"github.com","nbf":1000,"exp":1300}`)) + "." + enc.EncodeToString(sum[:])
}

// An allowance keyed on destination alone would let any JWT reach the release
// host. Only a grant GitHub issued for that host may; every other token in the
// query keeps the URL blocked.
func TestScan_GitHubReleaseGrantJWT_RequiresGrantClaims(t *testing.T) {
	t.Parallel()
	s := MustNew(credentialAudienceTestConfig())
	defer s.Close()
	grant := fakeAudienceJWT()
	unrelated := claimJWT(`{"aud":"api.vendor.example","iss":"auth.vendor.example","sub":"svc"}`)
	for _, tc := range []struct {
		name      string
		query     string
		wantAllow bool
	}{
		{"real grant", "jwt=" + grant, true},
		{"audience list naming the host", "jwt=" + claimJWT(`{"aud":["other.example","release-assets.githubusercontent.com"],"iss":"github.com","nbf":1000,"exp":1300}`), false},
		{"extra claim beside a valid grant shape", "jwt=" + claimJWT(`{"aud":"release-assets.githubusercontent.com","iss":"github.com","nbf":1000,"exp":1300,"x":"data"}`), false},
		{"archive grant lifetime", "jwt=" + claimJWT(`{"aud":"release-assets.githubusercontent.com","iss":"github.com","key":"key1","nbf":1000,"exp":2800,"path":"releaseassetproduction.blob.core.windows.net"}`), true},
		{"large archive grant lifetime", "jwt=" + claimJWT(`{"aud":"release-assets.githubusercontent.com","iss":"github.com","key":"key1","nbf":1000,"exp":4600,"path":"releaseassetproduction.blob.core.windows.net"}`), true},
		{"lifetime one second past a large archive grant", "jwt=" + claimJWT(`{"aud":"release-assets.githubusercontent.com","iss":"github.com","key":"key1","nbf":1000,"exp":4601,"path":"releaseassetproduction.blob.core.windows.net"}`), false},
		{"lifetime longer than a grant", "jwt=" + claimJWT(`{"aud":"release-assets.githubusercontent.com","iss":"github.com","nbf":1000,"exp":8200}`), false},
		{"expiry before not-before", "jwt=" + claimJWT(`{"aud":"release-assets.githubusercontent.com","iss":"github.com","nbf":1300,"exp":1000}`), false},
		{"header with an extra field", "jwt=" + oddHeaderJWT(), false},
		{"signature longer than an HS256 MAC", "jwt=" + fakeAudienceJWT() + "AAAAAAAAAAAAAAAAAAAAAA", false},
		{"unrelated service token", "jwt=" + claimJWT(`{"aud":"api.vendor.example","iss":"auth.vendor.example","sub":"svc"}`), false},
		{"right audience, wrong issuer", "jwt=" + claimJWT(`{"aud":"release-assets.githubusercontent.com","iss":"auth.vendor.example"}`), false},
		{"right audience, no issuer", "jwt=" + claimJWT(`{"aud":"release-assets.githubusercontent.com"}`), false},
		{"github issuer, other audience", "jwt=" + claimJWT(`{"aud":"api.vendor.example","iss":"github.com"}`), false},
		{"no audience", "jwt=" + claimJWT(`{"iss":"github.com"}`), false},
		{"payload truncated json", "jwt=" + claimJWT(`{"aud":"release-assets.githubusercontent.com","iss":"github.com"`), false},
		{"grant plus an unrelated token", "jwt=" + grant + "&t=" + claimJWT(`{"aud":"api.vendor.example","iss":"auth.vendor.example"}`), false},
		{"unrelated token before the grant", "t=" + claimJWT(`{"aud":"api.vendor.example","iss":"auth.vendor.example"}`) + "&jwt=" + grant, false},
		{"grant plus a base64-hidden unrelated token", "jwt=" + grant + "&t=" + base64.StdEncoding.EncodeToString([]byte(unrelated)), false},
		{"grant plus a hex-hidden unrelated token", "jwt=" + grant + "&t=" + hex.EncodeToString([]byte(unrelated)), false},
		{"grant plus an unrelated token as a key", "jwt=" + grant + "&" + unrelated + "=1", false},
		{"grant with bytes appended in the same value", "jwt=" + grant + "&t=" + grant + "AAAAAAAA", false},
		{"grant with bytes appended, base64 in a value", "jwt=" + grant + "&t=" + base64.StdEncoding.EncodeToString([]byte(grant+"AAAAAAAA")), false},
		{"grant plus an unrelated token split around noise", "jwt=" + grant + "&a=" + unrelated[:40] + "&noise=A&b=" + unrelated[40:], false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := s.Scan(context.Background(), githubReleaseAssetsBase+"?"+tc.query)
			if result.Allowed != tc.wantAllow {
				t.Fatalf("Allowed = %v (reason %q), want %v", result.Allowed, result.Reason, tc.wantAllow)
			}
		})
	}
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
		{"split across query values", githubReleaseAssetsBase + "?a=" + jwt[:40] + "&b=" + jwt[40:] + "&c=1", false},

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

// releaseGrantSASSig returns a 44-character base64 signature (32 raw bytes,
// one trailing '=') from seed: the exact shape of a real Azure user-delegation
// SAS HMAC-SHA256 signature, matching the "Azure SAS Token" pattern's
// unpadded-base64 alternative once percent-encoded in a query. sha256.Sum256
// is 32 bytes by construction, so this never needs a literal length constant.
func releaseGrantSASSig(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// releaseGrantSASQuery builds GitHub's real release-asset redirect query
// shape: the twelve Azure user-delegation SAS parameters releaseGrantSASShapeValid
// requires, the two response-content overrides GitHub also sends (never
// required), and the release download grant JWT beside them.
func releaseGrantSASQuery(jwt, sigSeed string) string {
	return "sp=r&sv=2018-11-09&sr=b&spr=https&se=2026-09-30T00%3A37%3A09Z" +
		"&rscd=attachment%3B+filename%3Dtool_1.0_checksums.txt&rsct=application%2Foctet-stream" +
		"&skoid=00000000-0000-4000-8000-000000000001&sktid=00000000-0000-4000-8000-000000000002" +
		"&skt=2026-09-29T23%3A36%3A42Z&ske=2026-09-30T00%3A37%3A09Z&sks=b&skv=2018-11-09" +
		"&sig=" + url.QueryEscape(releaseGrantSASSig(sigSeed)) + "&jwt=" + jwt +
		"&response-content-disposition=attachment%3B%20filename%3Dtool_1.0_checksums.txt" +
		"&response-content-type=application%2Foctet-stream"
}

// The real redirect shape: a long signed query with a base64 signature beside
// the grant. Default entropy thresholds stay on, so this fails if the query
// entropy check, or the Azure SAS DLP pattern itself, blocks the grant, the
// signature, or any of the SAS's other signed parameters.
func TestScan_GitHubReleaseGrantJWT_RealRedirectShapeDefaultEntropy(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	cfg.Internal = nil
	s := MustNew(cfg)
	defer s.Close()
	query := releaseGrantSASQuery(fakeAudienceJWT(), "release-redirect-sig-fixture")
	target := "https://" + githubReleaseAssetsHost + "/github-production-release-asset/212613049/00000000-0000-4000-8000-000000000003?" + query

	result := s.Scan(context.Background(), target)
	if !result.Allowed {
		t.Fatalf("release redirect blocked: scanner=%s reason=%s", result.Scanner, result.Reason)
	}
	assertAudienceAllowContains(t, result, jwtPatternName)
	assertAudienceAllowContains(t, result, "Azure SAS Token")

	other := s.Scan(context.Background(), strings.Replace(target, githubReleaseAssetsHost, "api.vendor.example", 1))
	if other.Allowed {
		t.Fatal("same redirect shape allowed at a non-audience host")
	}
}

// The Azure SAS is trusted only as part of the whole grant: it must be
// HTTPS, at the exact release-asset host, carrying a JWT this scanner
// verifies as GitHub's release grant for that host, with every signed SAS
// parameter present. Any one of those failing keeps the DLP match and
// blocks, even though the query otherwise looks like a genuine redirect.
func TestScan_GitHubReleaseGrantSAS_RequiresGrantAndShape(t *testing.T) {
	t.Parallel()
	s := MustNew(credentialAudienceTestConfig())
	defer s.Close()
	jwt := fakeAudienceJWT()
	wrongHostJWT := claimJWT(`{"aud":"api.vendor.example","iss":"github.com","nbf":1000,"exp":1300}`)
	fullQuery := releaseGrantSASQuery(jwt, "sas-shape-fixture")

	for _, tc := range []struct {
		name      string
		target    string
		wantAllow bool
	}{
		{"allow: real redirect shape", "https://" + githubReleaseAssetsHost + "/asset/1?" + fullQuery, true},
		{"allow: one hour grant with SAS", "https://" + githubReleaseAssetsHost + "/asset/1?" + releaseGrantSASQuery(claimJWT(`{"aud":"release-assets.githubusercontent.com","iss":"github.com","nbf":1000,"exp":4600}`), "sas-hour-fixture"), true},
		{"deny: grant one second past cap with SAS", "https://" + githubReleaseAssetsHost + "/asset/1?" + releaseGrantSASQuery(claimJWT(`{"aud":"release-assets.githubusercontent.com","iss":"github.com","nbf":1000,"exp":4601}`), "sas-over-cap-fixture"), false},
		{"deny: SAS without any jwt", "https://" + githubReleaseAssetsHost + "/asset/1?" + strings.Replace(fullQuery, "&jwt="+jwt, "", 1), false},
		{"deny: jwt issued for a different host", "https://" + githubReleaseAssetsHost + "/asset/1?" + strings.Replace(fullQuery, jwt, wrongHostJWT, 1), false},
		{"deny: SAS on a lookalike host", "https://" + githubReleaseAssetsHost + ".evil.example/asset/1?" + fullQuery, false},
		{"deny: SAS on a real Azure blob host", "https://vendorstorage.blob.core.windows.net/asset/1?" + fullQuery, false},
		{"deny: SAS over plain http", "http://" + githubReleaseAssetsHost + "/asset/1?" + fullQuery, false},
		{"deny: missing a required delegation-key parameter", "https://" + githubReleaseAssetsHost + "/asset/1?" + strings.Replace(fullQuery, "skoid=00000000-0000-4000-8000-000000000001&", "", 1), false},
		// The allowance covers the query's one sig parameter only. A second
		// signature smuggled into another parameter, encoded or plain, or a
		// duplicate sig (including an encoded key), keeps the URL blocked.
		{"deny: second SAS encoded in another parameter", "https://" + githubReleaseAssetsHost + "/asset/1?" + fullQuery + "&x=" + url.QueryEscape("sig="+releaseGrantSASSig("smuggled-fixture")), false},
		{"deny: second SAS in a parameter key", "https://" + githubReleaseAssetsHost + "/asset/1?" + fullQuery + "&" + url.QueryEscape("sig="+releaseGrantSASSig("smuggled-fixture")) + "=1", false},
		{"deny: duplicate sig parameter", "https://" + githubReleaseAssetsHost + "/asset/1?" + fullQuery + "&sig=" + url.QueryEscape(releaseGrantSASSig("smuggled-fixture")), false},
		{"deny: duplicate sig under an encoded key", "https://" + githubReleaseAssetsHost + "/asset/1?" + fullQuery + "&si%67=" + url.QueryEscape(releaseGrantSASSig("smuggled-fixture")), false},
		// Each signed field must hold its documented format, exactly once, so
		// none can carry other data under the grant's DLP and entropy allowance.
		{"deny: key object ID carrying a non-GUID secret", "https://" + githubReleaseAssetsHost + "/asset/1?" + strings.Replace(fullQuery, "skoid=00000000-0000-4000-8000-000000000001", "skoid="+releaseGrantSASSig("entropy-smuggle"), 1), false},
		{"deny: expiry that is not a timestamp", "https://" + githubReleaseAssetsHost + "/asset/1?" + strings.Replace(fullQuery, "se=2026-09-30T00%3A37%3A09Z", "se=tomorrow", 1), false},
		{"deny: signature of the wrong length", "https://" + githubReleaseAssetsHost + "/asset/1?" + strings.Replace(fullQuery, "&sig="+url.QueryEscape(releaseGrantSASSig("sas-shape-fixture")), "&sig="+url.QueryEscape(releaseGrantSASSig("sas-shape-fixture")+"AAAA"), 1), false},
		{"deny: a signed field given twice", "https://" + githubReleaseAssetsHost + "/asset/1?" + fullQuery + "&sp=r", false},
		{"deny: account-key SAS shape (no delegation-key fields)", "https://" + githubReleaseAssetsHost + "/asset/1?sp=r&sv=2018-11-09&sr=b&spr=https&se=2026-09-30T00%3A37%3A09Z&sig=" + url.QueryEscape(releaseGrantSASSig("account-key-fixture")) + "&jwt=" + jwt, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := s.Scan(context.Background(), tc.target)
			if result.Allowed != tc.wantAllow {
				t.Fatalf("Allowed = %v (scanner=%s reason=%q), want %v", result.Allowed, result.Scanner, result.Reason, tc.wantAllow)
			}
			if tc.wantAllow {
				assertAudienceAllowContains(t, result, "Azure SAS Token")
				assertAudienceAllowContains(t, result, jwtPatternName)
			}
		})
	}
}

// A SAS with GitHub's exact shape, sitting beside a valid grant's query,
// still blocks when the matched SAS text itself is planted in the path
// rather than the query: co-occurrence with a valid grant is not a license
// to move the credential surface.
func TestScan_GitHubReleaseGrantSAS_PathCarriageStaysBlocked(t *testing.T) {
	t.Parallel()
	s := MustNew(credentialAudienceTestConfig())
	defer s.Close()
	jwt := fakeAudienceJWT()
	sig := releaseGrantSASSig("path-carriage-fixture")
	query := releaseGrantSASQuery(jwt, "path-carriage-fixture")
	// The malicious "sig=" also appears in the path; the query still has a
	// valid grant and SAS shape, so only the path placement is under test.
	target := "https://" + githubReleaseAssetsHost + "/asset/sig=" + url.QueryEscape(sig) + "?" + query
	result := s.Scan(context.Background(), target)
	if result.Allowed {
		t.Fatal("path-carried SAS text allowed beside a valid query grant")
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

// No other built-in audience gained query carriage. The JWT built-in is the
// only pattern on CredentialAudienceCarrierURLQuery; the Azure SAS Token
// built-in is the only pattern on the separate ReleaseGrantSAS carrier, and
// shares the JWT's exact host list because it is granted only alongside that
// same JWT grant, never on its own.
func TestBuiltInAudiencesQueryCarriageIsJWTOnly(t *testing.T) {
	t.Parallel()
	for _, p := range config.DefaultDLPPatterns() {
		hasQuery := p.CredentialAudienceCarrierMask&config.CredentialAudienceCarrierURLQuery != 0
		hasReleaseSAS := p.CredentialAudienceCarrierMask&config.CredentialAudienceCarrierReleaseGrantSAS != 0
		switch p.Name {
		case jwtPatternName:
			if !hasQuery || hasReleaseSAS || p.CredentialAudienceCarrierMask != config.CredentialAudienceCarrierURLQuery|config.CredentialAudienceCarrierRegistryBearer|config.CredentialAudienceCarrierRegistryBasic ||
				len(p.CredentialAudienceHosts) != 1 || p.CredentialAudienceHosts[0] != githubReleaseAssetsHost {
				t.Errorf("JWT audience = hosts %v mask %d", p.CredentialAudienceHosts, p.CredentialAudienceCarrierMask)
			}
		case "Azure SAS Token":
			if hasQuery || !hasReleaseSAS || p.CredentialAudienceCarrierMask != config.CredentialAudienceCarrierReleaseGrantSAS ||
				len(p.CredentialAudienceHosts) != 1 || p.CredentialAudienceHosts[0] != githubReleaseAssetsHost {
				t.Errorf("Azure SAS Token audience = hosts %v mask %d", p.CredentialAudienceHosts, p.CredentialAudienceCarrierMask)
			}
		default:
			if hasQuery || hasReleaseSAS {
				t.Errorf("%s gained URL-query or release-SAS carriage", p.Name)
			}
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
		if got := s.urlDLPAudienceSurface(tc.pattern, tc.target, nil); got != tc.want {
			t.Errorf("%s: surface = %q, want %q", tc.name, got, tc.want)
		}
	}

	// Only the audience host pays for the query-less rescan, and one scan's
	// memo computes it once however many matches ask.
	otherHost := &queryLessDLPMemo{}
	if got := s.urlDLPAudienceSurface(jwtPattern, parse("https://api.vendor.example/a?j="+jwt), otherHost); got != "url" || otherHost.done {
		t.Fatalf("non-audience host: surface = %q, rescanned = %v; want url without a rescan", got, otherHost.done)
	}
	shared := &queryLessDLPMemo{}
	release := parse(githubReleaseAssetsBase + "?j=" + jwt)
	for i := 0; i < 2; i++ {
		if got := s.urlDLPAudienceSurface(jwtPattern, release, shared); got != credentialAudienceURLQuerySurface || !shared.done || !shared.clean {
			t.Fatalf("audience host pass %d: surface = %q, memo = %+v", i, got, *shared)
		}
	}
	dirty := &queryLessDLPMemo{done: true, clean: false}
	if got := s.urlDLPAudienceSurface(jwtPattern, release, dirty); got != "url" {
		t.Fatalf("a memoized dirty query-less URL must keep the bare url surface, got %q", got)
	}

	if got := s.urlDLPAudienceSurfaceForTarget(jwtPattern, "https://%zz/a?j="+jwt, nil); got != "url" {
		t.Errorf("malformed target surface = %q, want url", got)
	}
	if got := s.urlDLPAudienceSurfaceForTarget(jwtPattern, githubReleaseAssetsBase+"?j="+jwt, nil); got != credentialAudienceURLQuerySurface {
		t.Errorf("valid target surface = %q, want url_query", got)
	}

	// A bare "url" surface must not earn the allow through the subsequence path.
	kept, allows := s.credentialAudienceAllows(jwtPattern, "https://"+githubReleaseAssetsHost+"/a?j="+jwt, "url")
	if allows || kept.PatternName != "" {
		t.Errorf("bare url surface earned the query grant: %#v", kept)
	}
}

// assertAudienceAllowContains checks one allow record by pattern name without
// requiring it be the only record, for a scan where more than one compiled
// audience earns an allow at once (a JWT grant plus its co-located SAS). Both
// this file's built-in query-carrier audiences share the release-asset host.
func assertAudienceAllowContains(t *testing.T, result Result, pattern string) {
	t.Helper()
	for _, got := range result.CredentialAudienceAllows {
		if got.PatternName != pattern {
			continue
		}
		if got.Surface != "url" || got.Destination != githubReleaseAssetsHost {
			t.Fatalf("audience allow for %q = %#v, want surface=url destination=%q", pattern, got, githubReleaseAssetsHost)
		}
		return
	}
	t.Fatalf("no audience allow for %q in %#v", pattern, result.CredentialAudienceAllows)
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

// The query-entropy exemption matches signed field names exactly, as the SAS
// shape check does, so a case alias of a signed field gets no exemption.
func TestReleaseGrantSASQueryValueAllowed_ExactFieldNames(t *testing.T) {
	t.Parallel()
	s := MustNew(credentialAudienceTestConfig())
	defer s.Close()
	parsed, err := url.Parse("https://" + githubReleaseAssetsHost + "/asset/1?" + releaseGrantSASQuery(fakeAudienceJWT(), "exact-name-fixture"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !s.releaseGrantSASQueryValueAllowed(parsed, "skoid") {
		t.Fatal("signed field skoid lost its exemption under a valid grant")
	}
	for _, alias := range []string{"SKOID", "Sig", "SKT"} {
		if s.releaseGrantSASQueryValueAllowed(parsed, alias) {
			t.Errorf("case alias %q got the signed-field exemption", alias)
		}
	}
}
