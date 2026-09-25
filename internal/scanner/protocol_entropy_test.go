// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	// entropyTestMixed is a long mixed-alphabet token of the kind the gate
	// exists to stop. Its whole-string entropy is asserted below.
	entropyTestMixed = "Zq8xLm2Pv7Rt4Ws9Kd3Hf6Jb1Nc5Yg0UeAoIt"
	// entropyTestAlphabet is 42 distinct characters, entropy about 5.39.
	entropyTestAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP"
	// rfc7636Challenge is the S256 code_challenge from RFC 7636 Appendix B.
	rfc7636Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

func newProtocolEntropyScanner(t *testing.T) *Scanner {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	return s
}

func percentEncodeAll(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		_, _ = fmt.Fprintf(&b, "%%%02X", s[i])
	}
	return b.String()
}

// TestProtocolValueEntropyFixtures pins the premise of every case below: each
// fixture that is expected to pass only because of the new scoring must be
// over the threshold when measured the old way, as one string.
func TestProtocolValueEntropyFixtures(t *testing.T) {
	const threshold = 4.5
	for name, v := range map[string]string{
		"mixed":            entropyTestMixed,
		"alphabet":         entropyTestAlphabet,
		"pkce challenge":   rfc7636Challenge,
		"idp authorize":    "https://dev-12345678.idp.vendor.example/oauth2/default/v1/authorize",
		"account callback": "https://123456789012.auth.region-1.vendor.example/oauth2/idpresponse",
		"asset segment":    "ChunkVendorsMap-webpack.Dk3mN8pQ.js",
		"asset map":        "ChunkVendorsMap-webpack.Dk3mN8pQ.js.map",
	} {
		if e := payloadEntropy(v); e <= threshold {
			t.Errorf("fixture %s must exceed %.2f as one string, got %.3f", name, threshold, e)
		}
	}
}

func TestProtocolValueEntropy(t *testing.T) {
	s := newProtocolEntropyScanner(t)
	esc := url.QueryEscape
	pkce := func(extra string) string {
		return "https://idp.vendor.example/authorize?response_type=code&client_id=app-client&code_challenge=" +
			rfc7636Challenge + extra
	}
	threeDeep := "https://a.vendor.example/y?u=" + esc("https://b.vendor.example/x?u="+esc("https://evil.example/"+entropyTestMixed))

	cases := []struct {
		name     string
		raw      string
		block    bool
		wantPart string
	}{
		// Nested URLs whose parts are ordinary pass, although the whole value is over.
		{"idp authorize URL as a query value", "https://app.vendor.example/login?next=" + esc("https://dev-12345678.idp.vendor.example/oauth2/default/v1/authorize"), false, ""},
		{"account-numbered callback as redirect_uri", "https://idp.vendor.example/authorize?redirect_uri=" + esc("https://123456789012.auth.region-1.vendor.example/oauth2/idpresponse"), false, ""},

		// Every part of a nested URL is still measured.
		{"secret in nested path", "https://app.vendor.example/login?next=" + esc("https://evil.example/"+entropyTestMixed), true, "nested URL path segment"},
		{"secret in nested userinfo", "https://app.vendor.example/login?next=" + esc("https://"+entropyTestAlphabet+"@evil.example/"), true, "nested URL userinfo"},
		{"secret in nested password", "https://app.vendor.example/login?next=" + esc("https://u:"+entropyTestAlphabet+"@evil.example/"), true, "nested URL userinfo"},
		{"secret in nested fragment", "https://idp.vendor.example/authorize?redirect_uri=" + esc("https://app.vendor.example/cb#"+entropyTestAlphabet), true, "nested URL fragment"},
		{"secret in nested host label", "https://app.vendor.example/login?next=" + esc("https://"+entropyTestMixed+".evil.example/"), true, "nested URL host label"},
		{"secret in nested query value", "https://app.vendor.example/login?next=" + esc("https://evil.example/cb?t="+entropyTestMixed), true, "nested URL query value"},
		{"secret in nested query key", "https://app.vendor.example/login?next=" + esc("https://evil.example/cb?"+entropyTestMixed+"=1"), true, "nested URL query key"},
		{"extra percent-encoding layer", "https://app.vendor.example/login?next=" + esc("https://evil.example/"+percentEncodeAll(entropyTestAlphabet)), true, "nested URL path segment"},
		{"past the depth cap scored whole", "https://app.vendor.example/login?next=" + esc(threeDeep), true, "nested URL query value"},
		{"data URL stays whole", "https://app.vendor.example/login?next=" + esc("data:text/plain,"+entropyTestMixed), true, ""},
		{"javascript URL stays whole", "https://app.vendor.example/login?next=" + esc("javascript:"+entropyTestMixed), true, ""},
		{"nested URL beside a semicolon", "https://app.vendor.example/login?a=1;next=" + esc("https://evil.example/"+entropyTestMixed), true, "nested URL path segment"},

		// PKCE: only an exact S256 challenge on a request that declares S256.
		{"pkce S256", pkce("&code_challenge_method=S256"), false, ""},
		{"pkce S256 inside a nested authorize URL", "https://app.vendor.example/login?next=" + esc(pkce("&code_challenge_method=S256")), false, ""},
		{"pkce method missing", pkce(""), true, ""},
		{"pkce method plain", pkce("&code_challenge_method=plain"), true, ""},
		{"pkce method lower case", pkce("&code_challenge_method=s256"), true, ""},
		{"pkce S256 and plain", pkce("&code_challenge_method=S256&code_challenge_method=plain"), true, ""},
		{"pkce second challenge not hash shaped", pkce("&code_challenge_method=S256&code_challenge=" + rfc7636Challenge + "x"), true, ""},
		{"pkce padded challenge", "https://idp.vendor.example/authorize?code_challenge_method=S256&code_challenge=" + esc(rfc7636Challenge[:42]+"="), true, ""},
		{"pkce challenge under another name", "https://idp.vendor.example/authorize?code_challenge_method=S256&state=" + rfc7636Challenge, true, ""},
		// url.ParseQuery drops a pair containing ';', so the semicolon-aware
		// reader is the only one that sees this query. It applies the same gate
		// and still scores every other ';'-separated value on its own.
		{"pkce S256 beside a semicolon", pkce(";code_challenge_method=S256"), false, ""},
		{"secret after a semicolon pkce pair", pkce(";code_challenge_method=S256;x=" + entropyTestMixed), true, ""},

		// Asset names: a whole trailing hash slot of at most eight characters.
		{"hashed asset", "https://cdn.vendor.example/assets/ChunkVendorsMap-webpack.Dk3mN8pQ.js", false, ""},
		{"hashed source map", "https://cdn.vendor.example/assets/ChunkVendorsMap-webpack.Dk3mN8pQ.js.map", false, ""},
		{"all-hash asset name", "https://cdn.vendor.example/assets/a1B2c3D4e5F6g7H8i9J0.js", true, ""},
		{"long token before extension", "https://cdn.vendor.example/assets/app." + entropyTestMixed + ".js", true, ""},
		{"upper-case extension", "https://cdn.vendor.example/assets/ChunkVendorsMap-webpack.Dk3mN8pQ.JS", true, ""},
		{"unlisted extension", "https://cdn.vendor.example/assets/ChunkVendorsMap-webpack.Dk3mN8pQ.png", true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := url.Parse(tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			r := s.checkEntropy(parsed)
			if blocked := !r.Allowed; blocked != tc.block {
				t.Fatalf("blocked = %v, want %v (%s)", blocked, tc.block, r.Reason)
			}
			if tc.wantPart != "" && !strings.Contains(r.Reason, tc.wantPart) {
				t.Fatalf("reason %q does not name %q", r.Reason, tc.wantPart)
			}
			if tc.block && r.Scanner != ScannerEntropy {
				t.Fatalf("scanner = %q, want %q", r.Scanner, ScannerEntropy)
			}
		})
	}
}

// A nested-part reason keeps the shape remediation matches on, so the
// operator still gets the exact-parameter exclusion hint.
func TestNestedEntropyReasonIsQueryEntropy(t *testing.T) {
	s := newProtocolEntropyScanner(t)
	parsed, err := url.Parse("https://app.vendor.example/login?next=" + url.QueryEscape("https://evil.example/"+entropyTestMixed))
	if err != nil {
		t.Fatal(err)
	}
	r := s.checkEntropy(parsed)
	if r.Allowed {
		t.Fatal("nested secret was allowed")
	}
	if !strings.HasPrefix(r.Reason, queryEntropyParamReasonPrefix+`"next" nested URL path segment (`) {
		t.Fatalf("reason = %q", r.Reason)
	}
	if !IsQueryEntropyResult(r) {
		t.Fatalf("IsQueryEntropyResult(%q) = false", r.Reason)
	}
}

// The operator's exact-parameter exclusion still covers a nested finding.
func TestNestedEntropyHonorsParamExclusion(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.FetchProxy.Monitoring.QueryEntropyParamExclusions = []config.QueryEntropyParamExclusion{
		{Host: "app.vendor.example", Path: "/login", Param: "next"},
	}
	s := MustNew(cfg)
	defer s.Close()
	parsed, err := url.Parse("https://app.vendor.example/login?next=" + url.QueryEscape("https://evil.example/"+entropyTestMixed))
	if err != nil {
		t.Fatal(err)
	}
	if r := s.checkEntropy(parsed); !r.Allowed {
		t.Fatalf("excluded parameter blocked: %s", r.Reason)
	}
}

func TestAssetEntropySubject(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"app.min.a1b2c3d4.js", "app.min"},
		{"styles.Q9.css", "styles"},
		{"font.ab_-12CD.woff2", "font"},
		{"module.x.mjs", "module"},
		{"bundle.abc12345.js.map", "bundle"},
		{"bundle.abc12345.map", "bundle"},
		{"bundle.abc123456.js", "bundle.abc123456.js"}, // slot longer than eight
		{"bundle..js", "bundle..js"},                   // empty slot
		{"bundle.a+b.js", "bundle.a+b.js"},             // character outside the slot alphabet
		{"nodot.js", "nodot.js"},
		{"bundle.abc.js.", "bundle.abc.js."}, // trailing dot is not the extension
		{"bundle.abc.JS", "bundle.abc.JS"},
		{"plain-segment", "plain-segment"},
		{".abc.js", ""},
	} {
		if got := assetEntropySubject(tc.in); got != tc.want {
			t.Errorf("assetEntropySubject(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestPKCES256Declared(t *testing.T) {
	for _, tc := range []struct {
		methods []string
		want    bool
	}{
		{nil, false},
		{[]string{"S256"}, true},
		{[]string{"S256", "S256"}, true},
		{[]string{"S256", "plain"}, false},
		{[]string{"s256"}, false},
		{[]string{""}, false},
	} {
		if got := pkceS256Declared(tc.methods); got != tc.want {
			t.Errorf("pkceS256Declared(%q) = %v, want %v", tc.methods, got, tc.want)
		}
	}
}

func TestIsPKCES256Challenge(t *testing.T) {
	for _, tc := range []struct {
		name, key, value string
		s256             bool
		want             bool
	}{
		{"rfc sample", pkceChallengeParam, rfc7636Challenge, true, true},
		{"method not s256", pkceChallengeParam, rfc7636Challenge, false, false},
		{"other key", "code_verifier", rfc7636Challenge, true, false},
		{"42 chars", pkceChallengeParam, rfc7636Challenge[:42], true, false},
		{"44 chars", pkceChallengeParam, rfc7636Challenge + "A", true, false},
		{"standard base64 plus", pkceChallengeParam, rfc7636Challenge[:42] + "+", true, false},
		{"padding", pkceChallengeParam, rfc7636Challenge[:42] + "=", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPKCES256Challenge(tc.key, tc.value, tc.s256); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseEntropyNestedURL(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"https://app.vendor.example/cb", true},
		{"HTTP://app.vendor.example/cb", true},
		{percentEncodeAll("https://app.vendor.example/cb"), true},
		{"https:opaque-payload", false},
		{"https:///no-host", false},
		{"ftp://files.vendor.example/x", false},
		{"data:text/plain,abc", false},
		{"//app.vendor.example/cb", false},
		{"not a url", false},
		{"https://bad host/%zz", false},
	} {
		if _, got := parseEntropyNestedURL(tc.in); got != tc.want {
			t.Errorf("parseEntropyNestedURL(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
