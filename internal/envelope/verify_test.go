// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dunglas/httpsfv"
)

func TestVerifier_VerifyRequestAcceptsSignedEnvelope(t *testing.T) {
	t.Parallel()

	pub, priv := testSignerKey(t)
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	req := signedVerifierRequest(t, priv, now, strings.Repeat("a", 16))

	verifier := newTestVerifier(t, pub, now)
	env, err := verifier.VerifyRequest(req, []byte(strings.Repeat("a", 16)))
	if err != nil {
		t.Fatalf("VerifyRequest: %v", err)
	}
	if env.Actor != "spiffe://example.test/agent/alpha" {
		t.Fatalf("actor = %q", env.Actor)
	}
}

func TestVerifier_VerifyRequestAcceptsServerOriginFormTargetURI(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		targetURL string
		tls       bool
	}{
		{
			name:      "http path",
			targetURL: "http://upstream.example/api",
		},
		{
			name:      "http path and query",
			targetURL: "http://upstream.example/api?x=1&next=%2Fok",
		},
		{
			name:      "https path",
			targetURL: "https://upstream.example/api",
			tls:       true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pub, priv := testSignerKey(t)
			now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
			body := strings.Repeat("a", 16)
			signed := signedVerifierRequestWithURL(t, priv, now, tt.targetURL, body)

			serverReq := newTestRequest(t, signed.Method, signed.URL.RequestURI(), strings.NewReader(body))
			serverReq.Host = signed.URL.Host
			serverReq.Header = signed.Header.Clone()
			if tt.tls {
				serverReq.TLS = &tls.ConnectionState{}
			}

			verifier := newTestVerifier(t, pub, now)
			if _, err := verifier.VerifyRequest(serverReq, []byte(body)); err != nil {
				t.Fatalf("VerifyRequest with origin-form target URI: %v", err)
			}
		})
	}
}

func TestVerifier_RejectsOriginFormTargetURIMismatch(t *testing.T) {
	t.Parallel()

	pub, priv := testSignerKey(t)
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	body := strings.Repeat("a", 16)
	signed := signedVerifierRequestWithURL(t, priv, now, "https://upstream.example/api", body)

	t.Run("host mismatch", func(t *testing.T) {
		t.Parallel()

		serverReq := newTestRequest(t, signed.Method, signed.URL.RequestURI(), strings.NewReader(body))
		serverReq.Host = "attacker.example"
		serverReq.TLS = &tls.ConnectionState{}
		serverReq.Header = signed.Header.Clone()

		verifier := newTestVerifier(t, pub, now)
		if _, err := verifier.VerifyRequest(serverReq, []byte(body)); err == nil {
			t.Fatal("host mismatch should fail verification")
		}
	})

	t.Run("scheme mismatch", func(t *testing.T) {
		t.Parallel()

		serverReq := newTestRequest(t, signed.Method, signed.URL.RequestURI(), strings.NewReader(body))
		serverReq.Host = signed.URL.Host
		serverReq.Header = signed.Header.Clone()

		verifier := newTestVerifier(t, pub, now)
		if _, err := verifier.VerifyRequest(serverReq, []byte(body)); err == nil {
			t.Fatal("scheme mismatch should fail verification")
		}
	})
}

func TestTargetURIComponentRequiresAuthorityForOriginForm(t *testing.T) {
	t.Parallel()

	req := newTestRequest(t, http.MethodGet, "/", nil)
	req.Host = ""
	if _, err := targetURIComponent(req); err == nil {
		t.Fatal("origin-form request without Host should fail")
	}
}

func TestTargetURIComponentRejectsNilURL(t *testing.T) {
	t.Parallel()

	req := newTestRequest(t, http.MethodGet, "https://upstream.example/api", nil)
	req.URL = nil
	if _, err := targetURIComponent(req); err == nil {
		t.Fatal("request with nil URL should fail")
	}
}

func TestTargetURIComponentDefaultsEmptyRequestURIToSlash(t *testing.T) {
	t.Parallel()

	req := newTestRequest(t, http.MethodGet, "https://upstream.example/api", nil)
	req.URL = &url.URL{}
	req.Host = "upstream.example"

	target, err := targetURIComponent(req)
	if err != nil {
		t.Fatalf("targetURIComponent: %v", err)
	}
	if target != "http://upstream.example/" {
		t.Fatalf("target URI = %q, want %q", target, "http://upstream.example/")
	}
}

func TestVerifier_VerifyRequestRejectsTamperReplayExpiredAndUnknownSigner(t *testing.T) {
	t.Parallel()

	pub, priv := testSignerKey(t)
	otherPub, _ := testSignerKey(t)
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	t.Run("tampered", func(t *testing.T) {
		req := signedVerifierRequest(t, priv, now, "")
		req.Header.Set(HeaderName, strings.Replace(req.Header.Get(HeaderName), `vd="allow"`, `vd="block"`, 1))
		verifier := newTestVerifier(t, pub, now)
		if _, err := verifier.VerifyRequest(req, nil); err == nil {
			t.Fatal("tampered mediation header should fail verification")
		}
	})

	t.Run("replay", func(t *testing.T) {
		req := signedVerifierRequest(t, priv, now, "")
		verifier := newTestVerifier(t, pub, now)
		if _, err := verifier.VerifyRequest(req, nil); err != nil {
			t.Fatalf("first VerifyRequest: %v", err)
		}
		if _, err := verifier.VerifyRequest(req, nil); err == nil {
			t.Fatal("replayed nonce should fail verification")
		}
	})

	t.Run("expired", func(t *testing.T) {
		req := signedVerifierRequest(t, priv, now, "")
		verifier := newTestVerifier(t, pub, now.Add(10*time.Minute))
		if _, err := verifier.VerifyRequest(req, nil); err == nil {
			t.Fatal("expired signature should fail verification")
		}
	})

	t.Run("unknown signer", func(t *testing.T) {
		req := signedVerifierRequest(t, priv, now, "")
		verifier := newTestVerifier(t, otherPub, now)
		if _, err := verifier.VerifyRequest(req, nil); err == nil {
			t.Fatal("unknown signer should fail verification")
		}
	})
}

func TestReplayCacheConcurrentAndEviction(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	cache := newReplayCache(time.Minute, 1000, func() time.Time { return now })
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := range 64 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- cache.CheckAndStore("nonce-"+strconv.Itoa(i), now.Add(time.Minute))
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent CheckAndStore: %v", err)
		}
	}
	if err := cache.CheckAndStore("nonce-0", now.Add(time.Minute)); err == nil {
		t.Fatal("duplicate nonce should be rejected")
	}

	evict := newReplayCache(time.Minute, 1, func() time.Time { return now })
	if err := evict.CheckAndStore("old", now.Add(time.Minute)); err != nil {
		t.Fatalf("store old: %v", err)
	}
	if err := evict.CheckAndStore("new", now.Add(time.Minute)); err != nil {
		t.Fatalf("store new: %v", err)
	}
	if err := evict.CheckAndStore("old", now.Add(time.Minute)); err != nil {
		t.Fatalf("old nonce should have been cap-evicted: %v", err)
	}

	expired := newReplayCache(time.Minute, 2, func() time.Time { return now })
	if err := expired.CheckAndStore("gone", now.Add(time.Second)); err != nil {
		t.Fatalf("store gone: %v", err)
	}
	now = now.Add(2 * time.Second)
	if err := expired.CheckAndStore("gone", now.Add(time.Minute)); err != nil {
		t.Fatalf("expired nonce should have been window-evicted: %v", err)
	}
}

func TestReplayCacheHonorsVerifierSkew(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	cache := newReplayCache(time.Minute, 10, func() time.Time { return now })

	if err := cache.CheckAndStoreWithSkew("near-expired", now.Add(-30*time.Second), time.Minute); err != nil {
		t.Fatalf("near-expired signature should be accepted within skew: %v", err)
	}
	if err := cache.CheckAndStoreWithSkew("near-expired", now.Add(-30*time.Second), time.Minute); err == nil {
		t.Fatal("nonce accepted within skew must still be replay-protected")
	}
	if err := cache.CheckAndStoreWithSkew("too-old", now.Add(-2*time.Minute), time.Minute); err == nil {
		t.Fatal("signature older than skew should be rejected")
	}
}

func TestReplayCacheDefaultsAndNoopPaths(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	cache := newReplayCache(0, 0, nil)
	if cache.window != 5*time.Minute {
		t.Fatalf("default window = %s, want 5m", cache.window)
	}
	if cache.max != 10000 {
		t.Fatalf("default max = %d, want 10000", cache.max)
	}
	if cache.nowFn == nil {
		t.Fatal("default nowFn was not installed")
	}
	if err := ((*ReplayCache)(nil)).CheckAndStore("nonce", now); err != nil {
		t.Fatalf("nil cache should be a noop: %v", err)
	}

	cache = newReplayCache(time.Minute, 2, func() time.Time { return now })
	if err := cache.CheckAndStore("", now.Add(time.Minute)); err == nil {
		t.Fatal("empty nonce should be rejected")
	}
	if err := cache.CheckAndStoreWithSkew("negative-skew", now.Add(time.Minute), -time.Minute); err != nil {
		t.Fatalf("negative skew should clamp to zero: %v", err)
	}
	if err := cache.CheckAndStore("zero-expires", time.Time{}); err != nil {
		t.Fatalf("zero expires should default to cache window: %v", err)
	}
}

func TestParseAndFormatActor(t *testing.T) {
	t.Parallel()

	const anonymousActor = "anonymous"

	legacy, err := ParseActor("agent:legacy")
	if err != nil {
		t.Fatalf("ParseActor legacy: %v", err)
	}
	if legacy.IsSPIFFE {
		t.Fatal("legacy actor parsed as SPIFFE")
	}

	spiffe, err := ParseActor("spiffe://Example.Test/agent/alpha")
	if err != nil {
		t.Fatalf("ParseActor spiffe: %v", err)
	}
	if !spiffe.IsSPIFFE || spiffe.TrustDomain != testTrustDomain || spiffe.Workload != "/agent/alpha" {
		t.Fatalf("unexpected parsed SPIFFE actor: %+v", spiffe)
	}

	upper, err := ParseActor("SPIFFE://Example.Test/agent/alpha")
	if err != nil {
		t.Fatalf("ParseActor uppercase scheme: %v", err)
	}
	if !upper.IsSPIFFE || upper.TrustDomain != testTrustDomain {
		t.Fatalf("uppercase scheme parsed as %+v", upper)
	}

	formatted, err := FormatActor("Alpha Agent", ActorFormatSPIFFE, "Example.Test")
	if err != nil {
		t.Fatalf("FormatActor: %v", err)
	}
	if formatted != "spiffe://example.test/agent/Alpha-Agent" {
		t.Fatalf("FormatActor = %q", formatted)
	}
	preserved, err := FormatActor("SPIFFE://Example.Test/agent/alpha", ActorFormatSPIFFE, "example.test")
	if err != nil {
		t.Fatalf("FormatActor uppercase SPIFFE actor: %v", err)
	}
	if preserved != "SPIFFE://Example.Test/agent/alpha" {
		t.Fatalf("FormatActor preserved = %q", preserved)
	}
	if _, err := ParseActor("spiffe:///missing-domain"); err == nil {
		t.Fatal("malformed SPIFFE actor should fail")
	}
	if _, err := FormatActor("", ActorFormatLegacy, ""); err != nil {
		t.Fatalf("empty legacy actor should default anonymous: %v", err)
	}
	if _, err := FormatActor("alpha", ActorFormatSPIFFE, ""); err == nil {
		t.Fatal("SPIFFE format without trust_domain should fail")
	}
	if _, err := FormatActor("alpha", ActorFormatSPIFFE, "trust.example:8443"); err == nil {
		t.Fatal("SPIFFE format with invalid trust_domain should fail")
	}
	if _, err := FormatActor("alpha", "unknown", "trust.example"); err == nil {
		t.Fatal("unknown actor format should fail")
	}
	if got := escapeSPIFFEPathSegment(" / "); got != anonymousActor {
		t.Fatalf("empty escaped actor = %q, want anonymous", got)
	}
}

// TestParseActor_StrictSPIFFE pins the strictness gates added in the
// federation-hardening pass: SPIFFE-ID §2 prohibits userinfo and ports
// in the trust domain, and the workload path must be canonical so an
// allowlist comparison on Workload cannot be bypassed via ".." or empty
// segments. Each case is a real bypass surface, not a style preference.
func TestParseActor_StrictSPIFFE(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		raw  string
	}{
		{"userinfo", "spiffe://user:pass@trust.example/agent/x"},
		{"port", "spiffe://trust.example:8443/agent/x"},
		{"path traversal", "spiffe://trust.example/agent/../admin"},
		{"empty segment", "spiffe://trust.example/agent//x"},
		{"dot segment", "spiffe://trust.example/./agent/x"},
		{"trailing slash", "spiffe://trust.example/agent/x/"},
		// SPIFFE-ID §2 prohibits IP-address trust domains. A partner
		// claiming a numeric host could otherwise impersonate any
		// allowlist that compares trust domains as opaque strings.
		{"ipv4 trust domain", "spiffe://192.0.2.1/agent/x"},
		{"ipv6 trust domain", "spiffe://[2001:db8::1]/agent/x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := ParseActor(tc.raw); err == nil {
				t.Fatalf("ParseActor(%q) accepted, got %+v; want error", tc.raw, got)
			}
		})
	}
}

func TestParseActorStrictRequiresSPIFFE(t *testing.T) {
	t.Parallel()

	if _, err := ParseActorStrict("agent:legacy"); err == nil {
		t.Fatal("strict parser should reject free-form actors")
	}
	if _, err := ParseActorStrict("spiffe:///missing-domain"); err == nil {
		t.Fatal("strict parser should reject malformed SPIFFE actors")
	}
	parsed, err := ParseActorStrict("spiffe://Strict.Test/agent/alpha")
	if err != nil {
		t.Fatalf("ParseActorStrict SPIFFE: %v", err)
	}
	if !parsed.IsSPIFFE || parsed.TrustDomain != "strict.test" {
		t.Fatalf("strict parser returned %+v", parsed)
	}
}

func TestIsValidTrustDomain(t *testing.T) {
	t.Parallel()
	good := []string{"trust.example", "partner.internal", "a", "single-label"}
	for _, d := range good {
		if !IsValidTrustDomain(d) {
			t.Errorf("IsValidTrustDomain(%q) = false; want true", d)
		}
	}
	bad := []string{
		"", "trust.example/agent/x", "trust.example:8443", "u@trust.example",
		"scheme://trust", "with spaces", "trailing/",
		// SPIFFE-ID §2 forbids IP-address trust domains.
		"192.0.2.1", "10.0.0.1", "::1", "2001:db8::1",
	}
	for _, d := range bad {
		if IsValidTrustDomain(d) {
			t.Errorf("IsValidTrustDomain(%q) = true; want false", d)
		}
	}
}

func TestVerifierConfigAndErrorHelpers(t *testing.T) {
	t.Parallel()

	pub, _ := testSignerKey(t)
	if err := wrapVerificationError(VerificationFailureParse, nil); err != nil {
		t.Fatalf("nil wrap error = %v, want nil", err)
	}
	if code, ok := VerificationFailureCodeOf(errors.New("plain")); ok || code != "" {
		t.Fatalf("plain error code = %q, %v; want empty false", code, ok)
	}
	var nilVerifyErr *VerificationError
	if nilVerifyErr.Error() != string(VerificationFailureFailed) {
		t.Fatalf("nil VerificationError string = %q", nilVerifyErr.Error())
	}
	if nilVerifyErr.Unwrap() != nil {
		t.Fatal("nil VerificationError unwrap should be nil")
	}

	cases := []struct {
		name string
		cfg  VerifierConfig
	}{
		{"no keys", VerifierConfig{}},
		{"empty key id", VerifierConfig{TrustedKeys: []TrustedKey{{PublicKey: pub}}}},
		{"bad public key", VerifierConfig{TrustedKeys: []TrustedKey{{KeyID: "k", PublicKey: []byte("short")}}}},
		{"duplicate key id", VerifierConfig{TrustedKeys: []TrustedKey{
			{KeyID: "k", PublicKey: pub},
			{KeyID: "k", PublicKey: pub},
		}}},
		{"empty trust domain", VerifierConfig{TrustedKeys: []TrustedKey{{KeyID: "k", PublicKey: pub, TrustDomains: []string{" "}}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewVerifier(tc.cfg); err == nil {
				t.Fatal("NewVerifier should fail")
			}
		})
	}

	verifier, err := NewVerifier(VerifierConfig{TrustedKeys: []TrustedKey{{KeyID: "k", PublicKey: pub}}})
	if err != nil {
		t.Fatalf("NewVerifier default nowFn: %v", err)
	}
	if verifier.nowFn == nil {
		t.Fatal("default nowFn was not installed")
	}
}

func TestVerifierRejectsMalformedRequestsWithCodes(t *testing.T) {
	t.Parallel()

	pub, priv := testSignerKey(t)
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	checkCode := func(t *testing.T, err error, want VerificationFailureCode) {
		t.Helper()
		if err == nil {
			t.Fatalf("error = nil, want %s", want)
		}
		got, ok := VerificationFailureCodeOf(err)
		if !ok || got != want {
			t.Fatalf("code = %q, %v; want %s", got, ok, want)
		}
	}

	req := signedVerifierRequest(t, priv, now, "")
	var nilVerifier *Verifier
	_, err := nilVerifier.VerifyRequest(req, nil)
	checkCode(t, err, VerificationFailureFailed)

	verifier := newTestVerifier(t, pub, now)
	_, err = verifier.VerifyRequest(nil, nil)
	checkCode(t, err, VerificationFailureFailed)

	req = newTestRequest(t, http.MethodGet, "https://upstream.example/api", nil)
	_, err = verifier.VerifyRequest(req, nil)
	checkCode(t, err, VerificationFailureMissing)

	req = newTestRequest(t, http.MethodGet, "https://upstream.example/api", nil)
	req.Header.Set(HeaderName, "not a structured envelope")
	_, err = verifier.VerifyRequest(req, nil)
	checkCode(t, err, VerificationFailureParse)

	req = signedVerifierRequest(t, priv, now, "body")
	_, err = newTestVerifier(t, pub, now).VerifyRequest(req, nil)
	checkCode(t, err, VerificationFailureDigest)

	req = signedVerifierRequest(t, priv, now, "body")
	_, err = newTestVerifier(t, pub, now).VerifyRequest(req, []byte("tampered"))
	checkCode(t, err, VerificationFailureDigest)

	req = signedEmptyPostRequest(t, priv, now)
	req.ContentLength = 4
	_, err = newTestVerifier(t, pub, now).VerifyRequest(req, nil)
	checkCode(t, err, VerificationFailureDigest)

	req = signedVerifierRequest(t, priv, now, "")
	req.Header.Set("Signature-Input", strings.Replace(req.Header.Get("Signature-Input"), `alg="ed25519"`, `alg="rsa"`, 1))
	_, err = newTestVerifier(t, pub, now).VerifyRequest(req, nil)
	checkCode(t, err, VerificationFailureSignature)

	req = signedVerifierRequest(t, priv, now, "")
	req.Header.Set("Signature-Input", strings.Replace(req.Header.Get("Signature-Input"), `tag="pipelock-mediation"`, `tag="other"`, 1))
	_, err = newTestVerifier(t, pub, now).VerifyRequest(req, nil)
	checkCode(t, err, VerificationFailureParse)
}

func TestVerifierValidateTimeBranches(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	verifier := &Verifier{
		skew:                 time.Minute,
		maxSignatureLifetime: 5 * time.Minute,
		nowFn:                func() time.Time { return now },
	}
	cases := []struct {
		name    string
		created time.Time
		expires time.Time
	}{
		{"future created", now.Add(2 * time.Minute), now.Add(3 * time.Minute)},
		{"expired", now.Add(-10 * time.Minute), now.Add(-2 * time.Minute)},
		{"expires before created", now, now},
		{"lifetime exceeds max", now, now.Add(10 * time.Minute)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := verifier.validateTime(tc.created.Unix(), tc.expires.Unix()); err == nil {
				t.Fatal("validateTime should fail")
			}
		})
	}
}

func TestVerifierSignatureHelperErrors(t *testing.T) {
	t.Parallel()

	goodSigInput := `pipelock1=("@method");keyid="trusted-key";alg="ed25519";tag="pipelock-mediation";nonce="nonce";created=1;expires=2`
	cases := []struct {
		name string
		h    http.Header
	}{
		{"bad signature input", http.Header{testHeaderSigInput: {`"`}}},
		{"bad signature", http.Header{testHeaderSigInput: {goodSigInput}, testHeaderSig: {`"`}}},
		{"non inner list", http.Header{testHeaderSigInput: {`pipelock1=1`}, testHeaderSig: {testInvalidSigB64}}},
		{"wrong tag skipped", http.Header{testHeaderSigInput: {strings.Replace(goodSigInput, `tag="pipelock-mediation"`, `tag="other"`, 1)}, testHeaderSig: {testInvalidSigB64}}},
		{"missing signature member", http.Header{testHeaderSigInput: {goodSigInput}, testHeaderSig: {`sig1=:AQI=:`}}},
		{"unexpected signature item type", http.Header{testHeaderSigInput: {goodSigInput}, testHeaderSig: {`pipelock1=1`}}},
		{"signature value not bytes", http.Header{testHeaderSigInput: {goodSigInput}, testHeaderSig: {`pipelock1="not-bytes"`}}},
		{"wrong signature length", http.Header{testHeaderSigInput: {goodSigInput}, testHeaderSig: {testInvalidSigB64}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := mediationSignature(tc.h); err == nil {
				t.Fatal("mediationSignature should fail")
			}
		})
	}
}

func TestVerifierParameterHelperErrors(t *testing.T) {
	t.Parallel()

	inner := buildSigParams([]string{derivedMethod}, 1, 2, "nonce", "key")
	if got, err := innerComponents(inner); err != nil || len(got) != 1 || got[0] != derivedMethod {
		t.Fatalf("innerComponents valid = %v, %v", got, err)
	}
	for _, inner := range []httpsfv.InnerList{
		{},
		{Items: []httpsfv.Item{httpsfv.NewItem(int64(1))}},
		{Items: []httpsfv.Item{httpsfv.NewItem("unsupported")}},
	} {
		if _, err := innerComponents(inner); err == nil {
			t.Fatal("innerComponents should fail")
		}
	}

	emptyParams := httpsfv.InnerList{Params: httpsfv.NewParams()}
	if _, err := paramString(emptyParams, "keyid"); err == nil {
		t.Fatal("missing string param should fail")
	}
	badString := httpsfv.InnerList{Params: httpsfv.NewParams()}
	badString.Params.Add("keyid", int64(1))
	if _, err := paramString(badString, "keyid"); err == nil {
		t.Fatal("non-string param should fail")
	}
	blankString := httpsfv.InnerList{Params: httpsfv.NewParams()}
	blankString.Params.Add("keyid", " ")
	if _, err := paramString(blankString, "keyid"); err == nil {
		t.Fatal("blank string param should fail")
	}
	if _, err := paramInt64(emptyParams, "created"); err == nil {
		t.Fatal("missing int param should fail")
	}
	badInt := httpsfv.InnerList{Params: httpsfv.NewParams()}
	badInt.Params.Add("created", "now")
	if _, err := paramInt64(badInt, "created"); err == nil {
		t.Fatal("non-int param should fail")
	}

	if err := verifyContentDigest("", []byte("body")); err == nil {
		t.Fatal("missing content digest should fail")
	}
	if err := verifyContentDigest("sha-256=:bad:", []byte("body")); err == nil {
		t.Fatal("digest mismatch should fail")
	}
	if requestHasSignedBody(nil, []byte("body")) {
		t.Fatal("nil request should not be body-bearing")
	}
	if !requestHasSignedBody(newTestRequest(t, http.MethodPost, "https://upstream.example/api", nil), []byte("body")) {
		t.Fatal("non-empty body bytes should be body-bearing")
	}
	req := newTestRequest(t, http.MethodPost, "https://upstream.example/api", nil)
	req.ContentLength = 1
	if !requestHasSignedBody(req, nil) {
		t.Fatal("positive content length should be body-bearing")
	}
}

// TestVerifier_RejectsLifetimeOverWindow proves the cap added in
// validateTime: a signature whose expires-created span exceeds the
// configured MaxSignatureLifetime is refused, even if signed by a
// trusted key. Without the cap, an attacker who captured a long-lived
// signature could replay it after the nonce was evicted from the
// replay cache.
func TestVerifier_RejectsLifetimeOverWindow(t *testing.T) {
	t.Parallel()

	pub, priv := testSignerKey(t)
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	// Signer emits a 10-minute signature.
	signer, err := NewSigner(SignerConfig{
		PrivKey:          priv,
		KeyID:            testKeyIDTrusted,
		SignedComponents: []string{derivedMethod, derivedTargetURI, headerPipelockMediation},
		Expires:          10 * time.Minute,
		NowFn:            func() time.Time { return now },
		RandReader:       bytes.NewReader([]byte("0123456789abcdef")),
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	em := NewEmitter(EmitterConfig{
		ConfigHash:  strings.Repeat("a", 64),
		Signer:      signer,
		ActorFormat: ActorFormatSPIFFE,
		TrustDomain: testTrustDomain,
	})
	req := newTestRequest(t, http.MethodGet, "https://upstream.example/api", nil)
	if err := em.InjectAndSign(req, nil, BuildOpts{
		ActionID:  "01961f3a-7b2c-7000-8000-000000000003",
		Action:    testActionRead,
		Verdict:   testVerdictAllow,
		Actor:     testActorAlpha,
		ActorAuth: ActorAuthBound,
	}); err != nil {
		t.Fatalf("InjectAndSign: %v", err)
	}

	// Verifier caps lifetime at 5 minutes; the 10-min signature must be rejected.
	verifier, err := NewVerifier(VerifierConfig{
		TrustedKeys:          []TrustedKey{{KeyID: testKeyIDTrusted, PublicKey: pub}},
		ReplayCache:          newReplayCache(5*time.Minute, 1000, func() time.Time { return now }),
		Skew:                 time.Minute,
		MaxSignatureLifetime: 5 * time.Minute,
		NowFn:                func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, err := verifier.VerifyRequest(req, nil); err == nil {
		t.Fatal("over-window signature should fail verification")
	}
}

// TestVerifier_RejectsActorTrustDomainMismatch proves the per-key actor
// binding: a TrustedKey with a TrustDomains allowlist refuses to attest
// envelopes whose actor's trust domain is not in the list. Without this
// binding, a single compromised partner key signs envelopes for any
// other federation peer.
func TestVerifier_RejectsActorTrustDomainMismatch(t *testing.T) {
	t.Parallel()

	pub, priv := testSignerKey(t)
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	req := signedVerifierRequest(t, priv, now, "")

	// Trust list pins this key to "other.example", but the request's
	// actor is spiffe://example.test/agent/alpha — must reject.
	verifier, err := NewVerifier(VerifierConfig{
		TrustedKeys: []TrustedKey{{
			KeyID:        testKeyIDTrusted,
			PublicKey:    pub,
			TrustDomains: []string{"other.example"},
		}},
		ReplayCache: newReplayCache(5*time.Minute, 1000, func() time.Time { return now }),
		Skew:        time.Minute,
		NowFn:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, err := verifier.VerifyRequest(req, nil); err == nil {
		t.Fatal("actor trust domain mismatch should fail verification")
	}

	// Same key, but allowlist now includes the actor's trust domain — must accept.
	req2 := signedVerifierRequest(t, priv, now, "")
	verifier2, err := NewVerifier(VerifierConfig{
		TrustedKeys: []TrustedKey{{
			KeyID:        testKeyIDTrusted,
			PublicKey:    pub,
			TrustDomains: []string{"example.test"},
		}},
		ReplayCache: newReplayCache(5*time.Minute, 1000, func() time.Time { return now }),
		Skew:        time.Minute,
		NowFn:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, err := verifier2.VerifyRequest(req2, nil); err != nil {
		t.Fatalf("matching trust domain should verify: %v", err)
	}
}

func TestVerifier_TrustDomainPinRequiresSPIFFEActor(t *testing.T) {
	t.Parallel()

	pub, priv := testSignerKey(t)
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	req := signedLegacyActorRequest(t, priv, now)
	verifier, err := NewVerifier(VerifierConfig{
		TrustedKeys: []TrustedKey{{
			KeyID:        testKeyIDTrusted,
			PublicKey:    pub,
			TrustDomains: []string{"example.test"},
		}},
		ReplayCache: newReplayCache(5*time.Minute, 1000, func() time.Time { return now }),
		Skew:        time.Minute,
		NowFn:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, err := verifier.VerifyRequest(req, nil); err == nil {
		t.Fatal("trust-domain-pinned key should reject legacy actor")
	}
}

func TestVerifier_StrictActorFormatRejectsLegacyActor(t *testing.T) {
	t.Parallel()

	pub, priv := testSignerKey(t)
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	req := signedLegacyActorRequest(t, priv, now)
	verifier := newTestVerifier(t, pub, now)

	if _, err := verifier.VerifyRequest(req, nil); err == nil {
		t.Fatal("strict verifier should reject legacy actor")
	}
}

func TestVerifier_LegacyActorFormatAllowsMigrationPath(t *testing.T) {
	t.Parallel()

	pub, priv := testSignerKey(t)
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	req := signedLegacyActorRequest(t, priv, now)
	verifier, err := NewVerifier(VerifierConfig{
		TrustedKeys: []TrustedKey{{
			KeyID:     "trusted-key",
			PublicKey: pub,
		}},
		ReplayCache: newReplayCache(5*time.Minute, 1000, func() time.Time { return now }),
		Skew:        time.Minute,
		ActorFormat: ActorFormatLegacy,
		NowFn:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewVerifier legacy: %v", err)
	}
	if _, err := verifier.VerifyRequest(req, nil); err != nil {
		t.Fatalf("legacy actor should verify under migration format: %v", err)
	}
}

func TestVerifier_EmptyPOSTBodyDoesNotRequireContentDigest(t *testing.T) {
	t.Parallel()

	pub, priv := testSignerKey(t)
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	req := signedEmptyPostRequest(t, priv, now)
	req.Body = io.NopCloser(strings.NewReader(""))
	req.ContentLength = 0

	verifier := newTestVerifier(t, pub, now)
	if _, err := verifier.VerifyRequest(req, nil); err != nil {
		t.Fatalf("empty POST should verify without content-digest: %v", err)
	}
}

func TestVerifier_EmptyChunkedPOSTBodyDoesNotRequireContentDigest(t *testing.T) {
	t.Parallel()

	pub, priv := testSignerKey(t)
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	req := signedEmptyPostRequest(t, priv, now)
	req.Body = io.NopCloser(strings.NewReader(""))
	req.ContentLength = -1

	verifier := newTestVerifier(t, pub, now)
	if _, err := verifier.VerifyRequest(req, nil); err != nil {
		t.Fatalf("empty chunked POST should verify without content-digest: %v", err)
	}
}

func TestVerifierRejectsTaggedNonPipelockSignatureMember(t *testing.T) {
	t.Parallel()

	pub, priv := testSignerKey(t)
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	req := signedEmptyPostRequest(t, priv, now)
	req.Header.Set("Signature-Input", strings.Replace(req.Header.Get("Signature-Input"), "pipelock1=", "sig1=", 1))
	req.Header.Set("Signature", strings.Replace(req.Header.Get("Signature"), "pipelock1=", "sig1=", 1))

	verifier := newTestVerifier(t, pub, now)
	if _, err := verifier.VerifyRequest(req, nil); err == nil {
		t.Fatal("expected non-pipelock signature member to be rejected")
	}
}

func signedEmptyPostRequest(t *testing.T, priv ed25519.PrivateKey, now time.Time) *http.Request {
	t.Helper()
	signer, err := NewSigner(SignerConfig{
		PrivKey:          priv,
		KeyID:            testKeyIDTrusted,
		SignedComponents: []string{derivedMethod, derivedTargetURI, headerContentDigest, headerPipelockMediation},
		MaxBodyBytes:     1 << 20,
		NowFn:            func() time.Time { return now },
		RandReader:       bytes.NewReader([]byte("0123456789abcdef")),
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	em := NewEmitter(EmitterConfig{
		ConfigHash:  strings.Repeat("a", 64),
		Signer:      signer,
		ActorFormat: ActorFormatSPIFFE,
		TrustDomain: testTrustDomain,
	})
	req := newTestRequest(t, http.MethodPost, "https://upstream.example/api", nil)
	if err := em.InjectAndSign(req, nil, BuildOpts{
		ActionID:  "01961f3a-7b2c-7000-8000-000000000005",
		Action:    testActionRead,
		Verdict:   testVerdictAllow,
		Actor:     testActorAlpha,
		ActorAuth: ActorAuthBound,
	}); err != nil {
		t.Fatalf("InjectAndSign: %v", err)
	}
	return req
}

func signedLegacyActorRequest(t *testing.T, priv ed25519.PrivateKey, now time.Time) *http.Request {
	t.Helper()
	signer, err := NewSigner(SignerConfig{
		PrivKey:          priv,
		KeyID:            testKeyIDTrusted,
		SignedComponents: []string{derivedMethod, derivedTargetURI, headerPipelockMediation},
		NowFn:            func() time.Time { return now },
		RandReader:       bytes.NewReader([]byte("0123456789abcdef")),
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	em := NewEmitter(EmitterConfig{
		ConfigHash: strings.Repeat("a", 64),
		Signer:     signer,
	})
	req := newTestRequest(t, http.MethodGet, "https://upstream.example/api", nil)
	if err := em.InjectAndSign(req, nil, BuildOpts{
		ActionID:  "01961f3a-7b2c-7000-8000-000000000004",
		Action:    testActionRead,
		Verdict:   testVerdictAllow,
		Actor:     "legacy-agent",
		ActorAuth: ActorAuthBound,
	}); err != nil {
		t.Fatalf("InjectAndSign: %v", err)
	}
	return req
}

func signedVerifierRequest(t *testing.T, priv ed25519.PrivateKey, now time.Time, bodyText string) *http.Request {
	t.Helper()
	return signedVerifierRequestWithURL(t, priv, now, "https://upstream.example/api", bodyText)
}

func signedVerifierRequestWithURL(t *testing.T, priv ed25519.PrivateKey, now time.Time, targetURL, bodyText string) *http.Request {
	t.Helper()
	var bodyBytes []byte
	var body *strings.Reader
	if bodyText != "" {
		bodyBytes = []byte(bodyText)
		body = strings.NewReader(bodyText)
	}
	signer, err := NewSigner(SignerConfig{
		PrivKey:          priv,
		KeyID:            testKeyIDTrusted,
		SignedComponents: []string{derivedMethod, derivedTargetURI, headerContentDigest, headerPipelockMediation},
		MaxBodyBytes:     1 << 20,
		NowFn:            func() time.Time { return now },
		RandReader:       bytes.NewReader([]byte("0123456789abcdef")),
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	em := NewEmitter(EmitterConfig{
		ConfigHash:  strings.Repeat("a", 64),
		Signer:      signer,
		ActorFormat: ActorFormatSPIFFE,
		TrustDomain: testTrustDomain,
	})
	req := newTestRequest(t, http.MethodPost, targetURL, body)
	if body == nil {
		req = newTestRequest(t, http.MethodGet, targetURL, nil)
	}
	err = em.InjectAndSign(req, bodyBytes, BuildOpts{
		ActionID:  testReceiptID1,
		Action:    testActionRead,
		Verdict:   testVerdictAllow,
		Actor:     testActorAlpha,
		ActorAuth: ActorAuthBound,
	})
	if err != nil {
		t.Fatalf("InjectAndSign: %v", err)
	}
	return req
}

func newTestVerifier(t *testing.T, pub []byte, now time.Time) *Verifier {
	t.Helper()
	verifier, err := NewVerifier(VerifierConfig{
		TrustedKeys: []TrustedKey{{
			KeyID:     "trusted-key",
			PublicKey: pub,
		}},
		ReplayCache: newReplayCache(5*time.Minute, 1000, func() time.Time { return now }),
		Skew:        time.Minute,
		NowFn:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return verifier
}
