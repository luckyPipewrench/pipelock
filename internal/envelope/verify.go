// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dunglas/httpsfv"
)

// TrustedKey is an accepted inbound mediation signer. TrustDomains, when
// non-empty, restricts which actor trust domains this signer is allowed
// to attest. An envelope whose actor's TrustDomain is not in the list
// fails verification — preventing partner A's key from signing
// envelopes that claim partner B's trust domain. An empty TrustDomains
// list means "any trust domain", which is the v2.4 migration default
// for callers that have not yet declared per-key bindings.
type TrustedKey struct {
	KeyID        string
	PublicKey    ed25519.PublicKey
	TrustDomains []string
}

type VerifierConfig struct {
	TrustedKeys []TrustedKey
	ReplayCache *ReplayCache
	Skew        time.Duration
	// MaxSignatureLifetime caps the (expires - created) duration the
	// verifier accepts. Without a cap, a trusted-but-careless signer that
	// emits long-lived signatures defeats the replay window: the cache
	// evicts the nonce after `window` elapses, while the signature itself
	// stays valid much longer. Operators set this to ReplayCache.window +
	// Skew so the cache always outlives the signature. Zero disables the
	// cap (compat mode for the v2.4 migration default).
	MaxSignatureLifetime time.Duration
	NowFn                func() time.Time
}

// Verifier verifies inbound RFC 9421 mediation signatures.
type Verifier struct {
	keys                 map[string]trustedKey
	replayCache          *ReplayCache
	skew                 time.Duration
	maxSignatureLifetime time.Duration
	nowFn                func() time.Time
}

type trustedKey struct {
	publicKey    ed25519.PublicKey
	trustDomains map[string]struct{}
}

type VerificationFailureCode string

const (
	VerificationFailureReplay     VerificationFailureCode = "replay"
	VerificationFailureExpired    VerificationFailureCode = "expired"
	VerificationFailureNotTrusted VerificationFailureCode = "not_trusted"
	VerificationFailureMissing    VerificationFailureCode = "missing"
	VerificationFailureDigest     VerificationFailureCode = "digest"
	VerificationFailureSignature  VerificationFailureCode = "signature"
	VerificationFailureParse      VerificationFailureCode = "parse"
	VerificationFailureFailed     VerificationFailureCode = "failed"
)

type VerificationError struct {
	Code VerificationFailureCode
	Err  error
}

func (e *VerificationError) Error() string {
	if e == nil || e.Err == nil {
		return string(VerificationFailureFailed)
	}
	return e.Err.Error()
}

func (e *VerificationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func verificationError(code VerificationFailureCode, format string, args ...any) error {
	return &VerificationError{Code: code, Err: fmt.Errorf(format, args...)}
}

func wrapVerificationError(code VerificationFailureCode, err error) error {
	if err == nil {
		return nil
	}
	return &VerificationError{Code: code, Err: err}
}

func VerificationFailureCodeOf(err error) (VerificationFailureCode, bool) {
	var verifyErr *VerificationError
	if errors.As(err, &verifyErr) && verifyErr != nil && verifyErr.Code != "" {
		return verifyErr.Code, true
	}
	return "", false
}

func (k trustedKey) allowsTrustDomain(domain string) bool {
	if len(k.trustDomains) == 0 {
		return true
	}
	_, ok := k.trustDomains[strings.ToLower(domain)]
	return ok
}

func (k trustedKey) pinsTrustDomain() bool {
	return len(k.trustDomains) > 0
}

func NewVerifier(cfg VerifierConfig) (*Verifier, error) {
	if len(cfg.TrustedKeys) == 0 {
		return nil, fmt.Errorf("inbound envelope verifier requires at least one trusted key")
	}
	keys := make(map[string]trustedKey, len(cfg.TrustedKeys))
	for i, key := range cfg.TrustedKeys {
		keyID := strings.TrimSpace(key.KeyID)
		if keyID == "" {
			return nil, fmt.Errorf("trusted key %d has empty key_id", i)
		}
		if len(key.PublicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("trusted key %q public key length=%d, want %d", keyID, len(key.PublicKey), ed25519.PublicKeySize)
		}
		if _, dup := keys[keyID]; dup {
			return nil, fmt.Errorf("duplicate trusted key_id %q", keyID)
		}
		var domains map[string]struct{}
		if len(key.TrustDomains) > 0 {
			domains = make(map[string]struct{}, len(key.TrustDomains))
			for _, d := range key.TrustDomains {
				normalized := strings.ToLower(strings.TrimSpace(d))
				if normalized == "" {
					return nil, fmt.Errorf("trusted key %q trust_domains entry must not be empty", keyID)
				}
				domains[normalized] = struct{}{}
			}
		}
		keys[keyID] = trustedKey{
			publicKey:    append(ed25519.PublicKey(nil), key.PublicKey...),
			trustDomains: domains,
		}
	}
	now := cfg.NowFn
	if now == nil {
		now = time.Now
	}
	return &Verifier{
		keys:                 keys,
		replayCache:          cfg.ReplayCache,
		skew:                 cfg.Skew,
		maxSignatureLifetime: cfg.MaxSignatureLifetime,
		nowFn:                now,
	}, nil
}

// VerifyRequest verifies the inbound Pipelock-Mediation header and matching
// RFC 9421 signature. If body is non-nil and content-digest is covered, the
// digest is checked against body before signature verification succeeds.
func (v *Verifier) VerifyRequest(req *http.Request, body []byte) (Envelope, error) {
	if v == nil {
		return Envelope{}, verificationError(VerificationFailureFailed, "inbound envelope verifier is nil")
	}
	if req == nil {
		return Envelope{}, verificationError(VerificationFailureFailed, "inbound envelope verifier: nil request")
	}
	rawEnv := req.Header.Get(HeaderName)
	if rawEnv == "" {
		return Envelope{}, verificationError(VerificationFailureMissing, "missing %s header", HeaderName)
	}
	env, err := Parse(rawEnv)
	if err != nil {
		return Envelope{}, verificationError(VerificationFailureParse, "parse %s: %w", HeaderName, err)
	}
	parsedActor, err := ParseActor(env.Actor)
	if err != nil {
		return Envelope{}, verificationError(VerificationFailureParse, "parse actor: %w", err)
	}

	inner, sigBytes, err := mediationSignature(req.Header)
	if err != nil {
		return Envelope{}, wrapVerificationError(VerificationFailureParse, err)
	}
	keyID, err := paramString(inner, "keyid")
	if err != nil {
		return Envelope{}, wrapVerificationError(VerificationFailureParse, err)
	}
	tk, ok := v.keys[keyID]
	if !ok {
		return Envelope{}, verificationError(VerificationFailureNotTrusted, "untrusted key_id %q", keyID)
	}
	if tk.pinsTrustDomain() {
		if !parsedActor.IsSPIFFE {
			return Envelope{}, verificationError(VerificationFailureNotTrusted, "trusted key requires SPIFFE actor trust domain")
		}
		if !tk.allowsTrustDomain(parsedActor.TrustDomain) {
			return Envelope{}, verificationError(VerificationFailureNotTrusted, "trusted key not authorized for actor trust domain")
		}
	}
	alg, err := paramString(inner, "alg")
	if err != nil {
		return Envelope{}, wrapVerificationError(VerificationFailureParse, err)
	}
	if alg != pipelockSigAlg {
		return Envelope{}, verificationError(VerificationFailureSignature, "unsupported signature alg %q", alg)
	}
	tag, err := paramString(inner, "tag")
	if err != nil {
		return Envelope{}, wrapVerificationError(VerificationFailureParse, err)
	}
	if tag != pipelockSigTag {
		return Envelope{}, verificationError(VerificationFailureSignature, "unexpected signature tag %q", tag)
	}
	created, err := paramInt64(inner, "created")
	if err != nil {
		return Envelope{}, wrapVerificationError(VerificationFailureParse, err)
	}
	expires, err := paramInt64(inner, "expires")
	if err != nil {
		return Envelope{}, wrapVerificationError(VerificationFailureParse, err)
	}
	nonce, err := paramString(inner, "nonce")
	if err != nil {
		return Envelope{}, wrapVerificationError(VerificationFailureParse, err)
	}
	if err := v.validateTime(created, expires); err != nil {
		return Envelope{}, err
	}

	components, err := innerComponents(inner)
	if err != nil {
		return Envelope{}, wrapVerificationError(VerificationFailureParse, err)
	}
	if containsComponent(components, headerContentDigest) {
		if body == nil {
			return Envelope{}, verificationError(VerificationFailureDigest, "content-digest covered but body was not provided")
		}
		if err := verifyContentDigest(req.Header.Get("Content-Digest"), body); err != nil {
			return Envelope{}, wrapVerificationError(VerificationFailureDigest, err)
		}
	} else if requestHasSignedBody(req, body) {
		return Envelope{}, verificationError(VerificationFailureDigest, "body-bearing request signature must cover content-digest")
	}

	base, err := buildSignatureBase(req, body, components, inner)
	if err != nil {
		return Envelope{}, verificationError(VerificationFailureParse, "build signature base: %w", err)
	}
	if !ed25519.Verify(tk.publicKey, []byte(base), sigBytes) {
		return Envelope{}, verificationError(VerificationFailureSignature, "signature verification failed")
	}
	if err := v.replayCache.CheckAndStoreWithSkew(nonce, time.Unix(expires, 0).UTC(), v.skew); err != nil {
		code := VerificationFailureReplay
		if strings.Contains(strings.ToLower(err.Error()), "expired") {
			code = VerificationFailureExpired
		}
		return Envelope{}, wrapVerificationError(code, err)
	}
	return env, nil
}

func (v *Verifier) validateTime(created, expires int64) error {
	now := v.nowFn().UTC()
	createdAt := time.Unix(created, 0).UTC()
	expiresAt := time.Unix(expires, 0).UTC()
	if v.skew > 0 && createdAt.After(now.Add(v.skew)) {
		return verificationError(VerificationFailureExpired, "signature created in the future")
	}
	if !expiresAt.After(now.Add(-v.skew)) {
		return verificationError(VerificationFailureExpired, "signature expired")
	}
	if !expiresAt.After(createdAt) {
		return verificationError(VerificationFailureExpired, "signature expires before created")
	}
	if v.maxSignatureLifetime > 0 {
		// Cap declared signature lifetime so the replay cache (which
		// evicts at now+window) always outlives the signature. Without
		// this, an attacker can capture a long-lived signature and
		// replay it after the nonce has been forgotten.
		if expiresAt.Sub(createdAt) > v.maxSignatureLifetime {
			return verificationError(VerificationFailureExpired, "signature lifetime exceeds maximum")
		}
	}
	return nil
}

func mediationSignature(h http.Header) (httpsfv.InnerList, []byte, error) {
	input, err := httpsfv.UnmarshalDictionary(h.Values("Signature-Input"))
	if err != nil {
		return httpsfv.InnerList{}, nil, fmt.Errorf("parse Signature-Input: %w", err)
	}
	sigs, err := httpsfv.UnmarshalDictionary(h.Values("Signature"))
	if err != nil {
		return httpsfv.InnerList{}, nil, fmt.Errorf("parse Signature: %w", err)
	}
	for _, name := range input.Names() {
		if !strings.HasPrefix(name, pipelockMemberPrefix) {
			continue
		}
		member, _ := input.Get(name)
		inner, ok := member.(httpsfv.InnerList)
		if !ok {
			continue
		}
		tag, _ := paramString(inner, "tag")
		if tag != pipelockSigTag {
			continue
		}
		sigMember, ok := sigs.Get(name)
		if !ok {
			return httpsfv.InnerList{}, nil, fmt.Errorf("signature %q missing matching Signature member", name)
		}
		item, ok := sigMember.(httpsfv.Item)
		if !ok {
			return httpsfv.InnerList{}, nil, fmt.Errorf("signature %q member has unexpected type", name)
		}
		sigBytes, ok := item.Value.([]byte)
		if !ok {
			return httpsfv.InnerList{}, nil, fmt.Errorf("signature %q value is not a byte sequence", name)
		}
		if len(sigBytes) != ed25519.SignatureSize {
			return httpsfv.InnerList{}, nil, fmt.Errorf("signature %q length=%d, want %d", name, len(sigBytes), ed25519.SignatureSize)
		}
		return inner, sigBytes, nil
	}
	return httpsfv.InnerList{}, nil, fmt.Errorf("missing pipelock mediation signature")
}

func innerComponents(inner httpsfv.InnerList) ([]string, error) {
	out := make([]string, 0, len(inner.Items))
	for i, item := range inner.Items {
		value, ok := item.Value.(string)
		if !ok {
			return nil, fmt.Errorf("signature component %d is not a string", i)
		}
		normalized := strings.ToLower(strings.TrimSpace(value))
		if _, ok := supportedSignedComponents[normalized]; !ok {
			return nil, fmt.Errorf("unsupported signed component %q", value)
		}
		out = append(out, normalized)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("signature component list is empty")
	}
	return out, nil
}

func paramString(inner httpsfv.InnerList, name string) (string, error) {
	value, ok := inner.Params.Get(name)
	if !ok {
		return "", fmt.Errorf("signature parameter %q is required", name)
	}
	s, ok := value.(string)
	if !ok || strings.TrimSpace(s) == "" {
		return "", fmt.Errorf("signature parameter %q must be a non-empty string", name)
	}
	return s, nil
}

func paramInt64(inner httpsfv.InnerList, name string) (int64, error) {
	value, ok := inner.Params.Get(name)
	if !ok {
		return 0, fmt.Errorf("signature parameter %q is required", name)
	}
	n, ok := value.(int64)
	if !ok {
		return 0, fmt.Errorf("signature parameter %q must be an integer", name)
	}
	return n, nil
}

func verifyContentDigest(header string, body []byte) error {
	if header == "" {
		return fmt.Errorf("content-digest is required")
	}
	sum := sha256.Sum256(body)
	want := "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
	if header != want {
		return fmt.Errorf("content-digest mismatch")
	}
	return nil
}

// requestHasSignedBody mirrors the signer-side check in
// (*Signer).effectiveComponents: a request "has a signed body" only when
// it carries non-empty body bytes. The signer drops content-digest from
// the declared component list when len(body)==0; the verifier must use
// the same definition or it will reject legitimately body-less requests
// whose Body is set but empty (chunked POST with no payload, callers
// that pass an http.Request with Body=ioutil.NopCloser of an empty
// reader, etc.).
func requestHasSignedBody(req *http.Request, body []byte) bool {
	if req == nil {
		return false
	}
	if len(body) > 0 {
		return true
	}
	if req.ContentLength > 0 {
		return true
	}
	return false
}
