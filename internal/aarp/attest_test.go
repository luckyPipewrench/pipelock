// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package aarp

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/svid"
)

const (
	testSPIFFEID = "spiffe://example.org/mediators/pipelock-prod"
	testNonce    = "Zm9vYmFyYmF6cXV4MTIzNA"
)

// svidFixture is a minted ECDSA SVID leaf, its CA, and a pinned trust-bundle
// history covering a wide window around the action time.
type svidFixture struct {
	leafKey    *ecdsa.PrivateKey
	leafDER    []byte
	history    *svid.TrustBundleHistory
	actionTime time.Time
}

func mintSVID(t *testing.T, trustDomain, spiffeID string) svidFixture {
	t.Helper()
	now := time.Now().UTC()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             now.Add(-365 * 24 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	u, err := url.Parse(spiffeID)
	if err != nil {
		t.Fatalf("spiffe url: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		NotBefore:    now.Add(-1 * time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		URIs:         []*url.URL{u},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}

	gen, err := svid.NewGeneration(now.Add(-365*24*time.Hour), time.Time{}, []*x509.Certificate{caCert})
	if err != nil {
		t.Fatalf("generation: %v", err)
	}
	hist, err := svid.NewTrustBundleHistory(trustDomain, gen)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	return svidFixture{leafKey: leafKey, leafDER: leafDER, history: hist, actionTime: now}
}

// signedEvidence builds SVIDEvidence with a valid ECDSA proof-of-possession over
// the binding payload derived from env.
func signedEvidence(t *testing.T, env Envelope, fx svidFixture, spiffeID string) SVIDEvidence {
	t.Helper()
	// issued_at must fall within the SVID leaf validity window; the action time
	// (= leaf midpoint in the fixture) always does.
	return signedEvidenceAt(t, env, fx, spiffeID, fx.actionTime.UTC().Format(time.RFC3339Nano))
}

func signedEvidenceAt(t *testing.T, env Envelope, fx svidFixture, spiffeID, issuedAt string) SVIDEvidence {
	t.Helper()
	ev := SVIDEvidence{
		Type:       "x509",
		SPIFFEID:   spiffeID,
		LeafDERB64: base64.StdEncoding.EncodeToString(fx.leafDER),
		Nonce:      testNonce,
		IssuedAt:   issuedAt,
		Binding:    SVIDBinding{Alg: BindingAlgECDSAP256SHA256, Context: ContextSVIDBinding},
	}
	canonical, err := bindingCanonical(env, ev)
	if err != nil {
		t.Fatalf("bindingCanonical: %v", err)
	}
	sum := sha256.Sum256(canonical)
	sig, err := ecdsa.SignASN1(rand.Reader, fx.leafKey, sum[:])
	if err != nil {
		t.Fatalf("sign binding: %v", err)
	}
	ev.Binding.SignatureB64 = base64.StdEncoding.EncodeToString(sig)
	ev.Binding.PayloadSHA256 = hexSHA256(canonical)
	return ev
}

// signedEnvelopeForAttest returns a signed envelope whose trust_domain matches
// the SVID fixture, plus verify options trusting the assertion key.
func signedEnvelopeForAttest(t *testing.T) (Envelope, VerifyOptions, svidFixture, SVIDVerifyOptions) {
	t.Helper()
	fx := mintSVID(t, testTrustDomain, testSPIFFEID)
	pub, priv := genKey(t)
	signer, err := NewEd25519Signer(testKeyID, "mediator", priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	e := baseEnvelope()
	e.Assertion.EvidenceRefs = []string{"spiffe_svid"}
	env, err := Sign(e, signer)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	vopts := VerifyOptions{
		TrustedKeys: map[string]ed25519.PublicKey{testKeyID: pub},
		Trust:       map[string]TrustEntry{testKeyID: {MediatorID: testMediatorID, Role: "mediator", TrustDomain: testTrustDomain}},
	}
	svopts := SVIDVerifyOptions{TrustDomain: testTrustDomain, History: fx.history, ActionTime: fx.actionTime}
	return env, vopts, fx, svopts
}

func TestSVID_ValidBindingVerifies(t *testing.T) {
	env, vopts, fx, svopts := signedEnvelopeForAttest(t)
	ev := signedEvidence(t, env, fx, testSPIFFEID)

	spiffeID, err := VerifySVIDBinding(env, ev, svopts)
	if err != nil {
		t.Fatalf("VerifySVIDBinding: %v", err)
	}
	if spiffeID != testSPIFFEID {
		t.Fatalf("spiffe id = %q", spiffeID)
	}

	ap, err := AppraiseWithSVID(env, &ev, vopts, svopts)
	if err != nil {
		t.Fatalf("AppraiseWithSVID: %v", err)
	}
	for _, want := range []string{ClaimSigningWorkloadSVIDChainValidated, ClaimSigningWorkloadSVIDBound, ClaimSigningWorkloadSVIDValidAtActionTime} {
		if !contains(ap.VerifiedClaims, want) {
			t.Errorf("missing verified claim %q in %v", want, ap.VerifiedClaims)
		}
	}
	if !contains(ap.Axes[AxisIdentity], ClaimSigningWorkloadSVIDChainValidated) {
		t.Error("signing_workload_svid_chain_validated not on identity axis")
	}
	if !contains(ap.Axes[AxisFreshness], ClaimSigningWorkloadSVIDValidAtActionTime) {
		t.Error("signing_workload_svid_valid_at_action_time not on freshness axis")
	}
}

func TestSVID_ExpiredAtActionTime(t *testing.T) {
	env, _, fx, svopts := signedEnvelopeForAttest(t)
	ev := signedEvidence(t, env, fx, testSPIFFEID)
	svopts.ActionTime = fx.actionTime.Add(48 * time.Hour) // past leaf NotAfter (+24h)
	if _, err := VerifySVIDBinding(env, ev, svopts); !errors.Is(err, ErrSVIDBinding) {
		t.Fatalf("expired: got %v, want ErrSVIDBinding", err)
	}
}

func TestSVID_NotYetValidAtActionTime(t *testing.T) {
	env, _, fx, svopts := signedEnvelopeForAttest(t)
	ev := signedEvidence(t, env, fx, testSPIFFEID)
	svopts.ActionTime = fx.actionTime.Add(-2 * time.Hour) // before leaf NotBefore (-1h)
	if _, err := VerifySVIDBinding(env, ev, svopts); !errors.Is(err, ErrSVIDBinding) {
		t.Fatalf("not-yet-valid: got %v, want ErrSVIDBinding", err)
	}
}

func TestSVID_ReplayAcrossActions(t *testing.T) {
	// Evidence signed for envelope A is presented with envelope B (different
	// receipt digests). The binding payload digest changes, so the PoP fails.
	envA, _, fx, svopts := signedEnvelopeForAttest(t)
	ev := signedEvidence(t, envA, fx, testSPIFFEID)

	envB := envA
	envB.Subject.ActionRecordSHA256 = digest64(9) // different action
	if _, err := VerifySVIDBinding(envB, ev, svopts); !errors.Is(err, ErrSVIDBinding) {
		t.Fatalf("replay: got %v, want ErrSVIDBinding", err)
	}
}

func TestSVID_WrongLeafKeySignature(t *testing.T) {
	env, _, fx, svopts := signedEnvelopeForAttest(t)
	ev := signedEvidence(t, env, fx, testSPIFFEID)
	// Re-sign the binding with a DIFFERENT (attacker) key but keep the real SVID
	// cert. The PoP must fail under the cert's real public key.
	attackerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	canonical, _ := bindingCanonical(env, ev)
	sum := sha256.Sum256(canonical)
	sig, _ := ecdsa.SignASN1(rand.Reader, attackerKey, sum[:])
	ev.Binding.SignatureB64 = base64.StdEncoding.EncodeToString(sig)
	if _, err := VerifySVIDBinding(env, ev, svopts); !errors.Is(err, ErrSVIDBinding) {
		t.Fatalf("wrong key: got %v, want ErrSVIDBinding", err)
	}
}

func TestSVID_TrustDomainConfusion(t *testing.T) {
	env, _, fx, svopts := signedEnvelopeForAttest(t)
	ev := signedEvidence(t, env, fx, testSPIFFEID)
	// Validate the example.org SVID against a different trust domain's history.
	otherFx := mintSVID(t, "staging.example", "spiffe://staging.example/x")
	svopts.TrustDomain = "staging.example"
	svopts.History = otherFx.history
	if _, err := VerifySVIDBinding(env, ev, svopts); !errors.Is(err, ErrSVIDBinding) {
		t.Fatalf("trust-domain confusion: got %v, want ErrSVIDBinding", err)
	}
}

func TestSVID_StaleOrForkedBundle(t *testing.T) {
	env, _, fx, svopts := signedEnvelopeForAttest(t)
	ev := signedEvidence(t, env, fx, testSPIFFEID)
	// A history for example.org pinned to a DIFFERENT CA (not the SVID's issuer).
	forked := mintSVID(t, testTrustDomain, testSPIFFEID)
	svopts.History = forked.history
	if _, err := VerifySVIDBinding(env, ev, svopts); !errors.Is(err, ErrSVIDBinding) {
		t.Fatalf("forked bundle: got %v, want ErrSVIDBinding", err)
	}
}

func TestSVID_SPIFFEIDNotPermitted(t *testing.T) {
	env, _, fx, svopts := signedEnvelopeForAttest(t)
	ev := signedEvidence(t, env, fx, testSPIFFEID)
	svopts.AllowedSPIFFEIDs = []string{"spiffe://example.org/some/other/id"}
	if _, err := VerifySVIDBinding(env, ev, svopts); !errors.Is(err, ErrSVIDNotPermitted) {
		t.Fatalf("not permitted: got %v, want ErrSVIDNotPermitted", err)
	}
}

func TestSVID_SPIFFEIDMismatch(t *testing.T) {
	env, _, fx, svopts := signedEnvelopeForAttest(t)
	// Claim a different spiffe_id than the SVID's URI SAN.
	ev := signedEvidence(t, env, fx, "spiffe://example.org/wrong")
	if _, err := VerifySVIDBinding(env, ev, svopts); !errors.Is(err, ErrSVIDBinding) {
		t.Fatalf("spiffe mismatch: got %v, want ErrSVIDBinding", err)
	}
}

func TestSVID_ContextMismatch(t *testing.T) {
	env, _, fx, svopts := signedEnvelopeForAttest(t)
	ev := signedEvidence(t, env, fx, testSPIFFEID)
	ev.Binding.Context = "wrong/context"
	if _, err := VerifySVIDBinding(env, ev, svopts); !errors.Is(err, ErrSVIDBinding) {
		t.Fatalf("context mismatch: got %v, want ErrSVIDBinding", err)
	}
}

func TestSVID_NonX509Rejected(t *testing.T) {
	env, _, fx, svopts := signedEnvelopeForAttest(t)
	ev := signedEvidence(t, env, fx, testSPIFFEID)
	ev.Type = "jwt"
	if _, err := VerifySVIDBinding(env, ev, svopts); !errors.Is(err, ErrSVIDEvidence) {
		t.Fatalf("jwt: got %v, want ErrSVIDEvidence", err)
	}
}

func TestSVID_AlgKeyTypeMismatch(t *testing.T) {
	env, _, fx, svopts := signedEnvelopeForAttest(t)
	ev := signedEvidence(t, env, fx, testSPIFFEID)
	ev.Binding.Alg = BindingAlgEd25519 // ECDSA leaf, declared ed25519
	if _, err := VerifySVIDBinding(env, ev, svopts); !errors.Is(err, ErrSVIDBinding) {
		t.Fatalf("alg mismatch: got %v, want ErrSVIDBinding", err)
	}
}

func TestAppraiseWithSVID_UnsignedAssertionClaimOnly(t *testing.T) {
	env, _, fx, svopts := signedEnvelopeForAttest(t)
	ev := signedEvidence(t, env, fx, testSPIFFEID)
	// Verify with an empty trust set → assertion not signed.
	ap, err := AppraiseWithSVID(env, &ev, VerifyOptions{}, svopts)
	if err != nil {
		t.Fatalf("AppraiseWithSVID: %v", err)
	}
	if ap.AssertionSigned {
		t.Fatal("AssertionSigned true with empty trust set")
	}
	if contains(ap.VerifiedClaims, ClaimSigningWorkloadSVIDChainValidated) {
		t.Error("workload identity verified on an unsigned assertion")
	}
}

func TestAppraiseWithSVID_NilEvidence(t *testing.T) {
	env, vopts, _, svopts := signedEnvelopeForAttest(t)
	ap, err := AppraiseWithSVID(env, nil, vopts, svopts)
	if err != nil {
		t.Fatalf("AppraiseWithSVID(nil): %v", err)
	}
	if contains(ap.VerifiedClaims, ClaimSigningWorkloadSVIDChainValidated) {
		t.Error("workload identity verified with nil evidence")
	}
}

func TestSVID_BadBase64Leaf(t *testing.T) {
	env, _, fx, svopts := signedEnvelopeForAttest(t)
	ev := signedEvidence(t, env, fx, testSPIFFEID)
	ev.LeafDERB64 = "not!base64!"
	if _, err := VerifySVIDBinding(env, ev, svopts); !errors.Is(err, ErrSVIDEvidence) {
		t.Fatalf("bad b64: got %v, want ErrSVIDEvidence", err)
	}
}

func TestSVID_Ed25519LeafPoP(t *testing.T) {
	// Exercise the Ed25519 leaf PoP path (verifyLeafSignature ed25519 branch)
	// via a direct cert+key, independent of the ECDSA fixture.
	env, _, _, _ := signedEnvelopeForAttest(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	u, _ := url.Parse(testSPIFFEID)
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		URIs: []*url.URL{u}, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, pub, caKey)
	if err != nil {
		t.Fatalf("ed25519 leaf: %v", err)
	}
	gen, _ := svid.NewGeneration(now.Add(-2*time.Hour), time.Time{}, []*x509.Certificate{caCert})
	hist, _ := svid.NewTrustBundleHistory(testTrustDomain, gen)

	ev := SVIDEvidence{
		Type: "x509", SPIFFEID: testSPIFFEID,
		LeafDERB64: base64.StdEncoding.EncodeToString(leafDER),
		Nonce:      testNonce, IssuedAt: now.UTC().Format(time.RFC3339Nano),
		Binding: SVIDBinding{Alg: BindingAlgEd25519, Context: ContextSVIDBinding},
	}
	canonical, _ := bindingCanonical(env, ev)
	ev.Binding.SignatureB64 = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canonical))
	ev.Binding.PayloadSHA256 = hexSHA256(canonical)

	svopts := SVIDVerifyOptions{TrustDomain: testTrustDomain, History: hist, ActionTime: now}
	if _, err := VerifySVIDBinding(env, ev, svopts); err != nil {
		t.Fatalf("ed25519 PoP: %v", err)
	}

	// Wrong-length signature on an Ed25519 leaf fails closed (no panic).
	bad := ev
	bad.Binding.SignatureB64 = base64.StdEncoding.EncodeToString([]byte{1, 2, 3})
	if _, err := VerifySVIDBinding(env, bad, svopts); !errors.Is(err, ErrSVIDBinding) {
		t.Fatalf("ed25519 short sig: got %v, want ErrSVIDBinding", err)
	}
}
