// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package aarp

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/svid"
)

func TestSVID_P384CurveConfusion(t *testing.T) {
	// A P-384 leaf declared under ecdsa-p256-sha256 must fail closed: the alg id
	// names P-256 and ecdsa.VerifyASN1 is curve-agnostic.
	env, _, _, _ := signedEnvelopeForAttest(t)
	now := time.Now().UTC()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	p384Key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	u, _ := url.Parse(testSPIFFEID)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		URIs: []*url.URL{u}, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &p384Key.PublicKey, caKey)
	gen, _ := svid.NewGeneration(now.Add(-2*time.Hour), time.Time{}, []*x509.Certificate{caCert})
	hist, _ := svid.NewTrustBundleHistory(testTrustDomain, gen)

	ev := SVIDEvidence{
		Type: "x509", SPIFFEID: testSPIFFEID,
		LeafDERB64: base64.StdEncoding.EncodeToString(leafDER),
		Nonce:      testNonce, IssuedAt: now.UTC().Format(time.RFC3339Nano),
		Binding: SVIDBinding{Alg: BindingAlgECDSAP256SHA256, Context: ContextSVIDBinding},
	}
	canonical, _ := bindingCanonical(env, ev)
	sum := sha256.Sum256(canonical)
	sig, _ := ecdsa.SignASN1(rand.Reader, p384Key, sum[:])
	ev.Binding.SignatureB64 = base64.StdEncoding.EncodeToString(sig)

	svopts := SVIDVerifyOptions{TrustDomain: testTrustDomain, History: hist, ActionTime: now}
	if _, err := VerifySVIDBinding(env, ev, svopts); !errors.Is(err, ErrSVIDBinding) {
		t.Fatalf("P-384 leaf under ecdsa-p256-sha256 = %v, want ErrSVIDBinding", err)
	}
}

func TestSVID_ShortNonceRejected(t *testing.T) {
	env, _, fx, svopts := signedEnvelopeForAttest(t)
	ev := signedEvidence(t, env, fx, testSPIFFEID)
	ev.Nonce = base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3}) // 3 bytes < 16
	if _, err := VerifySVIDBinding(env, ev, svopts); !errors.Is(err, ErrSVIDEvidence) {
		t.Fatalf("short nonce = %v, want ErrSVIDEvidence", err)
	}
}

func TestSVID_NonBase64URLNonceRejected(t *testing.T) {
	env, _, fx, svopts := signedEnvelopeForAttest(t)
	ev := signedEvidence(t, env, fx, testSPIFFEID)
	ev.Nonce = "not valid base64url!!"
	if _, err := VerifySVIDBinding(env, ev, svopts); !errors.Is(err, ErrSVIDEvidence) {
		t.Fatalf("bad nonce encoding = %v, want ErrSVIDEvidence", err)
	}
}

func TestSVID_EmptyLeafDERRejected(t *testing.T) {
	env, _, fx, svopts := signedEnvelopeForAttest(t)
	ev := signedEvidence(t, env, fx, testSPIFFEID)
	ev.LeafDERB64 = "" // decodes to empty
	if _, err := VerifySVIDBinding(env, ev, svopts); !errors.Is(err, ErrSVIDEvidence) {
		t.Fatalf("empty leaf DER = %v, want ErrSVIDEvidence", err)
	}
}

func TestSVID_AssertionTrustDomainMismatch(t *testing.T) {
	// A valid example.org SVID must NOT back an assertion claiming a different
	// trust domain (trust-domain confusion at the appraisal layer).
	fx := mintSVID(t, testTrustDomain, testSPIFFEID)
	pub, priv := genKey(t)
	signer, _ := NewEd25519Signer(testKeyID, "mediator", priv)
	e := baseEnvelope()
	e.Assertion.TrustDomain = "other.example" // claims a domain the SVID is not in
	e.Assertion.EvidenceRefs = []string{"spiffe_svid"}
	env, err := Sign(e, signer)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	ev := signedEvidence(t, env, fx, testSPIFFEID)
	svopts := SVIDVerifyOptions{TrustDomain: testTrustDomain, History: fx.history, ActionTime: fx.actionTime}

	if _, err := VerifySVIDBinding(env, ev, svopts); !errors.Is(err, ErrSVIDBinding) {
		t.Fatalf("trust-domain confusion: got %v, want ErrSVIDBinding", err)
	}
	ap, err := AppraiseWithSVID(env, &ev, VerifyOptions{TrustedKeys: map[string]ed25519.PublicKey{testKeyID: pub}}, svopts)
	if err != nil {
		t.Fatalf("AppraiseWithSVID: %v", err)
	}
	if contains(ap.VerifiedClaims, ClaimSigningWorkloadSVIDChainValidated) {
		t.Fatal("workload_identity_verified despite trust-domain confusion")
	}
}

func TestSVID_AssertionTrustDomainRequired(t *testing.T) {
	fx := mintSVID(t, testTrustDomain, testSPIFFEID)
	_, priv := genKey(t)
	signer, _ := NewEd25519Signer(testKeyID, "mediator", priv)
	e := baseEnvelope()
	e.Assertion.TrustDomain = "" // missing with an SVID binding present
	env, err := Sign(e, signer)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	ev := signedEvidence(t, env, fx, testSPIFFEID)
	svopts := SVIDVerifyOptions{TrustDomain: testTrustDomain, History: fx.history, ActionTime: fx.actionTime}
	if _, err := VerifySVIDBinding(env, ev, svopts); !errors.Is(err, ErrSVIDBinding) {
		t.Fatalf("empty trust_domain: got %v, want ErrSVIDBinding", err)
	}
}

func TestSVID_IssuedAtOutsideLeafWindow(t *testing.T) {
	env, _, fx, svopts := signedEnvelopeForAttest(t)
	// Sign a binding stamped 48h out — past the leaf NotAfter (action+24h) —
	// modeling post-expiry use of a later-obtained leaf key.
	future := fx.actionTime.Add(48 * time.Hour).UTC().Format(time.RFC3339Nano)
	ev := signedEvidenceAt(t, env, fx, testSPIFFEID, future)
	if _, err := VerifySVIDBinding(env, ev, svopts); !errors.Is(err, ErrSVIDBinding) {
		t.Fatalf("issued_at after expiry: got %v, want ErrSVIDBinding", err)
	}
}

func TestUnmarshal_TypeMismatchIsSchemaError(t *testing.T) {
	// A decode error that is NOT an unknown field (here, a type mismatch) must
	// classify as ErrSchema, not ErrUnknownField.
	raw := []byte(`{"profile":"aarp/v0.1","subject":{},"assertion":{},"signatures":"should-be-array"}`)
	_, err := Unmarshal(raw)
	if !errors.Is(err, ErrSchema) {
		t.Fatalf("Unmarshal(type mismatch) = %v, want ErrSchema", err)
	}
	if errors.Is(err, ErrUnknownField) {
		t.Fatal("type mismatch misclassified as ErrUnknownField")
	}
}

func TestAppraiseWithSVID_InvalidEnvelopeErrors(t *testing.T) {
	// A structurally invalid envelope must error out of AppraiseWithSVID (the
	// core appraisal rejects it), regardless of evidence.
	bad := baseEnvelope() // unsigned: no signatures
	if _, err := AppraiseWithSVID(bad, nil, VerifyOptions{}, SVIDVerifyOptions{}); !errors.Is(err, ErrSchema) {
		t.Fatalf("AppraiseWithSVID(invalid) = %v, want ErrSchema", err)
	}
}

func TestSVID_EmptyNonceRejected(t *testing.T) {
	env, _, fx, svopts := signedEnvelopeForAttest(t)
	ev := signedEvidence(t, env, fx, testSPIFFEID)
	ev.Nonce = ""
	if _, err := VerifySVIDBinding(env, ev, svopts); !errors.Is(err, ErrSVIDEvidence) {
		t.Fatalf("empty nonce: got %v", err)
	}
}

func TestSVID_BadIssuedAtRejected(t *testing.T) {
	env, _, fx, svopts := signedEnvelopeForAttest(t)
	ev := signedEvidence(t, env, fx, testSPIFFEID)
	ev.IssuedAt = "not-a-time"
	if _, err := VerifySVIDBinding(env, ev, svopts); !errors.Is(err, ErrSVIDEvidence) {
		t.Fatalf("bad issued_at: got %v", err)
	}
}

func TestSVID_PayloadSHA256Mismatch(t *testing.T) {
	env, _, fx, svopts := signedEnvelopeForAttest(t)
	ev := signedEvidence(t, env, fx, testSPIFFEID)
	ev.Binding.PayloadSHA256 = digest64(5) // wrong digest
	if _, err := VerifySVIDBinding(env, ev, svopts); !errors.Is(err, ErrSVIDBinding) {
		t.Fatalf("payload sha mismatch: got %v", err)
	}
}

func TestSVID_BadBindingSignatureBase64(t *testing.T) {
	env, _, fx, svopts := signedEnvelopeForAttest(t)
	ev := signedEvidence(t, env, fx, testSPIFFEID)
	ev.Binding.SignatureB64 = "not!base64!"
	if _, err := VerifySVIDBinding(env, ev, svopts); !errors.Is(err, ErrSVIDEvidence) {
		t.Fatalf("bad sig b64: got %v", err)
	}
}

func TestSVID_AllowedSPIFFEIDMatch(t *testing.T) {
	env, _, fx, svopts := signedEnvelopeForAttest(t)
	ev := signedEvidence(t, env, fx, testSPIFFEID)
	svopts.AllowedSPIFFEIDs = []string{"spiffe://example.org/other", testSPIFFEID}
	if _, err := VerifySVIDBinding(env, ev, svopts); err != nil {
		t.Fatalf("allowed id should pass: %v", err)
	}
}

func TestSVID_ChainDEREncoded(t *testing.T) {
	// Exercise the chain-encoding branch of svidPEM by including an extra cert.
	env, _, fx, svopts := signedEnvelopeForAttest(t)
	ev := signedEvidence(t, env, fx, testSPIFFEID)
	ev.ChainDERB64 = []string{base64.StdEncoding.EncodeToString(fx.leafDER)}
	// Re-sign: the chain field is not part of the binding payload, so the
	// existing signature still verifies; this just drives the PEM assembly path.
	if _, err := VerifySVIDBinding(env, ev, svopts); err != nil {
		t.Fatalf("chain-encoded evidence: %v", err)
	}
}

func TestSVID_BadChainBase64(t *testing.T) {
	env, _, fx, svopts := signedEnvelopeForAttest(t)
	ev := signedEvidence(t, env, fx, testSPIFFEID)
	ev.ChainDERB64 = []string{"not!base64!"}
	if _, err := VerifySVIDBinding(env, ev, svopts); !errors.Is(err, ErrSVIDEvidence) {
		t.Fatalf("bad chain b64: got %v", err)
	}
}

func TestSVID_UnsupportedLeafKeyType(t *testing.T) {
	// An RSA SVID leaf: the chain validates, but the PoP path has no RSA branch,
	// so it fails closed with ErrSVIDBinding (unsupported key type).
	env, _, _, _ := signedEnvelopeForAttest(t)
	now := time.Now().UTC()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	u, _ := url.Parse(testSPIFFEID)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		URIs: []*url.URL{u}, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &rsaKey.PublicKey, caKey)
	gen, _ := svid.NewGeneration(now.Add(-2*time.Hour), time.Time{}, []*x509.Certificate{caCert})
	hist, _ := svid.NewTrustBundleHistory(testTrustDomain, gen)

	ev := SVIDEvidence{
		Type: "x509", SPIFFEID: testSPIFFEID,
		LeafDERB64: base64.StdEncoding.EncodeToString(leafDER),
		Nonce:      testNonce, IssuedAt: now.UTC().Format(time.RFC3339Nano),
		Binding: SVIDBinding{Alg: BindingAlgECDSAP256SHA256, Context: ContextSVIDBinding},
	}
	canonical, _ := bindingCanonical(env, ev)
	sum := sha256.Sum256(canonical)
	sig, _ := rsa.SignPKCS1v15(rand.Reader, rsaKey, 0, sum[:])
	ev.Binding.SignatureB64 = base64.StdEncoding.EncodeToString(sig)

	svopts := SVIDVerifyOptions{TrustDomain: testTrustDomain, History: hist, ActionTime: now}
	if _, err := VerifySVIDBinding(env, ev, svopts); !errors.Is(err, ErrSVIDBinding) {
		t.Fatalf("rsa leaf: got %v, want ErrSVIDBinding (unsupported key type)", err)
	}
}

func TestAppraiseWithSVID_FailedBindingWarns(t *testing.T) {
	env, vopts, fx, svopts := signedEnvelopeForAttest(t)
	ev := signedEvidence(t, env, fx, testSPIFFEID)
	ev.Binding.Context = "wrong" // make the binding fail
	ap, err := AppraiseWithSVID(env, &ev, vopts, svopts)
	if err != nil {
		t.Fatalf("AppraiseWithSVID: %v", err)
	}
	if contains(ap.VerifiedClaims, ClaimSigningWorkloadSVIDChainValidated) {
		t.Error("workload identity verified despite failed binding")
	}
	var warned bool
	for _, w := range ap.Warnings {
		if strings.Contains(w, "SVID attestation did not verify") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("expected a failed-attestation warning, got %v", ap.Warnings)
	}
}
