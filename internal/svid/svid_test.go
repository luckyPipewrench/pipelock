// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package svid

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"testing"
	"time"
)

// ---- test PKI helpers (all in-memory; no key material ever touches disk) ----

const (
	tdExample = "example.test"
	tdOther   = "other.test"
	idAlpha   = "spiffe://example.test/agent/alpha"
	idBeta    = "spiffe://other.test/agent/beta"
)

// base anchors every fixture window. Validation is driven exclusively by the
// caller-supplied `At`, never time.Now(), so fixed dates here cannot time-bomb.
var base = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func mustSerial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	return n
}

// newTestCA mints a self-signed CA. The CA window is deliberately wide so only
// the leaf SVID's window drives expiry tests.
func newTestCA(t *testing.T, commonName string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          mustSerial(t),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             base.Add(-10 * 365 * 24 * time.Hour),
		NotAfter:              base.Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	return &testCA{cert: cert, key: key}
}

// newIntermediate mints an intermediate CA signed by parent.
func (ca *testCA) newIntermediate(t *testing.T, commonName string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("int key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          mustSerial(t),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             base.Add(-10 * 365 * 24 * time.Hour),
		NotAfter:              base.Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("int cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse int: %v", err)
	}
	return &testCA{cert: cert, key: key}
}

// issueSVID returns the leaf SVID certificate DER, signed by ca, carrying
// spiffeID as its sole URI SAN and the given validity window.
func (ca *testCA) issueSVID(t *testing.T, spiffeID string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	u, err := url.Parse(spiffeID)
	if err != nil {
		t.Fatalf("spiffe uri: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          mustSerial(t),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		URIs:                  []*url.URL{u},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &leafKey.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return cert
}

func certsToPEM(certs ...*x509.Certificate) []byte {
	var buf bytes.Buffer
	for _, c := range certs {
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return buf.Bytes()
}

// openHistory builds a single open-ended-generation history for td pinned to ca.
func openHistory(t *testing.T, td string, ca *testCA) *TrustBundleHistory {
	t.Helper()
	gen, err := NewGeneration(base.Add(-365*24*time.Hour), time.Time{}, []*x509.Certificate{ca.cert})
	if err != nil {
		t.Fatalf("NewGeneration: %v", err)
	}
	h, err := NewTrustBundleHistory(td, gen)
	if err != nil {
		t.Fatalf("NewTrustBundleHistory: %v", err)
	}
	return h
}

// ---- happy path ----

func TestValidateSVID_GenuineSVID_ValidatesOffline(t *testing.T) {
	ca := newTestCA(t, "example.test root")
	at := base.Add(time.Hour)
	leaf := ca.issueSVID(t, idAlpha, base, base.Add(2*time.Hour))
	h := openHistory(t, tdExample, ca)

	got, err := ValidateSVID(certsToPEM(leaf), Options{TrustDomain: tdExample, History: h, At: at})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if got.SPIFFEID != idAlpha {
		t.Errorf("SPIFFEID = %q, want %q", got.SPIFFEID, idAlpha)
	}
	if got.Leaf == nil || !got.Leaf.Equal(leaf) {
		t.Errorf("Leaf not returned correctly")
	}
}

func TestValidateSVID_IntermediateChain(t *testing.T) {
	root := newTestCA(t, "example.test root")
	inter := root.newIntermediate(t, "example.test intermediate")
	at := base.Add(time.Hour)
	leaf := inter.issueSVID(t, idAlpha, base, base.Add(2*time.Hour))
	h := openHistory(t, tdExample, root) // only the ROOT is pinned

	got, err := ValidateSVID(
		certsToPEM(leaf, inter.cert), // leaf first, intermediate follows
		Options{TrustDomain: tdExample, History: h, At: at},
	)
	if err != nil {
		t.Fatalf("expected success through intermediate, got %v", err)
	}
	if got.SPIFFEID != idAlpha {
		t.Errorf("SPIFFEID = %q, want %q", got.SPIFFEID, idAlpha)
	}
}

// ---- point-in-time / expiry (exact boundary) ----

func TestValidateSVID_ExpiryBoundary(t *testing.T) {
	ca := newTestCA(t, "example.test root")
	notBefore := base
	notAfter := base.Add(2 * time.Hour)
	leaf := ca.issueSVID(t, idAlpha, notBefore, notAfter)
	h := openHistory(t, tdExample, ca)

	// Valid exactly at NotAfter (x509 uses After(NotAfter), so the boundary is valid).
	if _, err := ValidateSVID(certsToPEM(leaf), Options{TrustDomain: tdExample, History: h, At: notAfter}); err != nil {
		t.Fatalf("valid at exact NotAfter: unexpected error %v", err)
	}
	// One nanosecond past expiry must reject.
	_, err := ValidateSVID(certsToPEM(leaf), Options{TrustDomain: tdExample, History: h, At: notAfter.Add(time.Nanosecond)})
	if !errors.Is(err, ErrExpiredAtTime) {
		t.Fatalf("at NotAfter+1ns: want ErrExpiredAtTime, got %v", err)
	}
	// Valid exactly at NotBefore.
	if _, err := ValidateSVID(certsToPEM(leaf), Options{TrustDomain: tdExample, History: h, At: notBefore}); err != nil {
		t.Fatalf("valid at exact NotBefore: unexpected error %v", err)
	}
	// One nanosecond before validity must reject (not-yet-valid).
	_, err = ValidateSVID(certsToPEM(leaf), Options{TrustDomain: tdExample, History: h, At: notBefore.Add(-time.Nanosecond)})
	if !errors.Is(err, ErrExpiredAtTime) {
		t.Fatalf("at NotBefore-1ns: want ErrExpiredAtTime, got %v", err)
	}
}

// "Valid now but NOT valid at action time" — the audit-replay defense.
func TestValidateSVID_ValidNowButNotAtActionTime(t *testing.T) {
	ca := newTestCA(t, "example.test root")
	// SVID window straddles base (would be "valid" if checked near base).
	leaf := ca.issueSVID(t, idAlpha, base.Add(-time.Hour), base.Add(time.Hour))
	h := openHistory(t, tdExample, ca)

	// Action happened two hours before the SVID was even issued.
	at := base.Add(-2 * time.Hour)
	_, err := ValidateSVID(certsToPEM(leaf), Options{TrustDomain: tdExample, History: h, At: at})
	if !errors.Is(err, ErrExpiredAtTime) {
		t.Fatalf("want ErrExpiredAtTime for action before issuance, got %v", err)
	}
}

// The zero-At guard: must never silently fall back to time.Now().
func TestValidateSVID_ZeroAt_Rejects(t *testing.T) {
	ca := newTestCA(t, "example.test root")
	leaf := ca.issueSVID(t, idAlpha, base, base.Add(2*time.Hour))
	h := openHistory(t, tdExample, ca)
	_, err := ValidateSVID(certsToPEM(leaf), Options{TrustDomain: tdExample, History: h}) // At zero
	if !errors.Is(err, ErrMalformedInput) {
		t.Fatalf("want ErrMalformedInput for zero At, got %v", err)
	}
}

// ---- wrong key ----

func TestValidateSVID_WrongKey_UntrustedChain(t *testing.T) {
	pinned := newTestCA(t, "example.test root")
	attacker := newTestCA(t, "attacker root")
	at := base.Add(time.Hour)
	// SVID with the right SPIFFE ID but signed by an unpinned root.
	leaf := attacker.issueSVID(t, idAlpha, base, base.Add(2*time.Hour))
	h := openHistory(t, tdExample, pinned)

	_, err := ValidateSVID(certsToPEM(leaf), Options{TrustDomain: tdExample, History: h, At: at})
	if !errors.Is(err, ErrUntrustedChain) {
		t.Fatalf("want ErrUntrustedChain for unpinned signer, got %v", err)
	}
}

// A CA-flagged leaf is not a valid SVID and must reject (not panic).
func TestValidateSVID_CALeaf_Rejects(t *testing.T) {
	ca := newTestCA(t, "example.test root")
	at := base.Add(time.Hour)
	// Re-use the CA itself (IsCA=true) as if it were a leaf SVID. It has no
	// URI SAN, so it should classify as malformed (not a SVID).
	h := openHistory(t, tdExample, ca)
	_, err := ValidateSVID(certsToPEM(ca.cert), Options{TrustDomain: tdExample, History: h, At: at})
	if err == nil {
		t.Fatalf("CA-as-leaf must reject")
	}
	if !errors.Is(err, ErrMalformedInput) && !errors.Is(err, ErrUntrustedChain) {
		t.Fatalf("CA-as-leaf: want malformed or untrusted, got %v", err)
	}
}

// ---- trust-domain confusion ----

func TestValidateSVID_TrustDomainConfusion(t *testing.T) {
	caA := newTestCA(t, "example.test root")
	caB := newTestCA(t, "other.test root")
	at := base.Add(time.Hour)
	// A genuine SVID for example.test...
	leaf := caA.issueSVID(t, idAlpha, base, base.Add(2*time.Hour))
	// ...presented for validation against other.test's pinned bundle.
	hB := openHistory(t, tdOther, caB)

	_, err := ValidateSVID(certsToPEM(leaf), Options{TrustDomain: tdOther, History: hB, At: at})
	if !errors.Is(err, ErrTrustDomainMismatch) {
		t.Fatalf("want ErrTrustDomainMismatch, got %v", err)
	}

	// Symmetric: a genuine other.test SVID presented against example.test.
	betaLeaf := caB.issueSVID(t, idBeta, base, base.Add(2*time.Hour))
	hA := openHistory(t, tdExample, caA)
	_, err = ValidateSVID(certsToPEM(betaLeaf), Options{TrustDomain: tdExample, History: hA, At: at})
	if !errors.Is(err, ErrTrustDomainMismatch) {
		t.Fatalf("symmetric: want ErrTrustDomainMismatch, got %v", err)
	}
}

// Options.TrustDomain and History must agree; a mismatch is caller misconfig.
func TestValidateSVID_OptionsHistoryDomainMismatch(t *testing.T) {
	caA := newTestCA(t, "example.test root")
	at := base.Add(time.Hour)
	leaf := caA.issueSVID(t, idAlpha, base, base.Add(2*time.Hour))
	hA := openHistory(t, tdExample, caA)
	// History is for example.test, but caller claims other.test.
	_, err := ValidateSVID(certsToPEM(leaf), Options{TrustDomain: tdOther, History: hA, At: at})
	if !errors.Is(err, ErrMalformedInput) {
		t.Fatalf("want ErrMalformedInput for opts/history domain mismatch, got %v", err)
	}
}

// ---- malformed input (no panic) ----

func TestValidateSVID_MalformedInput(t *testing.T) {
	ca := newTestCA(t, "example.test root")
	h := openHistory(t, tdExample, ca)
	at := base.Add(time.Hour)

	// non-SVID X.509: a leaf with no URI SAN.
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	nonSVIDTmpl := &x509.Certificate{
		SerialNumber: mustSerial(t),
		NotBefore:    base,
		NotAfter:     base.Add(2 * time.Hour),
		Subject:      pkix.Name{CommonName: "no-uri.example"},
	}
	nonSVIDDER, err := x509.CreateCertificate(rand.Reader, nonSVIDTmpl, ca.cert, &leafKey.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("non-svid cert: %v", err)
	}
	nonSVID, _ := x509.ParseCertificate(nonSVIDDER)

	good := ca.issueSVID(t, idAlpha, base, base.Add(2*time.Hour))
	truncated := certsToPEM(good)
	truncated = truncated[:len(truncated)/2]

	cases := []struct {
		name string
		pem  []byte
	}{
		{"garbage", []byte("this is not pem at all")},
		{"whitespace only", []byte("   \n\t  \n ")},
		{"empty", nil},
		{"truncated cert", truncated},
		{"non-svid x509 (no URI SAN)", certsToPEM(nonSVID)},
		{"pem but wrong block type", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("xx")})},
		{"empty cert block body", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: nil})},
		{"leading garbage before valid cert", append([]byte("junk before cert\n"), certsToPEM(good)...)},
		{"valid cert then trailing garbage", append(certsToPEM(good), []byte("\nthis is trailing garbage that did not PEM-decode")...)},
		{"junk between valid cert blocks", append(append(certsToPEM(good), []byte("\njunk between certs\n")...), certsToPEM(good)...)},
		{"valid cert then undecodable second block", append(certsToPEM(good), []byte("\n-----BEGIN CERTIFICATE-----\nnot base64!!!\n-----END CERTIFICATE-----\n")...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidateSVID(tc.pem, Options{TrustDomain: tdExample, History: h, At: at})
			if !errors.Is(err, ErrMalformedInput) {
				t.Fatalf("want ErrMalformedInput, got %v", err)
			}
		})
	}
}

func TestValidateSVID_InvalidOptionsTrustDomain(t *testing.T) {
	ca := newTestCA(t, "example.test root")
	leaf := ca.issueSVID(t, idAlpha, base, base.Add(2*time.Hour))
	h := openHistory(t, tdExample, ca)
	// Empty opts.TrustDomain is not a parseable SPIFFE trust domain.
	_, err := ValidateSVID(certsToPEM(leaf), Options{TrustDomain: "", History: h, At: base.Add(time.Hour)})
	if !errors.Is(err, ErrMalformedInput) {
		t.Fatalf("want ErrMalformedInput for empty opts.TrustDomain, got %v", err)
	}
}

func TestValidateSVID_NilHistory(t *testing.T) {
	ca := newTestCA(t, "example.test root")
	leaf := ca.issueSVID(t, idAlpha, base, base.Add(2*time.Hour))
	_, err := ValidateSVID(certsToPEM(leaf), Options{TrustDomain: tdExample, History: nil, At: base.Add(time.Hour)})
	if !errors.Is(err, ErrMalformedInput) {
		t.Fatalf("want ErrMalformedInput for nil history, got %v", err)
	}
}

// ---- trust bundle history / rotation ----

func TestTrustBundleHistory_RotationValidatesPriorGeneration(t *testing.T) {
	caGen0 := newTestCA(t, "example.test gen0")
	caGen1 := newTestCA(t, "example.test gen1")
	t0 := base
	t1 := base.Add(24 * time.Hour)

	gen0, err := NewGeneration(t0, t1, []*x509.Certificate{caGen0.cert})
	if err != nil {
		t.Fatalf("gen0: %v", err)
	}
	gen1, err := NewGeneration(t1, time.Time{}, []*x509.Certificate{caGen1.cert})
	if err != nil {
		t.Fatalf("gen1: %v", err)
	}
	h, err := NewTrustBundleHistory(tdExample, gen0, gen1)
	if err != nil {
		t.Fatalf("history: %v", err)
	}

	// SVID issued under gen0, action time within gen0's window — validates even
	// though the history has since rotated to gen1.
	leaf := caGen0.issueSVID(t, idAlpha, t0, t0.Add(time.Hour))
	at := t0.Add(30 * time.Minute)
	if _, err := ValidateSVID(certsToPEM(leaf), Options{TrustDomain: tdExample, History: h, At: at}); err != nil {
		t.Fatalf("gen0 SVID at gen0 time after rotation: %v", err)
	}

	// An SVID from gen0's CA, but action time in gen1's window, must NOT chain
	// to gen1's (different) root.
	atGen1 := t1.Add(time.Hour)
	leaf2 := caGen0.issueSVID(t, idAlpha, t1, t1.Add(2*time.Hour))
	_, err = ValidateSVID(certsToPEM(leaf2), Options{TrustDomain: tdExample, History: h, At: atGen1})
	if !errors.Is(err, ErrUntrustedChain) {
		t.Fatalf("gen0 root at gen1 time: want ErrUntrustedChain, got %v", err)
	}
}

// During SPIFFE rotation overlap, the new generation's bundle carries BOTH
// authorities; an SVID from the prior root still validates.
func TestTrustBundleHistory_RotationOverlap(t *testing.T) {
	caOld := newTestCA(t, "example.test old")
	caNew := newTestCA(t, "example.test new")
	t1 := base.Add(24 * time.Hour)

	// gen1 (overlap) pins both old and new authorities.
	gen, err := NewGeneration(t1, time.Time{}, []*x509.Certificate{caOld.cert, caNew.cert})
	if err != nil {
		t.Fatalf("overlap gen: %v", err)
	}
	h, err := NewTrustBundleHistory(tdExample, gen)
	if err != nil {
		t.Fatalf("history: %v", err)
	}

	leaf := caOld.issueSVID(t, idAlpha, t1, t1.Add(time.Hour))
	at := t1.Add(30 * time.Minute)
	if _, err := ValidateSVID(certsToPEM(leaf), Options{TrustDomain: tdExample, History: h, At: at}); err != nil {
		t.Fatalf("old-root SVID in overlap window: %v", err)
	}
}

func TestTrustBundleHistory_NoGenerationForActionTime(t *testing.T) {
	ca := newTestCA(t, "example.test root")
	t0 := base
	t1 := base.Add(24 * time.Hour)
	gen, err := NewGeneration(t0, t1, []*x509.Certificate{ca.cert})
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	h, err := NewTrustBundleHistory(tdExample, gen)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	leaf := ca.issueSVID(t, idAlpha, t0, t1)

	// Action time before the pinned generation begins → stale, no authoritative bundle.
	_, err = ValidateSVID(certsToPEM(leaf), Options{TrustDomain: tdExample, History: h, At: t0.Add(-time.Hour)})
	if !errors.Is(err, ErrStaleOrForkedBundle) {
		t.Fatalf("action before pinned window: want ErrStaleOrForkedBundle, got %v", err)
	}
	// Action time after the closed generation ends (gap) → stale.
	_, err = ValidateSVID(certsToPEM(leaf), Options{TrustDomain: tdExample, History: h, At: t1.Add(time.Hour)})
	if !errors.Is(err, ErrStaleOrForkedBundle) {
		t.Fatalf("action after pinned window: want ErrStaleOrForkedBundle, got %v", err)
	}
	// Boundary: half-open window [t0, t1). Exactly t1 is NOT covered.
	_, err = ValidateSVID(certsToPEM(leaf), Options{TrustDomain: tdExample, History: h, At: t1})
	if !errors.Is(err, ErrStaleOrForkedBundle) {
		t.Fatalf("action at exact NotAfter (half-open): want ErrStaleOrForkedBundle, got %v", err)
	}
	// Boundary: exactly t0 IS covered (so the SVID, valid then, validates).
	if _, err := ValidateSVID(certsToPEM(leaf), Options{TrustDomain: tdExample, History: h, At: t0}); err != nil {
		t.Fatalf("action at exact NotBefore: unexpected %v", err)
	}
}

func TestTrustBundleHistory_Pin_ForkRejected(t *testing.T) {
	caGen0 := newTestCA(t, "gen0")
	caGen1 := newTestCA(t, "gen1")
	t0 := base
	t1 := base.Add(24 * time.Hour)
	gen0, _ := NewGeneration(t0, time.Time{}, []*x509.Certificate{caGen0.cert})
	h, err := NewTrustBundleHistory(tdExample, gen0)
	if err != nil {
		t.Fatalf("history: %v", err)
	}

	// Legitimate forward rotation closes the open generation and appends.
	gen1, _ := NewGeneration(t1, time.Time{}, []*x509.Certificate{caGen1.cert})
	if err := h.Pin(gen1); err != nil {
		t.Fatalf("legitimate forward pin: %v", err)
	}

	// Backward pin (rewriting already-pinned history) is a fork → reject.
	backward, _ := NewGeneration(base.Add(-time.Hour), base.Add(time.Hour), []*x509.Certificate{caGen0.cert})
	if err := h.Pin(backward); !errors.Is(err, ErrStaleOrForkedBundle) {
		t.Fatalf("backward pin: want ErrStaleOrForkedBundle, got %v", err)
	}

	// Overlapping pin (inside an already-closed window) is a fork → reject.
	overlap, _ := NewGeneration(t1.Add(time.Hour), time.Time{}, []*x509.Certificate{caGen1.cert})
	// t1.Add(time.Hour) is after gen1.NotBefore (t1) which is now the open gen;
	// a forward pin is fine, but a pin whose NotBefore <= current open gen's
	// NotBefore must reject.
	if err := h.Pin(overlap); err != nil {
		t.Fatalf("forward pin after open gen should succeed: %v", err)
	}
	conflict, _ := NewGeneration(t1, time.Time{}, []*x509.Certificate{caGen0.cert})
	if err := h.Pin(conflict); !errors.Is(err, ErrStaleOrForkedBundle) {
		t.Fatalf("pin at/behind current open gen: want ErrStaleOrForkedBundle, got %v", err)
	}
}

func TestTrustBundleHistory_ConstructionErrors(t *testing.T) {
	ca := newTestCA(t, "root")
	good := func() Generation {
		g, _ := NewGeneration(base, time.Time{}, []*x509.Certificate{ca.cert})
		return g
	}

	t.Run("empty trust domain", func(t *testing.T) {
		if _, err := NewTrustBundleHistory("", good()); !errors.Is(err, ErrMalformedInput) {
			t.Fatalf("want ErrMalformedInput, got %v", err)
		}
	})
	t.Run("ip trust domain", func(t *testing.T) {
		if _, err := NewTrustBundleHistory("192.0.2.1", good()); !errors.Is(err, ErrMalformedInput) {
			t.Fatalf("want ErrMalformedInput, got %v", err)
		}
	})
	t.Run("no generations", func(t *testing.T) {
		if _, err := NewTrustBundleHistory(tdExample); !errors.Is(err, ErrMalformedInput) {
			t.Fatalf("want ErrMalformedInput, got %v", err)
		}
	})
	t.Run("empty authorities", func(t *testing.T) {
		if _, err := NewGeneration(base, time.Time{}, nil); !errors.Is(err, ErrMalformedInput) {
			t.Fatalf("want ErrMalformedInput, got %v", err)
		}
	})
	t.Run("nil authority element", func(t *testing.T) {
		if _, err := NewGeneration(base, time.Time{}, []*x509.Certificate{nil}); !errors.Is(err, ErrMalformedInput) {
			t.Fatalf("want ErrMalformedInput, got %v", err)
		}
	})
	t.Run("non-ca authority", func(t *testing.T) {
		leaf := ca.issueSVID(t, idAlpha, base, base.Add(time.Hour))
		if _, err := NewGeneration(base, time.Time{}, []*x509.Certificate{leaf}); !errors.Is(err, ErrMalformedInput) {
			t.Fatalf("want ErrMalformedInput, got %v", err)
		}
	})
	t.Run("ca authority lacking cert-sign usage", func(t *testing.T) {
		// A cert flagged IsCA but whose KeyUsage is set without CertSign cannot
		// actually sign certificates, so it must not be accepted as a trust authority.
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("key: %v", err)
		}
		tmpl := &x509.Certificate{
			SerialNumber:          mustSerial(t),
			Subject:               pkix.Name{CommonName: "ca without certsign"},
			NotBefore:             base.Add(-time.Hour),
			NotAfter:              base.Add(time.Hour),
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageDigitalSignature, // non-zero, but no CertSign
			BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatalf("cert: %v", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if _, err := NewGeneration(base, time.Time{}, []*x509.Certificate{cert}); !errors.Is(err, ErrMalformedInput) {
			t.Fatalf("want ErrMalformedInput for CA lacking cert-sign usage, got %v", err)
		}
	})
	t.Run("authority without DER", func(t *testing.T) {
		if _, err := NewGeneration(base, time.Time{}, []*x509.Certificate{{
			IsCA:     true,
			KeyUsage: x509.KeyUsageCertSign,
		}}); !errors.Is(err, ErrMalformedInput) {
			t.Fatalf("want ErrMalformedInput, got %v", err)
		}
	})
	t.Run("authority with non-empty but unparseable DER", func(t *testing.T) {
		if _, err := NewGeneration(base, time.Time{}, []*x509.Certificate{{
			IsCA:     true,
			KeyUsage: x509.KeyUsageCertSign,
			Raw:      []byte{0x01, 0x02, 0x03}, // non-empty, not valid DER
		}}); !errors.Is(err, ErrMalformedInput) {
			t.Fatalf("want ErrMalformedInput for unparseable DER, got %v", err)
		}
	})
	t.Run("zero notBefore", func(t *testing.T) {
		if _, err := NewGeneration(time.Time{}, time.Time{}, []*x509.Certificate{ca.cert}); !errors.Is(err, ErrMalformedInput) {
			t.Fatalf("want ErrMalformedInput, got %v", err)
		}
	})
	t.Run("pin zero-value generation", func(t *testing.T) {
		h := openHistory(t, tdExample, ca)
		if err := h.Pin(Generation{}); !errors.Is(err, ErrMalformedInput) {
			t.Fatalf("Pin(zero-value): want ErrMalformedInput, got %v", err)
		}
	})
	t.Run("pin generation with valid window but no authorities", func(t *testing.T) {
		// A hand-built Generation can carry a valid window yet nil authorities;
		// the append boundary must still reject it fail-closed.
		h := openHistory(t, tdExample, ca)
		if err := h.Pin(Generation{NotBefore: base.Add(time.Hour)}); !errors.Is(err, ErrMalformedInput) {
			t.Fatalf("Pin(no authorities): want ErrMalformedInput, got %v", err)
		}
	})
	t.Run("notAfter before notBefore", func(t *testing.T) {
		if _, err := NewGeneration(base.Add(time.Hour), base, []*x509.Certificate{ca.cert}); !errors.Is(err, ErrMalformedInput) {
			t.Fatalf("want ErrMalformedInput, got %v", err)
		}
	})
	t.Run("mutated zero notBefore rejected at history append", func(t *testing.T) {
		g := good()
		g.NotBefore = time.Time{}
		if _, err := NewTrustBundleHistory(tdExample, g); !errors.Is(err, ErrMalformedInput) {
			t.Fatalf("want ErrMalformedInput, got %v", err)
		}
	})
	t.Run("mutated inverted window rejected at pin", func(t *testing.T) {
		h := openHistory(t, tdExample, ca)
		g := good()
		g.NotBefore = base.Add(2 * time.Hour)
		g.NotAfter = base.Add(time.Hour)
		if err := h.Pin(g); !errors.Is(err, ErrMalformedInput) {
			t.Fatalf("want ErrMalformedInput, got %v", err)
		}
	})
	t.Run("overlapping generations", func(t *testing.T) {
		g0, _ := NewGeneration(base, base.Add(2*time.Hour), []*x509.Certificate{ca.cert})
		g1, _ := NewGeneration(base.Add(time.Hour), base.Add(3*time.Hour), []*x509.Certificate{ca.cert})
		if _, err := NewTrustBundleHistory(tdExample, g0, g1); !errors.Is(err, ErrStaleOrForkedBundle) {
			t.Fatalf("want ErrStaleOrForkedBundle, got %v", err)
		}
	})
	t.Run("two open generations auto-close into a valid rotation", func(t *testing.T) {
		// Passing two "open-ended" generations is the rotation case: the
		// earlier one is closed at the later one's start. The result is a
		// valid, queryable two-generation history.
		caOld := newTestCA(t, "old")
		caNew := newTestCA(t, "new")
		g0, _ := NewGeneration(base, time.Time{}, []*x509.Certificate{caOld.cert})
		g1, _ := NewGeneration(base.Add(time.Hour), time.Time{}, []*x509.Certificate{caNew.cert})
		h, err := NewTrustBundleHistory(tdExample, g0, g1)
		if err != nil {
			t.Fatalf("two open generations should auto-close: %v", err)
		}
		// gen0 authoritative before the rotation point...
		oldLeaf := caOld.issueSVID(t, idAlpha, base, base.Add(2*time.Hour))
		if _, err := ValidateSVID(certsToPEM(oldLeaf), Options{TrustDomain: tdExample, History: h, At: base.Add(30 * time.Minute)}); err != nil {
			t.Fatalf("gen0 SVID before rotation: %v", err)
		}
		// ...gen1 authoritative after it.
		newLeaf := caNew.issueSVID(t, idAlpha, base.Add(time.Hour), base.Add(3*time.Hour))
		if _, err := ValidateSVID(certsToPEM(newLeaf), Options{TrustDomain: tdExample, History: h, At: base.Add(2 * time.Hour)}); err != nil {
			t.Fatalf("gen1 SVID after rotation: %v", err)
		}
	})
}

func TestNewGenerationPEM(t *testing.T) {
	ca := newTestCA(t, "root")
	gen, err := NewGenerationPEM(base, time.Time{}, certsToPEM(ca.cert))
	if err != nil {
		t.Fatalf("NewGenerationPEM: %v", err)
	}
	h, err := NewTrustBundleHistory(tdExample, gen)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	leaf := ca.issueSVID(t, idAlpha, base, base.Add(2*time.Hour))
	if _, err := ValidateSVID(certsToPEM(leaf), Options{TrustDomain: tdExample, History: h, At: base.Add(time.Hour)}); err != nil {
		t.Fatalf("validate with PEM-built generation: %v", err)
	}

	if _, err := NewGenerationPEM(base, time.Time{}, []byte("not pem")); !errors.Is(err, ErrMalformedInput) {
		t.Fatalf("want ErrMalformedInput for bad PEM, got %v", err)
	}
}

func TestTrustBundleHistory_AuthorityClonePreventsCallerMutation(t *testing.T) {
	ca := newTestCA(t, "root")
	leaf := ca.issueSVID(t, idAlpha, base, base.Add(2*time.Hour))
	gen, err := NewGeneration(base, time.Time{}, []*x509.Certificate{ca.cert})
	if err != nil {
		t.Fatalf("NewGeneration: %v", err)
	}
	h, err := NewTrustBundleHistory(tdExample, gen)
	if err != nil {
		t.Fatalf("history: %v", err)
	}

	ca.cert.IsCA = false
	ca.cert.Raw = nil

	if _, err := ValidateSVID(certsToPEM(leaf), Options{TrustDomain: tdExample, History: h, At: base.Add(time.Hour)}); err != nil {
		t.Fatalf("source authority mutation affected pinned history: %v", err)
	}
}

func TestTrustBundleHistory_TrustDomainAccessor(t *testing.T) {
	ca := newTestCA(t, "root")
	h := openHistory(t, tdExample, ca)
	if h.TrustDomain() != tdExample {
		t.Errorf("TrustDomain() = %q, want %q", h.TrustDomain(), tdExample)
	}
}

// Conductor rotates trust bundles at runtime while validations are in flight.
// Concurrent Pin + ValidateSVID must be race-free (run under -race).
func TestTrustBundleHistory_ConcurrentPinAndValidate(t *testing.T) {
	ca := newTestCA(t, "example.test gen0")
	gen0, _ := NewGeneration(base, time.Time{}, []*x509.Certificate{ca.cert})
	h, err := NewTrustBundleHistory(tdExample, gen0)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	leaf := ca.issueSVID(t, idAlpha, base, base.Add(100*24*time.Hour))
	pemBytes := certsToPEM(leaf)

	rotations := make([]Generation, 0, 50)
	for i := 1; i <= 50; i++ {
		caN := newTestCA(t, "rotation")
		g, gErr := NewGeneration(base.Add(time.Duration(i)*time.Hour), time.Time{}, []*x509.Certificate{caN.cert})
		if gErr != nil {
			t.Fatalf("gen %d: %v", i, gErr)
		}
		rotations = append(rotations, g)
	}

	done := make(chan error, 1)
	go func() {
		for i, g := range rotations {
			if pErr := h.Pin(g); pErr != nil {
				done <- fmt.Errorf("pin %d: %w", i+1, pErr)
				return
			}
		}
		done <- nil
	}()
	for i := 0; i < 200; i++ {
		// Validate at gen0's window; result may be valid or stale depending on
		// interleaving, but it must never race or panic.
		_, _ = ValidateSVID(pemBytes, Options{TrustDomain: tdExample, History: h, At: base.Add(30 * time.Minute)})
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
