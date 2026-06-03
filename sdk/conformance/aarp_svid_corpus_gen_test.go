// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/aarp"
	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/svidsidecar"
)

// This file generates the SVID X.509 attestation arm of the AARP hostile corpus.
// It builds a deterministic test CA and leaf SVIDs in-generator (no real network,
// no wall clock; every certificate window and action time is fixed), assembles
// the proof-of-possession binding, and emits one sidecar (<name>.svid.json) per
// fixture read by every reference verifier via --svid.
//
// The corpus deliberately uses a single-CA, leaf-directly-under-root chain (no
// intermediates): it keeps the cross-language X.509 path validation tractable and
// identical across Go/TS/Rust/Python while still exercising every attestation
// attack. Multi-intermediate chains are a documented out-of-scope extension.
//
// An SVID attack is NEVER envelope-fatal. Every SVID fixture is verdictAppraise:
// a failed/absent binding simply withholds the three workload-identity claims
// (workload_identity_verified, x509_svid_bound, svid_valid_at_action_time) and
// surfaces the producer's workload_identity_verified claim as claimed-unverified.
// The gate's appraise path (four-way byte equality + match to the committed
// baseline) is what catches any verifier that inflates a claim the others reject.

// SVID corpus identities and trust domains. Vendor-neutral SPIFFE placeholders.
const (
	svidTrustDomain      = "example.org"
	svidWrongTrustDomain = "other.example"
	svidIDAgentA         = "spiffe://example.org/workload/agent-a"
	svidIDImposter       = "spiffe://example.org/workload/imposter"

	bindingAlgP256    = aarp.BindingAlgECDSAP256SHA256
	bindingAlgEd25519 = aarp.BindingAlgEd25519

	leafKindECDSAP256 = "ecdsa-p256"
	leafKindECDSAP384 = "ecdsa-p384"
	leafKindEd25519   = "ed25519"
)

// The on-disk SVID sidecar schema (svidsidecar.Sidecar / VerifyBlock / BundleGen)
// is shared with the cmd/pipelock-verifier --svid loader, so the bytes this
// generator writes are exactly the bytes every reference verifier parses.

// detReader is a deterministic, infinite byte stream seeded from a phrase:
// block_i = sha256(seed_hash || big-endian uint64 counter). It makes every key,
// certificate, and ECDSA signature in the SVID corpus reproducible (same Go
// version) so -update-aarp yields stable bytes. TEST ONLY — never key material a
// real deployment would trust.
type detReader struct {
	seed [32]byte
	ctr  uint64
	buf  []byte
}

func newDetReader(phrase string) *detReader {
	return &detReader{seed: sha256.Sum256([]byte("aarp-corpus-detrand/" + phrase))}
}

func (r *detReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if len(r.buf) == 0 {
			var ctr [8]byte
			binary.BigEndian.PutUint64(ctr[:], r.ctr)
			r.ctr++
			block := sha256.Sum256(append(append([]byte(nil), r.seed[:]...), ctr[:]...))
			r.buf = block[:]
		}
		m := copy(p[n:], r.buf)
		r.buf = r.buf[m:]
		n += m
	}
	return n, nil
}

// serialFromSeed derives a stable positive 128-bit certificate serial number.
func serialFromSeed(seed string) *big.Int {
	sum := sha256.Sum256([]byte("aarp-corpus-serial/" + seed))
	return new(big.Int).SetBytes(sum[:16])
}

// detBytes returns n deterministic bytes derived from a seed phrase.
func detBytes(seed string, n int) []byte {
	out := make([]byte, n)
	_, _ = io.ReadFull(newDetReader(seed), out)
	return out
}

// b64std and rfc are the corpus serialization helpers for DER and times.
func b64std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
func rfc(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// ecdhCurveFor maps an elliptic.Curve to its crypto/ecdh equivalent. crypto/ecdh
// gives a non-deprecated scalar->point path (elliptic.Curve.ScalarBaseMult is
// deprecated), which is all the corpus needs for deterministic ECDSA.
func ecdhCurveFor(c elliptic.Curve) ecdh.Curve {
	switch c.Params().Name {
	case "P-256":
		return ecdh.P256()
	case "P-384":
		return ecdh.P384()
	default:
		return nil
	}
}

// scalarFromSeed maps seed bytes into [1, n-1] deterministically. The extra
// bytes over the modulus width keep the modular bias negligible (corpus only).
func scalarFromSeed(seed string, n *big.Int) *big.Int {
	width := (n.BitLen()+7)/8 + 8
	v := new(big.Int).SetBytes(detBytes(seed, width))
	nm1 := new(big.Int).Sub(n, big.NewInt(1))
	v.Mod(v, nm1)
	return v.Add(v, big.NewInt(1))
}

// detECDSAKey derives a deterministic ECDSA private key on curve c from a seed.
// crypto/ecdsa.GenerateKey calls randutil.MaybeReadByte, which DELIBERATELY makes
// key generation nondeterministic even with a fixed reader — so the corpus needs
// stable certs cannot rely on it. We derive the scalar directly and recover the
// public point through crypto/ecdh.
func (g *aarpGen) detECDSAKey(c elliptic.Curve, seed string) *ecdsa.PrivateKey {
	ec := ecdhCurveFor(c)
	if ec == nil {
		g.t.Fatalf("unsupported ECDSA curve %s", c.Params().Name)
	}
	byteLen := (c.Params().BitSize + 7) / 8
	d := scalarFromSeed("ecdsa-d/"+seed, c.Params().N)
	db := make([]byte, byteLen)
	d.FillBytes(db)
	priv, err := ec.NewPrivateKey(db)
	if err != nil {
		g.t.Fatalf("derive ECDSA key: %v", err)
	}
	pub := priv.PublicKey().Bytes() // 0x04 || X || Y (uncompressed SEC1)
	x := new(big.Int).SetBytes(pub[1 : 1+byteLen])
	y := new(big.Int).SetBytes(pub[1+byteLen:])
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: c, X: x, Y: y}, D: d}
}

// detECDSASignASN1 produces a deterministic ASN.1 ECDSA signature over hash.
// ecdsa.SignASN1 is also nondeterministic (MaybeReadByte + hedged nonce), so we
// derive the nonce from the seed and compute (r,s) directly. The result verifies
// under the standard ecdsa.VerifyASN1 the reference verifier uses.
func (g *aarpGen) detECDSASignASN1(priv *ecdsa.PrivateKey, hash []byte, seed string) []byte {
	c := priv.Curve
	ec := ecdhCurveFor(c)
	n := c.Params().N
	byteLen := (c.Params().BitSize + 7) / 8
	// |hash| (SHA-256, 32 bytes) <= bitlen for P-256/P-384, so no truncation.
	e := new(big.Int).SetBytes(hash)
	for i := 0; ; i++ {
		k := scalarFromSeed(seed+"/"+strconv.Itoa(i), n)
		kb := make([]byte, byteLen)
		k.FillBytes(kb)
		kp, err := ec.NewPrivateKey(kb)
		if err != nil {
			continue
		}
		r := new(big.Int).Mod(new(big.Int).SetBytes(kp.PublicKey().Bytes()[1:1+byteLen]), n)
		if r.Sign() == 0 {
			continue
		}
		kInv := new(big.Int).ModInverse(k, n)
		if kInv == nil {
			continue
		}
		s := new(big.Int).Mul(priv.D, r)
		s.Add(s, e)
		s.Mul(s, kInv)
		s.Mod(s, n)
		if s.Sign() == 0 {
			continue
		}
		der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
		if err != nil {
			g.t.Fatalf("marshal ECDSA signature: %v", err)
		}
		return der
	}
}

// testCA is a deterministic self-signed Ed25519 CA. Ed25519 self-signing is
// deterministic by construction, so the CA DER is byte-stable across runs.
type testCA struct {
	cert *x509.Certificate
	der  []byte
	priv ed25519.PrivateKey
}

func (g *aarpGen) newEd25519CA(seed, commonName string, notBefore, notAfter time.Time) *testCA {
	rdr := newDetReader("ca/" + seed)
	pub, priv, err := ed25519.GenerateKey(rdr)
	if err != nil {
		g.t.Fatalf("generate CA key: %v", err)
	}
	if notAfter.IsZero() {
		notAfter = notBefore.AddDate(10, 0, 0)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serialFromSeed("ca/" + seed),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rdr, tmpl, tmpl, pub, priv)
	if err != nil {
		g.t.Fatalf("create CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		g.t.Fatalf("parse CA certificate: %v", err)
	}
	return &testCA{cert: cert, der: der, priv: priv}
}

// leaf is a generated SVID leaf certificate plus the private key that can issue
// its proof-of-possession binding signature.
type leaf struct {
	der    []byte
	signer crypto.Signer
}

// issueLeaf issues an SVID leaf for the corpus identity (svidIDAgentA) with the
// given key kind and validity window, signed by the CA. The leaf's own key kind
// (P-256, P-384, Ed25519) is independent of the chain signature (always the
// Ed25519 CA), so a P-384 leaf still chains cleanly — its curve only matters to
// the binding alg check (curve-confusion fixture).
func (g *aarpGen) issueLeaf(ca *testCA, seed, kind string, notBefore, notAfter time.Time) leaf {
	return g.issueLeafURI(ca, seed, kind, svidIDAgentA, notBefore, notAfter)
}

// issueLeafURI is issueLeaf with an explicit URI SAN, so a fixture can present a
// leaf whose SAN is a malformed SPIFFE ID (e.g. a dot-segment path) to exercise
// strict-vs-loose SPIFFE-ID grammar across the four verifiers.
func (g *aarpGen) issueLeafURI(ca *testCA, seed, kind, spiffeURI string, notBefore, notAfter time.Time) leaf {
	return g.issueLeafURIWithParent(ca, ca.cert, seed, kind, spiffeURI, notBefore, notAfter)
}

// issueLeafURIWithParent signs with ca.priv while letting the caller choose the
// parent certificate whose Subject becomes the leaf Issuer. Passing a parent
// with the same public key but a different Subject creates an issuer-linkage
// mismatch: raw signature verification succeeds, but a real X.509 chain builder
// rejects the leaf because issuer DN != pinned CA subject.
func (g *aarpGen) issueLeafURIWithParent(ca *testCA, parent *x509.Certificate, seed, kind, spiffeURI string, notBefore, notAfter time.Time) leaf {
	rdr := newDetReader("leaf/" + seed)
	u, err := url.Parse(spiffeURI)
	if err != nil {
		g.t.Fatalf("parse spiffe id %q: %v", spiffeURI, err)
	}

	var pub any
	var signer crypto.Signer
	switch kind {
	case leafKindECDSAP256:
		k := g.detECDSAKey(elliptic.P256(), seed)
		pub, signer = &k.PublicKey, k
	case leafKindECDSAP384:
		k := g.detECDSAKey(elliptic.P384(), seed)
		pub, signer = &k.PublicKey, k
	case leafKindEd25519:
		p, s, err := ed25519.GenerateKey(rdr)
		if err != nil {
			g.t.Fatalf("generate Ed25519 leaf key: %v", err)
		}
		pub, signer = p, s
	default:
		g.t.Fatalf("unknown leaf kind %q", kind)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serialFromSeed("leaf/" + seed),
		Subject:      pkix.Name{CommonName: "aarp-corpus-leaf"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		URIs:         []*url.URL{u},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rdr, tmpl, parent, pub, ca.priv)
	if err != nil {
		g.t.Fatalf("create leaf certificate: %v", err)
	}
	return leaf{der: der, signer: signer}
}

func (g *aarpGen) parentWithSubject(ca *testCA, commonName string) *x509.Certificate {
	cp := *ca.cert
	cp.Subject = pkix.Name{CommonName: commonName}
	cp.RawSubject = nil
	return &cp
}

// svidBindingCanonical reproduces internal/aarp.bindingCanonical (which is
// unexported) for the corpus: the JCS-canonical bytes the SVID leaf key signs.
// The field set, names, and canonicalization MUST match the Go reference exactly
// or the generated binding signature would never verify.
func (g *aarpGen) svidBindingCanonical(e aarp.Envelope, spiffeID, issuedAt, nonce string) []byte {
	assertionDigest, err := e.PayloadDigest()
	if err != nil {
		g.t.Fatalf("payload digest for binding: %v", err)
	}
	bp := map[string]any{
		"context":                    aarp.ContextSVIDBinding,
		"profile":                    aarp.Profile,
		"action_record_sha256":       e.Subject.ActionRecordSHA256,
		"receipt_envelope_sha256":    e.Subject.ReceiptEnvelopeSHA256,
		"assurance_assertion_sha256": assertionDigest,
		"receipt_signer_key":         e.Subject.ReceiptSignerKey,
		"mediator_id":                e.Assertion.MediatorID,
		"spiffe_id":                  spiffeID,
		"issued_at":                  issuedAt,
		"nonce":                      nonce,
	}
	raw, err := json.Marshal(bp)
	if err != nil {
		g.t.Fatalf("marshal binding payload: %v", err)
	}
	tree, err := contract.ParseJSONStrict(raw)
	if err != nil {
		g.t.Fatalf("parse binding payload: %v", err)
	}
	out, err := contract.Canonicalize(tree)
	if err != nil {
		g.t.Fatalf("canonicalize binding payload: %v", err)
	}
	return out
}

// signBinding signs the canonical binding payload with the given signer and alg,
// returning the standard-base64 wire signature. ECDSA signs SHA-256(payload) as
// ASN.1; Ed25519 signs the payload bytes directly.
func (g *aarpGen) signBinding(signer crypto.Signer, alg, seed string, canonical []byte) string {
	switch alg {
	case bindingAlgP256:
		k, ok := signer.(*ecdsa.PrivateKey)
		if !ok {
			g.t.Fatalf("binding alg %s needs an ECDSA key, got %T", alg, signer)
		}
		sum := sha256.Sum256(canonical)
		return b64std(g.detECDSASignASN1(k, sum[:], "bindsig/"+seed))
	case bindingAlgEd25519:
		k, ok := signer.(ed25519.PrivateKey)
		if !ok {
			g.t.Fatalf("binding alg %s needs an Ed25519 key, got %T", alg, signer)
		}
		return b64std(ed25519.Sign(k, canonical))
	default:
		g.t.Fatalf("unknown binding alg %q", alg)
		return ""
	}
}

// svidEvidenceParams collects the knobs a fixture varies to build evidence.
type svidEvidenceParams struct {
	env          aarp.Envelope // the (signed) receipt envelope the binding ties to
	leafDER      []byte
	signer       crypto.Signer // key that produces the binding signature
	alg          string        // declared binding alg
	spiffeID     string        // claimed spiffe_id (== leaf SAN unless substituting)
	evidenceType string        // "x509" unless testing JWT-as-verified
	issuedAt     string
	nonce        string
	seed         string
}

func (g *aarpGen) buildEvidence(p svidEvidenceParams) aarp.SVIDEvidence {
	canonical := g.svidBindingCanonical(p.env, p.spiffeID, p.issuedAt, p.nonce)
	return aarp.SVIDEvidence{
		Type:       p.evidenceType,
		SPIFFEID:   p.spiffeID,
		LeafDERB64: b64std(p.leafDER),
		Nonce:      p.nonce,
		IssuedAt:   p.issuedAt,
		Binding: aarp.SVIDBinding{
			Alg:           p.alg,
			Context:       aarp.ContextSVIDBinding,
			PayloadSHA256: hexSHA256(canonical),
			SignatureB64:  g.signBinding(p.signer, p.alg, p.seed, canonical),
		},
	}
}

// nonceFor returns a deterministic >=128-bit base64url (no padding) nonce.
func nonceFor(seed string) string { return base64RawURL(detBytes("nonce/"+seed, 16)) }

// base64RawURL encodes bytes as base64url with no padding (the nonce wire form).
func base64RawURL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// hexSHA256 returns the lowercase-hex SHA-256 digest of b.
func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// flipB64Char flips one standard-base64 character of a bare signature so it stays
// well-formed base64 but no longer verifies.
func flipB64Char(b64 string) string {
	if len(b64) == 0 {
		return b64
	}
	out := []byte(b64)
	if out[0] == 'A' {
		out[0] = 'B'
	} else {
		out[0] = 'A'
	}
	return string(out)
}

// svidComparable mirrors the verifier --svid loader for generation: it returns
// the authoritative ComparableAppraisal bytes (with trailing newline) every
// verifier must match for an SVID fixture.
func (g *aarpGen) svidComparable(body []byte, sc *svidsidecar.Sidecar) []byte {
	return append(svidComparableBytes(g.t, body, sc, g.verifyOpts), '\n')
}

// svidComparableBytes appraises an SVID fixture (envelope + sidecar) with the Go
// reference AppraiseWithSVID and returns its ComparableAppraisal bytes (no
// trailing newline). It resolves the verifier-pinned options through the shared
// svidsidecar package — the same path the CLI --svid loader takes — so the Go
// arm exercises exactly the wire form the four-language gate feeds the verifiers.
// Shared by the generator and the Go-arm conformance test.
func svidComparableBytes(tb testing.TB, body []byte, sc *svidsidecar.Sidecar, opts aarp.VerifyOptions) []byte {
	tb.Helper()
	env, err := aarp.Unmarshal(body)
	if err != nil {
		tb.Fatalf("svid fixture failed to unmarshal: %v", err)
	}
	svidOpts, err := sc.Options()
	if err != nil {
		tb.Fatalf("svid fixture verify block: %v", err)
	}
	ev := sc.Evidence
	ap, err := aarp.AppraiseWithSVID(env, &ev, opts, svidOpts)
	if err != nil {
		tb.Fatalf("svid fixture failed to appraise: %v", err)
	}
	c, err := aarp.ComparableAppraisal(ap)
	if err != nil {
		tb.Fatalf("comparable appraisal: %v", err)
	}
	return c
}
