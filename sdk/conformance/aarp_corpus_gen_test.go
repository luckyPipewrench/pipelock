// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/aarp"
	"github.com/luckyPipewrench/pipelock/internal/svidsidecar"
)

// updateAARP regenerates the AARP corpus when passed.
// Run: go test ./sdk/conformance/ -run TestGenerateAARPCorpus -update-aarp.
var updateAARP = flag.Bool("update-aarp", false, "regenerate the AARP hostile corpus")

// The AARP corpus is the language-neutral hostile-fixtures directory consumed by
// all four reference verifiers (Go, TypeScript, Rust, Python). Each fixture is a
// JSON envelope (single) or JSONL stream (chain) paired with:
//
//   - <name>.expect.json   human-readable metadata + the cross-language verdict
//     ("appraise" or "fatal") and attack_class.
//   - <name>.appraisal.json  for "appraise" fixtures only: the exact
//     ComparableAppraisal bytes every verifier MUST emit.
//
// The generator is the source of truth: for every "appraise" fixture it runs the
// Go reference aarp.Verify and writes its ComparableAppraisal, so a port that
// diverges by even one byte fails the gate. "fatal" fixtures carry no appraisal;
// the cross-language signal is that every verifier rejects (non-zero exit).
const (
	aarpCorpusDir   = "testdata/aarp-corpus"
	aarpTrustFile   = "trust.json"
	aarpKeysFile    = "test-keys.json"
	verdictAppraise = "appraise"
	verdictFatal    = "fatal"

	catGolden    = "golden"
	catMalicious = "malicious"
	catEdge      = "edge"
	catChain     = "chain"
	catSVID      = "svid"
)

// Deterministic test-key seed phrases. Obviously test keys; never production.
const (
	seedSigner   = "pipelock-aarp-corpus-signer-key-v1"
	seedIssuer   = "pipelock-aarp-corpus-issuer-key-v1"
	seedOther    = "pipelock-aarp-corpus-untrusted-key-v1"
	seedReceipt  = "pipelock-aarp-corpus-receipt-signer-v1"
	keyIDSigner  = "k-signer"
	keyIDIssuer  = "k-issuer"
	keyIDOther   = "k-other"
	keyIDPQ      = "k-pq"
	mediatorID   = "mediator.example"
	issuerStream = "issuer.example"
	roleMediator = "mediator"
	roleCountsig = "countersig"
	roleIssuer   = "issuer"
)

// Fixed RFC3339Nano timestamps so the corpus is byte-deterministic.
const (
	tsIssued = "2026-04-15T12:00:00.000000000Z"
)

// keyFromSeed derives a deterministic Ed25519 keypair from a seed phrase.
func keyFromSeed(phrase string) (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := sha256.Sum256([]byte(phrase))
	priv := ed25519.NewKeyFromSeed(seed[:])
	return priv.Public().(ed25519.PublicKey), priv
}

// fixedDigest returns a deterministic 64-hex digest derived from a label, so the
// corpus carries stable, distinct subject digests without real receipts.
func fixedDigest(label string) string {
	sum := sha256.Sum256([]byte("aarp-corpus-digest/" + label))
	return hex.EncodeToString(sum[:])
}

// aarpFixture is one generated corpus entry.
type aarpFixture struct {
	name        string
	category    string
	attackClass string
	description string
	verdict     string // verdictAppraise or verdictFatal
	isChain     bool
	body        []byte // the fixture bytes (.aarp.json or .aarp.jsonl)
	// svid, when non-nil, is the SVID attestation sidecar written as
	// <name>.svid.json and fed to the verifier via --svid. SVID fixtures are
	// always verdictAppraise: an SVID attack is never envelope-fatal, it merely
	// withholds the workload-identity claims (no inflation).
	svid *svidsidecar.Sidecar
}

// TestGenerateAARPCorpus writes the full hostile corpus when run with
// -update-aarp. Normal runs skip it.
func TestGenerateAARPCorpus(t *testing.T) {
	if !*updateAARP {
		t.Skip("pass -update-aarp to regenerate the AARP corpus")
	}

	signerPub, signerPriv := keyFromSeed(seedSigner)
	issuerPub, issuerPriv := keyFromSeed(seedIssuer)
	otherPub, otherPriv := keyFromSeed(seedOther)
	receiptPub, _ := keyFromSeed(seedReceipt)

	g := &aarpGen{
		t:          t,
		signerPub:  signerPub,
		signerPriv: signerPriv,
		issuerPub:  issuerPub,
		issuerPriv: issuerPriv,
		otherPub:   otherPub,
		otherPriv:  otherPriv,
		receiptKey: hex.EncodeToString(receiptPub),
		verifyOpts: corpusVerifyOptions(signerPub, issuerPub),
	}

	if err := os.MkdirAll(aarpCorpusDir, 0o750); err != nil {
		t.Fatalf("mkdir corpus: %v", err)
	}

	g.writeTrustAndKeys()

	fixtures := g.allFixtures()
	for _, f := range fixtures {
		g.writeFixture(f)
	}
	t.Logf("regenerated %d AARP fixtures in %s", len(fixtures), aarpCorpusDir)
}

// corpusVerifyOptions is the pinned trust the corpus is generated and verified
// against. k-signer is pinned to the mediator identity with the mediator role;
// k-issuer is a trusted key with NO trust entry (verifies signatures but cannot
// confirm mediator_key_pinned). k-other is intentionally absent (untrusted).
func corpusVerifyOptions(signerPub, issuerPub ed25519.PublicKey) aarp.VerifyOptions {
	return aarp.VerifyOptions{
		TrustedKeys: map[string]ed25519.PublicKey{
			keyIDSigner: signerPub,
			keyIDIssuer: issuerPub,
		},
		Trust: map[string]aarp.TrustEntry{
			keyIDSigner: {MediatorID: mediatorID, Role: roleMediator},
		},
	}
}

type aarpGen struct {
	t          *testing.T
	signerPub  ed25519.PublicKey
	signerPriv ed25519.PrivateKey
	issuerPub  ed25519.PublicKey
	issuerPriv ed25519.PrivateKey
	otherPub   ed25519.PublicKey
	otherPriv  ed25519.PrivateKey
	receiptKey string
	verifyOpts aarp.VerifyOptions
}

// writeTrustAndKeys writes the pinned trust file (consumed by every verifier)
// and the test-key material (so any verifier can reproduce the keys).
func (g *aarpGen) writeTrustAndKeys() {
	trust := map[string]any{
		"trusted_keys": map[string]string{
			keyIDSigner: hex.EncodeToString(g.signerPub),
			keyIDIssuer: hex.EncodeToString(g.issuerPub),
		},
		"trust_entries": map[string]any{
			keyIDSigner: map[string]string{
				"mediator_id": mediatorID,
				"role":        roleMediator,
			},
		},
	}
	g.writeJSON(aarpTrustFile, trust)

	keys := map[string]any{
		"note": "TEST KEYS ONLY. Derived from sha256(seed_phrase). Never use for production signing.",
		"keys": map[string]any{
			keyIDSigner: keyMaterial(seedSigner, g.signerPub),
			keyIDIssuer: keyMaterial(seedIssuer, g.issuerPub),
			keyIDOther:  keyMaterial(seedOther, g.otherPub),
		},
		"receipt_signer_key_hex": g.receiptKey,
	}
	g.writeJSON(aarpKeysFile, keys)
}

func keyMaterial(seed string, pub ed25519.PublicKey) map[string]string {
	s := sha256.Sum256([]byte(seed))
	return map[string]string{
		"seed_phrase":    seed,
		"seed_hex":       hex.EncodeToString(s[:]),
		"public_key_hex": hex.EncodeToString(pub),
		"alg":            "ed25519",
	}
}

// ---- envelope builders ----

// baseSubject returns the shared subject. label distinguishes digests so
// replay/substitution fixtures bind to a different subject than their stolen
// signature was made for.
func (g *aarpGen) baseSubject(label string) aarp.Subject {
	return aarp.Subject{
		ActionRecordSHA256:    fixedDigest("action/" + label),
		ReceiptEnvelopeSHA256: fixedDigest("envelope/" + label),
		ReceiptSignerKey:      g.receiptKey,
		ReceiptType:           aarp.ReceiptTypeActionV1,
	}
}

// baseAssertion returns the shared assertion claiming mediated + complete-mediation.
func baseAssertion(claimed ...string) aarp.Assertion {
	if len(claimed) == 0 {
		claimed = []string{"mediated", "complete-mediation"}
	}
	return aarp.Assertion{
		Claimed:           claimed,
		MediatorID:        mediatorID,
		CompleteMediation: false,
		IssuedAt:          tsIssued,
	}
}

// signEd signs an envelope with the given key/role under a key id.
func (g *aarpGen) signEd(e aarp.Envelope, keyID, role string, priv ed25519.PrivateKey) aarp.Envelope {
	signer, err := aarp.NewEd25519Signer(keyID, role, priv)
	if err != nil {
		g.t.Fatalf("new signer %s: %v", keyID, err)
	}
	signed, err := aarp.Sign(e, signer)
	if err != nil {
		g.t.Fatalf("sign %s: %v", keyID, err)
	}
	return signed
}

func (g *aarpGen) marshal(e aarp.Envelope) []byte {
	b, err := aarp.Marshal(e)
	if err != nil {
		g.t.Fatalf("marshal envelope: %v", err)
	}
	return b
}

// pqSignature returns a typed-but-unverifiable ML-DSA-65 parallel signature. The
// wire bytes are a deterministic non-empty placeholder; the verifier reports it
// "unimplemented" regardless (the PQ slot has no verifier), so the bytes never
// matter — they only prove a PQ slot does not break a parallel Ed25519 verify.
func pqSignature() aarp.Signature {
	placeholder := base64.StdEncoding.EncodeToString([]byte("ml-dsa-65-placeholder-signature"))
	return aarp.Signature{
		Protected: aarp.ProtectedHeader{
			Profile:    aarp.Profile,
			Canon:      aarp.CanonID,
			Alg:        string(aarp.AlgMLDSA65),
			KeyType:    "ml-dsa",
			KeyID:      keyIDPQ,
			SignerRole: roleCountsig,
		},
		Sig: "ml-dsa-65:" + placeholder,
	}
}

// unknownSuiteSignature returns a parallel signature under an unrecognized
// algorithm. validateStructure does not reject it (alg recognition is a
// per-signature outcome); appraiseSignature reports unknown_suite with no
// fallback verification.
func unknownSuiteSignature() aarp.Signature {
	return aarp.Signature{
		Protected: aarp.ProtectedHeader{
			Profile:    aarp.Profile,
			Canon:      aarp.CanonID,
			Alg:        "rsa-2048",
			KeyType:    "rsa",
			KeyID:      "k-rsa",
			SignerRole: roleCountsig,
		},
		Sig: "rsa-2048:" + base64.StdEncoding.EncodeToString([]byte("not-a-real-signature")),
	}
}

// ---- the fixture set ----

func (g *aarpGen) allFixtures() []aarpFixture {
	var out []aarpFixture
	out = append(out, g.goldenFixtures()...)
	out = append(out, g.maliciousFixtures()...)
	out = append(out, g.parserFixtures()...)
	out = append(out, g.chainFixtures()...)
	out = append(out, g.svidFixtures()...)
	return out
}

func (g *aarpGen) goldenFixtures() []aarpFixture {
	var out []aarpFixture

	// g01: single Ed25519 signature by the pinned mediator key.
	{
		e := aarp.Envelope{Subject: g.baseSubject("g01"), Assertion: baseAssertion("mediated")}
		e = g.signEd(e, keyIDSigner, roleMediator, g.signerPriv)
		out = append(out, aarpFixture{
			name: "g01-single-ed25519-mediated", category: catGolden, attackClass: "baseline",
			description: "single Ed25519 signature by the pinned mediator key; mediated is confirmed",
			verdict:     verdictAppraise, body: g.marshal(e),
		})
	}

	// g02: parallel Ed25519 + ML-DSA-65 (PQ unimplemented). The PQ slot must not
	// break the Ed25519 verify and must never count as verified.
	{
		e := aarp.Envelope{Subject: g.baseSubject("g02"), Assertion: baseAssertion("mediated")}
		e = g.signEd(e, keyIDSigner, roleMediator, g.signerPriv)
		e.Signatures = append(e.Signatures, pqSignature())
		out = append(out, aarpFixture{
			name: "g02-multisig-ed25519-pq", category: catGolden, attackClass: "baseline-multisig",
			description: "parallel Ed25519 + ML-DSA-65; PQ slot is unimplemented and does not mask or break the good signature",
			verdict:     verdictAppraise, body: g.marshal(e),
		})
	}

	// g03: chain-linked genesis envelope (single-envelope appraisal reports
	// chain_linked when the link is well-formed).
	{
		e := aarp.Envelope{
			Subject:   g.baseSubject("g03"),
			Assertion: baseAssertion("mediated"),
			Chain:     &aarp.ChainLink{IssuerID: issuerStream, Seq: "0", PriorHash: aarp.GenesisPriorHash},
		}
		e = g.signEd(e, keyIDSigner, roleMediator, g.signerPriv)
		out = append(out, aarpFixture{
			name: "g03-chain-genesis-linked", category: catGolden, attackClass: "baseline-chain",
			description: "genesis chain link is well-formed and signed; chain_linked is confirmed",
			verdict:     verdictAppraise, body: g.marshal(e),
		})
	}

	// g04: a verified signature whose key has no trust entry confirms the
	// signature but NOT mediator_key_pinned; mediated stays claimed-unverified.
	{
		e := aarp.Envelope{Subject: g.baseSubject("g04"), Assertion: baseAssertion("mediated")}
		e = g.signEd(e, keyIDIssuer, roleIssuer, g.issuerPriv)
		out = append(out, aarpFixture{
			name: "g04-signed-but-unpinned", category: catGolden, attackClass: "no-inflation",
			description: "trusted key with no mediator trust entry: signature verifies, mediated is NOT pinned",
			verdict:     verdictAppraise, body: g.marshal(e),
		})
	}

	// g05: mixed unknown-suite + valid Ed25519. The unknown signature is reported
	// and the good one still verifies — parallel independence, no masking.
	{
		e := aarp.Envelope{Subject: g.baseSubject("g05"), Assertion: baseAssertion("mediated")}
		e = g.signEd(e, keyIDSigner, roleMediator, g.signerPriv)
		e.Signatures = append(e.Signatures, unknownSuiteSignature())
		out = append(out, aarpFixture{
			name: "g05-unknown-suite-plus-valid", category: catGolden, attackClass: "no-masking",
			description: "an unknown-suite parallel signature does not mask or poison the valid Ed25519 signature",
			verdict:     verdictAppraise, body: g.marshal(e),
		})
	}

	// g06: no claims at all — a signed assertion that claims nothing still
	// reports assertion_signature_valid and an empty claimed_unverified.
	{
		e := aarp.Envelope{Subject: g.baseSubject("g06"), Assertion: baseAssertion("noclaims")}
		e.Assertion.Claimed = []string{}
		e = g.signEd(e, keyIDSigner, roleMediator, g.signerPriv)
		out = append(out, aarpFixture{
			name: "g06-signed-no-claims", category: catGolden, attackClass: "baseline",
			description: "a signed assertion with no producer claims verifies the signature and asserts nothing else",
			verdict:     verdictAppraise, body: g.marshal(e),
		})
	}

	// g07: NFC parity. mediator_id carries a non-ASCII character in NFD form
	// (lowercase e + U+0301 combining acute). The signature was made over the
	// JCS-canonical (NFC-normalized) payload, so a verifier that does NOT
	// NFC-normalize before hashing recomputes a different digest, the signature
	// fails, and assertion_signed flips to false — a cross-language differential
	// the gate catches. Signed by k-issuer (no trust entry), so mediated stays
	// claimed-unverified, isolating the NFC effect from the pinning logic.
	{
		nfdMediator := "me\u0301diator.example" // NFD: e + U+0301; NFC folds to precomposed e-acute
		e := aarp.Envelope{
			Subject:   g.baseSubject("g07"),
			Assertion: aarp.Assertion{Claimed: []string{"mediated"}, MediatorID: nfdMediator, IssuedAt: tsIssued},
		}
		e = g.signEd(e, keyIDIssuer, roleIssuer, g.issuerPriv)
		out = append(out, aarpFixture{
			name: "g07-nfc-mediator-id", category: catGolden, attackClass: "canonicalization-nfc",
			description: "a non-ASCII NFD mediator_id verifies only if the verifier NFC-normalizes before hashing",
			verdict:     verdictAppraise, body: g.marshal(e),
		})
	}

	// g08: astral (supplementary-plane) code point in a signed field. mediator_id
	// carries U+1F600, which UTF-16 represents as a surrogate PAIR. A verifier
	// that canonicalizes by walking UTF-16 code units and replacing every
	// surrogate (instead of only UNPAIRED ones) would mangle the astral char to
	// two U+FFFD, compute a different payload digest, and fail the signature while
	// the others verify -- a cross-language differential. Signed by k-issuer (no
	// trust entry), so the astral effect is isolated to assertion_signature_valid.
	{
		astralMediator := "\U0001F600mediator.example"
		e := aarp.Envelope{
			Subject:   g.baseSubject("g08"),
			Assertion: aarp.Assertion{Claimed: []string{"mediated"}, MediatorID: astralMediator, IssuedAt: tsIssued},
		}
		e = g.signEd(e, keyIDIssuer, roleIssuer, g.issuerPriv)
		out = append(out, aarpFixture{
			name: "g08-astral-mediator-id", category: catGolden, attackClass: "canonicalization-astral",
			description: "an astral (supplementary-plane) code point in a signed field must be preserved, not mangled to U+FFFD",
			verdict:     verdictAppraise, body: g.marshal(e),
		})
	}

	return out
}

func (g *aarpGen) maliciousFixtures() []aarpFixture {
	var out []aarpFixture

	// m01: forged signature (one wire byte flipped). The signature fails; no
	// claim inflates; the envelope is still appraisable (per-signature failure).
	{
		e := aarp.Envelope{Subject: g.baseSubject("m01"), Assertion: baseAssertion("mediated")}
		e = g.signEd(e, keyIDSigner, roleMediator, g.signerPriv)
		e.Signatures[0].Sig = flipSigByte(e.Signatures[0].Sig)
		out = append(out, aarpFixture{
			name: "m01-forged-signature", category: catMalicious, attackClass: "forged",
			description: "a tampered signature does not verify; assertion_signed is false and no claim inflates",
			verdict:     verdictAppraise, body: g.marshal(e),
		})
	}

	// m02: replayed signature — a valid signature lifted from a different subject
	// is attached to this envelope. It does not verify over this payload digest.
	{
		victim := aarp.Envelope{Subject: g.baseSubject("m02-victim"), Assertion: baseAssertion("mediated")}
		victim = g.signEd(victim, keyIDSigner, roleMediator, g.signerPriv)
		target := aarp.Envelope{Subject: g.baseSubject("m02-target"), Assertion: baseAssertion("mediated")}
		target.Profile = aarp.Profile
		target.Signatures = victim.Signatures // stolen signature
		out = append(out, aarpFixture{
			name: "m02-replayed-signature", category: catMalicious, attackClass: "replayed",
			description: "a valid signature lifted from another envelope does not verify over this payload digest",
			verdict:     verdictAppraise, body: g.marshal(target),
		})
	}

	// m03: PQ-only downgrade. A recognized-but-unimplemented suite never verifies;
	// assertion_signed is false and every claim is unverified.
	{
		e := aarp.Envelope{Subject: g.baseSubject("m03"), Assertion: baseAssertion("mediated")}
		e.Profile = aarp.Profile
		e.Signatures = []aarp.Signature{pqSignature()}
		out = append(out, aarpFixture{
			name: "m03-downgrade-pq-only", category: catMalicious, attackClass: "downgraded",
			description: "a PQ-only envelope cannot verify: the PQ slot is unimplemented and there is no fallback",
			verdict:     verdictAppraise, body: g.marshal(e),
		})
	}

	// m04: unknown-suite-only. Unrecognized algorithm, no fallback verification.
	{
		e := aarp.Envelope{Subject: g.baseSubject("m04"), Assertion: baseAssertion("mediated")}
		e.Profile = aarp.Profile
		e.Signatures = []aarp.Signature{unknownSuiteSignature()}
		out = append(out, aarpFixture{
			name: "m04-unknown-suite-only", category: catMalicious, attackClass: "downgraded",
			description: "an unrecognized signature algorithm never verifies and never falls back to a known suite",
			verdict:     verdictAppraise, body: g.marshal(e),
		})
	}

	// m05: untrusted-but-valid signature. The math is valid but the key id is not
	// in the trusted set; it is reported unknown_key and never counts.
	{
		e := aarp.Envelope{Subject: g.baseSubject("m05"), Assertion: baseAssertion("mediated")}
		e = g.signEd(e, keyIDOther, roleMediator, g.otherPriv)
		out = append(out, aarpFixture{
			name: "m05-untrusted-key", category: catMalicious, attackClass: "forged",
			description: "a cryptographically valid signature under an untrusted key is unknown_key, never verified",
			verdict:     verdictAppraise, body: g.marshal(e),
		})
	}

	// m06: role escalation. A key pinned to the mediator role signs under the
	// countersig role; mediator_key_pinned must stay false (role mismatch).
	{
		e := aarp.Envelope{Subject: g.baseSubject("m06"), Assertion: baseAssertion("mediated")}
		e = g.signEd(e, keyIDSigner, roleCountsig, g.signerPriv)
		out = append(out, aarpFixture{
			name: "m06-role-escalation", category: catMalicious, attackClass: "downgraded",
			description: "a key scoped to the mediator role signing as countersig cannot satisfy a mediated claim",
			verdict:     verdictAppraise, body: g.marshal(e),
		})
	}

	// m07: post-sign claim addition. A claim is appended after signing; the
	// payload digest changes and the signature fails.
	{
		signed := aarp.Envelope{Subject: g.baseSubject("m07"), Assertion: baseAssertion("mediated")}
		signed = g.signEd(signed, keyIDSigner, roleMediator, g.signerPriv)
		tampered := signed
		tampered.Assertion.Claimed = []string{"mediated", "transparency_inclusion"}
		out = append(out, aarpFixture{
			name: "m07-post-sign-claim-add", category: catMalicious, attackClass: "forged",
			description: "appending a claim after signing changes the payload digest; the signature no longer verifies",
			verdict:     verdictAppraise, body: g.marshal(tampered),
		})
	}

	// m08: mediator-id swap after signing. The signed payload bound the original
	// mediator id; swapping it breaks the digest and the signature.
	{
		signed := aarp.Envelope{Subject: g.baseSubject("m08"), Assertion: baseAssertion("mediated")}
		signed = g.signEd(signed, keyIDSigner, roleMediator, g.signerPriv)
		tampered := signed
		tampered.Assertion.MediatorID = "evil.example"
		out = append(out, aarpFixture{
			name: "m08-mediator-id-swap", category: catMalicious, attackClass: "forged",
			description: "swapping mediator_id after signing breaks the payload digest and the signature",
			verdict:     verdictAppraise, body: g.marshal(tampered),
		})
	}

	// m09: profile mismatch — envelope-fatal (the verifier cannot interpret it).
	{
		signed := aarp.Envelope{Subject: g.baseSubject("m09"), Assertion: baseAssertion("mediated")}
		signed = g.signEd(signed, keyIDSigner, roleMediator, g.signerPriv)
		signed.Profile = "aarp/v9.9"
		out = append(out, aarpFixture{
			name: "m09-profile-mismatch", category: catMalicious, attackClass: "profile-mismatch",
			description: "an envelope profile the verifier does not implement is fatal: it is never appraised",
			verdict:     verdictFatal, body: g.marshal(signed),
		})
	}

	// m10: signature names a different canonicalization. This is a PER-SIGNATURE
	// failure (unknown_suite), not envelope-fatal: a bad suite on one parallel
	// signature must not reject an envelope that could also carry a good one. The
	// signature never verifies (no fallback), so assertion_signed stays false.
	{
		signed := aarp.Envelope{Subject: g.baseSubject("m10"), Assertion: baseAssertion("mediated")}
		signed = g.signEd(signed, keyIDSigner, roleMediator, g.signerPriv)
		signed.Signatures[0].Protected.Canon = "jcs-but-different"
		out = append(out, aarpFixture{
			name: "m10-canon-mismatch", category: catMalicious, attackClass: "canon-mismatch",
			description: "a signature naming a different canonicalization is reported unknown_suite per signature and never verifies",
			verdict:     verdictAppraise, body: g.marshal(signed),
		})
	}

	// m11: unknown ENVELOPE-level critical extension — envelope-fatal. The crit
	// ext is added after signing (a signer refuses to sign an unprocessable
	// critical extension); the envelope is fatal before any signature check.
	{
		signed := aarp.Envelope{Subject: g.baseSubject("m11"), Assertion: baseAssertion("mediated")}
		signed = g.signEd(signed, keyIDSigner, roleMediator, g.signerPriv)
		signed.CritExt = []string{"x-unknown-critical"}
		out = append(out, aarpFixture{
			name: "m11-unknown-critical-extension", category: catMalicious, attackClass: "unknown-critical-extension",
			description: "an unknown envelope-level critical extension is fatal: a flagged-critical name the verifier cannot process",
			verdict:     verdictFatal, body: g.marshal(signed),
		})
	}

	// m12: unknown SIGNATURE-level critical extension. Like an unknown suite, this
	// is a PER-SIGNATURE failure (unknown_suite): the signature cannot be
	// processed and never verifies, but it does not reject the whole envelope.
	// (An ENVELOPE-level unknown critical extension, m11, IS still fatal.)
	{
		signed := aarp.Envelope{Subject: g.baseSubject("m12"), Assertion: baseAssertion("mediated")}
		signed = g.signEd(signed, keyIDSigner, roleMediator, g.signerPriv)
		signed.Signatures[0].Protected.Crit = []string{"x-unknown-critical"}
		out = append(out, aarpFixture{
			name: "m12-sig-unknown-critical-extension", category: catMalicious, attackClass: "unknown-critical-extension",
			description: "an unknown per-signature critical extension is reported unknown_suite per signature, not envelope-fatal",
			verdict:     verdictAppraise, body: g.marshal(signed),
		})
	}

	// m13: empty signature set — envelope-fatal (schema).
	{
		e := aarp.Envelope{Subject: g.baseSubject("m13"), Assertion: baseAssertion("mediated")}
		e.Profile = aarp.Profile
		e.Signatures = []aarp.Signature{}
		out = append(out, aarpFixture{
			name: "m13-empty-signatures", category: catMalicious, attackClass: "schema",
			description: "an envelope with no signatures is fatal: there is nothing to appraise",
			verdict:     verdictFatal, body: g.marshal(e),
		})
	}

	return out
}

func (g *aarpGen) parserFixtures() []aarpFixture {
	var out []aarpFixture

	// validSigned builds a signed, valid envelope to tamper at the byte level.
	validSigned := func(label string) []byte {
		e := aarp.Envelope{Subject: g.baseSubject(label), Assertion: baseAssertion("mediated")}
		e = g.signEd(e, keyIDSigner, roleMediator, g.signerPriv)
		return g.marshal(e)
	}

	// p01: raw JSON number outside the I-JSON safe-integer range, smuggled in a
	// non-critical ext field. EnforceSafeNumbers rejects it before appraisal.
	out = append(out, aarpFixture{
		name: "p01-unsafe-integer", category: catEdge, attackClass: "number-safety",
		description: "a raw JSON integer above 2^53-1 is fatal: it would round to a float in some language parsers",
		verdict:     verdictFatal, body: injectExtRaw(validSigned("p01"), `9007199254740993`),
	})

	// p02: float literal.
	out = append(out, aarpFixture{
		name: "p02-float", category: catEdge, attackClass: "number-safety",
		description: "a raw JSON float is fatal: identity/amount fields must be typed strings",
		verdict:     verdictFatal, body: injectExtRaw(validSigned("p02"), `1.5`),
	})

	// p03: exponent form.
	out = append(out, aarpFixture{
		name: "p03-exponent", category: catEdge, attackClass: "number-safety",
		description: "a raw JSON number in exponent form is fatal: its value-vs-text relationship diverges across parsers",
		verdict:     verdictFatal, body: injectExtRaw(validSigned("p03"), `1e3`),
	})

	// p04: negative zero.
	out = append(out, aarpFixture{
		name: "p04-negative-zero", category: catEdge, attackClass: "number-safety",
		description: "raw negative zero is fatal: it is a distinct text with an ambiguous canonical form",
		verdict:     verdictFatal, body: injectExtRaw(validSigned("p04"), `-0`),
	})

	// p05: duplicate key at the top level (parser-differential smuggling guard).
	out = append(out, aarpFixture{
		name: "p05-duplicate-key", category: catEdge, attackClass: "parser-differential",
		description: "a duplicate object key is fatal: last-wins parser differentials are a smuggling vector",
		verdict:     verdictFatal, body: duplicateProfileKey(validSigned("p05")),
	})

	// p06: trailing tokens after the JSON value.
	out = append(out, aarpFixture{
		name: "p06-trailing-tokens", category: catEdge, attackClass: "parser-differential",
		description: "non-whitespace tokens after the envelope are fatal: trailing data is an injection vector",
		verdict:     verdictFatal, body: append(validSigned("p06"), []byte(" {\"trailing\":true}")...),
	})

	// p07: unknown field in an AARP-controlled object (assertion).
	out = append(out, aarpFixture{
		name: "p07-unknown-field", category: catEdge, attackClass: "schema",
		description: "an unknown field in an AARP object is fatal: a producer cannot smuggle unsigned content past appraisal",
		verdict:     verdictFatal, body: injectAssertionField(validSigned("p07"), `"smuggled":"x"`),
	})

	// p08: bad digest grammar (uppercase hex in a typed-string field).
	out = append(out, aarpFixture{
		name: "p08-bad-digest-grammar", category: catEdge, attackClass: "grammar",
		description: "an uppercase-hex digest is fatal: typed-string identity fields have a strict lowercase-hex grammar",
		verdict:     verdictFatal, body: uppercaseFirstDigest(validSigned("p08")),
	})

	// p09: malformed issued_at timestamp. Set after signing (a signer would not
	// emit a malformed time); fatal at validation before any signature check.
	// Forces every verifier to enforce the RFC3339Nano typed-time grammar
	// identically rather than accept arbitrary strings.
	{
		signed := aarp.Envelope{Subject: g.baseSubject("p09"), Assertion: baseAssertion("mediated")}
		signed = g.signEd(signed, keyIDSigner, roleMediator, g.signerPriv)
		signed.Assertion.IssuedAt = "not-a-timestamp"
		out = append(out, aarpFixture{
			name: "p09-bad-timestamp", category: catEdge, attackClass: "grammar",
			description: "a malformed issued_at is fatal: typed-time fields require an RFC3339Nano grammar",
			verdict:     verdictFatal, body: g.marshal(signed),
		})
	}

	// p10: unpaired JSON surrogate escape. Go's encoding/json accepts this and
	// decodes it as U+FFFD, so every port must do the same rather than treating
	// it as fatal. The post-sign mediator_id edit breaks the signature, so the
	// fixture remains appraisable but unverified.
	out = append(out, aarpFixture{
		name: "p10-unpaired-surrogate", category: catEdge, attackClass: "parser-differential",
		description: "an unpaired JSON surrogate escape decodes to U+FFFD like Go encoding/json; it is appraised, not fatal",
		verdict:     verdictAppraise, body: replaceMediatorIDRaw(validSigned("p10"), `\ud800.example`),
	})

	return out
}

func (g *aarpGen) chainFixtures() []aarpFixture {
	// Compute prior hashes from each envelope's payload digest, so the valid
	// stream is genuinely linked.
	digestOf := func(e aarp.Envelope) string {
		d, err := e.PayloadDigest()
		if err != nil {
			g.t.Fatalf("payload digest: %v", err)
		}
		return d
	}

	var out []aarpFixture

	// c01: valid 3-link stream.
	{
		labels := []string{"c01-0", "c01-1", "c01-2"}
		e0 := g.signEd(aarp.Envelope{
			Subject: g.baseSubject(labels[0]), Assertion: baseAssertion("mediated"),
			Chain: &aarp.ChainLink{IssuerID: issuerStream, Seq: "0", PriorHash: aarp.GenesisPriorHash},
		}, keyIDSigner, roleMediator, g.signerPriv)
		e1 := g.signEd(aarp.Envelope{
			Subject: g.baseSubject(labels[1]), Assertion: baseAssertion("mediated"),
			Chain: &aarp.ChainLink{IssuerID: issuerStream, Seq: "1", PriorHash: digestOf(e0)},
		}, keyIDSigner, roleMediator, g.signerPriv)
		e2 := g.signEd(aarp.Envelope{
			Subject: g.baseSubject(labels[2]), Assertion: baseAssertion("mediated"),
			Chain: &aarp.ChainLink{IssuerID: issuerStream, Seq: "2", PriorHash: digestOf(e1)},
		}, keyIDSigner, roleMediator, g.signerPriv)
		out = append(out, aarpFixture{
			name: "c01-valid-stream", category: catChain, attackClass: "baseline-chain", isChain: true,
			description: "a contiguous, hash-linked, single-issuer stream verifies",
			verdict:     verdictAppraise, body: jsonl(g, e0, e1, e2),
		})

		// c02: reorder (swap envelopes 1 and 2) — prior_hash mismatch.
		out = append(out, aarpFixture{
			name: "c02-reordered-stream", category: catChain, attackClass: "reorder", isChain: true,
			description: "reordering two envelopes breaks the prior_hash linkage",
			verdict:     verdictFatal, body: jsonl(g, e0, e2, e1),
		})

		// c04: backdating — a fourth link claims an earlier seq.
		e3back := g.signEd(aarp.Envelope{
			Subject: g.baseSubject("c04-3"), Assertion: baseAssertion("mediated"),
			Chain: &aarp.ChainLink{IssuerID: issuerStream, Seq: "1", PriorHash: digestOf(e2)},
		}, keyIDSigner, roleMediator, g.signerPriv)
		out = append(out, aarpFixture{
			name: "c04-backdated-stream", category: catChain, attackClass: "backdate", isChain: true,
			description: "a non-incrementing sequence number signals backdating within the stream",
			verdict:     verdictFatal, body: jsonl(g, e0, e1, e2, e3back),
		})
	}

	// c03: mixed issuer — second envelope from a different issuer stream.
	{
		e0 := g.signEd(aarp.Envelope{
			Subject: g.baseSubject("c03-0"), Assertion: baseAssertion("mediated"),
			Chain: &aarp.ChainLink{IssuerID: issuerStream, Seq: "0", PriorHash: aarp.GenesisPriorHash},
		}, keyIDSigner, roleMediator, g.signerPriv)
		e1 := g.signEd(aarp.Envelope{
			Subject: g.baseSubject("c03-1"), Assertion: baseAssertion("mediated"),
			Chain: &aarp.ChainLink{IssuerID: "other-issuer.example", Seq: "1", PriorHash: digestOf(e0)},
		}, keyIDSigner, roleMediator, g.signerPriv)
		out = append(out, aarpFixture{
			name: "c03-mixed-issuer-stream", category: catChain, attackClass: "insertion", isChain: true,
			description: "a stream that mixes two issuers is broken: a verified stream is single-issuer",
			verdict:     verdictFatal, body: jsonl(g, e0, e1),
		})
	}

	return out
}

// jsonl renders envelopes as one compact JSON object per line.
func jsonl(g *aarpGen, envs ...aarp.Envelope) []byte {
	var buf strings.Builder
	for _, e := range envs {
		buf.Write(g.marshal(e))
		buf.WriteByte('\n')
	}
	return []byte(buf.String())
}

// ---- byte-level tampering helpers ----

// ensureTrailingNewline returns body with exactly one trailing newline.
func ensureTrailingNewline(body []byte) []byte {
	trimmed := bytes.TrimRight(body, "\n")
	return append(trimmed, '\n')
}

// flipSigByte flips one base64 character of an "<alg>:<base64>" signature so it
// stays well-formed base64 but no longer verifies.
func flipSigByte(wire string) string {
	idx := strings.IndexByte(wire, ':')
	if idx < 0 || idx+1 >= len(wire) {
		return wire
	}
	b := []byte(wire)
	c := b[idx+1]
	if c == 'A' {
		b[idx+1] = 'B'
	} else {
		b[idx+1] = 'A'
	}
	return string(b)
}

// injectExtRaw inserts an "ext":{"x":<raw>} member into a valid envelope JSON so
// EnforceSafeNumbers sees the raw number. raw is spliced verbatim (no quoting).
func injectExtRaw(body []byte, raw string) []byte {
	return spliceMember(body, `"ext":{"x":`+raw+`}`)
}

// injectAssertionField inserts a raw member into the assertion object.
func injectAssertionField(body []byte, member string) []byte {
	s := string(body)
	marker := `"assertion":{`
	i := strings.Index(s, marker)
	if i < 0 {
		panic("assertion object not found")
	}
	at := i + len(marker)
	return []byte(s[:at] + member + "," + s[at:])
}

// duplicateProfileKey inserts a second top-level "profile" member.
func duplicateProfileKey(body []byte) []byte {
	return spliceMember(body, `"profile":"`+aarp.Profile+`"`)
}

// uppercaseFirstDigest uppercases the action_record_sha256 value so its
// lowercase-hex grammar fails.
func uppercaseFirstDigest(body []byte) []byte {
	s := string(body)
	marker := `"action_record_sha256":"`
	i := strings.Index(s, marker)
	if i < 0 {
		panic("action_record_sha256 not found")
	}
	start := i + len(marker)
	end := start + 64
	return []byte(s[:start] + strings.ToUpper(s[start:end]) + s[end:])
}

// replaceMediatorIDRaw replaces the first assertion mediator_id value with a
// raw JSON string body. replacement is spliced inside the quotes verbatim, so it
// can carry escape sequences such as \ud800.
func replaceMediatorIDRaw(body []byte, replacement string) []byte {
	s := string(body)
	marker := `"mediator_id":"`
	i := strings.Index(s, marker)
	if i < 0 {
		panic("mediator_id not found")
	}
	start := i + len(marker)
	endRel := strings.IndexByte(s[start:], '"')
	if endRel < 0 {
		panic("mediator_id closing quote not found")
	}
	end := start + endRel
	return []byte(s[:start] + replacement + s[end:])
}

// spliceMember inserts member right after the opening brace of the top-level
// object, producing JSON with the member first.
func spliceMember(body []byte, member string) []byte {
	s := strings.TrimSpace(string(body))
	if len(s) == 0 || s[0] != '{' {
		panic("envelope is not a JSON object")
	}
	return []byte("{" + member + "," + s[1:])
}

// ---- writers ----

func (g *aarpGen) writeFixture(f aarpFixture) {
	dir := filepath.Join(aarpCorpusDir, f.category)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		g.t.Fatalf("mkdir %s: %v", dir, err)
	}
	ext := ".aarp.json"
	if f.isChain {
		ext = ".aarp.jsonl"
	}
	// Write fixtures with a trailing newline, matching the existing conformance
	// generator convention and the repo's end-of-file-fixer. A trailing newline
	// is JSON trailing whitespace, which every verifier tolerates on the fixture
	// input (it never reaches the compared appraisal bytes).
	g.writeRaw(filepath.Join(dir, f.name+ext), ensureTrailingNewline(f.body))

	expect := map[string]any{
		"fixture_id":   f.name,
		"category":     f.category,
		"attack_class": f.attackClass,
		"input_format": map[bool]string{true: "chain", false: "envelope"}[f.isChain],
		"verdict":      f.verdict,
		"description":  f.description,
	}
	g.writeJSONAt(filepath.Join(dir, f.name+".expect.json"), expect)

	// SVID fixtures carry a sidecar (evidence + pinned bundle/action-time) read
	// by every verifier via --svid.
	if f.svid != nil {
		g.writeJSONAt(filepath.Join(dir, f.name+".svid.json"), f.svid)
	}

	// Appraise fixtures carry the authoritative comparable output.
	if f.verdict != verdictAppraise {
		return
	}
	switch {
	case f.svid != nil:
		g.writeRaw(filepath.Join(dir, f.name+".appraisal.json"), g.svidComparable(f.body, f.svid))
	case f.isChain:
		g.writeRaw(filepath.Join(dir, f.name+".appraisal.json"), g.chainComparable(f.body))
	default:
		g.writeRaw(filepath.Join(dir, f.name+".appraisal.json"), g.envelopeComparable(f.body))
	}
}

// envelopeComparable runs the Go reference verifier over a single-envelope
// fixture and returns its ComparableAppraisal bytes (the authoritative output).
func (g *aarpGen) envelopeComparable(body []byte) []byte {
	env, err := aarp.Unmarshal(body)
	if err != nil {
		g.t.Fatalf("appraise fixture failed to unmarshal: %v", err)
	}
	ap, err := aarp.Verify(env, g.verifyOpts)
	if err != nil {
		g.t.Fatalf("appraise fixture failed to verify: %v", err)
	}
	c, err := aarp.ComparableAppraisal(ap)
	if err != nil {
		g.t.Fatalf("comparable appraisal: %v", err)
	}
	return append(c, '\n')
}

// chainComparable runs VerifyChain over a chain fixture and returns the canonical
// chain comparable JSON.
func (g *aarpGen) chainComparable(body []byte) []byte {
	envs := g.parseChain(body)
	c, err := aarp.ComparableChain(envs)
	if err != nil {
		g.t.Fatalf("comparable chain: %v", err)
	}
	return append(c, '\n')
}

func (g *aarpGen) parseChain(body []byte) []aarp.Envelope {
	var envs []aarp.Envelope
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		e, err := aarp.Unmarshal([]byte(line))
		if err != nil {
			g.t.Fatalf("chain line unmarshal: %v", err)
		}
		envs = append(envs, e)
	}
	return envs
}

func (g *aarpGen) writeJSON(name string, v any) {
	g.writeJSONAt(filepath.Join(aarpCorpusDir, name), v)
}

func (g *aarpGen) writeJSONAt(path string, v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		g.t.Fatalf("marshal %s: %v", path, err)
	}
	g.writeRaw(path, append(data, '\n'))
}

func (g *aarpGen) writeRaw(path string, data []byte) {
	if err := os.WriteFile(path, data, 0o600); err != nil {
		g.t.Fatalf("write %s: %v", path, err)
	}
}
