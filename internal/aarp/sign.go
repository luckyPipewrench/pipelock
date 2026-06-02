// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package aarp

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
)

// Signer produces one parallel signature under a fixed protected suite. Each
// signer binds the same shared payload digest under its own suite, so adding a
// signer adds a parallel signature and never re-signs another signer's output.
type Signer interface {
	// Header returns the protected suite header this signer emits. It is covered
	// by the signature, so the verifier learns the exact suite from signed bytes.
	Header() ProtectedHeader
	// signInput signs the canonical signing-input bytes and returns the
	// "<alg>:<base64-std>" wire form.
	signInput(input []byte) (string, error)
}

// Ed25519Signer signs the assurance assertion with Ed25519 PureEdDSA, the
// default and only implemented suite.
type Ed25519Signer struct {
	keyID      string
	signerRole string
	priv       ed25519.PrivateKey
}

// NewEd25519Signer builds an Ed25519 signer for the given key id and signer
// role. The role must be in the known role vocabulary.
func NewEd25519Signer(keyID, signerRole string, priv ed25519.PrivateKey) (*Ed25519Signer, error) {
	if keyID == "" {
		return nil, fmt.Errorf("%w: empty key_id", ErrMalformedSuite)
	}
	if !knownSignerRoles[signerRole] {
		return nil, fmt.Errorf("%w: unknown signer_role %q", ErrMalformedSuite, signerRole)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: ed25519 private key size %d, want %d", ErrMalformedSuite, len(priv), ed25519.PrivateKeySize)
	}
	return &Ed25519Signer{keyID: keyID, signerRole: signerRole, priv: priv}, nil
}

// Header returns the protected suite for this Ed25519 signer.
func (s *Ed25519Signer) Header() ProtectedHeader {
	return ProtectedHeader{
		Profile:    Profile,
		Canon:      CanonID,
		Alg:        string(AlgEd25519),
		KeyType:    keyTypeForAlg[AlgEd25519],
		KeyID:      s.keyID,
		SignerRole: s.signerRole,
	}
}

func (s *Ed25519Signer) signInput(input []byte) (string, error) {
	sig := ed25519.Sign(s.priv, input)
	return string(AlgEd25519) + ":" + base64.StdEncoding.EncodeToString(sig), nil
}

// MLDSA65Signer is the typed-but-unimplemented post-quantum signer slot. Its
// header makes a PQ or hybrid envelope structurally first-class today; signing
// fails closed with ErrSuiteUnimplemented until FIPS 204 / ML-DSA errata settle.
type MLDSA65Signer struct {
	keyID      string
	signerRole string
}

// NewMLDSA65Signer builds the typed PQ signer slot. Calling Sign with it returns
// ErrSuiteUnimplemented; it exists so the multi-signature envelope shape is
// proven against a real second suite without shipping unsettled PQ crypto.
func NewMLDSA65Signer(keyID, signerRole string) (*MLDSA65Signer, error) {
	if keyID == "" {
		return nil, fmt.Errorf("%w: empty key_id", ErrMalformedSuite)
	}
	if !knownSignerRoles[signerRole] {
		return nil, fmt.Errorf("%w: unknown signer_role %q", ErrMalformedSuite, signerRole)
	}
	return &MLDSA65Signer{keyID: keyID, signerRole: signerRole}, nil
}

// Header returns the protected suite for the PQ slot.
func (s *MLDSA65Signer) Header() ProtectedHeader {
	return ProtectedHeader{
		Profile:    Profile,
		Canon:      CanonID,
		Alg:        string(AlgMLDSA65),
		KeyType:    keyTypeForAlg[AlgMLDSA65],
		KeyID:      s.keyID,
		SignerRole: s.signerRole,
	}
}

func (s *MLDSA65Signer) signInput([]byte) (string, error) {
	return "", fmt.Errorf("%w: alg %q", ErrSuiteUnimplemented, AlgMLDSA65)
}

// Sign populates an envelope's Signatures by signing the shared payload digest
// with each signer in parallel. The envelope's Profile/Subject/Assertion (and
// optional Chain) must already be set and valid; existing Signatures are
// replaced. At least one signer is required, and every signer's suite must be
// shape-valid and implemented.
// isNilSigner reports whether s is nil, including a typed-nil pointer wrapped in
// the Signer interface (a non-nil interface holding a nil *Ed25519Signer or
// *MLDSA65Signer). Calling a method on such a value would dereference nil.
func isNilSigner(s Signer) bool {
	switch v := s.(type) {
	case nil:
		return true
	case *Ed25519Signer:
		return v == nil
	case *MLDSA65Signer:
		return v == nil
	default:
		return false
	}
}

func Sign(e Envelope, signers ...Signer) (Envelope, error) {
	if len(signers) == 0 {
		return Envelope{}, fmt.Errorf("%w: at least one signer is required", ErrSchema)
	}
	if e.Profile == "" {
		e.Profile = Profile
	}
	if err := e.validatePayloadParts(); err != nil {
		return Envelope{}, err
	}
	digest, err := e.PayloadDigest()
	if err != nil {
		return Envelope{}, err
	}
	sigs := make([]Signature, 0, len(signers))
	seenKeyIDs := make(map[string]struct{}, len(signers))
	for i, signer := range signers {
		// Guard typed-nil and untyped-nil signers before any method call: a
		// nil *Ed25519Signer / *MLDSA65Signer would panic on Header().
		if isNilSigner(signer) {
			return Envelope{}, fmt.Errorf("%w: signer[%d] is nil", ErrSchema, i)
		}
		h := signer.Header()
		if err := h.validateSuiteShape(); err != nil {
			return Envelope{}, fmt.Errorf("signer[%d]: %w", i, err)
		}
		if err := h.checkImplemented(); err != nil {
			return Envelope{}, fmt.Errorf("signer[%d]: %w", i, err)
		}
		// Two signatures under the same key id would be redundant and ambiguous
		// for per-signature appraisal; require distinct key ids in one envelope.
		if _, dup := seenKeyIDs[h.KeyID]; dup {
			return Envelope{}, fmt.Errorf("%w: duplicate signer key_id %q", ErrSchema, h.KeyID)
		}
		seenKeyIDs[h.KeyID] = struct{}{}

		input, err := signingInput(digest, h)
		if err != nil {
			return Envelope{}, err
		}
		wire, err := signer.signInput(input)
		if err != nil {
			return Envelope{}, fmt.Errorf("signer[%d]: %w", i, err)
		}
		sigs = append(sigs, Signature{Protected: h, Sig: wire})
	}
	e.Signatures = sigs
	return e, nil
}

// decodeSigWire splits an "<alg>:<base64-std>" signature into its algorithm and
// raw bytes. A wrong prefix or bad base64 is a malformed signature.
func decodeSigWire(alg, wire string) ([]byte, error) {
	prefix := alg + ":"
	if !strings.HasPrefix(wire, prefix) {
		return nil, fmt.Errorf("%w: signature wire missing %q prefix", ErrSchema, prefix)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(wire, prefix))
	if err != nil {
		return nil, fmt.Errorf("%w: signature base64: %w", ErrSchema, err)
	}
	return raw, nil
}
