// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package aarp

import (
	"errors"
	"fmt"
)

// Suite failure classes. Compare with errors.Is.
var (
	// ErrUnknownSuite means a protected signature header names a profile,
	// canonicalization, or algorithm this verifier does not implement. Such a
	// signature never verifies and is never "downgraded" to verification under
	// a different suite — there is no fallback.
	ErrUnknownSuite = errors.New("aarp: unknown signature suite; fail closed, no fallback")

	// ErrSuiteUnimplemented means the suite is a recognized, typed slot whose
	// signing/verification is not yet built (the post-quantum slot). A signature
	// under such a suite is reported as unverified, never as valid.
	ErrSuiteUnimplemented = errors.New("aarp: signature suite recognized but not implemented")

	// ErrMalformedSuite means the protected header is structurally invalid: a
	// missing key id, an empty role, or an algorithm/key-type mismatch.
	ErrMalformedSuite = errors.New("aarp: malformed signature suite")

	// ErrUnknownCriticalExtension means a signature or envelope marks an
	// extension critical that this verifier does not understand. The whole
	// envelope is rejected: a producer that flags something critical is
	// asserting it must be processed, and a verifier that cannot process it
	// cannot safely appraise the envelope. Fail closed.
	ErrUnknownCriticalExtension = errors.New("aarp: unknown critical extension; cannot appraise, fail closed")
)

// AlgID identifies a signature algorithm in a protected suite.
type AlgID string

const (
	// AlgEd25519 is Ed25519 PureEdDSA, the default and only implemented suite.
	AlgEd25519 AlgID = "ed25519"
	// AlgMLDSA65 is the FIPS 204 ML-DSA-65 post-quantum slot. It is a recognized,
	// typed suite so a hybrid or PQ-only envelope is structurally first-class
	// today, but its signer/verifier is deferred until the standard's errata
	// settle. Verification of an ML-DSA-65 signature returns ErrSuiteUnimplemented.
	AlgMLDSA65 AlgID = "ml-dsa-65"
)

// keyTypeForAlg maps each recognized algorithm to its required key type. A
// protected header whose key_type disagrees with its alg is malformed.
var keyTypeForAlg = map[AlgID]string{
	AlgEd25519: "ed25519",
	AlgMLDSA65: "ml-dsa",
}

// implementedAlgs is the set of algorithms whose verification is built. An alg
// that is recognized (in keyTypeForAlg) but not implemented here is a typed
// stub: it fails closed with ErrSuiteUnimplemented, never a fallback verify.
var implementedAlgs = map[AlgID]bool{
	AlgEd25519: true,
}

// knownSignerRoles is the closed set of signer roles a protected header may
// claim. The role is advisory for display and policy; an unknown role is a
// malformed suite (the producer is outside the agreed vocabulary).
var knownSignerRoles = map[string]bool{
	"mediator":   true,
	"issuer":     true,
	"countersig": true,
}

// knownCriticalExtensions is the registry of critical-extension names this
// verifier understands. It is empty in v0.1: no critical extension is defined
// yet, so any name flagged critical fails the envelope closed. New critical
// extensions are added here as they are specified and implemented.
var knownCriticalExtensions = map[string]bool{}

// ProtectedHeader is the per-signature suite descriptor. It is covered by its
// own signature's bytes (it is part of the canonical signing input), so a
// verifier can never be tricked into matching bytes produced under a different
// algorithm, canonicalization, or profile version. This is authenticated
// agility: agility lives inside the signed envelope, not in an unprotected
// sibling label.
type ProtectedHeader struct {
	Profile    string   `json:"profile"`
	Canon      string   `json:"canon"`
	Alg        string   `json:"alg"`
	KeyType    string   `json:"key_type"`
	KeyID      string   `json:"key_id"`
	SignerRole string   `json:"signer_role"`
	Crit       []string `json:"crit,omitempty"`
}

// validateSuiteShape checks structural suite validity that applies regardless of
// whether the alg is implemented: profile/canon match, key id and role present,
// alg recognized, key_type consistent with alg, and all critical extensions
// understood. It does NOT decide implementability — that is checkImplemented.
func (h ProtectedHeader) validateSuiteShape() error {
	if h.Profile != Profile {
		return fmt.Errorf("%w: profile %q, want %q", ErrUnknownSuite, h.Profile, Profile)
	}
	if h.Canon != CanonID {
		return fmt.Errorf("%w: canon %q, want %q", ErrUnknownSuite, h.Canon, CanonID)
	}
	wantKeyType, ok := keyTypeForAlg[AlgID(h.Alg)]
	if !ok {
		return fmt.Errorf("%w: alg %q", ErrUnknownSuite, h.Alg)
	}
	if h.KeyType != wantKeyType {
		return fmt.Errorf("%w: alg %q requires key_type %q, got %q", ErrMalformedSuite, h.Alg, wantKeyType, h.KeyType)
	}
	if h.KeyID == "" {
		return fmt.Errorf("%w: empty key_id", ErrMalformedSuite)
	}
	if !knownSignerRoles[h.SignerRole] {
		return fmt.Errorf("%w: unknown signer_role %q", ErrMalformedSuite, h.SignerRole)
	}
	if err := checkCriticalExtensions(h.Crit); err != nil {
		return err
	}
	return nil
}

// checkImplemented reports whether the (already shape-valid) suite's algorithm
// has a built verifier. A recognized-but-unimplemented alg returns
// ErrSuiteUnimplemented so the caller reports the signature unverified.
func (h ProtectedHeader) checkImplemented() error {
	if !implementedAlgs[AlgID(h.Alg)] {
		return fmt.Errorf("%w: alg %q", ErrSuiteUnimplemented, h.Alg)
	}
	return nil
}

// checkCriticalExtensions rejects any critical-extension name not in the known
// registry. Duplicate and empty names are also rejected as malformed: a
// critical-extension list must be an unambiguous set of understood names.
//
// Structural validity (no empty, no duplicate) is checked first, then
// known-ness, so a duplicated unknown name is reported as the duplicate it is
// rather than masked by the unknown check. Both outcomes fail the envelope
// closed; the ordering only sharpens the error.
func checkCriticalExtensions(crit []string) error {
	seen := make(map[string]struct{}, len(crit))
	for _, name := range crit {
		if name == "" {
			return fmt.Errorf("%w: empty critical extension name", ErrMalformedSuite)
		}
		if _, dup := seen[name]; dup {
			return fmt.Errorf("%w: duplicate critical extension %q", ErrMalformedSuite, name)
		}
		seen[name] = struct{}{}
	}
	for name := range seen {
		if !knownCriticalExtensions[name] {
			return fmt.Errorf("%w: %q", ErrUnknownCriticalExtension, name)
		}
	}
	return nil
}
