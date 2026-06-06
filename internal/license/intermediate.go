// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Intermediate-key PKI primitive.
//
// The root key is the SOLE trust anchor. The root (kept offline, e.g. on a USB
// token) signs a short-lived intermediate certificate; the cluster license
// service then holds only the intermediate private key and signs license tokens
// with it. A pod compromise loses the intermediate, never the root.
//
// Verification chain (offline):
//
//	verify(intermediate cert sig, root pubkey)
//	   && intermediate within its validity window
//	   && intermediate serial not revoked (CRL)
//	   && verify(token sig, intermediate pubkey)
//
// The license token wire format (license.go) is UNCHANGED: a token is still
// payload+Ed25519-signature. Which key signed it - root (legacy) or an
// intermediate - is decided by the verifier from the configured intermediate
// cert, not by anything in the token. This keeps the highest-blast-radius
// surface (the token format) frozen while adding the new trust tier alongside
// the existing CRL distribution channel.

const (
	// IntermediateVersion is the supported intermediate-cert payload version.
	IntermediateVersion = 1

	// PurposeLicenseSigning is the only purpose an intermediate cert may carry.
	// Purpose is pinned: the verifier never accepts a root-signed cert for any
	// other purpose, so the root signature alone is not a blank check.
	PurposeLicenseSigning = "license-signing"

	// AlgorithmEd25519 is the only signature algorithm accepted for the chain.
	AlgorithmEd25519 = "ed25519"

	// maxIntermediateBytes caps the decoded cert size before allocation.
	maxIntermediateBytes = 64 * 1024

	// maxIntermediateValidity caps how long the root may certify an
	// intermediate. The spec calls for 90-day or 1-year intermediates; 400 days
	// leaves slack for a 1-year cert plus clock skew while rejecting absurd,
	// effectively-permanent intermediates at sign time.
	maxIntermediateValidity = 400 * 24 * time.Hour
)

var (
	// ErrIntermediateMalformed covers structural / pinned-field failures
	// (bad version, empty serial, unparseable or wrong-size public key).
	ErrIntermediateMalformed = errors.New("intermediate certificate malformed")
	// ErrIntermediatePurpose is returned when the cert's purpose is not the
	// pinned license-signing purpose.
	ErrIntermediatePurpose = errors.New("intermediate certificate purpose not permitted")
	// ErrIntermediateAlgorithm is returned when the cert's algorithm is not the
	// pinned Ed25519 algorithm.
	ErrIntermediateAlgorithm = errors.New("intermediate certificate algorithm not permitted")
	// ErrIntermediateExpired is returned when verification time is past NotAfter.
	ErrIntermediateExpired = errors.New("intermediate certificate expired")
	// ErrIntermediateNotYetValid is returned when verification time precedes NotBefore.
	ErrIntermediateNotYetValid = errors.New("intermediate certificate not yet valid")
	// ErrIntermediateSignature is returned when the root signature over the
	// cert does not verify.
	ErrIntermediateSignature = errors.New("invalid intermediate certificate signature")
)

// IntermediatePayload is the signed claim set of an intermediate signing cert.
type IntermediatePayload struct {
	Version   int    `json:"version"`
	Serial    string `json:"serial"`  // serial / key id; the CRL revocation key
	Purpose   string `json:"purpose"` // pinned: license-signing
	Algorithm string `json:"alg"`     // pinned: ed25519
	PublicKey string `json:"pub"`     // hex-encoded intermediate Ed25519 public key
	NotBefore int64  `json:"nbf"`     // unix seconds
	NotAfter  int64  `json:"naf"`     // unix seconds
	IssuedAt  int64  `json:"iat"`     // unix seconds
}

// Intermediate is a root-signed intermediate signing certificate. Like the CRL,
// the wire format stores the exact signed payload bytes so signature
// verification covers those bytes, not a re-marshaled struct.
type Intermediate struct {
	Payload   IntermediatePayload
	Signature string

	payload []byte            // canonical signed bytes
	pub     ed25519.PublicKey // parsed intermediate public key
}

type intermediateWire struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// PublicKey returns a copy of the intermediate's signing public key.
func (i Intermediate) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), i.pub...)
}

// Serial returns the intermediate's serial / key id (the CRL revocation key).
func (i Intermediate) Serial() string { return i.Payload.Serial }

// validAt enforces the cert's validity window at the supplied time.
func (i Intermediate) validAt(now time.Time) error {
	ts := now.Unix()
	if ts < i.Payload.NotBefore {
		return ErrIntermediateNotYetValid
	}
	if ts > i.Payload.NotAfter {
		return ErrIntermediateExpired
	}
	return nil
}

// SignIntermediate signs an intermediate certificate payload with the ROOT
// private key. This is the only operation in the chain that touches the root
// key. It validates the pinned purpose/algorithm and the validity window before
// signing so the root never issues a structurally invalid intermediate.
func SignIntermediate(payload IntermediatePayload, rootPriv ed25519.PrivateKey) (Intermediate, error) {
	if len(rootPriv) != ed25519.PrivateKeySize {
		return Intermediate{}, errors.New("invalid root private key size")
	}
	if payload.Version == 0 {
		payload.Version = IntermediateVersion
	}
	// validateIntermediatePayload enforces the pinned fields AND the full
	// validity-window rules (issued_at/not_before/not_after presence, ordering,
	// and max window), so the signer never emits a structurally invalid cert.
	// The verifier shares this exact function, so no checks are duplicated here.
	pub, err := validateIntermediatePayload(payload)
	if err != nil {
		return Intermediate{}, err
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return Intermediate{}, fmt.Errorf("marshal intermediate payload: %w", err)
	}
	sig := ed25519.Sign(rootPriv, data)
	return Intermediate{
		Payload:   payload,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
		payload:   append([]byte(nil), data...),
		pub:       pub,
	}, nil
}

// MarshalJSON renders the cert as the CRL-style {payload, signature} wire blob,
// preserving the exact signed payload bytes.
func (i Intermediate) MarshalJSON() ([]byte, error) {
	payload := i.payload
	if len(payload) == 0 {
		var err error
		payload, err = json.Marshal(i.Payload)
		if err != nil {
			return nil, fmt.Errorf("marshal intermediate payload: %w", err)
		}
	}
	return json.Marshal(intermediateWire{
		Payload:   base64.RawURLEncoding.EncodeToString(payload),
		Signature: i.Signature,
	})
}

// ParseAndVerifyIntermediate decodes an intermediate cert, verifies its
// signature against the ROOT public key, and enforces the pinned purpose +
// algorithm and the validity window at `now`. It does NOT consult the CRL;
// revocation is checked separately (CheckIntermediate) so the caller can supply
// the loaded CRL. A returned Intermediate is always root-verified and
// structurally valid.
func ParseAndVerifyIntermediate(data []byte, rootPub ed25519.PublicKey, now time.Time) (Intermediate, error) {
	if len(data) > maxIntermediateBytes {
		return Intermediate{}, fmt.Errorf("%w: exceeds maximum size", ErrIntermediateMalformed)
	}
	var wire intermediateWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return Intermediate{}, fmt.Errorf("%w: %w", ErrIntermediateMalformed, err)
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(wire.Payload)
	if err != nil {
		return Intermediate{}, fmt.Errorf("%w: decode payload: %w", ErrIntermediateMalformed, err)
	}
	return verifyIntermediateBytes(payloadBytes, wire.Signature, rootPub, now)
}

// verifyIntermediateObject defensively re-validates an already decoded
// Intermediate against the root trust anchor. VerifyChain calls this so future
// wiring cannot accidentally trust a hand-built or stale Intermediate value.
func verifyIntermediateObject(im Intermediate, rootPub ed25519.PublicKey, now time.Time) (Intermediate, error) {
	payloadBytes := im.payload
	if len(payloadBytes) == 0 {
		var err error
		payloadBytes, err = json.Marshal(im.Payload)
		if err != nil {
			return Intermediate{}, fmt.Errorf("marshal intermediate payload: %w", err)
		}
	}
	return verifyIntermediateBytes(payloadBytes, im.Signature, rootPub, now)
}

// verifyIntermediateBytes is the shared verification core. It checks the root
// signature over the exact payload bytes, enforces the pinned + structural
// payload rules, and the validity window at now, returning a fully verified
// Intermediate. Both ParseAndVerifyIntermediate (wire bytes off disk) and
// verifyIntermediateObject (an already-decoded value) funnel through it so the
// trust checks are identical and never duplicated.
func verifyIntermediateBytes(payloadBytes []byte, signatureB64 string, rootPub ed25519.PublicKey, now time.Time) (Intermediate, error) {
	if len(rootPub) != ed25519.PublicKeySize {
		return Intermediate{}, errors.New("invalid root public key")
	}
	sig, err := base64.RawURLEncoding.DecodeString(signatureB64)
	if err != nil {
		return Intermediate{}, fmt.Errorf("%w: decode signature: %w", ErrIntermediateMalformed, err)
	}
	if len(sig) != ed25519.SignatureSize {
		return Intermediate{}, fmt.Errorf("%w: bad signature size", ErrIntermediateMalformed)
	}
	if !ed25519.Verify(rootPub, payloadBytes, sig) {
		return Intermediate{}, ErrIntermediateSignature
	}
	var payload IntermediatePayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return Intermediate{}, fmt.Errorf("%w: parse payload: %w", ErrIntermediateMalformed, err)
	}
	pub, err := validateIntermediatePayload(payload)
	if err != nil {
		return Intermediate{}, err
	}
	im := Intermediate{
		Payload:   payload,
		Signature: signatureB64,
		payload:   append([]byte(nil), payloadBytes...),
		pub:       pub,
	}
	if err := im.validAt(now); err != nil {
		return Intermediate{}, err
	}
	return im, nil
}

// validateIntermediatePayload enforces version + pinned purpose/algorithm +
// serial presence + public-key well-formedness, returning the parsed public
// key. It is shared by sign and verify so both paths pin identically (the
// verifier never trusts that the signer validated).
func validateIntermediatePayload(payload IntermediatePayload) (ed25519.PublicKey, error) {
	if payload.Version != IntermediateVersion {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrIntermediateMalformed, payload.Version)
	}
	if payload.Serial == "" {
		return nil, fmt.Errorf("%w: empty serial", ErrIntermediateMalformed)
	}
	if payload.IssuedAt <= 0 {
		return nil, fmt.Errorf("%w: missing issued_at", ErrIntermediateMalformed)
	}
	if payload.NotBefore <= 0 || payload.NotAfter <= 0 {
		return nil, fmt.Errorf("%w: missing validity window", ErrIntermediateMalformed)
	}
	if payload.NotAfter <= payload.NotBefore {
		return nil, fmt.Errorf("%w: not_after must be after not_before", ErrIntermediateMalformed)
	}
	if payload.IssuedAt > payload.NotAfter {
		return nil, fmt.Errorf("%w: issued_at must not be after not_after", ErrIntermediateMalformed)
	}
	if payload.NotAfter-payload.NotBefore > int64(maxIntermediateValidity.Seconds()) {
		return nil, fmt.Errorf("%w: validity window exceeds maximum %s", ErrIntermediateMalformed, maxIntermediateValidity)
	}
	if payload.Purpose != PurposeLicenseSigning {
		return nil, fmt.Errorf("%w: %q", ErrIntermediatePurpose, payload.Purpose)
	}
	if payload.Algorithm != AlgorithmEd25519 {
		return nil, fmt.Errorf("%w: %q", ErrIntermediateAlgorithm, payload.Algorithm)
	}
	return decodeIntermediatePublicKey(payload.PublicKey)
}

func decodeIntermediatePublicKey(hexKey string) (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("%w: decode public key: %w", ErrIntermediateMalformed, err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: public key wrong size", ErrIntermediateMalformed)
	}
	return ed25519.PublicKey(raw), nil
}

// VerifyChain verifies a license token using an OPTIONAL intermediate cert.
// rootPub is the sole trust anchor.
//
//   - im == nil: legacy direct-root verification only (token signed by root),
//     including CRL license-revocation.
//   - im != nil: im MUST have come from ParseAndVerifyIntermediate (already
//     root-verified). VerifyChain defensively re-checks the validity window at
//     `now` and the intermediate's CRL status, then verifies the token against
//     the intermediate public key, FALLING BACK to direct-root verification for
//     legacy root-signed tokens. License-level CRL revocation is always
//     enforced on either path.
func VerifyChain(token string, im *Intermediate, rootPub ed25519.PublicKey, crl *CRL, now time.Time) (License, error) {
	if im == nil {
		return VerifyWithCRL(token, rootPub, crl)
	}
	verified, err := verifyIntermediateObject(*im, rootPub, now)
	if err != nil {
		return License{}, err
	}
	if crl != nil {
		if err := crl.CheckIntermediate(verified.Serial()); err != nil {
			return License{}, err
		}
	}
	// Primary path: token signed by the active intermediate.
	lic, err := VerifyWithCRL(token, verified.PublicKey(), crl)
	if err == nil {
		return lic, nil
	}
	// A definitive expiry/revocation on the intermediate path means the token IS
	// intermediate-signed and must fail closed - never fall back to root.
	if errors.Is(err, ErrLicenseExpired) || errors.Is(err, ErrLicenseRevoked) {
		return License{}, err
	}
	// Otherwise the signature simply did not match the intermediate key: try the
	// legacy direct-root path for old root-signed tokens.
	legacyLic, legacyErr := VerifyWithCRL(token, rootPub, crl)
	if legacyErr == nil {
		return legacyLic, nil
	}
	// If the legacy path produced a definitive expiry/revocation, the token is
	// root-signed; surface that specific reason rather than the intermediate
	// signature-mismatch error.
	if errors.Is(legacyErr, ErrLicenseExpired) || errors.Is(legacyErr, ErrLicenseRevoked) {
		return License{}, legacyErr
	}
	return License{}, err
}

// VerifyTokenWithOptionalIntermediate is the single call-site entry point that
// enforces the fail-closed contract for a CONFIGURED intermediate cert.
//
// intermediateCert is the raw configured cert bytes (nil/empty = not
// configured):
//
//   - not configured: legacy direct-root verification only.
//   - configured: the cert MUST parse, verify against root, be within its
//     validity window, and not be revoked. ANY failure fails closed and is
//     surfaced verbatim - a configured-but-invalid cert is never silently
//     treated as "missing", and it blocks ALL verification (including legacy
//     root-signed tokens) per the fail-closed doctrine. The operator reverts by
//     explicitly removing the cert configuration. On a valid cert, the token is
//     verified against the intermediate key with legacy direct-root fallback.
func VerifyTokenWithOptionalIntermediate(token string, intermediateCert []byte, rootPub ed25519.PublicKey, crl *CRL, now time.Time) (License, error) {
	if len(intermediateCert) == 0 {
		return VerifyWithCRL(token, rootPub, crl)
	}
	im, err := ParseAndVerifyIntermediate(intermediateCert, rootPub, now)
	if err != nil {
		return License{}, fmt.Errorf("configured intermediate certificate rejected: %w", err)
	}
	if crl != nil {
		if err := crl.CheckIntermediate(im.Serial()); err != nil {
			return License{}, err
		}
	}
	return VerifyChain(token, &im, rootPub, crl, now)
}
