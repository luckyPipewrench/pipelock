// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/contract"
)

// Sentinel errors for roster loading and key resolution.
var (
	ErrRosterRead                    = errors.New("roster read failed")
	ErrRosterDecode                  = errors.New("roster decode failed")
	ErrRosterUnsupportedExtension    = errors.New("unsupported roster file extension")
	ErrRosterInvalid                 = errors.New("roster body validation failed")
	ErrRosterSignatureFormat         = errors.New("roster signature format invalid")
	ErrRosterSignatureInvalid        = errors.New("roster signature does not verify")
	ErrRosterRootMissing             = errors.New("roster root key missing or wrong status")
	ErrRosterRootWrongPurpose        = errors.New("roster root key has wrong key_purpose")
	ErrRosterRootFingerprintMismatch = errors.New("roster root key fingerprint does not match pinned")
	ErrRosterKeyUnknown              = errors.New("key_id not in roster")
	ErrRosterKeyRevoked              = errors.New("key is revoked")
	ErrRosterKeyNotYetValid          = errors.New("key is not yet valid")
	ErrRosterKeyExpired              = errors.New("key is expired")
	ErrRosterKeyInvalidStatus        = errors.New("key has unknown status")
	ErrRosterKeyNotActive            = errors.New("key is not active")
	ErrRosterKeyMissingPublicKey     = errors.New("key has missing or malformed public_key_hex")
	ErrRosterKeyInvalidPurpose       = errors.New("key has unknown key_purpose")
)

// ed25519SignaturePrefix is the wire-format prefix for Ed25519 detached signatures.
const ed25519SignaturePrefix = "ed25519:"

// ed25519SignatureHexLen is the expected hex-encoded length of an Ed25519
// signature: 64 bytes = 128 hex characters.
const ed25519SignatureHexLen = 128

// LoadedRoster is a verified deployment-local key roster bound to the
// pinned roster-root fingerprint that was used to verify it.
type LoadedRoster struct {
	Body                  contract.KeyRoster
	Signature             string    // "ed25519:<hex>" form, kept for audit traces
	RosterRootFingerprint string    // pinned fingerprint that authenticated this roster
	LoadedAt              time.Time // wall-clock at successful verify
	SourcePath            string    // file path it came from, for diagnostic logs
}

// LoadRoster reads a roster file from disk, decodes it strictly, runs
// structural validation, then cryptographically verifies the detached
// signature against the key inside the roster body whose key_id matches
// roster_signed_by AND whose fingerprint matches the operator-pinned
// rosterRootFingerprint.
//
// Format: file extension determines decoder (.yaml/.yml -> DecodeStrictYAML,
// .json -> DecodeStrictJSON). Other extensions reject with a typed error.
//
// Reject cases (each gets a typed sentinel that errors.Is can match):
//
//   - File missing or unreadable                  -> ErrRosterRead
//   - Decoder failure                             -> ErrRosterDecode (wraps the underlying err)
//   - Body fails contract.KeyRoster.Validate()    -> ErrRosterInvalid
//   - signature missing or wrong prefix           -> ErrRosterSignatureFormat
//   - signature hex malformed or wrong length      -> ErrRosterSignatureFormat
//   - roster_signed_by key_id not in body.Keys    -> ErrRosterRootMissing
//   - referenced root key has wrong purpose       -> ErrRosterRootWrongPurpose
//   - referenced root key has wrong status         -> ErrRosterRootMissing
//   - referenced root key fingerprint != pinned   -> ErrRosterRootFingerprintMismatch
//   - signature does not verify                   -> ErrRosterSignatureInvalid
//
// On success returns *LoadedRoster bound to the pinned fingerprint.
func LoadRoster(path string, pinnedRootFingerprint string) (*LoadedRoster, error) {
	// Step 1: Read file from disk.
	cleanPath := filepath.Clean(path)
	raw, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRosterRead, err)
	}

	// Step 2: Decode based on file extension.
	var envelope contract.RosterEnvelope
	ext := strings.ToLower(filepath.Ext(cleanPath))
	switch ext {
	case envelopeExtJSON:
		if decErr := contract.DecodeStrictJSON(raw, &envelope); decErr != nil {
			return nil, fmt.Errorf("%w: %w", ErrRosterDecode, decErr)
		}
	case envelopeExtYAML, envelopeExtYML:
		if decErr := contract.DecodeStrictYAML(raw, &envelope); decErr != nil {
			return nil, fmt.Errorf("%w: %w", ErrRosterDecode, decErr)
		}
	default:
		return nil, fmt.Errorf("%w: %q", ErrRosterUnsupportedExtension, ext)
	}

	// Step 3: Structural validation of the body.
	if valErr := envelope.Body.Validate(); valErr != nil {
		return nil, fmt.Errorf("%w: %w", ErrRosterInvalid, valErr)
	}

	// Step 3b: Strict per-key validation. The contract package's Validate()
	// only checks duplicate IDs, root presence, and data class root. The
	// signing package owns runtime trust decisions, so it tightens the gate:
	// every key MUST have a known status, a known purpose, and a parseable
	// 32-byte ed25519 public key.
	if valErr := validateKeyInfos(envelope.Body.Keys); valErr != nil {
		return nil, fmt.Errorf("%w: %w", ErrRosterInvalid, valErr)
	}

	// Step 4: Validate signature format.
	sigBytes, err := parseSignature(envelope.Signature)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRosterSignatureFormat, err)
	}

	// Step 5: Locate the root key referenced by roster_signed_by.
	rootKey, err := findRootKey(envelope.Body)
	if err != nil {
		return nil, err
	}

	// Step 6: Verify root key purpose.
	rootPurpose := KeyPurpose(rootKey.KeyPurpose)
	if rootPurpose != PurposeRosterRoot {
		return nil, fmt.Errorf("%w: got %q, want %q",
			ErrRosterRootWrongPurpose, rootKey.KeyPurpose, PurposeRosterRoot)
	}

	// Step 7: Decode root public key and verify fingerprint against pinned.
	rootPubBytes, err := hex.DecodeString(rootKey.PublicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid root public key hex: %w", ErrRosterRootMissing, err)
	}
	if fpErr := VerifyFingerprint(rootPubBytes, pinnedRootFingerprint); fpErr != nil {
		if errors.Is(fpErr, ErrFingerprintMismatch) {
			return nil, fmt.Errorf("%w: %w", ErrRosterRootFingerprintMismatch, fpErr)
		}
		// Format errors in the pinned fingerprint also reject.
		return nil, fmt.Errorf("%w: %w", ErrRosterRootFingerprintMismatch, fpErr)
	}

	// Step 8: Compute preimage and verify signature.
	preimage, err := envelope.Body.SignablePreimage()
	if err != nil {
		return nil, fmt.Errorf("%w: preimage: %w", ErrRosterSignatureInvalid, err)
	}
	if !contract.VerifyEd25519PureEdDSA(rootPubBytes, preimage, sigBytes) {
		return nil, fmt.Errorf("%w", ErrRosterSignatureInvalid)
	}

	return &LoadedRoster{
		Body:                  envelope.Body,
		Signature:             envelope.Signature,
		RosterRootFingerprint: pinnedRootFingerprint,
		LoadedAt:              time.Now(),
		SourcePath:            cleanPath,
	}, nil
}

// parseSignature validates and decodes the "ed25519:<hex>" wire format.
// Returns descriptive errors WITHOUT a package-level sentinel; callers wrap
// with their own ErrXxxSignatureFormat sentinel so that errors.Is works for
// the right scope.
func parseSignature(sig string) ([]byte, error) {
	if sig == "" {
		return nil, errors.New("empty signature")
	}
	if !strings.HasPrefix(sig, ed25519SignaturePrefix) {
		return nil, fmt.Errorf("missing %q prefix", ed25519SignaturePrefix)
	}
	hexPart := sig[len(ed25519SignaturePrefix):]
	if len(hexPart) != ed25519SignatureHexLen {
		return nil, fmt.Errorf("hex length %d, want %d", len(hexPart), ed25519SignatureHexLen)
	}
	sigBytes, err := hex.DecodeString(hexPart)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}
	return sigBytes, nil
}

// validateKeyInfos runs strict per-key checks on every entry in a roster
// body. It is the runtime-trust gate that catches values the contract
// package's structural Validate() intentionally lets through (the contract
// package validates SCHEMA; the signing package validates TRUST).
//
// Reject cases:
//   - Status not in {active, revoked, root}              -> ErrRosterKeyInvalidStatus
//   - KeyPurpose is not one of the six known purposes     -> ErrRosterKeyInvalidPurpose
//   - PublicKeyHex is empty, non-hex, or wrong length     -> ErrRosterKeyMissingPublicKey
func validateKeyInfos(keys []contract.KeyInfo) error {
	for _, k := range keys {
		switch k.Status {
		case contract.KeyStatusActive, contract.KeyStatusRevoked, contract.KeyStatusRoot:
			// known
		default:
			return fmt.Errorf("%w: key_id=%q status=%q", ErrRosterKeyInvalidStatus, k.KeyID, k.Status)
		}
		if err := KeyPurpose(k.KeyPurpose).Validate(); err != nil {
			return fmt.Errorf("%w: key_id=%q: %w", ErrRosterKeyInvalidPurpose, k.KeyID, err)
		}
		pub, err := hex.DecodeString(k.PublicKeyHex)
		if err != nil {
			return fmt.Errorf("%w: key_id=%q hex decode: %w", ErrRosterKeyMissingPublicKey, k.KeyID, err)
		}
		if len(pub) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: key_id=%q got %d bytes, want %d",
				ErrRosterKeyMissingPublicKey, k.KeyID, len(pub), ed25519.PublicKeySize)
		}
	}
	return nil
}

// findRootKey locates the key in body.Keys whose key_id matches
// body.RosterSignedBy AND whose status is "root".
func findRootKey(body contract.KeyRoster) (contract.KeyInfo, error) {
	for _, k := range body.Keys {
		if k.KeyID == body.RosterSignedBy {
			if k.Status != contract.KeyStatusRoot {
				return contract.KeyInfo{}, fmt.Errorf("%w: key %q has status %q, want %q",
					ErrRosterRootMissing, k.KeyID, k.Status, contract.KeyStatusRoot)
			}
			return k, nil
		}
	}
	return contract.KeyInfo{}, fmt.Errorf("%w: key_id %q not found", ErrRosterRootMissing, body.RosterSignedBy)
}

// ResolveKey returns the active, in-window key info for the given key_id.
// Only keys with status="active" are resolvable; revoked, root, and any
// unrecognised status reject. Root keys are intentionally not resolvable
// here because they sign rosters and root transitions, never runtime
// payloads — the loader uses findRootKey internally for that lookup.
//
// Reject cases (typed sentinels):
//   - key_id not in roster                        -> ErrRosterKeyUnknown
//   - key status is revoked                       -> ErrRosterKeyRevoked
//   - key status is root                          -> ErrRosterKeyNotActive
//   - key status is anything else                 -> ErrRosterKeyInvalidStatus
//   - now < valid_from                            -> ErrRosterKeyNotYetValid
//   - now > valid_until (when valid_until is set) -> ErrRosterKeyExpired
//
// LoadRoster runs validateKeyInfos before this method is reachable, so
// unknown statuses are normally rejected at load time. The defense-in-depth
// check here is for callers who construct a LoadedRoster by other means.
//
// The now parameter is for testability; pass time.Now() in production.
// valid_from / valid_until on the wire are RFC 3339 UTC strings.
func (r *LoadedRoster) ResolveKey(keyID string, now time.Time) (contract.KeyInfo, error) {
	for _, k := range r.Body.Keys {
		if k.KeyID != keyID {
			continue
		}

		// Status check: only active keys are resolvable.
		switch k.Status {
		case contract.KeyStatusActive:
			// proceed to window check
		case contract.KeyStatusRevoked:
			return contract.KeyInfo{}, fmt.Errorf("%w: %q", ErrRosterKeyRevoked, keyID)
		case contract.KeyStatusRoot:
			return contract.KeyInfo{}, fmt.Errorf("%w: key_id=%q has status=root", ErrRosterKeyNotActive, keyID)
		default:
			return contract.KeyInfo{}, fmt.Errorf("%w: key_id=%q status=%q", ErrRosterKeyInvalidStatus, keyID, k.Status)
		}

		// Window check: valid_from.
		validFrom, err := time.Parse(time.RFC3339, k.ValidFrom)
		if err != nil {
			return contract.KeyInfo{}, fmt.Errorf("%w: invalid valid_from: %w", ErrRosterKeyNotYetValid, err)
		}
		if now.Before(validFrom) {
			return contract.KeyInfo{}, fmt.Errorf("%w: %q valid_from=%s, now=%s",
				ErrRosterKeyNotYetValid, keyID, k.ValidFrom, now.Format(time.RFC3339))
		}

		// Window check: valid_until (optional).
		if k.ValidUntil != nil {
			validUntil, err := time.Parse(time.RFC3339, *k.ValidUntil)
			if err != nil {
				return contract.KeyInfo{}, fmt.Errorf("%w: invalid valid_until: %w", ErrRosterKeyExpired, err)
			}
			if now.After(validUntil) {
				return contract.KeyInfo{}, fmt.Errorf("%w: %q valid_until=%s, now=%s",
					ErrRosterKeyExpired, keyID, *k.ValidUntil, now.Format(time.RFC3339))
			}
		}

		return k, nil
	}
	return contract.KeyInfo{}, fmt.Errorf("%w: %q", ErrRosterKeyUnknown, keyID)
}

// AuthorizeSignerForPayload checks that signerKeyID is allowed to author the
// given payload kind RIGHT NOW. It is the lifecycle-and-purpose gate, NOT a
// cryptographic signature verifier — the actual Ed25519 verification happens
// at the call site using the resolved key's public key. The name reflects
// that distinction: this function answers "is this signer permitted?", not
// "is this signature valid?".
//
// Steps (all must pass; first failure returns):
//  1. Resolve the key via ResolveKey (active + in-window).
//  2. Validate the key's purpose enum (KeyPurpose.Validate).
//  3. Run AuthorizePayload(payloadKind, KeyPurpose(key.KeyPurpose)).
//
// Returns nil iff all three pass. Errors preserve errors.Is on every
// underlying sentinel (ResolveKey's, contract.ErrWrongKeyPurpose,
// contract.ErrUnknownPayloadKind, ErrUnknownKeyPurpose).
func (r *LoadedRoster) AuthorizeSignerForPayload(payloadKind, signerKeyID string, now time.Time) error {
	key, err := r.ResolveKey(signerKeyID, now)
	if err != nil {
		return err
	}

	purpose := KeyPurpose(key.KeyPurpose)
	if err := purpose.Validate(); err != nil {
		return err
	}

	return AuthorizePayload(payloadKind, purpose)
}
