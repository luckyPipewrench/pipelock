// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/contract"
)

// rootTransitionSchemaVersion is the expected schema version for root
// transition envelopes.
const rootTransitionSchemaVersion = 1

// rootTransitionFingerprintPattern validates "sha256:" followed by exactly 64
// lowercase hex characters. Same format as targetRosterHashPattern in
// recovery.go; own constant avoids cross-file coupling.
var rootTransitionFingerprintPattern = regexp.MustCompile(
	`^sha256:[0-9a-f]{64}$`,
)

// RootKind identifies which trust anchor a transition rotates.
type RootKind string

const (
	// RootKindRoster identifies a roster-root key transition.
	RootKindRoster RootKind = "roster-root"

	// RootKindRecovery identifies a recovery-root key transition.
	RootKindRecovery RootKind = "recovery-root"
)

// Validate returns nil if k is one of the two known kinds.
func (k RootKind) Validate() error {
	switch k {
	case RootKindRoster, RootKindRecovery:
		return nil
	default:
		return fmt.Errorf("%w: %q", ErrRootTransitionUnknownKind, string(k))
	}
}

// Sentinel errors for root transition loading and validation.
var (
	ErrRootTransitionRead                   = errors.New("root transition read failed")
	ErrRootTransitionDecode                 = errors.New("root transition decode failed")
	ErrRootTransitionUnsupportedExtension   = errors.New("unsupported root transition file extension")
	ErrRootTransitionInvalid                = errors.New("root transition body validation failed")
	ErrRootTransitionUnknownKind            = errors.New("root_kind must be roster-root or recovery-root")
	ErrRootTransitionFingerprintFormat      = errors.New("fingerprint must be sha256:<64 hex>")
	ErrRootTransitionIdentityRotation       = errors.New("old_fingerprint and new_fingerprint must differ")
	ErrRootTransitionEffectiveAtFormat      = errors.New("effective_at must be RFC 3339")
	ErrRootTransitionReasonRequired         = errors.New("root transition reason is required")
	ErrRootTransitionKeyLength              = errors.New("public key wrong length for ed25519")
	ErrRootTransitionOldFingerprintMismatch = errors.New("provided oldPubKey does not match body.old_fingerprint")
	ErrRootTransitionNewFingerprintMismatch = errors.New("provided newPubKey does not match body.new_fingerprint")
	ErrRootTransitionPinMismatch            = errors.New("body.old_fingerprint does not match operator-pinned fingerprint")
	ErrRootTransitionOldSignatureFormat     = errors.New("old_signature format invalid")
	ErrRootTransitionNewSignatureFormat     = errors.New("new_signature format invalid")
	ErrRootTransitionOldSignatureInvalid    = errors.New("old_signature does not verify")
	ErrRootTransitionNewSignatureInvalid    = errors.New("new_signature does not verify")
)

// RootTransitionBody is the typed signable body of a root rotation document.
type RootTransitionBody struct {
	SchemaVersion  int      `json:"schema_version"`
	RootKind       RootKind `json:"root_kind"`
	OldFingerprint string   `json:"old_fingerprint"`
	NewFingerprint string   `json:"new_fingerprint"`
	EffectiveAt    string   `json:"effective_at"`
	Reason         string   `json:"reason"`
}

// RootTransitionEnvelope is the on-disk wire format with TWO detached
// signatures: one from the OLD root, one from the NEW root.
type RootTransitionEnvelope struct {
	Body         RootTransitionBody `json:"body"`
	OldSignature string             `json:"old_signature"`
	NewSignature string             `json:"new_signature"`
}

// LoadedRootTransition is a verified root transition bound to both the old
// and new fingerprints that were used to verify it.
type LoadedRootTransition struct {
	Body         RootTransitionBody
	OldSignature string
	NewSignature string
	LoadedAt     time.Time
	SourcePath   string
}

// SignablePreimage returns JCS-canonical bytes of the body for signing
// and verification. Both old and new signatures cover this preimage.
func (b RootTransitionBody) SignablePreimage() ([]byte, error) {
	raw, err := json.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("marshal root_transition body: %w", err)
	}
	tree, err := contract.ParseJSONStrict(raw)
	if err != nil {
		return nil, fmt.Errorf("parse root_transition for canonicalization: %w", err)
	}
	return contract.Canonicalize(tree)
}

// Validate runs structural checks on the body (no signature verification,
// no fingerprint pinning):
//   - SchemaVersion == 1
//   - RootKind is roster-root or recovery-root
//   - OldFingerprint matches "sha256:<64 lowercase hex>"
//   - NewFingerprint matches "sha256:<64 lowercase hex>"
//   - OldFingerprint != NewFingerprint (must actually rotate; identity reject)
//   - EffectiveAt parses as RFC 3339
//   - Reason non-empty
func (b RootTransitionBody) Validate() error {
	if b.SchemaVersion != rootTransitionSchemaVersion {
		return fmt.Errorf("%w: schema_version=%d, want %d",
			ErrRootTransitionInvalid, b.SchemaVersion, rootTransitionSchemaVersion)
	}
	if err := b.RootKind.Validate(); err != nil {
		return err
	}
	if !rootTransitionFingerprintPattern.MatchString(b.OldFingerprint) {
		return fmt.Errorf("%w: old_fingerprint=%q", ErrRootTransitionFingerprintFormat, b.OldFingerprint)
	}
	if !rootTransitionFingerprintPattern.MatchString(b.NewFingerprint) {
		return fmt.Errorf("%w: new_fingerprint=%q", ErrRootTransitionFingerprintFormat, b.NewFingerprint)
	}
	if b.OldFingerprint == b.NewFingerprint {
		return fmt.Errorf("%w: %s", ErrRootTransitionIdentityRotation, b.OldFingerprint)
	}
	if _, err := time.Parse(time.RFC3339, b.EffectiveAt); err != nil {
		return fmt.Errorf("%w: %w", ErrRootTransitionEffectiveAtFormat, err)
	}
	if b.Reason == "" {
		return ErrRootTransitionReasonRequired
	}
	return nil
}

// LoadRootTransition reads a root transition file from disk, decodes it
// strictly, runs structural validation, then verifies BOTH detached
// signatures (old AND new) against the supplied public keys. Both
// signatures cover the same canonical preimage.
//
// Pinning by fingerprint:
//   - Fingerprint(oldPubKey) MUST equal body.old_fingerprint AND
//     equal pinnedOldFingerprint (the operator's currently-pinned root).
//   - Fingerprint(newPubKey) MUST equal body.new_fingerprint.
//
// If pinnedOldFingerprint is empty string, the body.old_fingerprint check
// against the supplied oldPubKey still runs but the operator-pin check
// is skipped (used for offline ceremony verification before runtime pin
// is updated).
//
// On success returns *LoadedRootTransition. The runtime applies the
// transition by updating the operator-pinned fingerprint to NewFingerprint.
func LoadRootTransition(
	path string,
	oldPubKey, newPubKey []byte,
	pinnedOldFingerprint string,
) (*LoadedRootTransition, error) {
	// Step 1: Read file from disk.
	cleanPath := filepath.Clean(path)
	raw, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRootTransitionRead, err)
	}

	// Step 2: Decode based on file extension.
	var envelope RootTransitionEnvelope
	if decErr := decodeRootTransitionEnvelope(cleanPath, raw, &envelope); decErr != nil {
		return nil, decErr
	}

	// Step 3: Structural validation of the body.
	if valErr := envelope.Body.Validate(); valErr != nil {
		return nil, valErr
	}

	// Step 4: Validate key lengths before fingerprinting.
	if len(oldPubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: oldPubKey is %d bytes, want %d",
			ErrRootTransitionKeyLength, len(oldPubKey), ed25519.PublicKeySize)
	}
	if len(newPubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: newPubKey is %d bytes, want %d",
			ErrRootTransitionKeyLength, len(newPubKey), ed25519.PublicKeySize)
	}

	// Step 5: Verify oldPubKey fingerprint matches body.old_fingerprint.
	oldFP, err := Fingerprint(oldPubKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRootTransitionOldFingerprintMismatch, err)
	}
	if oldFP != envelope.Body.OldFingerprint {
		return nil, fmt.Errorf("%w: computed %s, body has %s",
			ErrRootTransitionOldFingerprintMismatch, oldFP, envelope.Body.OldFingerprint)
	}

	// Step 6: Verify newPubKey fingerprint matches body.new_fingerprint.
	newFP, err := Fingerprint(newPubKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRootTransitionNewFingerprintMismatch, err)
	}
	if newFP != envelope.Body.NewFingerprint {
		return nil, fmt.Errorf("%w: computed %s, body has %s",
			ErrRootTransitionNewFingerprintMismatch, newFP, envelope.Body.NewFingerprint)
	}

	// Step 7: If an operator pin is supplied, verify body.old_fingerprint matches it.
	if pinnedOldFingerprint != "" && envelope.Body.OldFingerprint != pinnedOldFingerprint {
		return nil, fmt.Errorf("%w: body=%s, pinned=%s",
			ErrRootTransitionPinMismatch, envelope.Body.OldFingerprint, pinnedOldFingerprint)
	}

	// Step 8: Validate old_signature format.
	oldSigBytes, sigErr := parseSignature(envelope.OldSignature)
	if sigErr != nil {
		return nil, fmt.Errorf("%w: %w", ErrRootTransitionOldSignatureFormat, sigErr)
	}

	// Step 9: Validate new_signature format.
	newSigBytes, sigErr := parseSignature(envelope.NewSignature)
	if sigErr != nil {
		return nil, fmt.Errorf("%w: %w", ErrRootTransitionNewSignatureFormat, sigErr)
	}

	// Step 10: Compute preimage.
	preimage, err := envelope.Body.SignablePreimage()
	if err != nil {
		return nil, fmt.Errorf("%w: preimage: %w", ErrRootTransitionOldSignatureInvalid, err)
	}

	// Step 11: Verify old signature.
	if !contract.VerifyEd25519PureEdDSA(oldPubKey, preimage, oldSigBytes) {
		return nil, fmt.Errorf("%w", ErrRootTransitionOldSignatureInvalid)
	}

	// Step 12: Verify new signature.
	if !contract.VerifyEd25519PureEdDSA(newPubKey, preimage, newSigBytes) {
		return nil, fmt.Errorf("%w", ErrRootTransitionNewSignatureInvalid)
	}

	return &LoadedRootTransition{
		Body:         envelope.Body,
		OldSignature: envelope.OldSignature,
		NewSignature: envelope.NewSignature,
		LoadedAt:     time.Now(),
		SourcePath:   cleanPath,
	}, nil
}

// decodeRootTransitionEnvelope dispatches file-extension-based strict decoding.
func decodeRootTransitionEnvelope(cleanPath string, raw []byte, envelope *RootTransitionEnvelope) error {
	ext := strings.ToLower(filepath.Ext(cleanPath))
	switch ext {
	case envelopeExtJSON:
		if decErr := contract.DecodeStrictJSON(raw, envelope); decErr != nil {
			return fmt.Errorf("%w: %w", ErrRootTransitionDecode, decErr)
		}
	case envelopeExtYAML, envelopeExtYML:
		if decErr := contract.DecodeStrictYAML(raw, envelope); decErr != nil {
			return fmt.Errorf("%w: %w", ErrRootTransitionDecode, decErr)
		}
	default:
		return fmt.Errorf("%w: %q", ErrRootTransitionUnsupportedExtension, ext)
	}
	return nil
}
