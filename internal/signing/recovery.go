// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
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

// recoveryExpiryCeiling is the maximum allowed gap between now and expires_at.
// Per the design doc, recovery authorizations must expire within 1 hour.
const recoveryExpiryCeiling = time.Hour

// recoverySchemaVersion is the expected schema version for recovery
// authorization envelopes.
const recoverySchemaVersion = 1

// Envelope file extension constants. These are also used by roster.go's
// LoadRoster switch; a shared extraction is appropriate once both call sites
// are editable in the same PR.
const (
	envelopeExtJSON = ".json"
	envelopeExtYAML = ".yaml"
	envelopeExtYML  = ".yml"
)

// targetRosterHashPattern validates "sha256:" followed by exactly 64 lowercase
// hex characters.
var targetRosterHashPattern = regexp.MustCompile(
	`^sha256:[0-9a-f]{64}$`,
)

// Sentinel errors for recovery authorization loading and validation.
var (
	ErrRecoveryRead                 = errors.New("recovery authorization read failed")
	ErrRecoveryDecode               = errors.New("recovery authorization decode failed")
	ErrRecoveryUnsupportedExtension = errors.New("unsupported recovery authorization file extension")
	ErrRecoverySchemaVersion        = errors.New("unsupported recovery authorization schema_version; expected 1")
	ErrRecoveryReasonRequired       = errors.New("recovery authorization reason is required")
	ErrRecoveryOperatorRequired     = errors.New("recovery authorization operator_identity is required")
	ErrRecoveryExpiryFormat         = errors.New("recovery authorization expires_at must be RFC 3339")
	ErrRecoveryIssuedAtFormat       = errors.New("recovery authorization issued_at must be RFC 3339")
	ErrRecoveryTargetHashFormat     = errors.New("recovery authorization target_roster_hash must be sha256:<64 hex>")
	ErrRecoveryNotYetValid          = errors.New("recovery authorization issued_at is in the future")
	ErrRecoveryExpired              = errors.New("recovery authorization is expired")
	ErrRecoveryExpiryTooFar         = errors.New("recovery authorization expires more than 1h in the future")
	ErrRecoverySignatureFormat      = errors.New("recovery authorization signature format invalid")
	ErrRecoverySignatureInvalid     = errors.New("recovery authorization signature does not verify")
	ErrRecoveryFingerprintMismatch  = errors.New("recovery authorization signing key fingerprint does not match pinned")
)

// RecoveryAuthorizationBody is the typed signable body of a roster recovery
// authorization. The recovery-root signs the body's canonical preimage.
type RecoveryAuthorizationBody struct {
	SchemaVersion    int    `json:"schema_version"`
	Reason           string `json:"reason"`
	ExpiresAt        string `json:"expires_at"`
	TargetRosterHash string `json:"target_roster_hash"`
	OperatorIdentity string `json:"operator_identity"`
	IssuedAt         string `json:"issued_at"`
}

// RecoveryAuthorizationEnvelope is the on-disk wire format.
type RecoveryAuthorizationEnvelope struct {
	Body      RecoveryAuthorizationBody `json:"body"`
	Signature string                    `json:"signature"`
}

// LoadedRecoveryAuthorization is a verified recovery authorization bound to
// the pinned recovery-root fingerprint that was used to verify it.
type LoadedRecoveryAuthorization struct {
	Body                    RecoveryAuthorizationBody
	Signature               string
	RecoveryRootFingerprint string
	LoadedAt                time.Time
	SourcePath              string
}

// SignablePreimage returns the JCS-canonical bytes of the body for signing
// and verification. Mirrors the KeyRoster preimage pattern in the contract
// package: marshal -> ParseJSONStrict -> Canonicalize.
func (b RecoveryAuthorizationBody) SignablePreimage() ([]byte, error) {
	raw, err := json.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("marshal recovery_authorization body: %w", err)
	}
	tree, err := contract.ParseJSONStrict(raw)
	if err != nil {
		return nil, fmt.Errorf("parse recovery_authorization for canonicalization: %w", err)
	}
	return contract.Canonicalize(tree)
}

// Validate runs structural checks on the body (no signature verification,
// no time-window enforcement):
//   - SchemaVersion == 1
//   - Reason non-empty
//   - ExpiresAt parses as RFC 3339
//   - IssuedAt parses as RFC 3339
//   - TargetRosterHash matches "sha256:<64 hex>"
//   - OperatorIdentity non-empty
//
// Time-window enforcement happens in LoadRecoveryAuthorization, not here,
// because Validate must be deterministic for canonicalization purposes.
func (b RecoveryAuthorizationBody) Validate() error {
	if b.SchemaVersion != recoverySchemaVersion {
		return fmt.Errorf("%w: got %d", ErrRecoverySchemaVersion, b.SchemaVersion)
	}
	if b.Reason == "" {
		return ErrRecoveryReasonRequired
	}
	if _, err := time.Parse(time.RFC3339, b.ExpiresAt); err != nil {
		return fmt.Errorf("%w: %w", ErrRecoveryExpiryFormat, err)
	}
	if _, err := time.Parse(time.RFC3339, b.IssuedAt); err != nil {
		return fmt.Errorf("%w: %w", ErrRecoveryIssuedAtFormat, err)
	}
	// TODO: caller must match TargetRosterHash against the actual loaded roster body in a future PR.
	if !targetRosterHashPattern.MatchString(b.TargetRosterHash) {
		return fmt.Errorf("%w: got %q", ErrRecoveryTargetHashFormat, b.TargetRosterHash)
	}
	if b.OperatorIdentity == "" {
		return ErrRecoveryOperatorRequired
	}
	return nil
}

// LoadRecoveryAuthorization reads a recovery_authorization file from disk,
// decodes it strictly, runs structural validation, then cryptographically
// verifies the detached signature against the operator-pinned recovery-root
// public key.
//
// The recoveryRootPublicKey must be the raw 32-byte Ed25519 public key of the
// recovery-root. Pinning by fingerprint is enforced via VerifyFingerprint
// against pinnedRecoveryRootFingerprint before the signature check, so that
// passing the wrong key surfaces a fingerprint-mismatch error rather than a
// signature-mismatch error (more diagnostic).
//
// Time-window checks (clock-skew bounded, against the now parameter):
//   - now < IssuedAt       -> ErrRecoveryNotYetValid (issued in the future)
//   - now > ExpiresAt      -> ErrRecoveryExpired
//   - ExpiresAt - now > 1h -> ErrRecoveryExpiryTooFar
//
// The 1-hour ceiling is hard-coded per the design doc. There is no unsigned
// recovery path: callers must pass a valid signed envelope or get an error.
func LoadRecoveryAuthorization(
	path string,
	recoveryRootPublicKey []byte,
	pinnedRecoveryRootFingerprint string,
	now time.Time,
) (*LoadedRecoveryAuthorization, error) {
	// Step 1: Read file from disk.
	cleanPath := filepath.Clean(path)
	raw, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRecoveryRead, err)
	}

	// Step 2: Decode based on file extension.
	var envelope RecoveryAuthorizationEnvelope
	if decErr := decodeRecoveryEnvelope(cleanPath, raw, &envelope); decErr != nil {
		return nil, decErr
	}

	// Step 3: Structural validation of the body.
	if valErr := envelope.Body.Validate(); valErr != nil {
		return nil, valErr
	}

	// Step 4: Validate signature format (reuse the parse helper).
	sigBytes, sigErr := parseSignature(envelope.Signature)
	if sigErr != nil {
		return nil, fmt.Errorf("%w: %w", ErrRecoverySignatureFormat, sigErr)
	}

	// Step 5: Time-window checks.
	issuedAt, _ := time.Parse(time.RFC3339, envelope.Body.IssuedAt)
	if now.Before(issuedAt) {
		return nil, fmt.Errorf("%w: issued_at=%s, now=%s",
			ErrRecoveryNotYetValid, envelope.Body.IssuedAt, now.Format(time.RFC3339))
	}
	expiresAt, _ := time.Parse(time.RFC3339, envelope.Body.ExpiresAt)
	if now.After(expiresAt) {
		return nil, fmt.Errorf("%w: expires_at=%s, now=%s",
			ErrRecoveryExpired, envelope.Body.ExpiresAt, now.Format(time.RFC3339))
	}
	if expiresAt.Sub(now) > recoveryExpiryCeiling {
		return nil, fmt.Errorf("%w: expires_at=%s, now=%s, delta=%s",
			ErrRecoveryExpiryTooFar, envelope.Body.ExpiresAt, now.Format(time.RFC3339), expiresAt.Sub(now))
	}

	// Step 6: Verify recovery-root fingerprint pinning.
	if fpErr := VerifyFingerprint(recoveryRootPublicKey, pinnedRecoveryRootFingerprint); fpErr != nil {
		return nil, fmt.Errorf("%w: %w", ErrRecoveryFingerprintMismatch, fpErr)
	}

	// Step 7: Compute preimage and verify signature.
	preimage, err := envelope.Body.SignablePreimage()
	if err != nil {
		return nil, fmt.Errorf("%w: preimage: %w", ErrRecoverySignatureInvalid, err)
	}
	if !contract.VerifyEd25519PureEdDSA(recoveryRootPublicKey, preimage, sigBytes) {
		return nil, fmt.Errorf("%w", ErrRecoverySignatureInvalid)
	}

	return &LoadedRecoveryAuthorization{
		Body:                    envelope.Body,
		Signature:               envelope.Signature,
		RecoveryRootFingerprint: pinnedRecoveryRootFingerprint,
		LoadedAt:                now,
		SourcePath:              cleanPath,
	}, nil
}

// decodeRecoveryEnvelope dispatches file-extension-based strict decoding.
func decodeRecoveryEnvelope(cleanPath string, raw []byte, envelope *RecoveryAuthorizationEnvelope) error {
	ext := strings.ToLower(filepath.Ext(cleanPath))
	switch ext {
	case envelopeExtJSON:
		if decErr := contract.DecodeStrictJSON(raw, envelope); decErr != nil {
			return fmt.Errorf("%w: %w", ErrRecoveryDecode, decErr)
		}
	case envelopeExtYAML, envelopeExtYML:
		if decErr := contract.DecodeStrictYAML(raw, envelope); decErr != nil {
			return fmt.Errorf("%w: %w", ErrRecoveryDecode, decErr)
		}
	default:
		return fmt.Errorf("%w: %q", ErrRecoveryUnsupportedExtension, ext)
	}
	return nil
}
