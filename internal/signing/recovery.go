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
	ErrRecoveryLifetimeTooLong      = errors.New("recovery authorization lifetime (expires_at - issued_at) exceeds 1h ceiling")
	ErrRecoveryExpiresBeforeIssued  = errors.New("recovery authorization expires_at is before issued_at")
	ErrRecoveryTargetHashMismatch   = errors.New("recovery authorization target_roster_hash does not match expected")
	// ErrRecoveryTargetHashRequired is returned by LoadRecoveryAuthorization when
	// expectedTargetRosterHash is empty. The runtime entry point fails closed on
	// missing target binding so a forgotten argument never silently accepts a
	// valid authorization for an arbitrary roster body. Offline ceremony tooling
	// uses InspectRecoveryAuthorizationOffline instead.
	ErrRecoveryTargetHashRequired = errors.New("recovery authorization expectedTargetRosterHash is required at runtime; use InspectRecoveryAuthorizationOffline for ceremony review")
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
	// Format-only check here. The binding to a specific roster body is
	// enforced by LoadRecoveryAuthorization's expectedTargetRosterHash
	// argument; runtime callers must pass a non-empty value to make that
	// gate fire. Validate must stay deterministic for canonicalization.
	if !targetRosterHashPattern.MatchString(b.TargetRosterHash) {
		return fmt.Errorf("%w: got %q", ErrRecoveryTargetHashFormat, b.TargetRosterHash)
	}
	if b.OperatorIdentity == "" {
		return ErrRecoveryOperatorRequired
	}
	return nil
}

// LoadRecoveryAuthorization is the runtime entry point for verifying a
// recovery authorization before applying it to a live roster. It reads,
// decodes, structurally validates, fingerprint-pins, time-window-checks,
// and signature-verifies the envelope, then enforces the target-roster
// binding against expectedTargetRosterHash.
//
// Empty expectedTargetRosterHash is rejected with ErrRecoveryTargetHashRequired:
// at runtime, an authorization that is not bound to a specific roster body is
// an authorization for ANY roster body, which is an authorization-bypass
// footgun in a security-boundary product. Ceremony tooling that needs to
// inspect a file before the target hash is known calls
// InspectRecoveryAuthorizationOffline instead.
//
// recoveryRootPublicKey is the raw 32-byte Ed25519 key. Pinning by fingerprint
// runs via VerifyFingerprint against pinnedRecoveryRootFingerprint before the
// signature check, so that passing the wrong key surfaces a fingerprint
// mismatch (more diagnostic) rather than a signature mismatch.
//
// Time-window checks (clock-skew bounded, against the now parameter):
//   - now < IssuedAt              -> ErrRecoveryNotYetValid (issued in future)
//   - now > ExpiresAt             -> ErrRecoveryExpired
//   - ExpiresAt - now > 1h        -> ErrRecoveryExpiryTooFar (replay guard)
//   - ExpiresAt <= IssuedAt       -> ErrRecoveryExpiresBeforeIssued
//   - ExpiresAt - IssuedAt > 1h   -> ErrRecoveryLifetimeTooLong (lifetime cap)
//
// The 1-hour ceiling is enforced both on the LIFETIME (issued -> expired)
// and the REMAINING WINDOW (now -> expired). Without the lifetime cap, an
// authorization issued days ago but with expires_at = now + 30m would slip
// past the replay guard while having an effective lifetime of days, which
// violates the design's bounded blast-radius requirement.
//
// There is no unsigned recovery path: callers must pass a valid signed
// envelope or get an error.
func LoadRecoveryAuthorization(
	path string,
	recoveryRootPublicKey []byte,
	pinnedRecoveryRootFingerprint string,
	expectedTargetRosterHash string,
	now time.Time,
) (*LoadedRecoveryAuthorization, error) {
	if expectedTargetRosterHash == "" {
		return nil, ErrRecoveryTargetHashRequired
	}
	return loadRecoveryAuthorizationCore(
		path, recoveryRootPublicKey, pinnedRecoveryRootFingerprint,
		expectedTargetRosterHash, now)
}

// InspectRecoveryAuthorizationOffline is the offline-ceremony entry point. It
// runs every check LoadRecoveryAuthorization performs except the target-roster
// binding, returning a verified envelope when the file is structurally and
// cryptographically valid against the pinned recovery-root.
//
// Use this only from offline ceremony tooling (the pipelock signing recovery
// verify CLI) where the operator is reviewing an authorization before a target
// roster body exists. Runtime callers must use LoadRecoveryAuthorization so the
// target binding is enforced.
func InspectRecoveryAuthorizationOffline(
	path string,
	recoveryRootPublicKey []byte,
	pinnedRecoveryRootFingerprint string,
	now time.Time,
) (*LoadedRecoveryAuthorization, error) {
	return loadRecoveryAuthorizationCore(
		path, recoveryRootPublicKey, pinnedRecoveryRootFingerprint,
		"", now)
}

// loadRecoveryAuthorizationCore is the shared verification path. It is
// unexported so callers must pick the runtime (LoadRecoveryAuthorization) or
// offline-ceremony (InspectRecoveryAuthorizationOffline) entry point and the
// target-binding policy is visible in the API surface, not buried in an
// argument default.
func loadRecoveryAuthorizationCore(
	path string,
	recoveryRootPublicKey []byte,
	pinnedRecoveryRootFingerprint string,
	expectedTargetRosterHash string,
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
	expiresAt, _ := time.Parse(time.RFC3339, envelope.Body.ExpiresAt)

	// Lifetime cap: expires must be after issued, and the gap must not
	// exceed the 1h ceiling. Without these, a stale authorization with a
	// short remaining window slips past the replay guard.
	if !expiresAt.After(issuedAt) {
		return nil, fmt.Errorf("%w: issued_at=%s, expires_at=%s",
			ErrRecoveryExpiresBeforeIssued, envelope.Body.IssuedAt, envelope.Body.ExpiresAt)
	}
	if expiresAt.Sub(issuedAt) > recoveryExpiryCeiling {
		return nil, fmt.Errorf("%w: lifetime=%s, ceiling=%s",
			ErrRecoveryLifetimeTooLong, expiresAt.Sub(issuedAt), recoveryExpiryCeiling)
	}

	if now.Before(issuedAt) {
		return nil, fmt.Errorf("%w: issued_at=%s, now=%s",
			ErrRecoveryNotYetValid, envelope.Body.IssuedAt, now.Format(time.RFC3339))
	}
	if now.After(expiresAt) {
		return nil, fmt.Errorf("%w: expires_at=%s, now=%s",
			ErrRecoveryExpired, envelope.Body.ExpiresAt, now.Format(time.RFC3339))
	}
	// Replay guard: even with a lawful 1h lifetime, the remaining window
	// must also be no more than 1h. Cheap to enforce; same ceiling.
	if expiresAt.Sub(now) > recoveryExpiryCeiling {
		return nil, fmt.Errorf("%w: expires_at=%s, now=%s, delta=%s",
			ErrRecoveryExpiryTooFar, envelope.Body.ExpiresAt, now.Format(time.RFC3339), expiresAt.Sub(now))
	}

	// Step 5b: Bind to expected target roster, when caller supplied one.
	// LoadRecoveryAuthorization rejects the empty case at the entry point;
	// only InspectRecoveryAuthorizationOffline reaches here with empty
	// expectedTargetRosterHash.
	if expectedTargetRosterHash != "" && envelope.Body.TargetRosterHash != expectedTargetRosterHash {
		return nil, fmt.Errorf("%w: got %q, want %q",
			ErrRecoveryTargetHashMismatch, envelope.Body.TargetRosterHash, expectedTargetRosterHash)
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

	// Step 8: Compute the canonical fingerprint from the verified key
	// rather than echoing back the operator-supplied input. ParseFingerprint
	// accepts uppercase hex and normalizes; persisting the canonical form
	// keeps audit records consistent across systems regardless of how the
	// operator typed the pin in.
	canonicalFP, fpErr := Fingerprint(recoveryRootPublicKey)
	if fpErr != nil {
		// Unreachable: VerifyFingerprint above already proved key length is
		// 32 bytes, which is the only way Fingerprint fails. Preserve the
		// fail-closed invariant explicitly anyway.
		return nil, fmt.Errorf("%w: canonical fingerprint: %w", ErrRecoveryFingerprintMismatch, fpErr)
	}

	return &LoadedRecoveryAuthorization{
		Body:                    envelope.Body,
		Signature:               envelope.Signature,
		RecoveryRootFingerprint: canonicalFP,
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
