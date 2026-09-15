// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package authority

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/jcs"
	"golang.org/x/text/unicode/norm"
)

const (
	localReferencePrefix = "plauth1"
	localSchemaVersion   = 1
	// localCanonJCSRFC8785NFC is the existing AARP canonicalization profile.
	// It is explicit in newly issued references so verifiers do not infer a
	// signing scheme from an implementation detail.
	localCanonJCSRFC8785NFC = "jcs-rfc8785-nfc"
	// MaxReferenceBytes bounds authority references accepted from every
	// transport and by the local verifier.
	MaxReferenceBytes = 16 << 10
)

var errMalformedReference = errors.New("malformed local authority reference")

// LocalConfig configures an in-process reference verifier. TrustedIssuers and
// RevokedReferences are copied by NewLocalVerifier. Clock is optional and is
// intended for deterministic verification and conformance tests.
type LocalConfig struct {
	TrustedIssuers    map[string]ed25519.PublicKey
	RevokedReferences map[string]struct{}
	Clock             func() time.Time
}

// LocalVerifier verifies compact Ed25519 references against an in-memory key
// set. Legacy schema-1 references that omit canon use byte-exact RFC 8785 JCS.
// References with canon "jcs-rfc8785-nfc" use the AARP NFC profile. Both forms
// compare verified authority strings byte-for-byte; verification never changes
// an actor, action, or destination before matching. It performs no I/O.
type LocalVerifier struct {
	trustedIssuers    map[string]ed25519.PublicKey
	revokedReferences map[string]struct{}
	now               func() time.Time
}

// NewLocalVerifier constructs an in-process verifier and defensively copies its
// key and revocation inputs.
func NewLocalVerifier(config LocalConfig) (*LocalVerifier, error) {
	if len(config.TrustedIssuers) == 0 {
		return nil, errors.New("authority: at least one trusted issuer is required")
	}

	trustedIssuers := make(map[string]ed25519.PublicKey, len(config.TrustedIssuers))
	for issuer, publicKey := range config.TrustedIssuers {
		if strings.TrimSpace(issuer) == "" {
			return nil, errors.New("authority: trusted issuer name is required")
		}
		if len(publicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("authority: issuer %q public key length=%d, want %d", issuer, len(publicKey), ed25519.PublicKeySize)
		}
		trustedIssuers[issuer] = append(ed25519.PublicKey(nil), publicKey...)
	}

	revokedReferences := make(map[string]struct{}, len(config.RevokedReferences))
	for reference := range config.RevokedReferences {
		if strings.TrimSpace(reference) == "" {
			return nil, errors.New("authority: revoked reference name is required")
		}
		revokedReferences[reference] = struct{}{}
	}

	now := config.Clock
	if now == nil {
		now = time.Now
	}
	return &LocalVerifier{
		trustedIssuers:    trustedIssuers,
		revokedReferences: revokedReferences,
		now:               now,
	}, nil
}

// Verify checks a compact local reference without performing network or file
// I/O. Request fields are compared byte-for-byte; their canonical construction
// and equality rules remain outside this slice.
func (v *LocalVerifier) Verify(ctx context.Context, request Request) Result {
	if result, done := contextResult(ctx); done {
		return result
	}

	parsed, err := parseLocalReference(request.AuthorityRef)
	if err != nil {
		return Result{Decision: DecisionDeny, Reason: ReasonMalformedReference}
	}
	publicKey, trusted := v.trustedIssuers[parsed.payload.Issuer]
	if !trusted {
		return Result{Decision: DecisionDeny, Reason: ReasonUntrustedIssuer}
	}
	if !ed25519.Verify(publicKey, parsed.signingInput, parsed.signature) {
		return Result{Decision: DecisionDeny, Reason: ReasonInvalidSignature}
	}

	expiresAt, err := validateGrant(parsed.payload)
	if err != nil {
		return Result{Decision: DecisionDeny, Reason: ReasonMalformedReference}
	}
	verified := Result{
		Decision:  DecisionDeny,
		Issuer:    parsed.payload.Issuer,
		Reference: parsed.payload.Reference,
		ExpiresAt: expiresAt,
	}

	if result, done := contextResult(ctx); done {
		return result
	}
	if _, revoked := v.revokedReferences[parsed.payload.Reference]; revoked {
		verified.Reason = ReasonRevoked
		return verified
	}
	if !v.now().Before(expiresAt) {
		verified.Reason = ReasonExpired
		return verified
	}
	if request.Actor != parsed.payload.Actor {
		verified.Reason = ReasonActorMismatch
		return verified
	}
	if request.Action != parsed.payload.Action {
		verified.Reason = ReasonActionMismatch
		return verified
	}
	if request.Destination != parsed.payload.Destination {
		verified.Reason = ReasonDestinationMismatch
		return verified
	}

	verified.Decision = DecisionAllow
	verified.Reason = ReasonMatched
	return verified
}

type localGrant struct {
	SchemaVersion int    `json:"schema_version"`
	Canon         string `json:"canon,omitempty"`
	Issuer        string `json:"issuer"`
	Reference     string `json:"reference"`
	Actor         string `json:"actor"`
	Action        string `json:"action"`
	Destination   string `json:"destination"`
	ExpiresAt     string `json:"expires_at"`
}

type parsedReference struct {
	payload      localGrant
	signingInput []byte
	signature    []byte
}

func parseLocalReference(reference string) (parsedReference, error) {
	if len(reference) == 0 || len(reference) > MaxReferenceBytes {
		return parsedReference{}, errMalformedReference
	}
	parts := strings.Split(reference, ".")
	if len(parts) != 3 || parts[0] != localReferencePrefix || parts[1] == "" || parts[2] == "" {
		return parsedReference{}, errMalformedReference
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(payloadBytes) == 0 {
		return parsedReference{}, errMalformedReference
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return parsedReference{}, errMalformedReference
	}
	tree, err := jcs.Parse(payloadBytes)
	if err != nil {
		return parsedReference{}, errMalformedReference
	}
	object, ok := tree.(map[string]any)
	if !ok {
		return parsedReference{}, errMalformedReference
	}
	for field := range object {
		if field != "canon" && strings.EqualFold(field, "canon") {
			return parsedReference{}, errMalformedReference
		}
	}
	canon, present := object["canon"]
	if present {
		if profile, ok := canon.(string); !ok || profile != localCanonJCSRFC8785NFC {
			return parsedReference{}, errMalformedReference
		}
		if err := validateNFCGrantStrings(object); err != nil {
			return parsedReference{}, errMalformedReference
		}
	}
	canonical, err := jcs.Marshal(object)
	if err != nil || !bytes.Equal(canonical, payloadBytes) {
		return parsedReference{}, errMalformedReference
	}

	var payload localGrant
	decoder := json.NewDecoder(bytes.NewReader(payloadBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return parsedReference{}, errMalformedReference
	}

	return parsedReference{
		payload:      payload,
		signingInput: []byte(localReferencePrefix + "." + parts[1]),
		signature:    signature,
	}, nil
}

// validateNFCGrantStrings rejects non-NFC signed identity and scope strings.
// It never rewrites them: matching remains byte-exact after verification.
func validateNFCGrantStrings(grant map[string]any) error {
	// JSON struct decoding accepts case-insensitive field aliases. The named
	// profile uses exact field names so an alias cannot escape validation.
	for field := range grant {
		switch field {
		case "schema_version", "canon", "issuer", "reference", "actor", "action", "destination", "expires_at":
		default:
			return errMalformedReference
		}
	}
	for _, field := range []string{"canon", "issuer", "reference", "actor", "action", "destination", "expires_at"} {
		value, present := grant[field]
		if !present {
			continue
		}
		text, ok := value.(string)
		if !ok || !norm.NFC.IsNormalString(text) {
			return errMalformedReference
		}
	}
	return nil
}

func validateGrant(grant localGrant) (time.Time, error) {
	if grant.SchemaVersion != localSchemaVersion ||
		strings.TrimSpace(grant.Issuer) == "" ||
		strings.TrimSpace(grant.Reference) == "" ||
		grant.Actor == "" || grant.Action == "" || grant.Destination == "" || grant.ExpiresAt == "" {
		return time.Time{}, errMalformedReference
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, grant.ExpiresAt)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: expiry: %w", errMalformedReference, err)
	}
	return expiresAt, nil
}

func contextResult(ctx context.Context) (Result, bool) {
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return Result{Decision: DecisionIndeterminate, Reason: ReasonTimeout}, true
		}
		return Result{Decision: DecisionIndeterminate, Reason: ReasonCanceled}, true
	}
	return Result{}, false
}
