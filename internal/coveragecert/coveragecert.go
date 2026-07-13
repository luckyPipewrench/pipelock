// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package coveragecert defines the coverage certificate format
// (sign and verify) for bounded coverage attestation over a time window.
// The FORMAT and VERIFY operations are free/offline (Apache 2.0).
// Only GENERATION is license-gated in the enterprise CLI.
package coveragecert

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/contract"
)

// Schema is the certificate schema identifier.
const Schema = "pipelock.coverage_cert.v1"

// KeyPurpose is the key purpose for coverage certificate signing keys.
// This is a local constant; does NOT edit internal/signing/key_purpose.go.
const KeyPurpose = "coverage-cert-signing"

// requiredBoundaryPhrase is the substring that must appear in every Body.Boundary.
const requiredBoundaryPhrase = "mediated egress inside the declared Pipelock boundary"

// standingExclusionMediated is the standing exclusion about unmediated egress.
const standingExclusionMediated = "mediated evidence cannot prove unmediated egress did not occur"

// standingExclusionWallClock is the standing exclusion about wall-clock completeness.
const standingExclusionWallClock = "local recorder evidence cannot prove wall-clock completeness without external witnessing"

// Sentinel errors.
var (
	ErrBodyInvalid       = errors.New("coverage certificate body validation failed")
	ErrSignFailed        = errors.New("coverage certificate signing failed")
	ErrVerifyFailed      = errors.New("coverage certificate verification failed")
	ErrAggregateMismatch = errors.New("signed aggregate counts do not match re-derived values from sessions")
)

// SessionCoverage holds per-session coverage data within a certificate.
type SessionCoverage struct {
	ID                 string `json:"id"`
	ReceiptCount       uint64 `json:"receipt_count"`
	ChainIntact        bool   `json:"chain_intact"`
	Anchored           string `json:"anchored"`
	CompletenessStatus string `json:"completeness_status"`
	CompletenessReason string `json:"completeness_reason"`
}

// Body is the signed payload of a coverage certificate.
type Body struct {
	Schema           string            `json:"schema"`
	KeyPurpose       string            `json:"key_purpose"`
	Agent            string            `json:"agent"`
	WindowStart      time.Time         `json:"window_start"`
	WindowEnd        time.Time         `json:"window_end"`
	Sessions         []SessionCoverage `json:"sessions"`
	TotalReceipts    uint64            `json:"total_receipts"`
	ChainGaps        uint64            `json:"chain_gaps"`
	SessionsCovered  int               `json:"sessions_covered"`
	ChainsIntact     int               `json:"chains_intact"`
	ChainsBroken     int               `json:"chains_broken"`
	TrustedSignerKey string            `json:"trusted_signer_key"`
	Boundary         string            `json:"boundary"`
	// StandingExclusions documents honest limits of the coverage attestation.
	StandingExclusions []string `json:"standing_exclusions"`
}

// Certificate is the wire format: the signed body + detached signature + signer key.
type Certificate struct {
	Body      Body   `json:"body"`
	Signature string `json:"signature"`
	SignerKey string `json:"signer_key"`
}

// VerifyResult is the output of offline verification.
type VerifyResult struct {
	SignatureValid bool     `json:"signature_valid"`
	SignerTrusted  bool     `json:"signer_trusted"`
	AggregateValid bool     `json:"aggregate_valid"`
	Body           Body     `json:"body"`
	Lines          []string `json:"lines"`
}

// SignablePreimage returns JCS-canonical bytes of the body for signing and
// verification. Mirrors the root_transition pattern: marshal -> ParseJSONStrict -> Canonicalize.
func (b Body) SignablePreimage() ([]byte, error) {
	raw, err := json.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("marshal coverage cert body: %w", err)
	}
	tree, err := contract.ParseJSONStrict(raw)
	if err != nil {
		return nil, fmt.Errorf("parse coverage cert for canonicalization: %w", err)
	}
	return contract.Canonicalize(tree)
}

// Validate checks structural invariants on the body. It refuses ill-formed or
// over-claiming bodies (fail closed). Called by Sign before signing.
func (b Body) Validate() error {
	if err := b.validateStructure(); err != nil {
		return err
	}
	if mismatches := rederiveAggregates(b); len(mismatches) > 0 {
		return fmt.Errorf("%w: %w: %s", ErrBodyInvalid, ErrAggregateMismatch, strings.Join(mismatches, "; "))
	}
	return nil
}

func (b Body) validateStructure() error {
	if b.Schema != Schema {
		return fmt.Errorf("%w: schema=%q, want %q", ErrBodyInvalid, b.Schema, Schema)
	}
	if b.KeyPurpose != KeyPurpose {
		return fmt.Errorf("%w: key_purpose=%q, want %q", ErrBodyInvalid, b.KeyPurpose, KeyPurpose)
	}
	if b.Agent == "" {
		return fmt.Errorf("%w: agent is required", ErrBodyInvalid)
	}
	if b.WindowEnd.Before(b.WindowStart) {
		return fmt.Errorf("%w: window_end (%s) is before window_start (%s)",
			ErrBodyInvalid, b.WindowEnd.Format(time.RFC3339), b.WindowStart.Format(time.RFC3339))
	}
	if !strings.Contains(b.Boundary, requiredBoundaryPhrase) {
		return fmt.Errorf("%w: boundary must contain %q", ErrBodyInvalid, requiredBoundaryPhrase)
	}
	// Refuse over-claiming: boundary must NOT claim "all agent activity".
	if strings.Contains(strings.ToLower(b.Boundary), "all agent activity") {
		return fmt.Errorf("%w: boundary must not claim coverage of all agent activity", ErrBodyInvalid)
	}
	if err := validateCoverageCertSignerKey(b.TrustedSignerKey); err != nil {
		return fmt.Errorf("%w: trusted_signer_key: %w", ErrBodyInvalid, err)
	}
	return nil
}

// Sign validates the body, computes the canonical preimage, and signs it.
// Returns a Certificate with hex-encoded signature and signer public key.
// Refuses to sign an ill-formed or over-claiming body.
func Sign(b Body, priv ed25519.PrivateKey) (Certificate, error) {
	if err := b.Validate(); err != nil {
		return Certificate{}, fmt.Errorf("%w: %w", ErrSignFailed, err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return Certificate{}, fmt.Errorf("%w: private key length %d, want %d", ErrSignFailed, len(priv), ed25519.PrivateKeySize)
	}
	preimage, err := b.SignablePreimage()
	if err != nil {
		return Certificate{}, fmt.Errorf("%w: %w", ErrSignFailed, err)
	}
	sig := ed25519.Sign(priv, preimage)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return Certificate{}, fmt.Errorf("%w: private key did not yield an Ed25519 public key", ErrSignFailed)
	}
	return Certificate{
		Body:      b,
		Signature: hex.EncodeToString(sig),
		SignerKey: hex.EncodeToString(pub),
	}, nil
}

// Verify performs offline verification of a certificate. It re-derives the
// canonical preimage, verifies the Ed25519 signature, checks the signer
// against the trusted key set (NEVER TOFU), and re-derives aggregate counts
// from Sessions to flag tamper/inconsistency. Returns VerifyResult with
// bounded per-fact lines.
func Verify(cert Certificate, trustedKeys map[string]struct{}) (VerifyResult, error) {
	result := VerifyResult{Body: cert.Body}

	// Decode signer key.
	signerKeyBytes, err := hex.DecodeString(cert.SignerKey)
	if err != nil {
		return result, fmt.Errorf("%w: decode signer key: %w", ErrVerifyFailed, err)
	}
	if len(signerKeyBytes) != ed25519.PublicKeySize {
		return result, fmt.Errorf("%w: signer key length %d, want %d",
			ErrVerifyFailed, len(signerKeyBytes), ed25519.PublicKeySize)
	}
	if err := cert.Body.validateStructure(); err != nil {
		return result, fmt.Errorf("%w: body: %w", ErrVerifyFailed, err)
	}
	if cert.Body.TrustedSignerKey != cert.SignerKey {
		return result, fmt.Errorf("%w: body trusted_signer_key does not match certificate signer_key", ErrVerifyFailed)
	}

	// Decode signature.
	sigBytes, err := hex.DecodeString(cert.Signature)
	if err != nil {
		return result, fmt.Errorf("%w: decode signature: %w", ErrVerifyFailed, err)
	}

	// Recompute preimage from the body.
	preimage, err := cert.Body.SignablePreimage()
	if err != nil {
		return result, fmt.Errorf("%w: recompute preimage: %w", ErrVerifyFailed, err)
	}

	// Verify signature.
	result.SignatureValid = ed25519.Verify(signerKeyBytes, preimage, sigBytes)

	// Check signer trust (NEVER TOFU).
	if trustedKeys != nil {
		_, result.SignerTrusted = trustedKeys[cert.SignerKey]
	}

	mismatches := rederiveAggregates(cert.Body)
	result.AggregateValid = len(mismatches) == 0

	// Build bounded per-fact lines.
	result.Lines = buildVerifyLines(cert, result, mismatches)

	return result, nil
}

func validateCoverageCertSignerKey(value string) error {
	keyBytes, err := hex.DecodeString(value)
	if err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if len(keyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("length %d, want %d", len(keyBytes), ed25519.PublicKeySize)
	}
	if value != strings.ToLower(value) {
		return errors.New("must be lowercase hex")
	}
	return nil
}

// rederiveAggregates recomputes aggregate counts from Sessions and returns
// any mismatch lines.
func rederiveAggregates(b Body) []string {
	var totalReceipts uint64
	var chainsIntact, chainsBroken int
	var chainGaps uint64
	overflow := false
	for _, s := range b.Sessions {
		if math.MaxUint64-totalReceipts < s.ReceiptCount {
			overflow = true
		}
		totalReceipts += s.ReceiptCount
		if s.ChainIntact {
			chainsIntact++
		} else {
			chainsBroken++
			chainGaps++
		}
	}
	sessionsCovered := len(b.Sessions)

	var mismatches []string
	if overflow {
		mismatches = append(mismatches, "MISMATCH: re-derived total_receipts overflowed uint64")
	}
	if totalReceipts != b.TotalReceipts {
		mismatches = append(mismatches,
			fmt.Sprintf("MISMATCH: signed total_receipts=%d, re-derived=%d", b.TotalReceipts, totalReceipts))
	}
	if chainGaps != b.ChainGaps {
		mismatches = append(mismatches,
			fmt.Sprintf("MISMATCH: signed chain_gaps=%d, re-derived=%d", b.ChainGaps, chainGaps))
	}
	if chainsIntact != b.ChainsIntact {
		mismatches = append(mismatches,
			fmt.Sprintf("MISMATCH: signed chains_intact=%d, re-derived=%d", b.ChainsIntact, chainsIntact))
	}
	if chainsBroken != b.ChainsBroken {
		mismatches = append(mismatches,
			fmt.Sprintf("MISMATCH: signed chains_broken=%d, re-derived=%d", b.ChainsBroken, chainsBroken))
	}
	if sessionsCovered != b.SessionsCovered {
		mismatches = append(mismatches,
			fmt.Sprintf("MISMATCH: signed sessions_covered=%d, re-derived=%d", b.SessionsCovered, sessionsCovered))
	}
	return mismatches
}

func buildVerifyLines(cert Certificate, result VerifyResult, mismatches []string) []string {
	b := cert.Body
	var lines []string

	// Signature line.
	if result.SignatureValid {
		lines = append(lines, "Signature: valid (Ed25519 over canonical preimage)")
	} else {
		lines = append(lines, "Signature: INVALID")
	}

	// Signer trust line.
	if result.SignerTrusted {
		lines = append(lines, fmt.Sprintf("Signer: TRUSTED (key %s...%s)",
			cert.SignerKey[:8], cert.SignerKey[len(cert.SignerKey)-8:]))
	} else {
		lines = append(lines, fmt.Sprintf("Signer: NOT TRUSTED (key %s...%s)",
			cert.SignerKey[:8], cert.SignerKey[len(cert.SignerKey)-8:]))
	}

	// Agent.
	if b.Agent != "" {
		lines = append(lines, fmt.Sprintf("Agent: %s", b.Agent))
	} else {
		lines = append(lines, "Agent: not reported")
	}

	// Window.
	lines = append(lines, fmt.Sprintf("Window: %s to %s",
		b.WindowStart.Format(time.RFC3339), b.WindowEnd.Format(time.RFC3339)))

	// Sessions.
	lines = append(lines, fmt.Sprintf("Sessions covered: %d", b.SessionsCovered))
	lines = append(lines, fmt.Sprintf("Total receipts: %d", b.TotalReceipts))
	lines = append(lines, fmt.Sprintf("Chain gaps: %d", b.ChainGaps))
	lines = append(lines, fmt.Sprintf("Chains intact: %d", b.ChainsIntact))
	lines = append(lines, fmt.Sprintf("Chains broken: %d", b.ChainsBroken))

	lines = append(lines, mismatches...)

	// Boundary.
	if b.Boundary != "" {
		lines = append(lines, fmt.Sprintf("Boundary: %s", b.Boundary))
	} else {
		lines = append(lines, "Boundary: not reported")
	}

	// Standing exclusions.
	for _, ex := range b.StandingExclusions {
		lines = append(lines, fmt.Sprintf("Exclusion: %s", ex))
	}

	return lines
}

// Marshal serializes a Certificate to JSON.
func Marshal(cert Certificate) ([]byte, error) {
	return json.MarshalIndent(cert, "", "  ")
}

// Unmarshal deserializes a Certificate from JSON.
func Unmarshal(data []byte) (Certificate, error) {
	var cert Certificate
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cert); err != nil {
		return Certificate{}, fmt.Errorf("unmarshal coverage certificate: %w", err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Certificate{}, fmt.Errorf("unmarshal coverage certificate: trailing JSON content")
	}
	return cert, nil
}

// DefaultBoundary returns the honest boundary sentence for a standard
// Pipelock coverage certificate (no kernel containment evidence).
func DefaultBoundary() string {
	return "Coverage of mediated egress inside the declared Pipelock boundary for the stated agent and window"
}

// DefaultStandingExclusions returns the two standing exclusions that every
// honest coverage certificate must carry.
func DefaultStandingExclusions() []string {
	return []string{
		standingExclusionMediated,
		standingExclusionWallClock,
	}
}
