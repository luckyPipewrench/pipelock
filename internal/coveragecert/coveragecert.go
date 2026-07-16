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
	"unicode"

	"github.com/luckyPipewrench/pipelock/internal/contract"
	"golang.org/x/text/unicode/norm"
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

const (
	anchorLocal = "local"
	anchorNone  = "none"

	completenessLimited    = "LIMITED"
	completenessBroken     = "BROKEN"
	completenessUnverified = "UNVERIFIED"

	reasonBoundedClosed    = "bounded_closed"
	reasonAbnormalEnd      = "abnormal_end"
	reasonOpenAction       = "open_action"
	reasonHeartbeatGap     = "heartbeat_gap"
	reasonNoOpen           = "no_open"
	reasonNoLifecycle      = "no_lifecycle"
	reasonRecorderDisabled = "recorder_disabled"
	reasonNoReceipts       = "no_receipts"
	reasonChainBroken      = "chain_broken"
)

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
	SignatureValid  bool     `json:"signature_valid"`
	AggregateValid  bool     `json:"aggregate_valid"`
	StructuralValid bool     `json:"structural_valid"`
	SignerTrusted   bool     `json:"signer_trusted"`
	Body            Body     `json:"body"`
	Lines           []string `json:"lines"`
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
	if _, err := requireCanonicalBody(b, b.TrustedSignerKey); err != nil {
		return err
	}
	return nil
}

func deriveCanonicalBody(b Body, signerKey string) (Body, error) {
	if err := validateCoverageCertSignerKey(signerKey); err != nil {
		return Body{}, fmt.Errorf("%w: trusted_signer_key: %w", ErrBodyInvalid, err)
	}
	if err := validateCoverageCertIdentifier("agent", b.Agent); err != nil {
		return Body{}, err
	}
	if b.WindowStart.IsZero() {
		return Body{}, fmt.Errorf("%w: window_start is required", ErrBodyInvalid)
	}
	if b.WindowEnd.IsZero() {
		return Body{}, fmt.Errorf("%w: window_end is required", ErrBodyInvalid)
	}
	if b.WindowEnd.Before(b.WindowStart) {
		return Body{}, fmt.Errorf("%w: window_end (%s) is before window_start (%s)",
			ErrBodyInvalid, b.WindowEnd.Format(time.RFC3339Nano), b.WindowStart.Format(time.RFC3339Nano))
	}

	canonicalSessions, totalReceipts, chainsIntact, chainsBroken, chainGaps, err := deriveCanonicalSessions(b)
	if err != nil {
		return Body{}, err
	}
	if totalReceipts > 0 && !b.WindowEnd.After(b.WindowStart) {
		return Body{}, fmt.Errorf("%w: window_end must be after window_start when receipts are present", ErrBodyInvalid)
	}

	canonical := b
	canonical.Schema = Schema
	canonical.KeyPurpose = KeyPurpose
	canonical.Sessions = canonicalSessions
	canonical.TotalReceipts = totalReceipts
	canonical.ChainGaps = chainGaps
	canonical.SessionsCovered = len(canonicalSessions)
	canonical.ChainsIntact = chainsIntact
	canonical.ChainsBroken = chainsBroken
	canonical.TrustedSignerKey = signerKey
	canonical.Boundary = DefaultBoundary()
	canonical.StandingExclusions = DefaultStandingExclusions()
	return canonical, nil
}

func requireCanonicalBody(b Body, signerKey string) (Body, error) {
	canonical, err := deriveCanonicalBody(b, signerKey)
	if err != nil {
		return Body{}, err
	}
	if b.TrustedSignerKey != signerKey {
		return Body{}, fmt.Errorf("%w: body trusted_signer_key does not match certificate signer_key", ErrBodyInvalid)
	}
	equal, err := bodiesCanonicalEqual(b, canonical)
	if err != nil {
		return Body{}, fmt.Errorf("%w: compare canonical body: %w", ErrBodyInvalid, err)
	}
	if !equal {
		mismatches := rederiveAggregates(b)
		if len(mismatches) > 0 {
			return Body{}, fmt.Errorf("%w: %w: %s", ErrBodyInvalid, ErrAggregateMismatch, strings.Join(mismatches, "; "))
		}
		return Body{}, fmt.Errorf("%w: signed body is not the canonical coverage certificate body", ErrBodyInvalid)
	}
	return canonical, nil
}

func bodiesCanonicalEqual(a, b Body) (bool, error) {
	aPreimage, err := a.SignablePreimage()
	if err != nil {
		return false, err
	}
	bPreimage, err := b.SignablePreimage()
	if err != nil {
		return false, err
	}
	return bytes.Equal(aPreimage, bPreimage), nil
}

func deriveCanonicalSessions(b Body) ([]SessionCoverage, uint64, int, int, uint64, error) {
	if b.Sessions == nil {
		return nil, 0, 0, 0, 0, fmt.Errorf("%w: sessions must be an array, not null", ErrBodyInvalid)
	}
	canonicalSessions := make([]SessionCoverage, len(b.Sessions))
	copy(canonicalSessions, b.Sessions)
	seen := make(map[string]struct{}, len(canonicalSessions))
	var totalReceipts uint64
	var chainsIntact, chainsBroken int
	var chainGaps uint64
	var previousID string
	for i, s := range canonicalSessions {
		if err := validateSessionCoverage(i, s); err != nil {
			return nil, 0, 0, 0, 0, err
		}
		normalizedID := norm.NFC.String(s.ID)
		if _, ok := seen[normalizedID]; ok {
			return nil, 0, 0, 0, 0, fmt.Errorf("%w: duplicate session id %s after NFC normalization", ErrBodyInvalid, safeQuotedVerifyValue(normalizedID))
		}
		seen[normalizedID] = struct{}{}
		if i > 0 && previousID > normalizedID {
			return nil, 0, 0, 0, 0, fmt.Errorf("%w: sessions must be sorted by normalized id", ErrBodyInvalid)
		}
		previousID = normalizedID
		if math.MaxUint64-totalReceipts < s.ReceiptCount {
			return nil, 0, 0, 0, 0, fmt.Errorf("%w: total_receipts overflow", ErrBodyInvalid)
		}
		totalReceipts += s.ReceiptCount
		if s.ChainIntact {
			chainsIntact++
		} else {
			chainsBroken++
			chainGaps++
		}
	}
	return canonicalSessions, totalReceipts, chainsIntact, chainsBroken, chainGaps, nil
}

func validateSessionCoverage(index int, s SessionCoverage) error {
	label := fmt.Sprintf("sessions[%d]", index)
	if err := validateCoverageCertIdentifier(label+".id", s.ID); err != nil {
		return err
	}
	switch s.Anchored {
	case anchorLocal, anchorNone:
	default:
		return fmt.Errorf("%w: %s.anchored=%s is not in the coverage certificate vocabulary", ErrBodyInvalid, label, safeQuotedVerifyValue(s.Anchored))
	}
	if err := validateCompletenessCoupling(s); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrBodyInvalid, label, err)
	}
	if !s.ChainIntact && (s.CompletenessStatus != completenessBroken || s.CompletenessReason != reasonChainBroken) {
		return fmt.Errorf("%w: %s: broken chains must report BROKEN/chain_broken completeness", ErrBodyInvalid, label)
	}
	return nil
}

func validateCoverageCertIdentifier(label, value string) error {
	if value == "" {
		return fmt.Errorf("%w: %s is required", ErrBodyInvalid, label)
	}
	if value != strings.TrimSpace(value) {
		return fmt.Errorf("%w: %s must not have leading or trailing whitespace", ErrBodyInvalid, label)
	}
	if value != norm.NFC.String(value) {
		return fmt.Errorf("%w: %s must be NFC-normalized", ErrBodyInvalid, label)
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			return fmt.Errorf("%w: %s must not contain control, format, or line-separator characters", ErrBodyInvalid, label)
		}
	}
	return nil
}

func validateCompletenessCoupling(s SessionCoverage) error {
	switch s.CompletenessStatus {
	case completenessLimited:
		switch s.CompletenessReason {
		case reasonBoundedClosed, reasonAbnormalEnd, reasonOpenAction, reasonHeartbeatGap:
		default:
			return fmt.Errorf("LIMITED completeness cannot use reason %s", safeQuotedVerifyValue(s.CompletenessReason))
		}
	case completenessBroken:
		if s.CompletenessReason != reasonChainBroken {
			return fmt.Errorf("BROKEN completeness cannot use reason %s", safeQuotedVerifyValue(s.CompletenessReason))
		}
	case completenessUnverified:
		switch s.CompletenessReason {
		case reasonNoOpen, reasonNoLifecycle, reasonRecorderDisabled, reasonNoReceipts:
		default:
			return fmt.Errorf("UNVERIFIED completeness cannot use reason %s", safeQuotedVerifyValue(s.CompletenessReason))
		}
	default:
		return fmt.Errorf("completeness_status=%s is not in the coverage certificate vocabulary", safeQuotedVerifyValue(s.CompletenessStatus))
	}
	if s.ReceiptCount == 0 && s.CompletenessReason != reasonNoReceipts {
		return fmt.Errorf("zero receipt_count requires UNVERIFIED/no_receipts completeness")
	}
	if s.ReceiptCount > 0 && s.CompletenessReason == reasonNoReceipts {
		return fmt.Errorf("UNVERIFIED/no_receipts cannot have positive receipt_count")
	}
	return nil
}

// Sign validates the body, computes the canonical preimage, and signs it.
// Returns a Certificate with hex-encoded signature and signer public key.
// Refuses to sign an ill-formed or over-claiming body.
func Sign(b Body, priv ed25519.PrivateKey) (Certificate, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Certificate{}, fmt.Errorf("%w: private key length %d, want %d", ErrSignFailed, len(priv), ed25519.PrivateKeySize)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return Certificate{}, fmt.Errorf("%w: private key did not yield an Ed25519 public key", ErrSignFailed)
	}
	pubHex := hex.EncodeToString(pub)
	canonical, err := requireCanonicalBody(b, pubHex)
	if err != nil {
		return Certificate{}, fmt.Errorf("%w: %w", ErrSignFailed, err)
	}
	preimage, err := canonical.SignablePreimage()
	if err != nil {
		return Certificate{}, fmt.Errorf("%w: %w", ErrSignFailed, err)
	}
	sig := ed25519.Sign(priv, preimage)
	return Certificate{
		Body:      canonical,
		Signature: hex.EncodeToString(sig),
		SignerKey: pubHex,
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
	canonical, err := requireCanonicalBody(cert.Body, cert.SignerKey)
	if err != nil {
		if mismatches := rederiveAggregates(cert.Body); len(mismatches) > 0 {
			result.AggregateValid = false
			result.Lines = buildInvalidBodyVerifyLines(cert, result, mismatches)
		}
		return result, fmt.Errorf("%w: body: %w", ErrVerifyFailed, err)
	}

	// Decode signature.
	sigBytes, err := hex.DecodeString(cert.Signature)
	if err != nil {
		return result, fmt.Errorf("%w: decode signature: %w", ErrVerifyFailed, err)
	}

	// Recompute preimage from the body.
	preimage, err := canonical.SignablePreimage()
	if err != nil {
		return result, fmt.Errorf("%w: recompute preimage: %w", ErrVerifyFailed, err)
	}

	// Verify signature.
	result.SignatureValid = ed25519.Verify(signerKeyBytes, preimage, sigBytes)
	if !result.SignatureValid {
		result.StructuralValid = false
		result.Lines = buildVerifyLines(cert, result, nil)
		return result, fmt.Errorf("%w: signature is invalid", ErrVerifyFailed)
	}
	result.AggregateValid = true
	result.StructuralValid = true

	// Check signer trust (NEVER TOFU).
	if trustedKeys != nil {
		_, result.SignerTrusted = trustedKeys[cert.SignerKey]
		if !result.SignerTrusted {
			result.Lines = buildVerifyLines(cert, result, nil)
			return result, fmt.Errorf("%w: signer is not in the trusted-signer set", ErrVerifyFailed)
		}
	}

	// Build bounded per-fact lines.
	result.Lines = buildVerifyLines(cert, result, nil)

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
	lines := buildVerifyStatusLines(cert, result)

	// Agent.
	if b.Agent != "" {
		lines = append(lines, fmt.Sprintf("Agent: %s", safeVerifyLineValue(b.Agent)))
	} else {
		lines = append(lines, "Agent: not reported")
	}

	// Window.
	lines = append(lines, fmt.Sprintf("Window: %s to %s",
		b.WindowStart.Format(time.RFC3339Nano), b.WindowEnd.Format(time.RFC3339Nano)))

	// Sessions.
	lines = append(lines, fmt.Sprintf("Sessions covered: %d", b.SessionsCovered))
	lines = append(lines, fmt.Sprintf("Total receipts: %d", b.TotalReceipts))
	lines = append(lines, fmt.Sprintf("Chain gaps: %d", b.ChainGaps))
	lines = append(lines, fmt.Sprintf("Chains intact: %d", b.ChainsIntact))
	lines = append(lines, fmt.Sprintf("Chains broken: %d", b.ChainsBroken))

	lines = append(lines, mismatches...)

	// Boundary.
	if b.Boundary != "" {
		lines = append(lines, fmt.Sprintf("Boundary: %s", safeVerifyLineValue(b.Boundary)))
	} else {
		lines = append(lines, "Boundary: not reported")
	}

	// Standing exclusions.
	for _, ex := range b.StandingExclusions {
		lines = append(lines, fmt.Sprintf("Exclusion: %s", safeVerifyLineValue(ex)))
	}

	return lines
}

func buildInvalidBodyVerifyLines(cert Certificate, result VerifyResult, mismatches []string) []string {
	lines := buildVerifyStatusLines(cert, result)
	lines = append(lines, "Body: INVALID (not canonical)")
	lines = append(lines, mismatches...)
	return lines
}

func buildVerifyStatusLines(cert Certificate, result VerifyResult) []string {
	var lines []string
	if result.SignatureValid {
		lines = append(lines, "Signature: valid (Ed25519 over canonical preimage)")
	} else {
		lines = append(lines, "Signature: INVALID")
	}
	if result.SignerTrusted {
		lines = append(lines, fmt.Sprintf("Signer: TRUSTED (key %s...%s)",
			cert.SignerKey[:8], cert.SignerKey[len(cert.SignerKey)-8:]))
	} else {
		lines = append(lines, fmt.Sprintf("Signer: NOT TRUSTED (key %s...%s)",
			cert.SignerKey[:8], cert.SignerKey[len(cert.SignerKey)-8:]))
	}
	return lines
}

func safeVerifyLineValue(value string) string {
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 0x20 && r <= 0x7e && r != '\\':
			b.WriteRune(r)
		case r == '\\':
			b.WriteString(`\\`)
		case r <= 0xffff:
			_, _ = fmt.Fprintf(&b, `\u%04x`, r)
		default:
			_, _ = fmt.Fprintf(&b, `\U%08x`, r)
		}
	}
	return b.String()
}

func safeQuotedVerifyValue(value string) string {
	return `"` + safeVerifyLineValue(value) + `"`
}

// Marshal serializes a Certificate to JSON.
func Marshal(cert Certificate) ([]byte, error) {
	return json.MarshalIndent(cert, "", "  ")
}

// Unmarshal deserializes a Certificate from JSON.
func Unmarshal(data []byte) (Certificate, error) {
	if _, err := contract.ParseJSONStrict(data); err != nil {
		return Certificate{}, fmt.Errorf("unmarshal coverage certificate: %w", err)
	}
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
