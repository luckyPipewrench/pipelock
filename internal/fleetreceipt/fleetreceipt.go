// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package fleetreceipt verifies Fleet Receipt Reports: DSSE envelopes wrapping
// in-toto Statement v1 payloads with Pipelock's fleet-receipt/v1 predicate.
package fleetreceipt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	StatementType   = "https://in-toto.io/Statement/v1"
	PredicateType   = "https://pipelab.org/attestation/fleet-receipt/v1"
	DssePayloadType = "application/vnd.in-toto+json"

	VerificationLevelL1 = "L1"

	signatureAlgEd25519 = "ed25519"
	signaturePrefix     = "ed25519:"
)

var (
	ErrInvalidEnvelope  = errors.New("invalid fleet receipt envelope")
	ErrInvalidStatement = errors.New("invalid fleet receipt statement")
	ErrInvalidPredicate = errors.New("invalid fleet receipt predicate")
	ErrUntrustedKey     = errors.New("fleet receipt signer key is not trusted")
)

type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

type Signature struct {
	KeyID      string `json:"keyid"`
	KeyPurpose string `json:"key_purpose"`
	Algorithm  string `json:"algorithm"`
	Sig        string `json:"sig"`
}

type Statement struct {
	Type          string    `json:"_type"`
	Subject       []Subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     Predicate `json:"predicate"`
}

type Subject struct {
	Name   string `json:"name"`
	Digest Digest `json:"digest"`
}

type Digest struct {
	SHA256 string `json:"sha256"`
}

type Predicate struct {
	SchemaVersion        int                   `json:"schemaVersion"`
	ReportID             string                `json:"reportId"`
	GeneratedAt          string                `json:"generatedAt"`
	OrgID                string                `json:"orgId"`
	FleetID              string                `json:"fleetId"`
	ReportWindow         TimeWindow            `json:"reportWindow"`
	VerificationLevel    string                `json:"verificationLevel"`
	Conductor            Conductor             `json:"conductor"`
	SourceBatches        []SourceBatch         `json:"sourceBatches"`
	Summary              Summary               `json:"summary"`
	Completeness         Completeness          `json:"completeness"`
	Limits               []string              `json:"limits,omitempty"`
	ExternalCorrelations []ExternalCorrelation `json:"externalCorrelations,omitempty"`
}

type TimeWindow struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

type Conductor struct {
	ID      string `json:"id"`
	Version string `json:"version,omitempty"`
}

type SourceBatch struct {
	OrgID           string   `json:"orgId"`
	FleetID         string   `json:"fleetId"`
	InstanceID      string   `json:"instanceId"`
	BatchID         string   `json:"batchId"`
	SeqStart        uint64   `json:"seqStart"`
	SeqEnd          uint64   `json:"seqEnd"`
	EventCount      uint64   `json:"eventCount"`
	PayloadSHA256   string   `json:"payloadSha256"`
	PayloadBytes    uint64   `json:"payloadBytes"`
	EnvelopeHash    string   `json:"envelopeHash"`
	SegmentTailHash string   `json:"segmentTailHash"`
	DroppedCount    uint64   `json:"droppedCount"`
	EmittedAt       string   `json:"emittedAt"`
	ReceivedAt      string   `json:"receivedAt"`
	SignatureKeyIDs []string `json:"signatureKeyIds"`
}

type Summary struct {
	TotalActions uint64            `json:"totalActions"`
	ByFollower   map[string]uint64 `json:"byFollower,omitempty"`
	ByTransport  map[string]uint64 `json:"byTransport,omitempty"`
	ByActionType map[string]uint64 `json:"byActionType,omitempty"`
	ByVerdict    map[string]uint64 `json:"byVerdict,omitempty"`
	ByLayer      map[string]uint64 `json:"byLayer,omitempty"`
	BySeverity   map[string]uint64 `json:"bySeverity,omitempty"`
}

type Completeness struct {
	ObservedActions        uint64 `json:"observedActions"`
	DroppedObservedActions uint64 `json:"droppedObservedActions"`
	MediatedActions        uint64 `json:"mediatedActions"`
	MediatedFraction       string `json:"mediatedFraction"`
	Basis                  string `json:"basis"`
	Claim                  string `json:"claim"`
	NonClaim               string `json:"nonClaim"`
}

type ExternalCorrelation struct {
	System string `json:"system"`
	Ref    string `json:"ref"`
	Digest Digest `json:"digest,omitempty"`
}

type Verification struct {
	Statement        Statement
	SignerKeyID      string
	Trusted          bool
	Unpinned         bool
	PayloadSHA256    string
	SourceBatches    int
	TotalActions     uint64
	MediatedFraction string
}

func SignStatement(statement Statement, signerKeyID string, priv ed25519.PrivateKey) (Envelope, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Envelope{}, fmt.Errorf("%w: private key length=%d", ErrInvalidEnvelope, len(priv))
	}
	if err := statement.Validate(); err != nil {
		return Envelope{}, err
	}
	payload, err := CanonicalStatement(statement)
	if err != nil {
		return Envelope{}, err
	}
	if strings.TrimSpace(signerKeyID) == "" {
		signerKeyID = hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	}
	sig := ed25519.Sign(priv, pae(DssePayloadType, payload))
	return Envelope{
		PayloadType: DssePayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures: []Signature{{
			KeyID:      signerKeyID,
			KeyPurpose: signing.PurposeFleetReportSigning.String(),
			Algorithm:  signatureAlgEd25519,
			Sig:        signaturePrefix + base64.StdEncoding.EncodeToString(sig),
		}},
	}, nil
}

func Verify(data []byte, trustedKeys map[string]ed25519.PublicKey) (Verification, error) {
	env, err := UnmarshalEnvelope(data)
	if err != nil {
		return Verification{}, err
	}
	return VerifyEnvelope(env, trustedKeys)
}

func UnmarshalEnvelope(data []byte) (Envelope, error) {
	if err := jsonscan.RejectDuplicateKeys(data); err != nil {
		return Envelope{}, fmt.Errorf("%w: %w", ErrInvalidEnvelope, err)
	}
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return Envelope{}, fmt.Errorf("%w: %w", ErrInvalidEnvelope, err)
	}
	return env, nil
}

func VerifyEnvelope(env Envelope, trustedKeys map[string]ed25519.PublicKey) (Verification, error) {
	if env.PayloadType != DssePayloadType {
		return Verification{}, fmt.Errorf("%w: payloadType=%q", ErrInvalidEnvelope, env.PayloadType)
	}
	if len(env.Signatures) != 1 {
		return Verification{}, fmt.Errorf("%w: signatures=%d want 1", ErrInvalidEnvelope, len(env.Signatures))
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return Verification{}, fmt.Errorf("%w: decode payload: %w", ErrInvalidEnvelope, err)
	}
	statement, err := ParseStatement(payload)
	if err != nil {
		return Verification{}, err
	}
	if err := statement.Validate(); err != nil {
		return Verification{}, err
	}
	canonical, err := CanonicalStatement(statement)
	if err != nil {
		return Verification{}, err
	}
	if !bytes.Equal(payload, canonical) {
		return Verification{}, fmt.Errorf("%w: payload is not canonical JCS", ErrInvalidEnvelope)
	}
	sig := env.Signatures[0]
	if sig.KeyPurpose != signing.PurposeFleetReportSigning.String() {
		return Verification{}, fmt.Errorf("%w: key_purpose=%q", ErrInvalidEnvelope, sig.KeyPurpose)
	}
	if sig.Algorithm != signatureAlgEd25519 {
		return Verification{}, fmt.Errorf("%w: algorithm=%q", ErrInvalidEnvelope, sig.Algorithm)
	}
	rawSig, err := decodeSignature(sig.Sig)
	if err != nil {
		return Verification{}, err
	}
	pub, trusted, err := resolveVerifierKey(sig.KeyID, trustedKeys)
	if err != nil {
		return Verification{}, err
	}
	if !ed25519.Verify(pub, pae(env.PayloadType, payload), rawSig) {
		return Verification{}, fmt.Errorf("%w: signature verification failed", ErrInvalidEnvelope)
	}
	sum := sha256.Sum256(payload)
	return Verification{
		Statement:        statement,
		SignerKeyID:      sig.KeyID,
		Trusted:          trusted,
		Unpinned:         !trusted,
		PayloadSHA256:    hex.EncodeToString(sum[:]),
		SourceBatches:    len(statement.Predicate.SourceBatches),
		TotalActions:     statement.Predicate.Summary.TotalActions,
		MediatedFraction: statement.Predicate.Completeness.MediatedFraction,
	}, nil
}

func ParseStatement(payload []byte) (Statement, error) {
	if _, err := contract.ParseJSONStrict(payload); err != nil {
		return Statement{}, fmt.Errorf("%w: %w", ErrInvalidStatement, err)
	}
	var statement Statement
	if err := json.Unmarshal(payload, &statement); err != nil {
		return Statement{}, fmt.Errorf("%w: %w", ErrInvalidStatement, err)
	}
	return statement, nil
}

func CanonicalStatement(statement Statement) ([]byte, error) {
	raw, err := json.Marshal(statement)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal statement: %w", ErrInvalidStatement, err)
	}
	tree, err := contract.ParseJSONStrict(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: parse statement: %w", ErrInvalidStatement, err)
	}
	return contract.Canonicalize(tree)
}

func (s Statement) Validate() error {
	if s.Type != StatementType {
		return fmt.Errorf("%w: _type=%q", ErrInvalidStatement, s.Type)
	}
	if s.PredicateType != PredicateType {
		return fmt.Errorf("%w: predicateType=%q", ErrInvalidStatement, s.PredicateType)
	}
	if len(s.Subject) == 0 {
		return fmt.Errorf("%w: subject required", ErrInvalidStatement)
	}
	if err := s.Predicate.Validate(); err != nil {
		return err
	}
	return validateSubjects(s.Subject, s.Predicate.SourceBatches)
}

func (p Predicate) Validate() error {
	if p.SchemaVersion != 1 {
		return fmt.Errorf("%w: schemaVersion=%d", ErrInvalidPredicate, p.SchemaVersion)
	}
	for _, item := range []struct {
		name, value string
	}{
		{"reportId", p.ReportID},
		{"generatedAt", p.GeneratedAt},
		{"orgId", p.OrgID},
		{"fleetId", p.FleetID},
		{"reportWindow.start", p.ReportWindow.Start},
		{"reportWindow.end", p.ReportWindow.End},
		{"conductor.id", p.Conductor.ID},
		{"completeness.basis", p.Completeness.Basis},
		{"completeness.claim", p.Completeness.Claim},
		{"completeness.nonClaim", p.Completeness.NonClaim},
	} {
		if strings.TrimSpace(item.value) == "" {
			return fmt.Errorf("%w: %s required", ErrInvalidPredicate, item.name)
		}
	}
	if _, err := parseTime("generatedAt", p.GeneratedAt); err != nil {
		return err
	}
	start, err := parseTime("reportWindow.start", p.ReportWindow.Start)
	if err != nil {
		return err
	}
	end, err := parseTime("reportWindow.end", p.ReportWindow.End)
	if err != nil {
		return err
	}
	if !end.After(start) {
		return fmt.Errorf("%w: reportWindow.end must be after start", ErrInvalidPredicate)
	}
	if p.VerificationLevel != VerificationLevelL1 {
		return fmt.Errorf("%w: verificationLevel=%q", ErrInvalidPredicate, p.VerificationLevel)
	}
	if len(p.SourceBatches) == 0 {
		return fmt.Errorf("%w: sourceBatches required", ErrInvalidPredicate)
	}
	if err := validateSourceBatches(p.OrgID, p.FleetID, p.SourceBatches); err != nil {
		return err
	}
	if err := p.validateSummary(); err != nil {
		return err
	}
	return p.validateCompleteness()
}

func (p Predicate) validateSummary() error {
	if p.Summary.TotalActions == 0 {
		return fmt.Errorf("%w: summary.totalActions required", ErrInvalidPredicate)
	}
	for _, item := range []struct {
		name   string
		counts map[string]uint64
	}{
		{"byFollower", p.Summary.ByFollower},
		{"byTransport", p.Summary.ByTransport},
		{"byActionType", p.Summary.ByActionType},
		{"byVerdict", p.Summary.ByVerdict},
		{"byLayer", p.Summary.ByLayer},
		{"bySeverity", p.Summary.BySeverity},
	} {
		sum, err := validateCountMap(item.name, item.counts)
		if err != nil {
			return err
		}
		if len(item.counts) > 0 && sum != p.Summary.TotalActions {
			return fmt.Errorf("%w: summary.%s totals %d, want %d", ErrInvalidPredicate, item.name, sum, p.Summary.TotalActions)
		}
	}
	return nil
}

func (p Predicate) validateCompleteness() error {
	c := p.Completeness
	if c.ObservedActions != p.Summary.TotalActions {
		return fmt.Errorf("%w: completeness.observedActions=%d totalActions=%d", ErrInvalidPredicate, c.ObservedActions, p.Summary.TotalActions)
	}
	if c.MediatedActions > c.ObservedActions {
		return fmt.Errorf("%w: mediatedActions exceeds observedActions", ErrInvalidPredicate)
	}
	fraction, err := parseUnitDecimal("completeness.mediatedFraction", c.MediatedFraction)
	if err != nil {
		return err
	}
	want := new(big.Rat).SetFrac(
		new(big.Int).SetUint64(c.MediatedActions),
		new(big.Int).SetUint64(c.ObservedActions),
	)
	if fraction.Cmp(want) != 0 {
		return fmt.Errorf("%w: completeness.mediatedFraction=%s want %s/%s", ErrInvalidPredicate, c.MediatedFraction, want.Num(), want.Denom())
	}
	return nil
}

func validateSubjects(subjects []Subject, batches []SourceBatch) error {
	expected := make(map[string]string, len(batches))
	for _, batch := range batches {
		expected[sourceBatchSubjectName(batch)] = batch.EnvelopeHash
	}
	if len(subjects) != len(expected) {
		return fmt.Errorf("%w: subject count=%d want %d source batches", ErrInvalidStatement, len(subjects), len(expected))
	}
	seen := make(map[string]struct{}, len(subjects))
	for _, subject := range subjects {
		name := strings.TrimSpace(subject.Name)
		if name == "" {
			return fmt.Errorf("%w: subject.name required", ErrInvalidStatement)
		}
		if err := validateHexSHA256(ErrInvalidStatement, "subject.digest.sha256", subject.Digest.SHA256); err != nil {
			return err
		}
		if _, ok := seen[name]; ok {
			return fmt.Errorf("%w: duplicate subject %s", ErrInvalidStatement, name)
		}
		seen[name] = struct{}{}
		want, ok := expected[name]
		if !ok {
			return fmt.Errorf("%w: subject %s does not match a source batch", ErrInvalidStatement, name)
		}
		if subject.Digest.SHA256 != want {
			return fmt.Errorf("%w: subject %s digest %s, want source batch envelopeHash %s", ErrInvalidStatement, name, subject.Digest.SHA256, want)
		}
	}
	return nil
}

func sourceBatchSubjectName(b SourceBatch) string {
	return fmt.Sprintf("conductor-audit-batch:%s/%s/%s/%s", b.OrgID, b.FleetID, b.InstanceID, b.BatchID)
}

func validateSourceBatches(orgID, fleetID string, batches []SourceBatch) error {
	seen := map[string]struct{}{}
	lastSeq := map[string]uint64{}
	for _, b := range batches {
		key := strings.Join([]string{b.OrgID, b.FleetID, b.InstanceID, b.BatchID}, "\x00")
		if _, ok := seen[key]; ok {
			return fmt.Errorf("%w: duplicate source batch %s", ErrInvalidPredicate, b.BatchID)
		}
		seen[key] = struct{}{}
		if b.OrgID == "" || b.FleetID == "" || b.InstanceID == "" || b.BatchID == "" {
			return fmt.Errorf("%w: source batch identity required", ErrInvalidPredicate)
		}
		if b.OrgID != orgID || b.FleetID != fleetID {
			return fmt.Errorf("%w: source batch %s belongs to %s/%s, want %s/%s", ErrInvalidPredicate, b.BatchID, b.OrgID, b.FleetID, orgID, fleetID)
		}
		if b.SeqEnd < b.SeqStart {
			return fmt.Errorf("%w: invalid source batch sequence range", ErrInvalidPredicate)
		}
		followerKey := strings.Join([]string{b.OrgID, b.FleetID, b.InstanceID}, "\x00")
		if previous, ok := lastSeq[followerKey]; ok && b.SeqStart <= previous {
			return fmt.Errorf("%w: source batches overlap or are reordered for %s", ErrInvalidPredicate, b.InstanceID)
		}
		lastSeq[followerKey] = b.SeqEnd
		if b.EventCount == 0 || b.PayloadBytes == 0 {
			return fmt.Errorf("%w: source batch eventCount and payloadBytes required", ErrInvalidPredicate)
		}
		for name, value := range map[string]string{
			"payloadSha256":   b.PayloadSHA256,
			"envelopeHash":    b.EnvelopeHash,
			"segmentTailHash": b.SegmentTailHash,
		} {
			if err := validateHexSHA256(ErrInvalidPredicate, name, value); err != nil {
				return err
			}
		}
		if _, err := parseTime("emittedAt", b.EmittedAt); err != nil {
			return err
		}
		if _, err := parseTime("receivedAt", b.ReceivedAt); err != nil {
			return err
		}
		if len(b.SignatureKeyIDs) == 0 {
			return fmt.Errorf("%w: source batch signatureKeyIds required", ErrInvalidPredicate)
		}
		for _, keyID := range b.SignatureKeyIDs {
			if strings.TrimSpace(keyID) == "" {
				return fmt.Errorf("%w: source batch signatureKeyIds contains blank key", ErrInvalidPredicate)
			}
		}
	}
	return nil
}

func validateCountMap(name string, counts map[string]uint64) (uint64, error) {
	sum := uint64(0)
	for key, count := range counts {
		if strings.TrimSpace(key) == "" {
			return 0, fmt.Errorf("%w: %s has empty key", ErrInvalidPredicate, name)
		}
		if count == 0 {
			return 0, fmt.Errorf("%w: %s[%q] is zero", ErrInvalidPredicate, name, key)
		}
		next, ok := addUint64(sum, count)
		if !ok {
			return 0, fmt.Errorf("%w: %s totals overflow uint64", ErrInvalidPredicate, name)
		}
		sum = next
	}
	return sum, nil
}

func addUint64(a, b uint64) (uint64, bool) {
	if b > ^uint64(0)-a {
		return 0, false
	}
	return a + b, true
}

func validateHexSHA256(baseErr error, name, value string) error {
	if len(value) != sha256.Size*2 {
		return fmt.Errorf("%w: %s must be 64 hex chars", baseErr, name)
	}
	if _, err := hex.DecodeString(value); err != nil {
		return fmt.Errorf("%w: %s must be hex", baseErr, name)
	}
	if value != strings.ToLower(value) {
		return fmt.Errorf("%w: %s must be lowercase hex", baseErr, name)
	}
	return nil
}

func parseTime(name, value string) (time.Time, error) {
	if !strings.HasSuffix(value, "Z") {
		return time.Time{}, fmt.Errorf("%w: %s must be an RFC3339 UTC timestamp ending in Z", ErrInvalidPredicate, name)
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %s: %w", ErrInvalidPredicate, name, err)
	}
	return parsed, nil
}

func parseUnitDecimal(name, value string) (*big.Rat, error) {
	if strings.TrimSpace(value) == "" || strings.ContainsAny(value, "eE/") {
		return nil, fmt.Errorf("%w: %s must be a decimal string", ErrInvalidPredicate, name)
	}
	rat, ok := new(big.Rat).SetString(value)
	if !ok {
		return nil, fmt.Errorf("%w: %s must be a decimal string", ErrInvalidPredicate, name)
	}
	if rat.Sign() < 0 || rat.Cmp(big.NewRat(1, 1)) > 0 {
		return nil, fmt.Errorf("%w: %s must be between 0 and 1", ErrInvalidPredicate, name)
	}
	if !isUnitDecimalString(value) {
		return nil, fmt.Errorf("%w: %s must be a decimal string", ErrInvalidPredicate, name)
	}
	return rat, nil
}

func isUnitDecimalString(value string) bool {
	if value == "0" || value == "1" {
		return true
	}
	if strings.HasPrefix(value, "0.") && len(value) > len("0.") {
		for _, r := range value[len("0."):] {
			if r < '0' || r > '9' {
				return false
			}
		}
		return true
	}
	if strings.HasPrefix(value, "1.") && len(value) > len("1.") {
		for _, r := range value[len("1."):] {
			if r != '0' {
				return false
			}
		}
		return true
	}
	return false
}

func resolveVerifierKey(keyID string, trustedKeys map[string]ed25519.PublicKey) (ed25519.PublicKey, bool, error) {
	if strings.TrimSpace(keyID) == "" {
		return nil, false, fmt.Errorf("%w: signature keyid required", ErrInvalidEnvelope)
	}
	if len(trustedKeys) > 0 {
		pub, ok := trustedKeys[keyID]
		if !ok {
			return nil, false, fmt.Errorf("%w: %s", ErrUntrustedKey, keyID)
		}
		if len(pub) != ed25519.PublicKeySize {
			return nil, false, fmt.Errorf("%w: trusted key %s length=%d", ErrInvalidEnvelope, keyID, len(pub))
		}
		return pub, true, nil
	}
	raw, err := hex.DecodeString(keyID)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, false, fmt.Errorf("%w: unpinned keyid must be hex Ed25519 public key", ErrInvalidEnvelope)
	}
	return ed25519.PublicKey(raw), false, nil
}

func decodeSignature(value string) ([]byte, error) {
	raw := strings.TrimPrefix(value, signaturePrefix)
	if raw == value {
		return nil, fmt.Errorf("%w: signature missing %s prefix", ErrInvalidEnvelope, signaturePrefix)
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: decode signature: %w", ErrInvalidEnvelope, err)
	}
	if len(decoded) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: signature length=%d", ErrInvalidEnvelope, len(decoded))
	}
	return decoded, nil
}

func pae(payloadType string, payload []byte) []byte {
	pieces := [][]byte{
		[]byte("DSSEv1"),
		[]byte(strconv.Itoa(len(payloadType))),
		[]byte(payloadType),
		[]byte(strconv.Itoa(len(payload))),
		payload,
	}
	return bytes.Join(pieces, []byte(" "))
}

func MarshalEnvelope(env Envelope) ([]byte, error) {
	raw, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("%w: marshal envelope: %w", ErrInvalidEnvelope, err)
	}
	return raw, nil
}

func TrustedKeyMap(keys map[string]string) (map[string]ed25519.PublicKey, error) {
	out := make(map[string]ed25519.PublicKey, len(keys))
	ids := make([]string, 0, len(keys))
	for id := range keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		raw, err := hex.DecodeString(keys[id])
		if err != nil {
			return nil, fmt.Errorf("decode trusted key %s: %w", id, err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("trusted key %s length=%d want %d", id, len(raw), ed25519.PublicKeySize)
		}
		out[id] = ed25519.PublicKey(raw)
	}
	return out, nil
}
