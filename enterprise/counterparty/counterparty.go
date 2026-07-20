//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

// Package counterparty verifies enterprise-only side records that bind two
// already-existing receipts to the same transmitted payload.
//
// The binding lives beside the core receipt stream as its own signed side
// record (counterparty_receipt_v1). No field here is added to the v1
// ActionRecord schema, so the cross-language receipt verifiers are unaffected.
package counterparty

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

const (
	RecordType = "counterparty_receipt_v1"
	Version    = 1

	signatureAlg    = "ed25519"
	signaturePrefix = "ed25519:"
	hashPrefix      = "sha256:"

	// PayloadCaptureRecordType tags a party's signed payload-capture record.
	PayloadCaptureRecordType = "payload_capture_v1"

	// DirectionEgress and DirectionIngress name the side that captured a payload:
	// the sender captures on egress, the receiver captures on ingress.
	DirectionEgress  = "egress"
	DirectionIngress = "ingress"

	// maxTokenLen bounds identity, nonce, and receipt-id fields. These are
	// internal fleet identifiers, not free text; a tight bound cuts DoS and
	// normalization risk. The charset is restricted to printable, non-space
	// ASCII so NFC normalization is a no-op (see rejectNonASCII / B1 defense).
	maxTokenLen = 256
)

var (
	ErrUnknownField           = errors.New("unknown field on counterparty receipt")
	ErrTrailingTokens         = errors.New("trailing tokens after counterparty receipt")
	ErrFleetRequired          = errors.New("counterparty verification requires fleet feature")
	ErrTrustedReceiptKey      = errors.New("trusted receipt key required")
	ErrVerificationError      = errors.New("counterparty verification failed")
	ErrReceiptIdentity        = errors.New("receipt identity mismatch")
	ErrSideRecordKeyReuse     = errors.New("side-record signing key must be separate from receipt signing keys")
	ErrUntrustedSideRecordKey = errors.New("side-record signature must match the receiver's enrolled counterparty key")
	ErrMalformedBinding       = errors.New("counterparty binding is malformed")
	ErrReplayStoreRequired    = errors.New("counterparty verification requires a replay store")
	ErrFreshnessConfig        = errors.New("counterparty verification requires a verify time and positive age bounds")
	ErrPayloadCapture         = errors.New("payload capture is invalid")
)

// Binding is the signed counterparty assertion. It intentionally lives beside
// the core receipt stream; no field here is added to v1 ActionRecord.
type Binding struct {
	PayloadHash         string    `json:"payload_hash"`
	SenderIdentity      string    `json:"sender_identity"`
	ReceiverIdentity    string    `json:"receiver_identity"`
	Nonce               string    `json:"nonce"`
	SenderReceiptID     string    `json:"sender_receipt_id"`
	SenderReceiptHash   string    `json:"sender_receipt_hash"`
	ReceiverReceiptID   string    `json:"receiver_receipt_id"`
	ReceiverReceiptHash string    `json:"receiver_receipt_hash"`
	Timestamp           time.Time `json:"ts"`
	Version             int       `json:"version"`
}

// Signature is the receiver signature over the canonical RecordType+Binding
// hash. KeyID names the receiver's enrolled counterparty key.
type Signature struct {
	Alg   string `json:"alg"`
	KeyID string `json:"key_id"`
	Sig   string `json:"sig"`
}

// Record is a signed counterparty side record.
type Record struct {
	RecordType string    `json:"record_type"`
	Binding    Binding   `json:"binding"`
	Signature  Signature `json:"signature"`
}

// PayloadCapture is a party's signed attestation that it handled a specific
// on-the-wire payload for a specific signed action and counterparty. The core v1
// receipt schema has no payload-hash field and cannot gain one without breaking
// the cross-language verifiers, so each party commits to the payload here
// instead, signed by the same key that signs its receipts. Because BOTH the
// sender (egress) and the receiver (ingress) sign their own capture, no single
// party can fabricate the payload the other observed.
//
// Signature.KeyID on a capture is informational and NOT authenticated: the
// capture signature is verified against the caller-enrolled receipt public key,
// not against the KeyID. Audit or display code must not treat a capture's KeyID
// as a trusted identity; the enrolled key is the sole authority.
type PayloadCapture struct {
	RecordType           string    `json:"record_type"`
	ActionID             string    `json:"action_id"`
	ActionHash           string    `json:"action_hash"`
	PayloadHash          string    `json:"payload_hash"`
	Direction            string    `json:"direction"`
	PartyIdentity        string    `json:"party_identity"`
	CounterpartyIdentity string    `json:"counterparty_identity"`
	Signature            Signature `json:"signature"`
}

// BoundReceipt pairs a receipt with the party's signed payload capture. The
// verifier derives the payload hash from the verified capture, never from an
// unsigned caller-supplied value or unsigned receipt Ext data.
type BoundReceipt struct {
	Receipt receipt.Receipt
	Capture PayloadCapture
}

// NonceKey is the replay key for one signed side record. It scopes the nonce to
// the enrolled side-record key and both parties, so the same signed record
// cannot be re-counted. All fields are validated ASCII, so the raw string used
// here matches the NFC-normalized bytes the signature was computed over.
type NonceKey struct {
	SideRecordKeyID  string `json:"side_record_key_id"`
	SenderIdentity   string `json:"sender_identity"`
	ReceiverIdentity string `json:"receiver_identity"`
	Nonce            string `json:"nonce"`
}

// TransferKey is the replay key for one transfer regardless of nonce. It uses
// the signed action-record hashes, not the mutable receipt envelope hashes, so
// unsigned/canonical envelope changes (for example Ext or signature hex casing)
// cannot turn the same transfer into a new replay key.
type TransferKey struct {
	SenderIdentity     string
	ReceiverIdentity   string
	PayloadHash        string
	SenderReceiptID    string
	ReceiverReceiptID  string
	SenderActionHash   string
	ReceiverActionHash string
}

// VerifyRequest carries all inputs for cross-party verification.
type VerifyRequest struct {
	License license.License

	Sender   *BoundReceipt
	Receiver *BoundReceipt
	Record   *Record

	// SenderReceiptKey and ReceiverReceiptKey are the caller's trusted
	// identity-to-key anchors for the two receipt signers. Receipt envelopes are
	// self-describing, so verification must not trust an embedded signer_key
	// without checking it against these enrolled keys.
	SenderReceiptKey   ed25519.PublicKey
	ReceiverReceiptKey ed25519.PublicKey

	// ReceiverSideRecordKey and ReceiverSideRecordKeyID are the receiver's
	// enrolled counterparty side-record key. The receiver is the party that
	// co-signs "I received exactly this", so the side record must be signed by
	// the receiver's key, not by any globally trusted key (closes the
	// any-trusted-key attests-any-identity hole).
	ReceiverSideRecordKey   ed25519.PublicKey
	ReceiverSideRecordKeyID string

	// Freshness bounds. Now is the caller-injected verify time (the verifier
	// never reads the wall clock). A record older than MaxAge or further in the
	// future than MaxFutureSkew fails closed. All three are required (> 0).
	Now           time.Time
	MaxAge        time.Duration
	MaxFutureSkew time.Duration

	// ReplayStore is required. A record only passes after CommitIfNew accepts
	// it, so a replayed record (same nonce) or a re-signed same-transfer record
	// fails closed. A nil store fails closed.
	ReplayStore ReplayStore
}

type FailureCode string

const (
	FailureNone                FailureCode = ""
	FailureLicense             FailureCode = "license"
	FailureMissingInput        FailureCode = "missing_input"
	FailureMalformedBinding    FailureCode = "malformed_binding"
	FailureInvalidReceipt      FailureCode = "invalid_receipt"
	FailurePayloadCapture      FailureCode = "payload_capture"
	FailurePayloadHashMismatch FailureCode = "payload_hash_mismatch"
	FailureReceiptIDMismatch   FailureCode = "receipt_id_mismatch"
	FailureReceiptHashMismatch FailureCode = "receipt_hash_mismatch"
	FailureIdentityMismatch    FailureCode = "identity_mismatch"
	FailureStale               FailureCode = "stale"
	FailureFuture              FailureCode = "future"
	FailureReplay              FailureCode = "replay"
	FailureReplayStore         FailureCode = "replay_store"
	FailureSignature           FailureCode = "signature"
	FailureTrust               FailureCode = "trust"
	FailureSelfCounterparty    FailureCode = "self_counterparty"
)

// VerificationResult is structured so callers can distinguish a pass from the
// exact fail-closed reason without parsing text.
type VerificationResult struct {
	Passed      bool        `json:"passed"`
	FailureCode FailureCode `json:"failure_code,omitempty"`
	Error       string      `json:"error,omitempty"`
	Nonce       *NonceKey   `json:"nonce,omitempty"`
	SignerKeyID string      `json:"signer_key_id,omitempty"`
}

// PayloadHash returns the canonical labeled SHA-256 hash for transmitted bytes.
func PayloadHash(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hashPrefix + hex.EncodeToString(sum[:])
}

// SignRecord signs the record's canonical side-record hash with Ed25519.
func SignRecord(lic license.License, r Record, keyID string, privKey ed25519.PrivateKey) (Record, error) {
	if !lic.HasFeature(license.FeatureFleet) {
		return Record{}, ErrFleetRequired
	}
	if len(privKey) != ed25519.PrivateKeySize {
		return Record{}, fmt.Errorf("invalid private key size: got %d, want %d", len(privKey), ed25519.PrivateKeySize)
	}
	if keyID == "" {
		return Record{}, errors.New("key_id is required")
	}
	r.RecordType = RecordType
	r.Signature = Signature{}
	if err := validateBinding(r.Binding); err != nil {
		return Record{}, err
	}
	sum, err := canonicalRecordHash(r)
	if err != nil {
		return Record{}, err
	}
	sig := ed25519.Sign(privKey, sum[:])
	r.Signature = Signature{
		Alg:   signatureAlg,
		KeyID: keyID,
		Sig:   signaturePrefix + base64.StdEncoding.EncodeToString(sig),
	}
	return r, nil
}

// VerifyRecordSignature verifies only the side-record structure and signature
// against the receiver's enrolled key. It does not check the paired receipts;
// callers wanting the full cross-party proof use VerifyCounterparty.
func VerifyRecordSignature(lic license.License, r Record, expectedKeyID string, pubKey ed25519.PublicKey) error {
	if !lic.HasFeature(license.FeatureFleet) {
		return ErrFleetRequired
	}
	if r.RecordType != RecordType {
		return fmt.Errorf("unsupported record_type %q", r.RecordType)
	}
	if err := validateBinding(r.Binding); err != nil {
		return err
	}
	if r.Signature.Alg != signatureAlg {
		return fmt.Errorf("unsupported signature alg %q", r.Signature.Alg)
	}
	if r.Signature.KeyID == "" {
		return errors.New("signature key_id is required")
	}
	if expectedKeyID == "" {
		return fmt.Errorf("%w: no enrolled side-record key id", ErrUntrustedSideRecordKey)
	}
	if r.Signature.KeyID != expectedKeyID {
		return fmt.Errorf("%w: record key_id %q is not the receiver's enrolled key %q", ErrUntrustedSideRecordKey, r.Signature.KeyID, expectedKeyID)
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: enrolled key size = %d, want %d", ErrUntrustedSideRecordKey, len(pubKey), ed25519.PublicKeySize)
	}
	rawSig, err := decodeSignature(r.Signature.Sig)
	if err != nil {
		return err
	}
	sum, err := canonicalRecordHash(Record{RecordType: r.RecordType, Binding: r.Binding})
	if err != nil {
		return err
	}
	if !ed25519.Verify(pubKey, sum[:], rawSig) {
		return errors.New("signature verification failed")
	}
	return nil
}

// VerifyCounterpartyBytes strictly parses a raw side record and then verifies
// it. Callers handling untrusted bytes MUST use this entry point so duplicate
// keys, unknown fields, and trailing tokens cannot collapse into a pass-shaped
// Record. req.Record is ignored and set from the parsed bytes.
func VerifyCounterpartyBytes(req VerifyRequest, rawRecord []byte) VerificationResult {
	rec, err := UnmarshalRecord(rawRecord)
	if err != nil {
		return fail(FailureMalformedBinding, err)
	}
	req.Record = &rec
	return VerifyCounterparty(req)
}

// VerifyCounterparty appraises a counterparty side record against two existing
// receipts and the receiver's enrolled side-record key. It fails closed on
// license loss, missing configuration, malformed inputs, mismatched bindings,
// staleness, replay, untrusted keys, and signature failure. Replay state is
// only committed after every non-mutating check passes, so a rejected record
// never consumes a nonce.
func VerifyCounterparty(req VerifyRequest) VerificationResult {
	if !req.License.HasFeature(license.FeatureFleet) {
		return fail(FailureLicense, ErrFleetRequired)
	}
	if req.Sender == nil || req.Receiver == nil || req.Record == nil {
		return fail(FailureMissingInput, errors.New("sender receipt, receiver receipt, and counterparty record are required"))
	}
	if req.ReplayStore == nil {
		return fail(FailureMissingInput, ErrReplayStoreRequired)
	}
	if req.Now.IsZero() || req.MaxAge <= 0 || req.MaxFutureSkew <= 0 {
		return fail(FailureMissingInput, ErrFreshnessConfig)
	}

	r := *req.Record
	if err := validateBinding(r.Binding); err != nil {
		return fail(FailureMalformedBinding, err)
	}
	if r.Binding.SenderIdentity == r.Binding.ReceiverIdentity {
		return fail(FailureSelfCounterparty, errors.New("sender and receiver identities are the same"))
	}

	senderPayloadHash, err := verifyBoundReceipt("sender", *req.Sender, req.SenderReceiptKey, DirectionEgress, r.Binding.ReceiverIdentity)
	if err != nil {
		return fail(classifyBoundReceiptErr(err), err)
	}
	receiverPayloadHash, err := verifyBoundReceipt("receiver", *req.Receiver, req.ReceiverReceiptKey, DirectionIngress, r.Binding.SenderIdentity)
	if err != nil {
		return fail(classifyBoundReceiptErr(err), err)
	}

	if err := VerifyRecordSignature(req.License, r, req.ReceiverSideRecordKeyID, req.ReceiverSideRecordKey); err != nil {
		if errors.Is(err, ErrUntrustedSideRecordKey) {
			return fail(FailureTrust, err)
		}
		return fail(FailureSignature, err)
	}
	if err := rejectSideRecordKeyReuse(req.ReceiverSideRecordKey, req.SenderReceiptKey, req.ReceiverReceiptKey); err != nil {
		return fail(FailureTrust, err)
	}

	if senderPayloadHash != r.Binding.PayloadHash {
		return fail(FailurePayloadHashMismatch, fmt.Errorf("sender-attested payload hash %q does not match record payload_hash %q", senderPayloadHash, r.Binding.PayloadHash))
	}
	if receiverPayloadHash != r.Binding.PayloadHash {
		return fail(FailurePayloadHashMismatch, fmt.Errorf("receiver-attested payload hash %q does not match record payload_hash %q", receiverPayloadHash, r.Binding.PayloadHash))
	}
	if req.Sender.Receipt.ActionRecord.ActionID != r.Binding.SenderReceiptID {
		return fail(FailureReceiptIDMismatch, fmt.Errorf("sender receipt action_id %q does not match record sender_receipt_id %q", req.Sender.Receipt.ActionRecord.ActionID, r.Binding.SenderReceiptID))
	}
	if req.Receiver.Receipt.ActionRecord.ActionID != r.Binding.ReceiverReceiptID {
		return fail(FailureReceiptIDMismatch, fmt.Errorf("receiver receipt action_id %q does not match record receiver_receipt_id %q", req.Receiver.Receipt.ActionRecord.ActionID, r.Binding.ReceiverReceiptID))
	}
	if err := compareReceiptHash("sender", req.Sender.Receipt, r.Binding.SenderReceiptHash); err != nil {
		return fail(FailureReceiptHashMismatch, err)
	}
	if err := compareReceiptHash("receiver", req.Receiver.Receipt, r.Binding.ReceiverReceiptHash); err != nil {
		return fail(FailureReceiptHashMismatch, err)
	}

	if req.Sender.Receipt.SignerKey == req.Receiver.Receipt.SignerKey {
		return fail(FailureSelfCounterparty, errors.New("sender and receiver receipt signer keys are the same"))
	}
	if err := compareReceiptIdentity("sender", req.Sender.Receipt, r.Binding.SenderIdentity); err != nil {
		return fail(FailureIdentityMismatch, err)
	}
	if err := compareReceiptIdentity("receiver", req.Receiver.Receipt, r.Binding.ReceiverIdentity); err != nil {
		return fail(FailureIdentityMismatch, err)
	}

	if code, err := verifyFreshTimestamp("record ts", r.Binding.Timestamp, req.Now, req.MaxAge, req.MaxFutureSkew); err != nil {
		return fail(code, err)
	}
	if code, err := verifyFreshTimestamp("sender receipt timestamp", req.Sender.Receipt.ActionRecord.Timestamp, req.Now, req.MaxAge, req.MaxFutureSkew); err != nil {
		return fail(code, err)
	}
	if code, err := verifyFreshTimestamp("receiver receipt timestamp", req.Receiver.Receipt.ActionRecord.Timestamp, req.Now, req.MaxAge, req.MaxFutureSkew); err != nil {
		return fail(code, err)
	}

	nonce := NonceKey{
		SideRecordKeyID:  r.Signature.KeyID,
		SenderIdentity:   r.Binding.SenderIdentity,
		ReceiverIdentity: r.Binding.ReceiverIdentity,
		Nonce:            r.Binding.Nonce,
	}
	entry, err := newReplayEntry(r, nonce, req.Sender.Receipt, req.Receiver.Receipt)
	if err != nil {
		return failWithNonce(FailureReplayStore, err, &nonce, r.Signature.KeyID)
	}
	if err := req.ReplayStore.CommitIfNew(entry); err != nil {
		if errors.Is(err, ErrReplayConflict) {
			return failWithNonce(FailureReplay, err, &nonce, r.Signature.KeyID)
		}
		return failWithNonce(FailureReplayStore, err, &nonce, r.Signature.KeyID)
	}

	return VerificationResult{
		Passed:      true,
		Nonce:       &nonce,
		SignerKeyID: r.Signature.KeyID,
	}
}

// UnmarshalRecord strictly parses a counterparty side record.
func UnmarshalRecord(data []byte) (Record, error) {
	return unmarshalStrict[Record](data, "counterparty receipt")
}

// UnmarshalPayloadCapture strictly parses a raw payload-capture record. Callers
// handling untrusted capture bytes MUST use this (not encoding/json directly)
// before building a BoundReceipt, so duplicate keys, unknown fields, and
// trailing tokens cannot collapse into a pass-shaped struct while the raw
// artifact stays ambiguous for audit.
func UnmarshalPayloadCapture(data []byte) (PayloadCapture, error) {
	return unmarshalStrict[PayloadCapture](data, "payload capture")
}

func unmarshalStrict[T any](data []byte, label string) (T, error) {
	var v T
	if err := jsonscan.RejectDuplicateKeys(data); err != nil {
		return v, fmt.Errorf("unmarshal %s: %w", label, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return v, fmt.Errorf("unmarshal %s: %w: %w", label, ErrUnknownField, err)
		}
		return v, fmt.Errorf("unmarshal %s: %w", label, err)
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		if err != nil {
			return v, fmt.Errorf("unmarshal %s: %w: %w", label, ErrTrailingTokens, err)
		}
		return v, fmt.Errorf("unmarshal %s: %w", label, ErrTrailingTokens)
	}
	return v, nil
}

func newReplayEntry(r Record, nonce NonceKey, sender, receiver receipt.Receipt) (ReplayEntry, error) {
	sum, err := canonicalRecordHash(r)
	if err != nil {
		return ReplayEntry{}, err
	}
	senderActionHash, err := signedActionHash(sender)
	if err != nil {
		return ReplayEntry{}, fmt.Errorf("sender signed action hash: %w", err)
	}
	receiverActionHash, err := signedActionHash(receiver)
	if err != nil {
		return ReplayEntry{}, fmt.Errorf("receiver signed action hash: %w", err)
	}
	return ReplayEntry{
		NonceKey: nonce,
		TransferKey: TransferKey{
			SenderIdentity:     r.Binding.SenderIdentity,
			ReceiverIdentity:   r.Binding.ReceiverIdentity,
			PayloadHash:        r.Binding.PayloadHash,
			SenderReceiptID:    r.Binding.SenderReceiptID,
			ReceiverReceiptID:  r.Binding.ReceiverReceiptID,
			SenderActionHash:   senderActionHash,
			ReceiverActionHash: receiverActionHash,
		},
		RecordHash:        hashPrefix + hex.EncodeToString(sum[:]),
		Timestamp:         r.Binding.Timestamp,
		TransferTimestamp: earlierTime(sender.ActionRecord.Timestamp, receiver.ActionRecord.Timestamp),
	}, nil
}

func verifyFreshTimestamp(name string, ts, now time.Time, maxAge, maxFutureSkew time.Duration) (FailureCode, error) {
	if ts.Before(now.Add(-maxAge)) {
		return FailureStale, fmt.Errorf("%s %s is older than max age %s before %s", name, ts.UTC(), maxAge, now.UTC())
	}
	if ts.After(now.Add(maxFutureSkew)) {
		return FailureFuture, fmt.Errorf("%s %s is beyond max future skew %s after %s", name, ts.UTC(), maxFutureSkew, now.UTC())
	}
	return FailureNone, nil
}

func earlierTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func signedActionHash(r receipt.Receipt) (string, error) {
	hash, err := r.ActionRecord.Hash()
	if err != nil {
		return "", err
	}
	return hashPrefix + hash, nil
}

func canonicalRecordHash(r Record) ([sha256.Size]byte, error) {
	canonical, err := canonicalRecordBytes(r)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(canonical), nil
}

func canonicalRecordBytes(r Record) ([]byte, error) {
	unsigned := struct {
		RecordType string  `json:"record_type"`
		Binding    Binding `json:"binding"`
	}{
		RecordType: r.RecordType,
		Binding:    r.Binding,
	}
	raw, err := json.Marshal(unsigned)
	if err != nil {
		return nil, fmt.Errorf("marshal canonical counterparty record: %w", err)
	}
	tree, err := contract.ParseJSONStrict(raw)
	if err != nil {
		return nil, fmt.Errorf("parse canonical counterparty record: %w", err)
	}
	return contract.Canonicalize(tree)
}

func validateBinding(b Binding) error {
	if b.Version != Version {
		return fmt.Errorf("%w: unsupported binding version %d", ErrMalformedBinding, b.Version)
	}
	if err := validateHash("payload_hash", b.PayloadHash); err != nil {
		return err
	}
	if err := validateToken("sender_identity", b.SenderIdentity); err != nil {
		return err
	}
	if err := validateToken("receiver_identity", b.ReceiverIdentity); err != nil {
		return err
	}
	if err := validateToken("nonce", b.Nonce); err != nil {
		return err
	}
	if err := validateToken("sender_receipt_id", b.SenderReceiptID); err != nil {
		return err
	}
	if err := validateHash("sender_receipt_hash", b.SenderReceiptHash); err != nil {
		return err
	}
	if err := validateToken("receiver_receipt_id", b.ReceiverReceiptID); err != nil {
		return err
	}
	if err := validateHash("receiver_receipt_hash", b.ReceiverReceiptHash); err != nil {
		return err
	}
	if b.Timestamp.IsZero() {
		return fmt.Errorf("%w: ts is required", ErrMalformedBinding)
	}
	return nil
}

func classifyBoundReceiptErr(err error) FailureCode {
	switch {
	case errors.Is(err, ErrTrustedReceiptKey):
		return FailureTrust
	case errors.Is(err, ErrPayloadCapture):
		return FailurePayloadCapture
	default:
		return FailureInvalidReceipt
	}
}

// verifyBoundReceipt verifies the receipt and its signed payload capture against
// the party's enrolled key, then returns the payload hash the party attested.
func verifyBoundReceipt(name string, br BoundReceipt, expectedKey ed25519.PublicKey, direction, counterpartyIdentity string) (string, error) {
	expectedKeyHex, err := trustedReceiptKeyHex(name, expectedKey)
	if err != nil {
		return "", err
	}
	if br.Receipt.SignerKey != expectedKeyHex {
		return "", fmt.Errorf("%w: %s receipt signer_key %q does not match trusted key %q", ErrTrustedReceiptKey, name, br.Receipt.SignerKey, expectedKeyHex)
	}
	if err := receipt.VerifyWithKey(br.Receipt, expectedKeyHex); err != nil {
		return "", fmt.Errorf("%s receipt: %w", name, err)
	}
	actionHash, err := signedActionHash(br.Receipt)
	if err != nil {
		return "", fmt.Errorf("%s signed action hash: %w", name, err)
	}
	payloadHash, err := verifyPayloadCapture(name, br.Capture, expectedKey, captureExpectation{
		direction:            direction,
		actionID:             br.Receipt.ActionRecord.ActionID,
		actionHash:           actionHash,
		actor:                br.Receipt.ActionRecord.Actor,
		counterpartyIdentity: counterpartyIdentity,
	})
	if err != nil {
		return "", err
	}
	return payloadHash, nil
}

// SignPayloadCapture signs a party's payload-capture record with its Ed25519
// key. The signer is the same key that signs the party's receipts.
func SignPayloadCapture(c PayloadCapture, keyID string, privKey ed25519.PrivateKey) (PayloadCapture, error) {
	if len(privKey) != ed25519.PrivateKeySize {
		return PayloadCapture{}, fmt.Errorf("invalid private key size: got %d, want %d", len(privKey), ed25519.PrivateKeySize)
	}
	if keyID == "" {
		return PayloadCapture{}, errors.New("key_id is required")
	}
	c.RecordType = PayloadCaptureRecordType
	c.Signature = Signature{}
	if err := validateCaptureFields(c); err != nil {
		return PayloadCapture{}, err
	}
	sum, err := canonicalCaptureHash(c)
	if err != nil {
		return PayloadCapture{}, err
	}
	sig := ed25519.Sign(privKey, sum[:])
	c.Signature = Signature{
		Alg:   signatureAlg,
		KeyID: keyID,
		Sig:   signaturePrefix + base64.StdEncoding.EncodeToString(sig),
	}
	return c, nil
}

// captureExpectation carries the receipt- and binding-derived values a payload
// capture must match. It keeps verifyPayloadCapture within the parameter-count
// guideline and names each expected field at the call site.
type captureExpectation struct {
	direction            string
	actionID             string
	actionHash           string
	actor                string
	counterpartyIdentity string
}

// verifyPayloadCapture checks a payload capture is well-formed, matches its
// receipt (action id, action hash, party identity, direction) and counterparty,
// and is signed by the party's enrolled key; it returns the attested payload hash.
func verifyPayloadCapture(name string, c PayloadCapture, enrolledKey ed25519.PublicKey, exp captureExpectation) (string, error) {
	if c.RecordType != PayloadCaptureRecordType {
		return "", fmt.Errorf("%w: %s capture record_type %q", ErrPayloadCapture, name, c.RecordType)
	}
	if err := validateCaptureFields(c); err != nil {
		return "", err
	}
	if c.Direction != exp.direction {
		return "", fmt.Errorf("%w: %s capture direction %q, want %q", ErrPayloadCapture, name, c.Direction, exp.direction)
	}
	if c.ActionID != exp.actionID {
		return "", fmt.Errorf("%w: %s capture action_id %q does not match receipt action_id %q", ErrPayloadCapture, name, c.ActionID, exp.actionID)
	}
	if c.ActionHash != exp.actionHash {
		return "", fmt.Errorf("%w: %s capture action_hash %q does not match receipt action hash %q", ErrPayloadCapture, name, c.ActionHash, exp.actionHash)
	}
	if c.PartyIdentity != exp.actor {
		return "", fmt.Errorf("%w: %s capture party_identity %q does not match receipt actor %q", ErrPayloadCapture, name, c.PartyIdentity, exp.actor)
	}
	if c.CounterpartyIdentity != exp.counterpartyIdentity {
		return "", fmt.Errorf("%w: %s capture counterparty_identity %q does not match binding counterparty %q", ErrPayloadCapture, name, c.CounterpartyIdentity, exp.counterpartyIdentity)
	}
	if c.Signature.Alg != signatureAlg {
		return "", fmt.Errorf("%w: %s capture unsupported signature alg %q", ErrPayloadCapture, name, c.Signature.Alg)
	}
	if len(enrolledKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("%w: %s enrolled key size = %d, want %d", ErrPayloadCapture, name, len(enrolledKey), ed25519.PublicKeySize)
	}
	rawSig, err := decodeSignature(c.Signature.Sig)
	if err != nil {
		return "", fmt.Errorf("%w: %s capture: %s", ErrPayloadCapture, name, err.Error())
	}
	sum, err := canonicalCaptureHash(c)
	if err != nil {
		return "", err
	}
	if !ed25519.Verify(enrolledKey, sum[:], rawSig) {
		return "", fmt.Errorf("%w: %s capture signature verification failed", ErrPayloadCapture, name)
	}
	return c.PayloadHash, nil
}

func validateCaptureFields(c PayloadCapture) error {
	if err := validateToken("capture action_id", c.ActionID); err != nil {
		return fmt.Errorf("%w: %s", ErrPayloadCapture, err.Error())
	}
	if err := validateHash("capture action_hash", c.ActionHash); err != nil {
		return fmt.Errorf("%w: %s", ErrPayloadCapture, err.Error())
	}
	if err := validateToken("capture party_identity", c.PartyIdentity); err != nil {
		return fmt.Errorf("%w: %s", ErrPayloadCapture, err.Error())
	}
	if err := validateToken("capture counterparty_identity", c.CounterpartyIdentity); err != nil {
		return fmt.Errorf("%w: %s", ErrPayloadCapture, err.Error())
	}
	if err := validateHash("capture payload_hash", c.PayloadHash); err != nil {
		return fmt.Errorf("%w: %s", ErrPayloadCapture, err.Error())
	}
	if c.Direction != DirectionEgress && c.Direction != DirectionIngress {
		return fmt.Errorf("%w: capture direction %q must be %q or %q", ErrPayloadCapture, c.Direction, DirectionEgress, DirectionIngress)
	}
	return nil
}

func canonicalCaptureHash(c PayloadCapture) ([sha256.Size]byte, error) {
	unsigned := struct {
		RecordType           string `json:"record_type"`
		ActionID             string `json:"action_id"`
		ActionHash           string `json:"action_hash"`
		PayloadHash          string `json:"payload_hash"`
		Direction            string `json:"direction"`
		PartyIdentity        string `json:"party_identity"`
		CounterpartyIdentity string `json:"counterparty_identity"`
	}{
		RecordType:           c.RecordType,
		ActionID:             c.ActionID,
		ActionHash:           c.ActionHash,
		PayloadHash:          c.PayloadHash,
		Direction:            c.Direction,
		PartyIdentity:        c.PartyIdentity,
		CounterpartyIdentity: c.CounterpartyIdentity,
	}
	raw, err := json.Marshal(unsigned)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("marshal canonical payload capture: %w", err)
	}
	tree, err := contract.ParseJSONStrict(raw)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("parse canonical payload capture: %w", err)
	}
	canonical, err := contract.Canonicalize(tree)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(canonical), nil
}

func trustedReceiptKeyHex(name string, key ed25519.PublicKey) (string, error) {
	if len(key) != ed25519.PublicKeySize {
		return "", fmt.Errorf("%w: %s receipt key length = %d, want %d", ErrTrustedReceiptKey, name, len(key), ed25519.PublicKeySize)
	}
	return hex.EncodeToString(key), nil
}

func rejectSideRecordKeyReuse(sideKey, senderKey, receiverKey ed25519.PublicKey) error {
	if len(sideKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: side-record key size = %d, want %d", ErrUntrustedSideRecordKey, len(sideKey), ed25519.PublicKeySize)
	}
	if bytes.Equal(sideKey, senderKey) || bytes.Equal(sideKey, receiverKey) {
		return ErrSideRecordKeyReuse
	}
	return nil
}

func compareReceiptIdentity(name string, r receipt.Receipt, want string) error {
	if r.ActionRecord.Actor != want {
		return fmt.Errorf("%w: %s receipt actor %q does not match record identity %q", ErrReceiptIdentity, name, r.ActionRecord.Actor, want)
	}
	return nil
}

func compareReceiptHash(name string, r receipt.Receipt, want string) error {
	got, err := receipt.ReceiptHash(r)
	if err != nil {
		return fmt.Errorf("%s receipt hash: %w", name, err)
	}
	got = hashPrefix + got
	if got != want {
		return fmt.Errorf("%s receipt hash %q does not match record hash %q", name, got, want)
	}
	return nil
}

func validateHash(field, value string) error {
	if !strings.HasPrefix(value, hashPrefix) {
		return fmt.Errorf("%w: %s must have %s prefix", ErrMalformedBinding, field, hashPrefix)
	}
	raw := strings.TrimPrefix(value, hashPrefix)
	decoded, err := hex.DecodeString(raw)
	if err != nil {
		return fmt.Errorf("%w: %s must be lowercase hex SHA-256: %s", ErrMalformedBinding, field, err.Error())
	}
	if len(decoded) != sha256.Size {
		return fmt.Errorf("%w: %s length = %d, want %d", ErrMalformedBinding, field, len(decoded), sha256.Size)
	}
	if hex.EncodeToString(decoded) != raw {
		return fmt.Errorf("%w: %s must be lowercase hex SHA-256", ErrMalformedBinding, field)
	}
	return nil
}

// validateToken enforces a printable, non-space ASCII grammar with a length
// bound on identity/nonce/receipt-id fields. Restricting to ASCII guarantees
// NFC normalization is a no-op, so the raw field used for the replay key matches
// the normalized bytes the signature covers (closes the Unicode-normalization
// replay bypass).
func validateToken(field, value string) error {
	if value == "" {
		return fmt.Errorf("%w: %s is required", ErrMalformedBinding, field)
	}
	if len(value) > maxTokenLen {
		return fmt.Errorf("%w: %s length = %d, want <= %d", ErrMalformedBinding, field, len(value), maxTokenLen)
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c < 0x21 || c > 0x7e {
			return fmt.Errorf("%w: %s must be printable non-space ASCII", ErrMalformedBinding, field)
		}
	}
	return nil
}

func decodeSignature(value string) ([]byte, error) {
	if !strings.HasPrefix(value, signaturePrefix) {
		return nil, fmt.Errorf("signature must have %s prefix", signaturePrefix)
	}
	encoded := strings.TrimPrefix(value, signaturePrefix)
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	if len(raw) != ed25519.SignatureSize {
		return nil, fmt.Errorf("invalid signature length: got %d, want %d", len(raw), ed25519.SignatureSize)
	}
	if base64.StdEncoding.EncodeToString(raw) != encoded {
		return nil, errors.New("signature must be canonical base64")
	}
	return raw, nil
}

func fail(code FailureCode, err error) VerificationResult {
	return failWithNonce(code, err, nil, "")
}

func failWithNonce(code FailureCode, err error, nonce *NonceKey, signerKeyID string) VerificationResult {
	msg := ""
	if err != nil {
		msg = fmt.Errorf("%w: %w", ErrVerificationError, err).Error()
	}
	return VerificationResult{
		Passed:      false,
		FailureCode: code,
		Error:       msg,
		Nonce:       nonce,
		SignerKeyID: signerKeyID,
	}
}
