// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package provenance

// Per-message MCP signing — Free-tier single-agent verifier.
//
// This extends the existing tool-definition signing in sign.go to cover the
// per-call request/response messages crossing the MCP wire. Each signed
// message carries a SignedMessage payload under the `_meta` field at the
// JSON-RPC envelope level, keyed as "com.pipelock/message-signature".
//
// The Free-tier scope is intentionally narrow: a single operator-supplied
// trust anchor (one Ed25519 public key + key ID), a configured max-age
// window, and an injectable replay cache. Multi-agent trust roots, fleet
// key distribution, and centrally-managed replay windows are out of scope
// here and belong in the Pro tier (see v2.6 strategy follow-ups #7).
//
// Threat model: a cooperating MCP server signs every JSON-RPC message it
// emits. Pipelock verifies on receipt and emits a receipt with the
// verification status. Bad signatures, expired timestamps, replays, and
// mismatched key IDs all fail closed: the calling layer should treat any
// non-"verified" status from a configured-as-signed upstream as a block.
// Unsigned messages from an upstream the operator did not configure as
// signing-required pass through with status "unsigned" — operators choose
// their policy.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// MessageMetaKey is the _meta key under which message signatures are stored
// inside a JSON-RPC envelope. Sibling to provenance.metaKey (tool-definition
// signatures).
const MessageMetaKey = "com.pipelock/message-signature"

// MessageSigAlgEd25519 is the only supported signature algorithm for now.
const MessageSigAlgEd25519 = "ed25519"

// MinNonceLen is the minimum length (in raw bytes) for the per-message nonce.
// 16 bytes = 128 bits, well above the birthday bound for any realistic
// session volume.
const MinNonceLen = 16

// SignedMessage is the _meta payload added to an MCP JSON-RPC message to
// carry the per-message signature and replay-protection metadata.
type SignedMessage struct {
	// Algorithm names the signature scheme. Currently fixed at "ed25519".
	Algorithm string `json:"alg"`
	// KeyID identifies the signing key. Verification requires an exact
	// match against the configured trust anchor's KeyID.
	KeyID string `json:"kid"`
	// Timestamp is Unix seconds at which the signer produced the message.
	// Used to reject expired messages.
	Timestamp int64 `json:"ts"`
	// Nonce is a base64-encoded random value (>= MinNonceLen raw bytes).
	// Used to reject replays inside the max-age window.
	Nonce string `json:"nonce"`
	// Signature is base64-encoded over the canonical digest. See
	// canonicalMessageDigest for the byte layout.
	Signature string `json:"sig"`
}

// MessageVerifyStatus is the high-level outcome of verifying a per-message
// signature. Receipts include this status; security policy decisions hang
// off it.
type MessageVerifyStatus string

// Verification status constants. New values can be added; existing values
// are stable and may be referenced by external receipts.
const (
	MessageSigVerified  MessageVerifyStatus = "verified"
	MessageSigUnsigned  MessageVerifyStatus = "unsigned"
	MessageSigInvalid   MessageVerifyStatus = "invalid"
	MessageSigExpired   MessageVerifyStatus = "expired"
	MessageSigReplay    MessageVerifyStatus = "replay"
	MessageSigBadKeyID  MessageVerifyStatus = "bad_key_id"
	MessageSigBadAlg    MessageVerifyStatus = "bad_alg"
	MessageSigMalformed MessageVerifyStatus = "malformed"
)

// MessageVerifyResult describes the outcome of VerifyMessage.
type MessageVerifyResult struct {
	Status MessageVerifyStatus
	// Reason is a short, operator-readable explanation suitable for logs
	// and receipts. Never includes the signature or key material.
	Reason string
	// SignedBy is the KeyID from the message envelope, if it parsed. Empty
	// when the message was unsigned or malformed at the JSON-RPC layer.
	SignedBy string
}

// ReplayCache is the small interface VerifyMessage uses to detect replays
// inside the max-age window. The Free-tier in-process implementation is
// MemoryReplayCache; the Pro tier may swap in a shared cache.
type ReplayCache interface {
	// Seen returns true if the nonce has been recorded since `since`.
	// Cache implementations may evict entries older than the largest
	// max-age they've been asked about.
	Seen(nonce string, since time.Time) bool
	// Record stores the nonce with the given observation time.
	Record(nonce string, at time.Time)
}

// MessageVerifyConfig configures per-message signature verification.
//
// Zero-value MessageVerifyConfig is invalid; callers must supply at least PublicKey
// and MaxAge. NonceCache may be nil to skip replay detection (NOT recommended
// for production).
type MessageVerifyConfig struct {
	// PublicKey is the operator-supplied trust anchor.
	PublicKey ed25519.PublicKey
	// KeyID must match the SignedMessage.KeyID exactly.
	KeyID string
	// MaxAge bounds the timestamp-validity window. Messages older than
	// MaxAge from Clock() are rejected with MessageSigExpired.
	MaxAge time.Duration
	// NonceCache provides replay detection. Nil disables replay detection
	// (caller's responsibility to enable for production).
	NonceCache ReplayCache
	// Clock returns the current time. Defaults to time.Now if nil.
	// Injection point for tests.
	Clock func() time.Time
}

// MemoryReplayCache is a small in-process replay cache keyed by nonce.
// Safe for concurrent use. Evicts entries older than the largest observed
// max-age window on each Record call.
type MemoryReplayCache struct {
	mu     sync.Mutex
	seen   map[string]time.Time
	maxTTL time.Duration
}

// NewMemoryReplayCache returns an empty in-process cache.
func NewMemoryReplayCache() *MemoryReplayCache {
	return &MemoryReplayCache{seen: make(map[string]time.Time)}
}

// Seen reports whether the nonce was recorded at or after since.
func (c *MemoryReplayCache) Seen(nonce string, since time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.seen[nonce]
	if !ok {
		return false
	}
	return !t.Before(since)
}

// Record stores the nonce with the given observation time and opportunistically
// prunes entries older than the largest observed window.
func (c *MemoryReplayCache) Record(nonce string, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seen[nonce] = at
	// Track the largest observed window so eviction has a useful threshold.
	// VerifyMessage calls Record(now); the eviction floor is now-maxTTL.
	if c.maxTTL == 0 {
		return
	}
	cutoff := at.Add(-c.maxTTL)
	for k, ts := range c.seen {
		if ts.Before(cutoff) {
			delete(c.seen, k)
		}
	}
}

// SetMaxTTL configures the upper bound for cache retention. VerifyMessage
// sets this implicitly via the MaxAge field when using the standard cache.
func (c *MemoryReplayCache) SetMaxTTL(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if d > c.maxTTL {
		c.maxTTL = d
	}
}

// canonicalMessageDigest computes the SHA-256 hash that the signer signs
// and the verifier checks. The digest covers the fields that MUST be
// integrity-protected: method, params, id, timestamp, nonce, key ID, alg.
//
// Canonical form is the same approach as ToolDigest: marshal a struct
// with alphabetical field declarations, no whitespace, params normalized
// via the existing sortAndMarshal pipeline.
//
// Including timestamp + nonce in the digest binds them to the message —
// an attacker cannot replay a signed message with a freshly chosen
// nonce or timestamp.
func canonicalMessageDigest(method string, params, id json.RawMessage, alg, keyID string, ts int64, nonce string) (string, error) {
	type canonicalMsg struct {
		Alg       string          `json:"alg"`
		ID        json.RawMessage `json:"id,omitempty"`
		KeyID     string          `json:"kid"`
		Method    string          `json:"method"`
		Nonce     string          `json:"nonce"`
		Params    json.RawMessage `json:"params,omitempty"`
		Timestamp int64           `json:"ts"`
	}

	normalizedParams := normalizeSchema(params)
	if string(normalizedParams) == "null" && len(params) == 0 {
		normalizedParams = nil
	}
	normalizedID := id
	if len(id) == 0 || string(id) == "null" {
		normalizedID = nil
	}

	cm := canonicalMsg{
		Alg:       alg,
		ID:        normalizedID,
		KeyID:     keyID,
		Method:    method,
		Nonce:     nonce,
		Params:    normalizedParams,
		Timestamp: ts,
	}
	data, err := json.Marshal(cm)
	if err != nil {
		return "", fmt.Errorf("canonicalize message: %w", err)
	}
	h := sha256.Sum256(data)
	return base64.StdEncoding.EncodeToString(h[:]), nil
}

// SignMessage produces a SignedMessage payload for the given JSON-RPC fields.
// The signer must be in possession of the Ed25519 private key. Nonce must be
// caller-supplied (typically 16+ random bytes, base64-encoded).
func SignMessage(method string, params, id json.RawMessage, privKey ed25519.PrivateKey, keyID, nonce string, ts time.Time) (SignedMessage, error) {
	if len(privKey) != ed25519.PrivateKeySize {
		return SignedMessage{}, errors.New("invalid Ed25519 private key size")
	}
	if keyID == "" {
		return SignedMessage{}, errors.New("keyID required")
	}
	if err := validateNonce(nonce); err != nil {
		return SignedMessage{}, err
	}
	digest, err := canonicalMessageDigest(method, params, id, MessageSigAlgEd25519, keyID, ts.Unix(), nonce)
	if err != nil {
		return SignedMessage{}, err
	}
	sig := ed25519.Sign(privKey, []byte(digest))
	return SignedMessage{
		Algorithm: MessageSigAlgEd25519,
		KeyID:     keyID,
		Timestamp: ts.Unix(),
		Nonce:     nonce,
		Signature: base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// validateNonce enforces the minimum-length and base64-encoding rule.
func validateNonce(nonce string) error {
	if nonce == "" {
		return errors.New("nonce required")
	}
	decoded, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		return fmt.Errorf("nonce must be base64-encoded: %w", err)
	}
	if len(decoded) < MinNonceLen {
		return fmt.Errorf("nonce too short: got %d bytes, want at least %d", len(decoded), MinNonceLen)
	}
	return nil
}

// VerifyMessage verifies a SignedMessage against the configured trust anchor
// and replay window. Returns a MessageVerifyResult that callers should
// translate into a security-policy decision.
//
// rawMsg is the raw JSON-RPC envelope bytes. The function extracts the
// signature from rawMsg's _meta field, reconstructs the canonical digest
// from the other envelope fields, and verifies.
//
// Fail-closed: every error path returns a non-Verified status. The caller
// is responsible for treating non-Verified as a block when policy says so.
func VerifyMessage(rawMsg []byte, cfg MessageVerifyConfig) MessageVerifyResult {
	if len(cfg.PublicKey) != ed25519.PublicKeySize {
		return MessageVerifyResult{Status: MessageSigInvalid, Reason: "invalid trust-anchor public key"}
	}
	if cfg.KeyID == "" {
		return MessageVerifyResult{Status: MessageSigInvalid, Reason: "trust-anchor key ID required"}
	}
	if cfg.MaxAge <= 0 {
		return MessageVerifyResult{Status: MessageSigInvalid, Reason: "positive max-age required"}
	}

	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}

	// Parse envelope.
	var env struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params"`
		Meta    json.RawMessage `json:"_meta"`
	}
	if err := json.Unmarshal(rawMsg, &env); err != nil {
		return MessageVerifyResult{Status: MessageSigMalformed, Reason: "envelope is not valid JSON"}
	}

	// Extract signature from _meta.
	sig, found := extractSignedMessage(env.Meta)
	if !found {
		return MessageVerifyResult{Status: MessageSigUnsigned, Reason: "no signature in _meta"}
	}

	result := MessageVerifyResult{SignedBy: sig.KeyID}

	if sig.Algorithm != MessageSigAlgEd25519 {
		result.Status = MessageSigBadAlg
		result.Reason = "unsupported algorithm"
		return result
	}
	if sig.KeyID != cfg.KeyID {
		result.Status = MessageSigBadKeyID
		result.Reason = "key ID does not match configured trust anchor"
		return result
	}
	if err := validateNonce(sig.Nonce); err != nil {
		result.Status = MessageSigMalformed
		result.Reason = "nonce malformed: " + err.Error()
		return result
	}

	// Timestamp / max-age check.
	now := clock()
	signedAt := time.Unix(sig.Timestamp, 0)
	if now.Sub(signedAt) > cfg.MaxAge {
		result.Status = MessageSigExpired
		result.Reason = fmt.Sprintf("message older than max-age (%s)", cfg.MaxAge)
		return result
	}
	// Also reject far-future timestamps (clock-skew / forward-replay).
	// Allow MaxAge of slack in the future direction, mirroring the past
	// window. Operators with clocks more skewed than MaxAge have bigger
	// problems than replay protection.
	if signedAt.Sub(now) > cfg.MaxAge {
		result.Status = MessageSigExpired
		result.Reason = "message timestamp is in the future"
		return result
	}

	// Replay check.
	if cfg.NonceCache != nil {
		windowStart := now.Add(-cfg.MaxAge)
		if cfg.NonceCache.Seen(sig.Nonce, windowStart) {
			result.Status = MessageSigReplay
			result.Reason = "nonce previously seen within max-age window"
			return result
		}
	}

	// Recompute and verify signature.
	digest, err := canonicalMessageDigest(env.Method, env.Params, env.ID, sig.Algorithm, sig.KeyID, sig.Timestamp, sig.Nonce)
	if err != nil {
		result.Status = MessageSigMalformed
		result.Reason = "could not canonicalize envelope"
		return result
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sig.Signature)
	if err != nil {
		result.Status = MessageSigMalformed
		result.Reason = "signature not valid base64"
		return result
	}
	if len(sigBytes) != ed25519.SignatureSize {
		result.Status = MessageSigInvalid
		result.Reason = "signature wrong size"
		return result
	}
	if !ed25519.Verify(cfg.PublicKey, []byte(digest), sigBytes) {
		result.Status = MessageSigInvalid
		result.Reason = "signature did not verify"
		return result
	}

	// Verified. Record the nonce so subsequent replays trip.
	if cfg.NonceCache != nil {
		cfg.NonceCache.Record(sig.Nonce, now)
		if mc, ok := cfg.NonceCache.(*MemoryReplayCache); ok {
			mc.SetMaxTTL(cfg.MaxAge)
		}
	}
	result.Status = MessageSigVerified
	result.Reason = "ok"
	return result
}

// extractSignedMessage pulls the SignedMessage payload from a _meta blob.
// Returns false if _meta is absent, doesn't contain the message-signature
// key, or the payload is malformed.
func extractSignedMessage(meta json.RawMessage) (SignedMessage, bool) {
	if len(meta) == 0 || string(meta) == "null" {
		return SignedMessage{}, false
	}
	var asMap map[string]json.RawMessage
	if err := json.Unmarshal(meta, &asMap); err != nil {
		return SignedMessage{}, false
	}
	raw, ok := asMap[MessageMetaKey]
	if !ok {
		return SignedMessage{}, false
	}
	var sm SignedMessage
	if err := json.Unmarshal(raw, &sm); err != nil {
		return SignedMessage{}, false
	}
	if sm.Algorithm == "" && sm.Signature == "" {
		return SignedMessage{}, false
	}
	return sm, true
}

// EmbedMessageSignature inserts a SignedMessage into the _meta field of a
// JSON-RPC envelope, preserving existing _meta keys. Returns the new
// envelope bytes.
func EmbedMessageSignature(rawMsg []byte, sig SignedMessage) ([]byte, error) {
	var env map[string]json.RawMessage
	if err := json.Unmarshal(rawMsg, &env); err != nil {
		return nil, fmt.Errorf("parsing envelope: %w", err)
	}
	var meta map[string]json.RawMessage
	if rawMeta, ok := env["_meta"]; ok && len(rawMeta) > 0 && string(rawMeta) != "null" {
		if err := json.Unmarshal(rawMeta, &meta); err != nil {
			return nil, fmt.Errorf("parsing existing _meta: %w", err)
		}
	}
	if meta == nil {
		meta = make(map[string]json.RawMessage, 1)
	}
	sigJSON, err := json.Marshal(sig)
	if err != nil {
		return nil, fmt.Errorf("marshaling signature: %w", err)
	}
	meta[MessageMetaKey] = sigJSON
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return nil, fmt.Errorf("marshaling _meta: %w", err)
	}
	env["_meta"] = metaJSON
	return json.Marshal(env)
}
