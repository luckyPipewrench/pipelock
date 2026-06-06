// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package proxydecision emits signed EvidenceReceipt v2 proxy_decision records
// for live proxy enforcement decisions, alongside the legacy v1 ActionReceipt.
//
// It is the live emitter that BuildProxyDecisionReceipt was missing: the v2
// receipt machinery (JCS canonical preimage, detached SignatureProof, strict
// DisallowUnknownFields validation) already existed for shadow/activation
// lifecycle records, but no production code emitted the proxy_decision payload
// on the hot path. This package replicates the shadow emitter's signing
// sequence for that payload.
//
// Chain model: this emitter maintains its OWN per-receipt chain (chain_seq /
// chain_prev_hash), independent of the v1 ActionReceipt chain, both anchored at
// recorder.GenesisHash. Both chains write into the same recorder, whose outer
// hash chain spans every entry and provides the cross-record tamper-evidence;
// the per-emitter chains are the in-band sequence the verifier walks. The v1
// ActionReceipt chain is left untouched (expand-and-contract: v1 stays live).
package proxydecision

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	contractruntime "github.com/luckyPipewrench/pipelock/internal/contract/runtime"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const (
	evidenceReceiptEntryType = "evidence_receipt"
	recorderSessionID        = "proxy"
	signatureAlgorithm       = "ed25519"
	signaturePrefix          = "ed25519:"
	keyPurposeReceiptSigning = "receipt-signing"

	// Decision-source provenance labels. policy_sources / winning_source on the
	// v2 proxy_decision payload are GENERIC decision provenance, not
	// contract-only: a pure scanner block attributes to the scanner, a kill
	// switch to itself, and a contract-participated decision adds the contract
	// marker on top of the contract's own policy sources.
	SourceScanner    = "scanner"
	SourceKillSwitch = "kill_switch"
	SourceContract   = "contract"
)

// ErrSignatureSize is returned when the signer produces a non-Ed25519-sized
// signature. It is a programming/configuration error (wrong key type), never
// agent-reachable input.
var ErrSignatureSize = errors.New("proxydecision: signature size mismatch")

// Signer signs EvidenceReceipt v2 preimages. Matches the interface used by the
// shadow and activation emitters.
type Signer interface {
	KeyID() string
	Sign([]byte) ([]byte, error)
}

// Recorder is the recorder subset used by Emitter.
type Recorder interface {
	Record(recorder.Entry) error
}

// SanitizeFunc reports whether text is free of DLP matches. It is built from
// recorder.ReceiptRedactor at construction time and is nil when flight-recorder
// redaction is off, in which case targets pass through unchanged.
type SanitizeFunc func(string) bool

// SanitizeFromRedactor adapts a recorder.RedactFunc into a SanitizeFunc so the
// v2 emitter scrubs secrets with the exact function the recorder applies.
// Returns nil when rf is nil (redaction disabled), leaving targets unchanged.
// Both the startup and hot-reload construction paths use this so the v2
// emitter's sanitization stays in lockstep with the recorder.
func SanitizeFromRedactor(rf recorder.RedactFunc) SanitizeFunc {
	if rf == nil {
		return nil
	}
	return func(text string) bool { return rf(context.Background(), text).Clean }
}

// Decision is the per-call input describing one proxy enforcement decision.
// The proxy derives it from its receipt.EmitOpts; this package is transport
// agnostic and never sees agent-controlled structs directly.
type Decision struct {
	// ActionType labels the action class: "http_request", "mcp_tool_call",
	// or "websocket_frame".
	ActionType string
	// Transport is the surface label: "forward", "intercept", "fetch",
	// "websocket", "mcp_http", "mcp_stdio", "reverse".
	Transport string
	// Target is the RAW acted-upon target (URL / tool name / authority). It is
	// sanitized (#676) before it enters the signed payload.
	Target string
	// Verdict is the enforcement verdict the proxy applied.
	Verdict string
	// LiveVerdict surfaces a contract live/shadow divergence; omitted from the
	// wire payload when equal to Verdict.
	LiveVerdict string
	// WinningSource and PolicySources are generic decision provenance (see the
	// Source* constants). Both are required by the v2 payload validator.
	WinningSource string
	PolicySources []string
	// RuleID is the RAW matched rule / pattern label. It is sanitized before
	// signing because a scanner pattern can echo matched bytes.
	RuleID string

	// Contract envelope fields, populated ONLY when a real resolved contract
	// existed for this request. Empty for pure scanner / kill-switch decisions,
	// in which case nothing is stamped.
	ActiveManifestHash string
	ContractHash       string
	SelectorID         string
	ContractGeneration uint64
}

// EmitterConfig configures live proxy_decision emission.
type EmitterConfig struct {
	Recorder  Recorder
	Signer    Signer
	Sanitize  SanitizeFunc
	Principal string
	Actor     string
	Clock     func() time.Time
	EventID   func() (string, error)

	// ResumeSeq / ResumePrevHash carry the chain head forward across a hot
	// reload so the v2 chain stays continuous within a process when the
	// signing key (and therefore the emitter) is rebuilt. Leave both zero for
	// a fresh chain (ResumePrevHash defaults to GenesisHash).
	ResumeSeq      uint64
	ResumePrevHash string
}

// Emitter signs proxy_decision receipts and records them.
type Emitter struct {
	recorder  Recorder
	signer    Signer
	sanitize  SanitizeFunc
	principal string
	actor     string
	clock     func() time.Time
	eventID   func() (string, error)

	mu            sync.Mutex
	chainSeq      uint64
	chainPrevHash string
}

// NewEmitter returns nil when recorder or signer is missing, matching the
// legacy receipt emitter's no-op-when-disabled behavior so callers can store a
// nil pointer and call Emit unconditionally.
func NewEmitter(cfg EmitterConfig) *Emitter {
	if cfg.Recorder == nil || cfg.Signer == nil {
		return nil
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	eventID := cfg.EventID
	if eventID == nil {
		eventID = newEventID
	}
	prev := cfg.ResumePrevHash
	if prev == "" {
		prev = recorder.GenesisHash
	}
	return &Emitter{
		recorder:      cfg.Recorder,
		signer:        cfg.Signer,
		sanitize:      cfg.Sanitize,
		principal:     cfg.Principal,
		actor:         cfg.Actor,
		clock:         clock,
		eventID:       eventID,
		chainSeq:      cfg.ResumeSeq,
		chainPrevHash: prev,
	}
}

func newEventID() (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

// ChainState returns the current chain head (next seq, prev hash). A reload
// uses it to seed the replacement emitter's EmitterConfig so the v2 chain does
// not reset to genesis mid-process. Safe on a nil receiver.
func (e *Emitter) ChainState() (seq uint64, prevHash string) {
	if e == nil {
		return 0, recorder.GenesisHash
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.chainSeq, e.chainPrevHash
}

// Emit builds, signs, and records one v2 proxy_decision receipt. It is a no-op
// on a nil receiver. The mutex spans the whole build→sign→hash→persist→advance
// sequence so concurrent calls produce a well-ordered chain; chain state is
// advanced only after a successful record, so a failed write leaves the chain
// at its previous position (mirroring the v1 emitter and the shadow emitter).
func (e *Emitter) Emit(d Decision) error {
	if e == nil {
		return nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Sanitize secret-bearing fields BEFORE signing, byte-identically to the v1
	// emitter (#676). The signed target must never carry raw secret bytes.
	target := d.Target
	ruleID := d.RuleID
	if e.sanitize != nil {
		target = receipt.SanitizeTarget(target, e.sanitize)
		ruleID = receipt.CleanOrRedacted(ruleID, e.sanitize)
	}

	eventID, err := e.eventID()
	if err != nil {
		return fmt.Errorf("generate proxy_decision event id: %w", err)
	}

	rcpt, err := contractruntime.BuildProxyDecisionReceipt(contractruntime.ProxyDecisionInput{
		Decision: contractruntime.Decision{
			Verdict:       d.Verdict,
			LiveVerdict:   d.LiveVerdict,
			PolicySources: d.PolicySources,
			WinningSource: d.WinningSource,
			RuleID:        ruleID,
		},
		ActionType:    d.ActionType,
		Target:        target,
		Transport:     d.Transport,
		EventID:       eventID,
		Timestamp:     e.clock().UTC(),
		Principal:     e.principal,
		Actor:         e.actor,
		ChainSeq:      e.chainSeq,
		ChainPrevHash: e.chainPrevHash,
	})
	if err != nil {
		return fmt.Errorf("build proxy_decision receipt: %w", err)
	}

	// Stamp the contract envelope only when a real resolved contract existed.
	// For scanner / kill-switch decisions these fields are empty, so the stamp
	// is a no-op (the fields are omitempty in the wire form).
	rcpt = contractruntime.ReceiptContext{
		ActiveManifestHash: d.ActiveManifestHash,
		ContractHash:       d.ContractHash,
		SelectorID:         d.SelectorID,
		ContractGeneration: d.ContractGeneration,
	}.StampReceipt(rcpt)

	preimage, err := rcpt.SignablePreimage()
	if err != nil {
		return fmt.Errorf("build proxy_decision preimage: %w", err)
	}
	signature, err := e.signer.Sign(preimage)
	if err != nil {
		return fmt.Errorf("sign proxy_decision receipt: %w", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("%w: got %d want %d", ErrSignatureSize, len(signature), ed25519.SignatureSize)
	}
	rcpt.Signature = contractreceipt.SignatureProof{
		SignerKeyID: e.signer.KeyID(),
		KeyPurpose:  keyPurposeReceiptSigning,
		Algorithm:   signatureAlgorithm,
		Signature:   signaturePrefix + hex.EncodeToString(signature),
	}
	if err := rcpt.Validate(); err != nil {
		return fmt.Errorf("validate proxy_decision receipt: %w", err)
	}

	rcptHash, err := contractreceipt.ReceiptHash(rcpt)
	if err != nil {
		return fmt.Errorf("hash proxy_decision receipt: %w", err)
	}
	rcptJSON, err := json.Marshal(rcpt)
	if err != nil {
		return fmt.Errorf("marshal proxy_decision receipt: %w", err)
	}

	if err := e.recorder.Record(recorder.Entry{
		SessionID: recorderSessionID,
		Type:      evidenceReceiptEntryType,
		EventKind: string(contractreceipt.PayloadProxyDecision),
		Transport: d.Transport,
		Summary:   fmt.Sprintf("proxy_decision: %s %s via %s", d.ActionType, d.Verdict, d.WinningSource),
		Detail:    json.RawMessage(rcptJSON),
	}); err != nil {
		return fmt.Errorf("record proxy_decision receipt: %w", err)
	}
	e.chainPrevHash = rcptHash
	e.chainSeq++
	return nil
}

// KeyedSigner wraps an Ed25519 private key as a Signer. KeyID is the
// hex-encoded public key so any verifier holding the public key can match the
// receipt's signer_key_id without an out-of-band key registry.
type KeyedSigner struct {
	keyID string
	key   ed25519.PrivateKey
}

// NewKeyedSigner builds a KeyedSigner from an Ed25519 private key.
func NewKeyedSigner(key ed25519.PrivateKey) KeyedSigner {
	var keyID string
	if pub, ok := key.Public().(ed25519.PublicKey); ok {
		keyID = hex.EncodeToString(pub)
	}
	return KeyedSigner{keyID: keyID, key: key}
}

// KeyID returns the hex-encoded public key.
func (s KeyedSigner) KeyID() string { return s.keyID }

// Sign produces an Ed25519 signature over message.
func (s KeyedSigner) Sign(message []byte) ([]byte, error) {
	if len(s.key) != ed25519.PrivateKeySize {
		return nil, errors.New("proxydecision: signer key not initialized")
	}
	return ed25519.Sign(s.key, message), nil
}
