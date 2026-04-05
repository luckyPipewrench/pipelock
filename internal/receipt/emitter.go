// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// recorderEntryType is the recorder entry type for action receipts.
const recorderEntryType = "action_receipt"

// recorderSessionID is the session ID used for all recorder entries from the emitter.
// The recorder pins to the first session ID it sees, so all entries must use the same value.
const recorderSessionID = "proxy"

// Emitter produces signed action receipts and writes them to the flight recorder.
// It is safe for concurrent use — the underlying recorder handles its own locking.
type Emitter struct {
	recorder   *recorder.Recorder
	privKey    ed25519.PrivateKey
	configHash atomic.Value // stores string; updated on hot reload
	principal  string
	actor      string

	// Chain state — mutex-protected, updated on each Emit.
	chainMu       sync.Mutex
	chainSeq      uint64
	chainPrevHash string
	chainStart    time.Time // timestamp of first receipt
	chainEnd      time.Time // timestamp of most recent receipt
	rootEmitted   bool      // true after EmitTranscriptRoot; prevents duplicate roots
}

// EmitterConfig holds the configuration for creating an Emitter.
type EmitterConfig struct {
	Recorder   *recorder.Recorder
	PrivKey    ed25519.PrivateKey
	ConfigHash string
	Principal  string
	Actor      string
}

// NewEmitter creates a receipt emitter. Returns nil if the recorder is nil
// or the private key is missing — callers can safely call Emit on a nil Emitter.
func NewEmitter(cfg EmitterConfig) *Emitter {
	if cfg.Recorder == nil {
		return nil
	}
	if len(cfg.PrivKey) != ed25519.PrivateKeySize {
		return nil
	}
	e := &Emitter{
		recorder:      cfg.Recorder,
		privKey:       cfg.PrivKey,
		principal:     cfg.Principal,
		actor:         cfg.Actor,
		chainPrevHash: GenesisHash,
	}
	e.configHash.Store(cfg.ConfigHash)
	return e
}

// EmitOpts holds the per-decision context for emitting a receipt.
type EmitOpts struct {
	ActionID  string
	Verdict   string
	Layer     string
	Pattern   string
	Transport string
	Method    string
	Target    string
	RequestID string
	Agent     string

	// MCP-specific fields
	ToolName  string
	MCPMethod string
}

// Emit creates, signs, and records an action receipt for a proxy decision.
// The call is synchronous through the recorder mutex — same as recordDecision.
// Errors are returned but should be logged, not propagated to callers.
// Safe to call on a nil Emitter (no-op).
func (e *Emitter) Emit(opts EmitOpts) error {
	if e == nil {
		return nil
	}

	actionType := e.classifyAction(opts)
	sideEffect := SideEffectFromMethod(opts.Method)
	reversibility := ReversibilityFromMethod(opts.Method)

	// MCP tool calls have different classification paths
	if opts.MCPMethod != "" {
		sideEffect = sideEffectFromMCPAction(actionType)
		reversibility = ReversibilityUnknown
	}

	// Chain integrity: lock covers stamp → sign → hash → persist → advance.
	// The mutex must span from timestamp through persist so concurrent Emit
	// calls produce monotonic timestamps in chain order. State is only
	// advanced after successful write; a failed Record leaves the chain at
	// the previous position.
	e.chainMu.Lock()
	defer e.chainMu.Unlock()

	if e.rootEmitted {
		return ErrChainSealed
	}

	ar := ActionRecord{
		Version:         ActionRecordVersion,
		ActionID:        opts.ActionID,
		ActionType:      actionType,
		Timestamp:       time.Now().UTC(),
		Principal:       e.principal,
		Actor:           e.actorLabel(opts),
		DelegationChain: nil, // Populated when delegation tracking ships
		Target:          opts.Target,
		SideEffectClass: sideEffect,
		Reversibility:   reversibility,
		PolicyHash:      configHashString(e.configHash.Load()),
		Verdict:         NormalizeVerdict(opts.Verdict),
		Transport:       opts.Transport,
		Method:          opts.Method,
		Layer:           opts.Layer,
		Pattern:         opts.Pattern,
		RequestID:       opts.RequestID,
		ChainPrevHash:   e.chainPrevHash,
		ChainSeq:        e.chainSeq,
	}

	rcpt, err := Sign(ar, e.privKey)
	if err != nil {
		return fmt.Errorf("signing receipt: %w", err)
	}

	receiptHash, err := ReceiptHash(rcpt)
	if err != nil {
		return fmt.Errorf("hashing receipt: %w", err)
	}

	receiptJSON, err := Marshal(rcpt)
	if err != nil {
		return fmt.Errorf("marshaling receipt: %w", err)
	}

	// Advance chain state BEFORE persist. Record may write the entry
	// and then fail on checkpoint/rotation. If we left chain state
	// unchanged, the next Emit would reuse the same prev_hash/seq,
	// forking the chain. Advancing first means a failed Record
	// leaves a gap (missing entry) rather than a fork (duplicate link),
	// which is fail-closed: verify-chain detects gaps but not forks.
	e.chainPrevHash = receiptHash
	if e.chainSeq == 0 {
		e.chainStart = ar.Timestamp
	}
	e.chainEnd = ar.Timestamp
	e.chainSeq++

	if err := e.recorder.Record(recorder.Entry{
		SessionID: recorderSessionID,
		Type:      recorderEntryType,
		Transport: opts.Transport,
		Summary:   fmt.Sprintf("receipt: %s %s %s", ar.Verdict, ar.ActionType, ar.Target),
		Detail:    json.RawMessage(receiptJSON),
	}); err != nil {
		return fmt.Errorf("recording receipt: %w", err)
	}

	return nil
}

// UpdateConfigHash sets the config hash for new receipts. Called on hot reload.
// Safe for concurrent use with Emit — uses atomic.Value internally.
func (e *Emitter) UpdateConfigHash(hash string) {
	if e == nil {
		return
	}
	e.configHash.Store(hash)
}

func (e *Emitter) classifyAction(opts EmitOpts) ActionType {
	if opts.MCPMethod != "" {
		return ClassifyMCPTool(opts.ToolName, opts.MCPMethod)
	}
	if opts.Method != "" {
		return ClassifyHTTP(opts.Method)
	}
	return ActionUnclassified
}

func (e *Emitter) actorLabel(opts EmitOpts) string {
	if opts.Agent != "" {
		return opts.Agent
	}
	return e.actor
}

// sideEffectFromMCPAction maps action types to side-effect classes for MCP.
func sideEffectFromMCPAction(at ActionType) SideEffectClass {
	switch at {
	case ActionRead:
		return SideEffectExternalRead
	case ActionWrite, ActionCommit:
		return SideEffectExternalWrite
	case ActionDelegate:
		return SideEffectExternalWrite
	case ActionSpend:
		return SideEffectFinancial
	case ActionActuate:
		return SideEffectPhysical
	default:
		return SideEffectNone
	}
}

// transcriptRootEntryType is the recorder entry type for transcript roots.
const transcriptRootEntryType = "transcript_root"

// ErrRootAlreadyEmitted is returned when EmitTranscriptRoot is called more
// than once. Transcript roots are single-shot to prevent conflicting roots.
var ErrRootAlreadyEmitted = fmt.Errorf("transcript root already emitted")

// ErrChainSealed is returned when Emit is called after EmitTranscriptRoot.
// Once a root is emitted, the chain is sealed and no more receipts can be added.
var ErrChainSealed = fmt.Errorf("chain sealed: transcript root already emitted")

// EmitTranscriptRoot computes and records the transcript root for the current chain.
// Single-shot: returns ErrRootAlreadyEmitted on subsequent calls. This prevents
// an attacker from emitting multiple conflicting roots for the same session.
// Safe to call on a nil Emitter (no-op).
func (e *Emitter) EmitTranscriptRoot(sessionID string) error {
	if e == nil {
		return nil
	}

	e.chainMu.Lock()
	defer e.chainMu.Unlock()

	if e.rootEmitted {
		return ErrRootAlreadyEmitted
	}

	if e.chainSeq == 0 {
		return nil // no receipts emitted
	}

	root := TranscriptRoot{
		SessionID:    sessionID,
		FinalSeq:     e.chainSeq - 1,
		RootHash:     e.chainPrevHash,
		ReceiptCount: e.chainSeq,
		StartTime:    e.chainStart,
		EndTime:      e.chainEnd,
	}

	if err := e.recorder.Record(recorder.Entry{
		SessionID: recorderSessionID,
		Type:      transcriptRootEntryType,
		Summary:   fmt.Sprintf("transcript_root: %d receipts, root=%s", root.ReceiptCount, root.RootHash[:16]),
		Detail:    root,
	}); err != nil {
		return fmt.Errorf("recording transcript root: %w", err)
	}

	e.rootEmitted = true
	return nil
}

// configHashString safely extracts a string from an atomic.Value.
// Returns empty string if the value is nil or not a string.
func configHashString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
