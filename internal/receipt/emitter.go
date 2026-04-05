// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// recorderEntryType is the recorder entry type for action receipts.
const recorderEntryType = "action_receipt"

// Emitter produces signed action receipts and writes them to the flight recorder.
// It is safe for concurrent use — the underlying recorder handles its own locking.
type Emitter struct {
	recorder   *recorder.Recorder
	privKey    ed25519.PrivateKey
	configHash atomic.Value // stores string; updated on hot reload
	principal  string
	actor      string
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
		recorder:  cfg.Recorder,
		privKey:   cfg.PrivKey,
		principal: cfg.Principal,
		actor:     cfg.Actor,
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
		PolicyHash:      e.configHash.Load().(string),
		Verdict:         NormalizeVerdict(opts.Verdict),
		Transport:       opts.Transport,
		Method:          opts.Method,
		Layer:           opts.Layer,
		Pattern:         opts.Pattern,
		RequestID:       opts.RequestID,
	}

	receipt, err := Sign(ar, e.privKey)
	if err != nil {
		return fmt.Errorf("signing receipt: %w", err)
	}

	receiptJSON, err := Marshal(receipt)
	if err != nil {
		return fmt.Errorf("marshaling receipt: %w", err)
	}

	// Write to the flight recorder as a typed entry
	return e.recorder.Record(recorder.Entry{
		SessionID: "proxy",
		Type:      recorderEntryType,
		Transport: opts.Transport,
		Summary:   fmt.Sprintf("receipt: %s %s %s", ar.Verdict, ar.ActionType, ar.Target),
		Detail:    json.RawMessage(receiptJSON),
	})
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
