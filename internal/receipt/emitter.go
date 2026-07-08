// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// recorderEntryType is the recorder entry type for action receipts.
const recorderEntryType = "action_receipt"

// recorderSessionID is the session ID used for all recorder entries from the emitter.
// The recorder pins to the first session ID it sees, so all entries must use the same value.
const recorderSessionID = "proxy"

// MetricsSink receives receipt-emission observability signals. The proxy's
// metrics package implements it; tests can supply a stub. A nil sink is a
// no-op so the emitter never depends on metrics being wired.
type MetricsSink interface {
	// RecordEmitFailure increments the receipt-emit-failure counter, labeled
	// by a bounded-cardinality reason string.
	RecordEmitFailure(reason string)
}

// HealthSnapshot is a nil-safe, mutex-consistent read of the live receipt
// emitter chain state for observability and self-audit consumers.
type HealthSnapshot struct {
	InitErr     bool
	ChainSeq    uint64
	PrevHash    string
	LastEmit    time.Time
	RootEmitted bool
	RunNonce    string
}

// Emit-failure reason labels. Closed domain to keep metric cardinality bounded.
const (
	// FailReasonChainInit is the reason for failures that originate from a
	// chain that could not be initialized or resumed at construction time.
	FailReasonChainInit = "chain_init"
	// FailReasonSign is a signing failure.
	FailReasonSign = "sign"
	// FailReasonHash is a receipt-hash computation failure.
	FailReasonHash = "hash"
	// FailReasonMarshal is a receipt-marshal failure.
	FailReasonMarshal = "marshal"
	// FailReasonRecord is a recorder-write failure.
	FailReasonRecord = "record"
	// FailReasonSync is a recorder durability-sync failure.
	FailReasonSync = "sync"
	// FailReasonSealed is an emit attempt after the transcript root was emitted.
	FailReasonSealed = "sealed"
	// FailReasonUnavailable is a required-receipt emission attempt when no
	// receipt emitter is configured. Best-effort receipt paths intentionally
	// remain silent when receipts are disabled; this reason is for fail-closed
	// require_receipts decisions only.
	FailReasonUnavailable = "unavailable"
)

// Emitter produces signed action receipts and writes them to the flight recorder.
// It is safe for concurrent use - the underlying recorder handles its own locking.
type Emitter struct {
	recorder   *recorder.Recorder
	privKey    ed25519.PrivateKey
	configHash atomic.Value // stores string; updated on hot reload
	principal  string
	actor      string
	metrics    MetricsSink
	onReceipt  func(rcpt *Receipt)
	initErr    error
	healthMu   sync.RWMutex
	healthErr  error
	runNonce   string

	// Chain state - mutex-protected, updated on each Emit.
	chainMu       sync.Mutex
	chainSeq      uint64
	chainPrevHash string
	chainStart    time.Time // timestamp of first receipt
	chainEnd      time.Time // timestamp of most recent receipt
	rootEmitted   bool      // true after EmitTranscriptRoot; prevents duplicate roots
	closeEmitted  bool      // true after session_close; prevents duplicate closes
	openNonce     string
	heartbeatBeat uint64

	postureBinding PostureBinding

	// pendingTransition is set by resumeChain when the on-disk tail was
	// signed by a DIFFERENT (but self-valid) key, meaning a legitimate key
	// rotation occurred. It is stamped onto the first receipt of the new
	// segment by the next Emit, then cleared. nil when there is no pending
	// segment boundary.
	pendingTransition *KeyTransition

	// hasPriorTail carries the on-disk tail observed by resumeChain for this
	// process run. SessionOpen uses it to distinguish restart-open receipts
	// from a first-chain bound genesis.
	hasPriorTail  bool
	priorTailSeq  uint64
	priorTailHash string

	sessionOpenEmitted bool
	durabilityBlocks   atomic.Uint64
}

// EmitterConfig holds the configuration for creating an Emitter.
type EmitterConfig struct {
	Recorder   *recorder.Recorder
	PrivKey    ed25519.PrivateKey
	ConfigHash string
	Principal  string
	Actor      string
	// Metrics, when non-nil, receives emit-failure observability signals.
	Metrics MetricsSink
	// OnReceipt, when non-nil, is invoked with a copy of each signed receipt
	// AFTER it has been durably recorded, in chain order (the call happens
	// under the chain mutex, so observers see receipts in the same order they
	// were written). It is an OBSERVER only: the durable JSONL evidence file
	// remains the source of truth, and a panicking or slow observer must not be
	// able to corrupt the chain. Implementations MUST NOT block (push to a
	// buffered channel and drop on overflow) and MUST NOT mutate the receipt.
	// The default (nil) is a no-op, so the batch evidence path is unchanged.
	// Used by the live playground stream to surface decisions in real time.
	OnReceipt func(rcpt *Receipt)
	// PostureBinding, when set, is copied into session_open so offline
	// containment assessment can bind a receipt chain to a signed posture
	// capsule and contained UID.
	PostureBinding PostureBinding
}

// PostureBinding carries the signed posture-capsule fields that session_open
// records need for offline containment assessment.
type PostureBinding struct {
	CapsuleSHA256    string
	SignerKeyID      string
	ContainmentNonce string
	ContainedUID     string
}

// NewEmitter creates a receipt emitter. Returns nil if the recorder is nil
// or the private key is missing - callers can safely call Emit on a nil Emitter.
func NewEmitter(cfg EmitterConfig) *Emitter {
	if cfg.Recorder == nil {
		return nil
	}
	if len(cfg.PrivKey) != ed25519.PrivateKeySize {
		return nil
	}
	runNonce, nonceErr := newRunNonce()
	e := &Emitter{
		recorder:       cfg.Recorder,
		privKey:        cfg.PrivKey,
		principal:      cfg.Principal,
		actor:          cfg.Actor,
		metrics:        cfg.Metrics,
		onReceipt:      cfg.OnReceipt,
		runNonce:       runNonce,
		chainPrevHash:  GenesisHash,
		postureBinding: cfg.PostureBinding,
	}
	e.configHash.Store(cfg.ConfigHash)
	if nonceErr != nil {
		e.initErr = fmt.Errorf("generate run nonce: %w", nonceErr)
		return e
	}
	e.initErr = e.resumeChain()
	return e
}

// InitError returns the error (if any) that occurred while resuming the chain
// at construction time. A non-nil result means receipt emission is bricked for
// this emitter and Emit will return the wrapped error on every call. Callers
// should log this loudly once at startup with remediation guidance. Safe on a
// nil emitter.
func (e *Emitter) InitError() error {
	if e == nil {
		return nil
	}
	return e.initErr
}

// MarkUnhealthy bricks future emissions after a runtime receipt failure that
// makes the chain untrustworthy for required-receipt policy. Safe on nil.
func (e *Emitter) MarkUnhealthy(err error) {
	if e == nil || err == nil {
		return
	}
	e.healthMu.Lock()
	defer e.healthMu.Unlock()
	if e.healthErr == nil {
		e.healthErr = err
	}
}

// HealthError returns the first runtime health failure recorded by
// MarkUnhealthy. Safe on nil.
func (e *Emitter) HealthError() error {
	if e == nil {
		return nil
	}
	e.healthMu.RLock()
	defer e.healthMu.RUnlock()
	return e.healthErr
}

func (e *Emitter) HealthSnapshot() (HealthSnapshot, bool) {
	if e == nil {
		return HealthSnapshot{}, false
	}
	e.chainMu.Lock()
	defer e.chainMu.Unlock()
	return HealthSnapshot{
		InitErr:     e.initErr != nil,
		ChainSeq:    e.chainSeq,
		PrevHash:    e.chainPrevHash,
		LastEmit:    e.chainEnd,
		RootEmitted: e.rootEmitted,
		RunNonce:    e.runNonce,
	}, true
}

// SignerKeyHex returns the Ed25519 public key hex for receipts this emitter
// signs. It is used by reload code to distinguish a policy-only reload from a
// signer rotation without replacing a live emitter unnecessarily.
func (e *Emitter) SignerKeyHex() string {
	if e == nil || len(e.privKey) != ed25519.PrivateKeySize {
		return ""
	}
	return fmt.Sprintf("%x", e.privKey.Public().(ed25519.PublicKey))
}

// EmitOpts holds the per-decision context for emitting a receipt.
type EmitOpts struct {
	ActionID              string
	ParentActionID        string
	Verdict               string
	Layer                 string
	Pattern               string
	Severity              string
	RedactionProfile      string
	RedactionReport       *redact.Report
	Shield                *ShieldSummary
	Transport             string
	Method                string
	Target                string
	RequestID             string
	Agent                 string
	SessionTaintLevel     string
	SessionContaminated   bool
	RecentTaintSources    []session.TaintSourceRef
	SessionTaskID         string
	SessionTaskLabel      string
	AuthorityKind         string
	TaintDecision         string
	TaintDecisionReason   string
	TaskOverrideApplied   bool
	ContractWinningSource string
	ContractLiveVerdict   string
	ContractPolicySources []string
	ContractRuleID        string
	ActiveManifestHash    string
	ContractHash          string
	ContractSelectorID    string
	ContractGeneration    uint64
	// PolicyHash is the canonical policy hash for the resolved runtime config
	// that produced this decision. V2 EvidenceReceipt emission consumes this;
	// v1 action receipts keep using the emitter's config hash snapshot.
	PolicyHash string

	DecisionPhase     string
	DeferID           string
	ResolutionPolicy  string
	ResolutionSource  string
	SessionID         string
	SessionIDOriginal string

	// MCP-specific fields
	ToolName  string
	MCPMethod string

	// SessionControl is set only for signed lifecycle control records such as
	// session_open. Ordinary action receipts leave it nil.
	SessionControl *SessionControl
}

// ErrSessionOpenAlreadyEmitted is returned when a process run tries to emit a
// second session_open. A restart gets a fresh Emitter and fresh run_nonce.
var ErrSessionOpenAlreadyEmitted = fmt.Errorf("session_open already emitted for this run")

const (
	sessionControlTransport = "receipt_session"
	sessionOpenTarget       = "pipelock://session/open"
	sessionHeartbeatTarget  = "pipelock://session/heartbeat"
	sessionCloseTarget      = "pipelock://session/close"
)

// EmitSessionOpen emits the signed session_open control receipt for this
// emitter process run through the normal Emit/Record path. It is intentionally
// non-durable in this build unit; the durable receipt gate lands later.
func (e *Emitter) EmitSessionOpen() error {
	if e == nil {
		return nil
	}
	openNonce, err := newOpenNonce()
	if err != nil {
		e.recordFailure(FailReasonSign)
		return fmt.Errorf("generate open nonce: %w", err)
	}
	return e.Emit(EmitOpts{
		ActionID:  NewActionID(),
		Verdict:   config.ActionAllow,
		Transport: sessionControlTransport,
		Target:    sessionOpenTarget,
		SessionControl: &SessionControl{
			Kind: SessionControlOpen,
			Open: &SessionOpen{
				RunNonce:             e.runNonce,
				OpenNonce:            openNonce,
				RecorderSession:      recorderSessionID,
				PolicyHash:           configHashString(e.configHash.Load()),
				SignerKeyEpoch:       fmt.Sprintf("%x", e.privKey.Public().(ed25519.PublicKey)),
				PostureCapsuleSHA256: e.postureBinding.CapsuleSHA256,
				PostureSignerKeyID:   e.postureBinding.SignerKeyID,
				ContainmentNonce:     e.postureBinding.ContainmentNonce,
				ContainedUID:         e.postureBinding.ContainedUID,
			},
		},
	})
}

// DurabilityBlocks returns the cumulative number of durable emits whose
// fsync confirmation failed and therefore blocked egress. Nil emitters report
// zero.
func (e *Emitter) DurabilityBlocks() uint64 {
	if e == nil {
		return 0
	}
	return e.durabilityBlocks.Load()
}

// EmitHeartbeat emits a best-effort signed heartbeat control receipt. The
// heartbeat snapshots the current chain head under chainMu via emitWithControl,
// before the heartbeat receipt itself advances the chain, so ChainHead and
// ChainSeqHead are a race-free pair.
func (e *Emitter) EmitHeartbeat() error {
	if e == nil {
		return nil
	}
	return e.emitWithControl(EmitOpts{
		ActionID:  NewActionID(),
		Verdict:   config.ActionAllow,
		Transport: sessionControlTransport,
		Target:    sessionHeartbeatTarget,
	}, false, func() (*SessionControl, error) {
		e.heartbeatBeat++
		return &SessionControl{
			Kind: SessionControlHeartbeat,
			Heartbeat: &SessionHeartbeat{
				RunNonce:         e.runNonce,
				OpenNonce:        e.openNonce,
				Beat:             e.heartbeatBeat,
				ChainHead:        e.chainPrevHash,
				ChainSeqHead:     PreviousChainSeq(e.chainSeq),
				HeartbeatTime:    time.Now().UTC().Format(time.RFC3339Nano),
				FsyncErrorsGated: e.recorder.FsyncErrorsGated(),
				DurabilityBlocks: e.DurabilityBlocks(),
			},
		}, nil
	})
}

// EmitSessionClose emits a signed session_close control receipt that seals the
// current pre-close chain tail. The compat transcript_root remains separate and
// should be emitted after this method so it anchors the chain including close.
func (e *Emitter) EmitSessionClose(closeReason string) error {
	if e == nil {
		return nil
	}
	return e.emitWithControl(EmitOpts{
		ActionID:  NewActionID(),
		Verdict:   config.ActionAllow,
		Transport: sessionControlTransport,
		Target:    sessionCloseTarget,
	}, false, func() (*SessionControl, error) {
		if e.rootEmitted || e.closeEmitted || e.chainSeq == 0 {
			return nil, nil
		}
		return &SessionControl{
			Kind: SessionControlClose,
			Close: &SessionClose{
				RunNonce:         e.runNonce,
				OpenNonce:        e.openNonce,
				FinalSeq:         e.chainSeq,
				RootHash:         e.chainPrevHash,
				ReceiptCount:     e.chainSeq + 1,
				CloseReason:      closeReason,
				FsyncErrorsGated: e.recorder.FsyncErrorsGated(),
				DurabilityBlocks: e.DurabilityBlocks(),
			},
		}, nil
	})
}

// Emit creates, signs, and records an action receipt for a proxy decision.
// The call is synchronous through the recorder mutex - same as recordDecision.
// Errors are returned but should be logged, not propagated to callers.
// Safe to call on a nil Emitter (no-op).
func (e *Emitter) Emit(opts EmitOpts) error {
	return e.emitWithControl(opts, false, nil)
}

// EmitDurable creates, signs, records, and fsync-confirms an action receipt for
// a proxy decision. Safe to call on a nil Emitter (no-op).
func (e *Emitter) EmitDurable(opts EmitOpts) error {
	return e.emitWithControl(opts, true, nil)
}

type lockedSessionControlBuilder func() (*SessionControl, error)

func (e *Emitter) emitWithControl(opts EmitOpts, durable bool, buildControl lockedSessionControlBuilder) error {
	if e == nil {
		return nil
	}
	if e.initErr != nil {
		e.recordFailure(FailReasonChainInit)
		return fmt.Errorf("resume receipt chain: %w", e.initErr)
	}
	if healthErr := e.HealthError(); healthErr != nil {
		e.recordFailure(FailReasonUnavailable)
		return fmt.Errorf("receipt emitter unhealthy: %w", healthErr)
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
	// calls produce monotonic timestamps in chain order. State advances before
	// recorder persistence so a failed Record leaves a detectable gap instead
	// of reusing the same prev_hash/seq and forking the chain.
	e.chainMu.Lock()
	defer e.chainMu.Unlock()

	if e.rootEmitted {
		e.recordFailure(FailReasonSealed)
		return ErrChainSealed
	}
	if buildControl != nil {
		sessionControl, buildErr := buildControl()
		if buildErr != nil {
			return buildErr
		}
		if sessionControl == nil {
			return nil
		}
		opts.SessionControl = sessionControl
	}
	sessionControl, chainPrevHash, err := e.prepareSessionControlLocked(opts.SessionControl)
	if err != nil {
		return err
	}

	// Sanitize secret-bearing fields BEFORE signing. When redaction is enabled
	// the recorder would otherwise redact target/pattern AFTER signing,
	// desyncing the on-disk canonical bytes from both the signature and the
	// recorded receipt-hash binding. Sanitizing pre-sign with the same
	// DLP function makes the recorder's redaction a no-op, so the receipt
	// verifies from the evidence file alone. The redactor is read from the
	// recorder at emit time (not cached at construction) so it is always the
	// exact function the recorder will apply, with no drift surface; it is nil
	// when flight-recorder redaction is off, leaving targets unchanged.
	target := opts.Target
	pattern := opts.Pattern
	if rf := e.recorder.ReceiptRedactor(); rf != nil {
		clean := func(text string) bool { return rf(context.Background(), text).Clean }
		target = sanitizeTarget(target, clean)
		pattern = cleanOrRedacted(pattern, clean)
	}

	ar := ActionRecord{
		Version:               ActionRecordVersion,
		ActionID:              opts.ActionID,
		ParentActionID:        opts.ParentActionID,
		ActionType:            actionType,
		Timestamp:             time.Now().UTC(),
		Principal:             e.principal,
		Actor:                 e.actorLabel(opts),
		DelegationChain:       nil, // Populated when delegation tracking ships
		Target:                target,
		SideEffectClass:       sideEffect,
		Reversibility:         reversibility,
		PolicyHash:            configHashString(e.configHash.Load()),
		Verdict:               NormalizeVerdict(opts.Verdict),
		DecisionPhase:         opts.DecisionPhase,
		DeferID:               opts.DeferID,
		ResolutionPolicy:      opts.ResolutionPolicy,
		ResolutionSource:      opts.ResolutionSource,
		SessionID:             opts.SessionID,
		SessionIDOriginal:     opts.SessionIDOriginal,
		SessionTaintLevel:     opts.SessionTaintLevel,
		SessionContaminated:   opts.SessionContaminated,
		RecentTaintSources:    append([]session.TaintSourceRef(nil), opts.RecentTaintSources...),
		SessionTaskID:         opts.SessionTaskID,
		SessionTaskLabel:      opts.SessionTaskLabel,
		AuthorityKind:         opts.AuthorityKind,
		TaintDecision:         opts.TaintDecision,
		TaintDecisionReason:   opts.TaintDecisionReason,
		TaskOverrideApplied:   opts.TaskOverrideApplied,
		ContractWinningSource: opts.ContractWinningSource,
		ContractLiveVerdict:   opts.ContractLiveVerdict,
		ContractPolicySources: append([]string(nil), opts.ContractPolicySources...),
		ContractRuleID:        opts.ContractRuleID,
		ActiveManifestHash:    opts.ActiveManifestHash,
		ContractHash:          opts.ContractHash,
		ContractSelectorID:    opts.ContractSelectorID,
		ContractGeneration:    opts.ContractGeneration,
		Transport:             opts.Transport,
		Method:                opts.Method,
		Layer:                 opts.Layer,
		Pattern:               pattern,
		Severity:              opts.Severity,
		Redaction:             redactionSummaryFromReport(opts.RedactionProfile, opts.RedactionReport),
		Shield:                cloneShieldSummary(opts.Shield),
		RequestID:             opts.RequestID,
		ChainPrevHash:         chainPrevHash,
		ChainSeq:              e.chainSeq,
		RunNonce:              e.runNonce,
		// pendingTransition is non-nil only on the first receipt of a new
		// segment opened by resumeChain after a legitimate key rotation. It
		// is bound into the signed record so the segment boundary is provable
		// from this receipt alone, then cleared after a successful write.
		KeyTransition:  e.pendingTransition,
		SessionControl: sessionControl,
	}

	rcpt, err := Sign(ar, e.privKey)
	if err != nil {
		e.recordFailure(FailReasonSign)
		return fmt.Errorf("signing receipt: %w", err)
	}

	receiptHash, err := ReceiptHash(rcpt)
	if err != nil {
		e.recordFailure(FailReasonHash)
		return fmt.Errorf("hashing receipt: %w", err)
	}

	receiptJSON, err := Marshal(rcpt)
	if err != nil {
		e.recordFailure(FailReasonMarshal)
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
	// The transition marker was bound into the receipt just signed; clear it
	// so it is never re-stamped onto a later receipt (which would falsely
	// claim a second segment boundary). Cleared with the rest of the
	// advance-before-persist state for the same fork-avoidance reason.
	e.pendingTransition = nil
	openControl := isSessionOpenControl(sessionControl)
	closeControl := isSessionCloseControl(sessionControl)

	entry := recorder.Entry{
		SessionID: recorderSessionID,
		Type:      recorderEntryType,
		EventKind: string(ar.ActionType),
		Transport: opts.Transport,
		Summary:   fmt.Sprintf("receipt: %s %s %s", ar.Verdict, ar.ActionType, ar.Transport),
		Detail:    json.RawMessage(receiptJSON),
	}
	var recordErr error
	if durable {
		recordErr = e.recorder.RecordDurable(entry)
	} else {
		recordErr = e.recorder.Record(entry)
	}
	if recordErr != nil {
		// Persist failed AFTER the chain state advanced (advance-before-persist,
		// above). For the single-shot control receipts (open/close) mark the guard
		// "emitted" only when the receipt bytes actually reached disk — i.e. the
		// write succeeded but a later checkpoint/rotation/sync-confirm step failed
		// (receiptHashRecorded reads the evidence back to confirm). Then the record
		// exists and a retry must NOT duplicate it. If the bytes did NOT reach disk
		// (the write itself failed), leave the guard unset so a retry can re-emit;
		// the failed attempt left a detectable gap, and suppressing the retry would
		// instead let a transcript root seal a MISSING open/close as if present
		// (fail-open). Confirming on disk keeps this path fail-closed.
		if openControl && e.receiptHashRecorded(receiptHash) {
			e.sessionOpenEmitted = true
			e.openNonce = sessionControl.Open.OpenNonce
		}
		if closeControl && e.receiptHashRecorded(receiptHash) {
			e.closeEmitted = true
		}
		if durable && errors.Is(recordErr, recorder.ErrDurability) {
			e.durabilityBlocks.Add(1)
			e.recordFailure(FailReasonSync)
		} else {
			e.recordFailure(FailReasonRecord)
		}
		return fmt.Errorf("recording receipt: %w", recordErr)
	}
	if openControl {
		e.sessionOpenEmitted = true
		e.openNonce = sessionControl.Open.OpenNonce
	}
	if closeControl {
		e.closeEmitted = true
	}

	// Notify the observer (if any) AFTER the receipt is durably recorded, so a
	// streamed decision can never appear before it exists on disk. The call is
	// under the chain mutex, preserving chain order for observers. A copy is
	// passed so the observer cannot mutate emitter state, and the observer is
	// contractually non-blocking (see EmitterConfig.OnReceipt).
	if e.onReceipt != nil {
		rc := rcpt
		e.onReceipt(&rc)
	}

	return nil
}

func (e *Emitter) prepareSessionControlLocked(in *SessionControl) (*SessionControl, string, error) {
	chainPrevHash := e.chainPrevHash
	if in == nil {
		return nil, chainPrevHash, nil
	}
	if !isSessionOpenControl(in) {
		return cloneSessionControl(in), chainPrevHash, nil
	}
	if e.sessionOpenEmitted {
		e.recordFailure(FailReasonRecord)
		return nil, "", ErrSessionOpenAlreadyEmitted
	}

	out := cloneSessionControl(in)
	open := out.Open
	open.RunNonce = e.runNonce
	open.RecorderSession = recorderSessionID
	open.PolicyHash = configHashString(e.configHash.Load())
	open.SignerKeyEpoch = fmt.Sprintf("%x", e.privKey.Public().(ed25519.PublicKey))
	open.ChainOpenSeq = e.chainSeq

	if e.hasPriorTail {
		open.PriorChainHead = e.priorTailHash
		open.PriorChainSeq = e.priorTailSeq
		open.GenesisHash = ""
		return out, chainPrevHash, nil
	}

	if e.chainSeq == 0 && e.chainPrevHash == GenesisHash {
		open.GenesisHash = ""
		genesis := ComputeSessionOpenGenesis(*open)
		open.GenesisHash = genesis
		chainPrevHash = genesis
	}
	return out, chainPrevHash, nil
}

func isSessionOpenControl(in *SessionControl) bool {
	return in != nil && in.Kind == SessionControlOpen && in.Open != nil
}

func isSessionCloseControl(in *SessionControl) bool {
	return in != nil && in.Kind == SessionControlClose && in.Close != nil
}

func cloneSessionControl(in *SessionControl) *SessionControl {
	if in == nil {
		return nil
	}
	out := *in
	if in.Open != nil {
		open := *in.Open
		out.Open = &open
	}
	if in.Heartbeat != nil {
		heartbeat := *in.Heartbeat
		out.Heartbeat = &heartbeat
	}
	if in.Close != nil {
		closeRecord := *in.Close
		out.Close = &closeRecord
	}
	return &out
}

func (e *Emitter) receiptHashRecorded(wantHash string) bool {
	if e == nil || e.recorder == nil || wantHash == "" {
		return false
	}
	files, err := recorderFiles(e.recorder.Dir())
	if err != nil {
		return false
	}
	for _, file := range files {
		entries, readErr := recorder.ReadEntries(file)
		if readErr != nil {
			continue
		}
		for _, entry := range entries {
			if entry.Type != recorderEntryType {
				continue
			}
			raw, rawErr := receiptBytesFromEntry(entry)
			if rawErr != nil {
				continue
			}
			hash := sha256.Sum256(raw)
			if hex.EncodeToString(hash[:]) == wantHash {
				return true
			}
		}
	}
	return false
}

// recordFailure increments the emit-failure metric for reason when a sink is
// wired. Safe with a nil sink.
func (e *Emitter) recordFailure(reason string) {
	if e == nil || e.metrics == nil {
		return
	}
	e.metrics.RecordEmitFailure(reason)
}

// UpdateConfigHash sets the config hash for new receipts. Called on hot reload.
// Safe for concurrent use with Emit - uses atomic.Value internally.
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
	if e.initErr != nil {
		e.recordFailure(FailReasonChainInit)
		return fmt.Errorf("resume receipt chain: %w", e.initErr)
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
		EventKind: transcriptRootEntryType,
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

func newRunNonce() (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(nonce[:]), nil
}

func newOpenNonce() (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(nonce[:]), nil
}

func redactionSummaryFromReport(profile string, report *redact.Report) *RedactionSummary {
	if report == nil || report.TotalRedactions == 0 {
		return nil
	}
	byClass := make(map[string]int, len(report.ByClass))
	for class, count := range report.ByClass {
		if count > 0 {
			byClass[string(class)] = count
		}
	}
	return &RedactionSummary{
		Profile:         profile,
		Provider:        report.Provider,
		Parser:          report.Parser,
		TotalRedactions: report.TotalRedactions,
		ByClass:         byClass,
	}
}

func cloneShieldSummary(summary *ShieldSummary) *ShieldSummary {
	if summary == nil {
		return nil
	}
	clone := *summary
	return &clone
}

func (e *Emitter) resumeChain() error {
	if e == nil || e.recorder == nil {
		return nil
	}

	files, err := recorderFiles(e.recorder.Dir())
	if err != nil {
		return err
	}

	var lastReceipt *Receipt
	for i := len(files) - 1; i >= 0 && lastReceipt == nil; i-- {
		entries, readErr := recorder.ReadEntries(files[i])
		if readErr != nil {
			return fmt.Errorf("reading existing evidence file %s: %w", filepath.Base(files[i]), readErr)
		}
		for j := len(entries) - 1; j >= 0; j-- {
			switch entries[j].Type {
			case transcriptRootEntryType:
				// A transcript root is a clean-shutdown checkpoint that seals the
				// receipts emitted up to that point IN THIS PROCESS. It is not a
				// permanent on-disk seal: skip it and keep scanning back for the
				// last action receipt so the next start resumes emission into the
				// same hash-linked chain (a continuous chain still verifies, and
				// the root's historical claim over seq 0..N stays true). The old
				// behavior set rootEmitted=true here, which made every subsequent
				// Emit return ErrChainSealed - silently bricking receipts after
				// the first clean shutdown once EmitTranscriptRoot has a caller.
				// Skipping it is also evidence-suppression-resistant: an attacker
				// who appends a transcript_root to the evidence file cannot use it
				// to stop the proxy from recording (the tail action receipt is
				// still signature-verified below before we trust its chain state).
			case recorderEntryType:
				rcpt, unmarshalErr := receiptFromEntry(entries[j])
				if unmarshalErr != nil {
					return unmarshalErr
				}
				lastReceipt = rcpt
			}
			if lastReceipt != nil {
				break
			}
		}
	}
	if lastReceipt == nil {
		return nil
	}

	var firstReceipt *Receipt
	for _, file := range files {
		entries, readErr := recorder.ReadEntries(file)
		if readErr != nil {
			return fmt.Errorf("reading existing evidence file %s: %w", filepath.Base(file), readErr)
		}
		for _, entry := range entries {
			if entry.Type != recorderEntryType {
				continue
			}
			rcpt, unmarshalErr := receiptFromEntry(entry)
			if unmarshalErr != nil {
				return unmarshalErr
			}
			firstReceipt = rcpt
			break
		}
		if firstReceipt != nil {
			break
		}
	}

	// Trust model for resuming an on-disk chain across a possible signing-key
	// change. Three cases, distinguished by verifying the tail BEFORE
	// trusting its chain state:
	//
	//  1. Tail signed by the CURRENT key, signature valid  -> resume the
	//     same chain segment (the common case).
	//  2. Tail signed by a DIFFERENT key, but self-valid under its OWN
	//     embedded signer_key -> a legitimate signing-key rotation. The
	//     operator regenerated the key (e.g. `contain install`); the prior
	//     chain is intact, it is simply sealed under the old key. Open a NEW
	//     segment anchored to the prior tail's hash and stamp a transition
	//     marker on the next receipt, instead of bricking emission forever.
	//  3. Tail's OWN signature is INVALID (corrupt / tampered, regardless of
	//     key) -> FAIL CLOSED. This is the tamper case and must never be
	//     weakened into a silent reset.
	//
	// Why case 2 is safe: we require the tail to be self-consistently signed
	// by the key embedded in it (VerifyInternalConsistencyOnly). An attacker who can only write a
	// forged tail with a bad signature lands in case 3 and is rejected, so a
	// forged tail cannot force a silent segment reset that hides history. A
	// rotation reset preserves continuity two ways: the new segment's first
	// receipt carries the prior tail's hash as its ChainPrevHash plus an
	// explicit KeyTransition marker (prior signer key + prior seq + prior
	// hash), and the recorder's outer hash chain still spans every entry on
	// disk and remains the authoritative cross-segment tamper-evidence
	// layer. This mirrors the v2 proxy_decision emitter, which restarts at
	// genesis across process restarts and likewise leans on the recorder's
	// outer chain for cross-segment evidence.
	if e.privKey != nil {
		// Case 3 first: self-signature must be valid no matter the key.
		if verifyErr := VerifyInternalConsistencyOnly(*lastReceipt); verifyErr != nil {
			return fmt.Errorf("tail receipt signature invalid (seq %d): %w", lastReceipt.ActionRecord.ChainSeq, verifyErr)
		}

		currentKeyHex := fmt.Sprintf("%x", e.privKey.Public().(ed25519.PublicKey))
		if lastReceipt.SignerKey != currentKeyHex {
			// Case 2: legitimate rotation. Open a new segment.
			hash, err := ReceiptHash(*lastReceipt)
			if err != nil {
				return fmt.Errorf("hashing prior segment tail: %w", err)
			}
			e.chainSeq = 0
			e.chainPrevHash = hash
			e.hasPriorTail = true
			e.priorTailSeq = lastReceipt.ActionRecord.ChainSeq
			e.priorTailHash = hash
			e.pendingTransition = &KeyTransition{
				PriorSignerKey: lastReceipt.SignerKey,
				PriorChainSeq:  lastReceipt.ActionRecord.ChainSeq,
				PriorChainHash: hash,
			}
			// Carry the prior segment's start timestamp forward only if the
			// new segment has no receipts yet (it does not). chainStart is
			// set on the first Emit of the new segment, so leave it zero.
			return nil
		}
	}

	// Case 1: same key (or no key configured) - resume the same segment.
	hash, err := ReceiptHash(*lastReceipt)
	if err != nil {
		return fmt.Errorf("hashing existing receipt chain: %w", err)
	}
	e.chainPrevHash = hash
	e.chainSeq = lastReceipt.ActionRecord.ChainSeq + 1
	e.chainEnd = lastReceipt.ActionRecord.Timestamp
	e.hasPriorTail = true
	e.priorTailSeq = lastReceipt.ActionRecord.ChainSeq
	e.priorTailHash = hash
	if firstReceipt != nil {
		e.chainStart = firstReceipt.ActionRecord.Timestamp
	}
	return nil
}

func receiptFromEntry(entry recorder.Entry) (*Receipt, error) {
	detailJSON, err := receiptBytesFromEntry(entry)
	if err != nil {
		return nil, err
	}
	rcpt, err := Unmarshal(detailJSON)
	if err != nil {
		return nil, fmt.Errorf("unmarshal existing receipt at seq %d: %w", entry.Sequence, err)
	}
	return &rcpt, nil
}

func receiptBytesFromEntry(entry recorder.Entry) ([]byte, error) {
	if len(entry.RawDetail) > 0 {
		return entry.RawDetail, nil
	}
	detailJSON, err := json.Marshal(entry.Detail)
	if err != nil {
		return nil, fmt.Errorf("marshal existing receipt detail at seq %d: %w", entry.Sequence, err)
	}
	return detailJSON, nil
}

func recorderFiles(dir string) ([]string, error) {
	if dir == "" {
		return nil, nil
	}

	dirEntries, err := os.ReadDir(filepath.Clean(dir))
	if err != nil {
		return nil, fmt.Errorf("reading evidence directory: %w", err)
	}

	prefix := "evidence-" + recorderSessionID + "-"
	files := make([]string, 0)
	for _, de := range dirEntries {
		if de.IsDir() {
			continue
		}
		name := de.Name()
		if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, ".jsonl") {
			files = append(files, filepath.Join(filepath.Clean(dir), name))
		}
	}
	sort.Slice(files, func(i, j int) bool {
		return recorderSeqStart(files[i]) < recorderSeqStart(files[j])
	})
	return files, nil
}

func recorderSeqStart(path string) uint64 {
	name := filepath.Base(path)
	name = strings.TrimSuffix(name, ".jsonl")
	lastDash := strings.LastIndex(name, "-")
	if lastDash < 0 {
		return 0
	}
	seq, err := strconv.ParseUint(name[lastDash+1:], 10, 64)
	if err != nil {
		return 0
	}
	return seq
}
