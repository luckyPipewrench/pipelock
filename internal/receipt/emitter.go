// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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
	// FailReasonSealed is an emit attempt after the transcript root was emitted.
	FailReasonSealed = "sealed"
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
	initErr    error

	// Chain state - mutex-protected, updated on each Emit.
	chainMu       sync.Mutex
	chainSeq      uint64
	chainPrevHash string
	chainStart    time.Time // timestamp of first receipt
	chainEnd      time.Time // timestamp of most recent receipt
	rootEmitted   bool      // true after EmitTranscriptRoot; prevents duplicate roots

	// pendingTransition is set by resumeChain when the on-disk tail was
	// signed by a DIFFERENT (but self-valid) key, meaning a legitimate key
	// rotation occurred. It is stamped onto the first receipt of the new
	// segment by the next Emit, then cleared. nil when there is no pending
	// segment boundary.
	pendingTransition *KeyTransition
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
	e := &Emitter{
		recorder:      cfg.Recorder,
		privKey:       cfg.PrivKey,
		principal:     cfg.Principal,
		actor:         cfg.Actor,
		metrics:       cfg.Metrics,
		chainPrevHash: GenesisHash,
	}
	e.configHash.Store(cfg.ConfigHash)
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

	// MCP-specific fields
	ToolName  string
	MCPMethod string
}

// Emit creates, signs, and records an action receipt for a proxy decision.
// The call is synchronous through the recorder mutex - same as recordDecision.
// Errors are returned but should be logged, not propagated to callers.
// Safe to call on a nil Emitter (no-op).
func (e *Emitter) Emit(opts EmitOpts) error {
	if e == nil {
		return nil
	}
	if e.initErr != nil {
		e.recordFailure(FailReasonChainInit)
		return fmt.Errorf("resume receipt chain: %w", e.initErr)
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
		e.recordFailure(FailReasonSealed)
		return ErrChainSealed
	}

	// Sanitize secret-bearing fields BEFORE signing. When redaction is enabled
	// the recorder would otherwise redact target/pattern AFTER signing,
	// desyncing the on-disk canonical bytes from both the signature and the
	// recorded ReceiptHash (AARP) binding. Sanitizing pre-sign with the same
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
		ChainPrevHash:         e.chainPrevHash,
		ChainSeq:              e.chainSeq,
		// pendingTransition is non-nil only on the first receipt of a new
		// segment opened by resumeChain after a legitimate key rotation. It
		// is bound into the signed record so the segment boundary is provable
		// from this receipt alone, then cleared after a successful write.
		KeyTransition: e.pendingTransition,
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

	if err := e.recorder.Record(recorder.Entry{
		SessionID: recorderSessionID,
		Type:      recorderEntryType,
		EventKind: string(ar.ActionType),
		Transport: opts.Transport,
		Summary:   fmt.Sprintf("receipt: %s %s %s", ar.Verdict, ar.ActionType, ar.Transport),
		Detail:    json.RawMessage(receiptJSON),
	}); err != nil {
		e.recordFailure(FailReasonRecord)
		return fmt.Errorf("recording receipt: %w", err)
	}

	return nil
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
	// by the key embedded in it (Verify). An attacker who can only write a
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
		if verifyErr := Verify(*lastReceipt); verifyErr != nil {
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
	if firstReceipt != nil {
		e.chainStart = firstReceipt.ActionRecord.Timestamp
	}
	return nil
}

func receiptFromEntry(entry recorder.Entry) (*Receipt, error) {
	detailJSON, err := json.Marshal(entry.Detail)
	if err != nil {
		return nil, fmt.Errorf("marshal existing receipt detail at seq %d: %w", entry.Sequence, err)
	}
	rcpt, err := Unmarshal(detailJSON)
	if err != nil {
		return nil, fmt.Errorf("unmarshal existing receipt at seq %d: %w", entry.Sequence, err)
	}
	return &rcpt, nil
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
