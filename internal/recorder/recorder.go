// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/nacl/box"

	"github.com/luckyPipewrench/pipelock/internal/evidencename"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// Default values for recorder configuration.
const (
	defaultCheckpointInterval = 1000
	defaultMaxEntriesPerFile  = 10000
	checkpointType            = "checkpoint"

	// dirPermissions is the permission mode for evidence directories.
	dirPermissions = 0o750
	// filePermissions is the permission mode for evidence files.
	filePermissions = 0o600

	// x25519KeySize is the expected size of an X25519 public key in bytes.
	x25519KeySize = 32

	// recorderTypeReceipt is the entry type for action receipts. These get
	// selective field redaction (target/pattern only) instead of full detail
	// replacement, preserving receipt structure for audit while preventing
	// plaintext secrets in evidence files.
	recorderTypeReceipt = "action_receipt"

	// eventKindCheckpoint is the EventKind value stamped on checkpoint
	// entries written by the recorder. Fixed value - checkpoints are an
	// envelope concern owned by the recorder package.
	eventKindCheckpoint = "checkpoint"

	// eventKindProxyDecision is the EventKind value stamped on signed
	// decision entries written via RecordDecision. Fixed value - these are
	// signed verdict proofs and the classifier is the entry type itself.
	eventKindProxyDecision = "proxy_decision"
)

// Config configures the flight recorder.
type Config struct {
	Enabled            bool        `yaml:"enabled"`
	Dir                string      `yaml:"dir"`
	CheckpointInterval int         `yaml:"checkpoint_interval"`
	RetentionDays      int         `yaml:"retention_days"`
	Redact             bool        `yaml:"redact"`
	SignCheckpoints    bool        `yaml:"sign_checkpoints"`
	MaxEntriesPerFile  int         `yaml:"max_entries_per_file"`
	FileMode           os.FileMode `yaml:"file_mode"`
	RawEscrow          bool        `yaml:"raw_escrow"`
	EscrowPublicKey    string      `yaml:"escrow_public_key"`
	Metrics            MetricsSink `yaml:"-"`
}

func safeEvidenceFileMode(mode os.FileMode) bool {
	switch mode.Perm() {
	case 0o600, 0o640, 0o660:
		return mode&^os.ModePerm == 0
	default:
		return false
	}
}

// RedactFunc is the signature for DLP redaction. Matches scanner.ScanTextForDLP.
type RedactFunc func(ctx context.Context, text string) scanner.TextDLPResult

// ReceiptRedactor returns the DLP function this recorder applies to receipts,
// or nil when receipt redaction is disabled. Receipt emitters use it to
// sanitize secret-bearing fields BEFORE signing with the exact same function
// the recorder would apply AFTER signing, so the recorder's redaction pass
// becomes a no-op and signed receipts verify from the evidence file alone.
// Returning the recorder's own function (rather than re-deriving it) keeps the
// emitter and recorder in lockstep across reloads.
func (r *Recorder) ReceiptRedactor() RedactFunc {
	if r == nil || !r.cfg.Redact {
		return nil
	}
	return r.redactFn
}

// EntryObserver receives entries after they are durably flushed to the
// recorder. Observer failures must be handled internally; recorder writes
// cannot depend on optional downstream transports.
type EntryObserver interface {
	ObserveRecorderEntry(Entry)
}

type MetricsSink interface {
	RecordFsyncError(gated bool, n int)
}

// ErrDurability means a durable recorder write reached the userspace flush
// stage but could not be confirmed with File.Sync.
var ErrDurability = errors.New("recorder durability confirmation failed")

type durableBatch struct {
	file           *os.File
	generation     uint64
	leaderAssigned bool
	syncing        bool
	done           chan struct{}
	err            error
	entries        []durableBatchEntry
}

type durableBatchEntry struct {
	seq    uint64
	offset int64
}

type durableReservation struct {
	batch  *durableBatch
	leader bool
}

// Recorder writes hash-chained evidence entries to JSONL files.
type Recorder struct {
	cfg       Config
	redactFn  RedactFunc
	privKey   ed25519.PrivateKey
	escrowPub *[x25519KeySize]byte
	observer  EntryObserver
	metrics   MetricsSink

	mu             sync.Mutex
	seq            uint64
	prevHash       string
	writer         *bufio.Writer
	file           *os.File
	fileEntryCount int
	fileSeqStart   uint64
	fileGeneration uint64
	sessionID      string

	// Checkpoint tracking
	checkpointThreshold uint64
	sinceCheckpoint     uint64
	firstSeqInSpan      uint64
	closed              bool
	nop                 bool

	fileSync       func(*os.File) error
	durableCond    *sync.Cond
	durableBatch   *durableBatch
	durableSyncing bool
	durablePending map[uint64]int

	fsyncErrorsGated atomic.Uint64
}

// New creates a Recorder. The redactFn is used for DLP redaction (can be nil to skip).
// privKey is used for checkpoint signing (nil = unsigned checkpoints).
// When cfg.Enabled is false, returns a no-op recorder that discards all calls.
func New(cfg Config, redactFn RedactFunc, privKey ed25519.PrivateKey) (*Recorder, error) {
	if !cfg.Enabled {
		return &Recorder{nop: true}, nil
	}
	if strings.TrimSpace(cfg.Dir) == "" {
		return &Recorder{nop: true}, nil
	}

	// Fail closed on the sign-without-a-key footgun: SignCheckpoints defaults on,
	// so a persisted recorder (Dir set) with no signing key would silently write
	// checkpoints carrying an EMPTY signature — records that VerifyCheckpoints
	// later rejects as "missing signature", and that mislead an operator who
	// believes signing is active. Refuse to construct such a recorder so the
	// signed-vs-unsigned choice is explicit. Blank Dir returned a no-op above:
	// callers that never persist (e.g. the default MCP proxy path) are
	// unaffected, and the key-load path already fails closed on a
	// set-but-unloadable key upstream, so a nil key here means no key was
	// configured at all.
	// Validate the key LENGTH, not just non-nil: ed25519.PrivateKey is a byte
	// slice, so a non-nil zero-length or truncated key would pass a bare nil
	// check and then panic (or produce an unverifiable signature) at sign time.
	if cfg.SignCheckpoints && len(privKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("flight recorder sign_checkpoints is enabled but no valid signing key was provided; " +
			"set flight_recorder.signing_key_path, or set flight_recorder.sign_checkpoints: false for an " +
			"unsigned hash-chained recorder")
	}

	if cfg.CheckpointInterval <= 0 {
		cfg.CheckpointInterval = defaultCheckpointInterval
	}
	if cfg.MaxEntriesPerFile <= 0 {
		cfg.MaxEntriesPerFile = defaultMaxEntriesPerFile
	}
	if cfg.FileMode == 0 {
		cfg.FileMode = filePermissions
	}
	if !safeEvidenceFileMode(cfg.FileMode) {
		return nil, fmt.Errorf("evidence file mode %04o is unsafe; use 0600, 0640, or 0660", cfg.FileMode.Perm())
	}

	if err := os.MkdirAll(filepath.Clean(cfg.Dir), dirPermissions); err != nil {
		return nil, fmt.Errorf("creating evidence directory: %w", err)
	}

	// Writability probe: fail closed at startup if the evidence directory
	// exists but is not writable. Without this, pipelock boots successfully
	// with a read-only recorder dir (e.g. misconfigured volume mount or
	// wrong filesystem perms) and silently drops every receipt's persistence
	// while still enforcing policy - round-3 of the pre-tag gate finding. Operators end up
	// running in a degraded, non-auditable state without a clear signal.
	probe, probeErr := os.CreateTemp(filepath.Clean(cfg.Dir), ".pipelock-writability-probe-*")
	if probeErr != nil {
		return nil, fmt.Errorf("evidence directory %s is not writable (receipts would not persist): %w", cfg.Dir, probeErr)
	}
	probePath := probe.Name()
	_ = probe.Close()
	_ = os.Remove(probePath)

	r := &Recorder{
		cfg:                 cfg,
		redactFn:            redactFn,
		privKey:             privKey,
		metrics:             cfg.Metrics,
		prevHash:            GenesisHash,
		checkpointThreshold: safeUint64(cfg.CheckpointInterval, 1),
		fileSync:            func(f *os.File) error { return f.Sync() },
		durablePending:      make(map[uint64]int),
	}
	r.durableCond = sync.NewCond(&r.mu)

	if cfg.RawEscrow && cfg.EscrowPublicKey != "" {
		keyBytes, err := hex.DecodeString(cfg.EscrowPublicKey)
		if err != nil {
			return nil, fmt.Errorf("decoding escrow public key: %w", err)
		}
		if len(keyBytes) != x25519KeySize {
			return nil, fmt.Errorf("escrow public key must be %d bytes, got %d", x25519KeySize, len(keyBytes))
		}
		var pub [x25519KeySize]byte
		copy(pub[:], keyBytes)
		r.escrowPub = &pub
	}

	return r, nil
}

// SetSyncForTest replaces the File.Sync implementation used by RecordDurable.
// Passing nil restores the production implementation. This hook is exported
// because receipt package tests need to inject recorder durability failures
// across the internal package boundary; it is not wired to config or agent
// input, and production recorders default to real File.Sync.
func (r *Recorder) SetSyncForTest(syncFn func(*os.File) error) {
	if r == nil || r.nop {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if syncFn == nil {
		r.fileSync = func(f *os.File) error { return f.Sync() }
		return
	}
	r.fileSync = syncFn
}

// FsyncErrorsGated returns the cumulative count of failed durable sync batches.
// It counts File.Sync failures, not the number of callers blocked by one batch.
// Nil and no-op recorders report zero.
func (r *Recorder) FsyncErrorsGated() uint64 {
	if r == nil || r.nop {
		return 0
	}
	return r.fsyncErrorsGated.Load()
}

// Dir returns the recorder evidence directory. Empty for nil or no-op recorders.
func (r *Recorder) Dir() string {
	if r == nil || r.nop {
		return ""
	}
	return r.cfg.Dir
}

// SetObserver installs an optional post-write observer for newly recorded
// entries. It is intended for durable audit fan-out that must see the same
// recorder v2 entries written locally.
func (r *Recorder) SetObserver(observer EntryObserver) {
	if r == nil || r.nop {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.observer = observer
}

// Record writes an entry to the chain. Thread-safe. The caller provides the
// SessionID, Type, Transport, Summary, and Detail. Sequence, Timestamp,
// PrevHash, Hash, and Version are set by the recorder.
func (r *Recorder) Record(e Entry) error {
	if r.nop {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	written, err := r.prepareAndWriteEntryLocked(e, true)
	if err != nil {
		return err
	}

	// Advance chain state AFTER successful write. If ensureFile or
	// writeEntry fails, the next entry must re-link to the same prevHash
	// so the chain stays consistent with what reached disk.
	r.prevHash = written.Hash
	r.seq++

	r.sinceCheckpoint++
	r.fileEntryCount++
	if err := r.runPostRecordMaintenanceLocked(); err != nil {
		return err
	}

	return nil
}

// RecordDurable writes an entry and returns success only after File.Sync has
// confirmed the file generation that contains the entry.
func (r *Recorder) RecordDurable(e Entry) error {
	if r.nop {
		return nil
	}

	r.mu.Lock()
	written, err := r.prepareAndWriteEntryLocked(e, false)
	if err != nil {
		r.mu.Unlock()
		return err
	}

	r.prevHash = written.Hash
	r.seq++
	r.sinceCheckpoint++
	r.fileEntryCount++

	generation := r.fileGeneration
	reservation := r.enqueueDurabilityLocked(generation, written.Sequence, r.lastEntryOffsetLocked(written))
	r.mu.Unlock()

	if reservation.leader {
		r.runDurabilitySync(reservation.batch)
	}
	if err := r.waitDurability(reservation.batch, generation, written.Sequence); err != nil {
		return err
	}

	r.mu.Lock()
	err = r.runPostRecordMaintenanceLocked()
	r.mu.Unlock()
	if err != nil {
		return err
	}

	r.mu.Lock()
	r.notifyObserver(written)
	r.mu.Unlock()
	return nil
}

// RecordDecision writes a signed decision record through the standard entry
// path so hash-chaining, redaction, and optional raw escrow semantics stay
// consistent with all other recorder evidence.
func (r *Recorder) RecordDecision(dr DecisionRecord) error {
	dr = dr.Normalize()
	if dr.Signature == "" {
		if len(r.privKey) != ed25519.PrivateKeySize {
			return errors.New("decision record requires signature or recorder private key")
		}
		signed, err := dr.Sign(r.privKey)
		if err != nil {
			return fmt.Errorf("sign decision record: %w", err)
		}
		dr = signed
	} else {
		if err := dr.Validate(); err != nil {
			return fmt.Errorf("invalid decision record: %w", err)
		}
		// Verify pre-signed records cryptographically, not just structurally.
		// Reject if no verification key is available - accepting unverified
		// signatures into the evidence chain would undermine audit integrity.
		if len(r.privKey) != ed25519.PrivateKeySize {
			return errors.New("pre-signed decision record rejected: no verification key available")
		}
		pubKey := r.privKey.Public().(ed25519.PublicKey)
		if err := dr.Verify(pubKey); err != nil {
			return fmt.Errorf("pre-signed decision record failed verification: %w", err)
		}
	}

	layer := dr.ScannerResult.Layer
	if layer == "" {
		layer = "unknown"
	}
	summary := fmt.Sprintf("%s: %s", dr.Verdict, layer)
	if dr.ScannerResult.Pattern != "" {
		summary = fmt.Sprintf("%s (%s)", summary, dr.ScannerResult.Pattern)
	}

	// Store decision detail as generic JSON map so hash computation remains
	// stable after ReadEntries unmarshals Detail into interface{}.
	data, err := json.Marshal(dr)
	if err != nil {
		return fmt.Errorf("marshal decision record: %w", err)
	}
	var detail map[string]any
	if err := json.Unmarshal(data, &detail); err != nil {
		return fmt.Errorf("unmarshal decision record detail: %w", err)
	}

	return r.Record(Entry{
		SessionID: dr.SessionID,
		Type:      decisionEntryType,
		EventKind: eventKindProxyDecision,
		Transport: dr.RequestContext.Transport,
		Summary:   summary,
		Detail:    detail,
	})
}

// prepareAndWriteEntryLocked validates, stamps, redacts, hashes, opens the
// target file, and writes one JSONL entry. The recorder mutex must be held.
func (r *Recorder) prepareAndWriteEntryLocked(e Entry, notify bool) (Entry, error) {
	if r.closed {
		return Entry{}, fmt.Errorf("recorder is closed")
	}

	// Session ID validation: require non-empty, reject path separators
	// (defense against path traversal in filenames), and reject mismatches.
	if e.SessionID == "" {
		return Entry{}, errors.New("recorder: session_id required")
	}
	if strings.ContainsAny(e.SessionID, `/\`) {
		return Entry{}, fmt.Errorf("recorder: session_id contains path separator")
	}
	if r.sessionID == "" {
		if err := r.resumeSessionLocked(e.SessionID); err != nil {
			return Entry{}, fmt.Errorf("recorder: resume chain state: %w", err)
		}
	}
	if e.SessionID != r.sessionID {
		return Entry{}, fmt.Errorf("recorder: session_id mismatch (expected %q, got %q)", r.sessionID, e.SessionID)
	}

	e.Version = EntryVersion
	e.Sequence = r.seq
	e.Timestamp = time.Now().UTC()
	e.PrevHash = r.prevHash

	// Raw escrow: encrypt detail before redaction. Escrow must succeed
	// when enabled -- silent drops would lose raw evidence.
	if r.cfg.RawEscrow && r.escrowPub != nil {
		rawJSON, err := json.Marshal(e.Detail)
		if err != nil {
			return Entry{}, fmt.Errorf("marshal raw escrow: %w", err)
		}
		escrowPath, err := r.writeEscrow(rawJSON)
		if err != nil {
			return Entry{}, fmt.Errorf("write raw escrow: %w", err)
		}
		e.RawRef = filepath.Base(escrowPath)
	}

	// DLP redaction: receipt emitters sanitize target/pattern before signing
	// when recorder redaction is enabled, so receipt redaction is normally a
	// no-op and on-disk receipts still verify. This pass remains fail-closed
	// for malformed or legacy receipt details that still contain DLP hits.
	// Raw escrow preserves the exact detail passed to the recorder for
	// forensic replay.
	if r.cfg.Redact && r.redactFn != nil {
		if e.Type == recorderTypeReceipt {
			e.Detail = r.redactReceiptDetail(e.Detail)
		} else {
			e.Detail = r.redactDetail(e.Detail)
		}
	}

	e.Hash = ComputeHash(e)

	if err := r.writeEntryBounded(e, notify); err != nil {
		return Entry{}, fmt.Errorf("writing entry: %w", err)
	}
	return e, nil
}

// runPostRecordMaintenanceLocked applies checkpoint and rotation thresholds
// after an entry has already advanced the chain state. The recorder mutex must
// be held.
func (r *Recorder) runPostRecordMaintenanceLocked() error {
	needsCheckpoint := r.sinceCheckpoint >= r.checkpointThreshold
	needsRotation := r.fileEntryCount >= r.cfg.MaxEntriesPerFile
	if needsCheckpoint || needsRotation {
		r.waitDurableForCurrentFileLocked()
	}
	if needsCheckpoint {
		if err := r.checkpointLocked(); err != nil {
			return fmt.Errorf("writing checkpoint: %w", err)
		}
	}
	if needsRotation {
		if err := r.rotateFile(); err != nil {
			return fmt.Errorf("rotating file: %w", err)
		}
	}
	return nil
}

func (r *Recorder) enqueueDurabilityLocked(generation, seq uint64, offset int64) durableReservation {
	batch := r.durableBatch
	if batch == nil || batch.syncing || batch.generation != generation {
		batch = &durableBatch{
			file:       r.file,
			generation: generation,
			done:       make(chan struct{}),
		}
		r.durableBatch = batch
	}
	// A caller joins a batch only after writeEntry has flushed its JSONL bytes
	// under r.mu. The leader also marks batch.syncing under r.mu before
	// File.Sync, so a follower in this batch necessarily wrote before the
	// leader could start syncing; once syncing is true, later entries must use
	// a new batch.
	batch.entries = append(batch.entries, durableBatchEntry{seq: seq, offset: offset})
	r.durablePending[generation]++
	if !batch.leaderAssigned {
		batch.leaderAssigned = true
		return durableReservation{batch: batch, leader: true}
	}
	return durableReservation{batch: batch}
}

func (r *Recorder) runDurabilitySync(batch *durableBatch) {
	var err error
	syncStarted := false
	defer func() {
		if recovered := recover(); recovered != nil {
			if recoveredErr, ok := recovered.(error); ok {
				err = fmt.Errorf("panic during recorder durability sync: %w", recoveredErr)
			} else {
				err = fmt.Errorf("panic during recorder durability sync: %v", recovered)
			}
		}

		r.mu.Lock()
		batch.err = err
		if err != nil {
			r.fsyncErrorsGated.Add(1)
			if r.metrics != nil {
				r.metrics.RecordFsyncError(true, len(batch.entries))
			}
		}
		if syncStarted {
			r.durableSyncing = false
		}
		if r.durableBatch == batch {
			r.durableBatch = nil
		}
		close(batch.done)
		r.durableCond.Broadcast()
		r.mu.Unlock()
	}()

	r.mu.Lock()
	for r.durableSyncing {
		r.durableCond.Wait()
	}
	batch.syncing = true
	// Keep syncStarted adjacent to durableSyncing. There must be no panicking
	// operation between these two assignments, or panic recovery could leave
	// later durable syncs waiting forever on durableSyncing.
	r.durableSyncing = true
	syncStarted = true
	r.mu.Unlock()

	err = r.fileSync(batch.file)
}

func (r *Recorder) waitDurability(batch *durableBatch, generation, seq uint64) error {
	<-batch.done

	r.mu.Lock()
	r.durablePending[generation]--
	if r.durablePending[generation] <= 0 {
		delete(r.durablePending, generation)
	}
	r.durableCond.Broadcast()
	r.mu.Unlock()

	if batch.err != nil {
		return fmt.Errorf("%w: file generation %d seq %d: %w", ErrDurability, generation, seq, batch.err)
	}
	return nil
}

// Close flushes and closes the recorder, writing a final checkpoint.
func (r *Recorder) Close() error {
	if r.nop {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil
	}
	r.closed = true

	if r.sinceCheckpoint > 0 {
		r.waitDurableForCurrentFileLocked()
		if err := r.checkpointLocked(); err != nil {
			// Close the file even if checkpoint failed, but return
			// the checkpoint error since it means chain state is incomplete.
			_ = r.closeFile()
			return fmt.Errorf("final checkpoint: %w", err)
		}
	}

	return r.closeFile()
}

// checkpointLocked writes a signed checkpoint entry. Must be called with mu held.
func (r *Recorder) checkpointLocked() error {
	cpDetail := CheckpointDetail{
		EntryCount: r.sinceCheckpoint,
		FirstSeq:   r.firstSeqInSpan,
		LastSeq:    r.seq - 1,
	}

	// Build the checkpoint entry
	e := Entry{
		Version:   EntryVersion,
		Sequence:  r.seq,
		Timestamp: time.Now().UTC(),
		SessionID: r.sessionID,
		Type:      checkpointType,
		EventKind: eventKindCheckpoint,
		PrevHash:  r.prevHash,
	}

	// Sign if we have a key - sign the hash of the chain up to this point
	if r.cfg.SignCheckpoints && r.privKey != nil {
		// Sign the previous hash (represents the chain state)
		sig := ed25519.Sign(r.privKey, []byte(r.prevHash))
		cpDetail.Signature = hex.EncodeToString(sig)
	}

	e.Detail = cpDetail
	e.Summary = fmt.Sprintf("checkpoint: %d entries [seq %d-%d]",
		cpDetail.EntryCount, cpDetail.FirstSeq, cpDetail.LastSeq)
	e.Hash = ComputeHash(e)

	if r.file != nil {
		if err := r.writeEntryBounded(e, true); err != nil {
			return err
		}
		r.fileEntryCount++
	}

	// Advance chain state AFTER successful write. If writeEntry fails,
	// prevHash/seq must remain unchanged so the next attempt links correctly.
	r.prevHash = e.Hash
	r.seq++
	r.sinceCheckpoint = 0
	r.firstSeqInSpan = r.seq
	return nil
}

// redactDetail marshals Detail to JSON, runs DLP, and if any patterns match,
// replaces the detail with a redacted wrapper that lists detected patterns.
// The raw escrow (if enabled) preserves the original for forensic replay.
func (r *Recorder) redactDetail(detail any) any {
	if detail == nil {
		return nil
	}

	raw, err := json.Marshal(detail)
	if err != nil {
		return detail
	}

	result := r.redactFn(context.Background(), string(raw))
	if result.Clean {
		return detail
	}

	// Build redaction markers from detected patterns
	markers := make([]string, 0, len(result.Matches))
	for _, m := range result.Matches {
		markers = append(markers, "[REDACTED:"+m.PatternName+"]")
	}

	// Replace the entire detail with a redacted wrapper.
	// ScanTextForDLP returns pattern names but not match positions,
	// so surgical replacement is not possible without duplicating
	// the scanner's regex compilation. The raw escrow preserves
	// the original detail for IR replay with the decryption key.
	return map[string]any{
		"redacted":          true,
		"detected_patterns": markers,
		"original_size":     len(raw),
	}
}

// redactReceiptDetail selectively redacts sensitive fields (target, pattern)
// in a receipt entry while preserving the receipt structure. Current receipt
// emitters sanitize those fields before signing, so this should return the
// detail unchanged for normal receipts. If a malformed, legacy, or unexpected
// receipt still contains a DLP hit, fail closed rather than writing a secret
// to the evidence file; that fallback may make that receipt unverifiable.
func (r *Recorder) redactReceiptDetail(detail any) any {
	if detail == nil {
		return nil
	}

	raw, err := json.Marshal(detail)
	if err != nil {
		// Fail-closed: can't inspect, don't pass through unredacted.
		return map[string]any{
			"redacted": true,
			"reason":   "marshal error",
		}
	}

	// Quick check: does the whole detail contain any DLP matches?
	result := r.redactFn(context.Background(), string(raw))
	if result.Clean {
		return detail // No secrets found, no redaction needed
	}

	// Parse as map to access nested fields
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return r.redactDetail(detail) // fallback to full redaction
	}

	ar, ok := m["action_record"].(map[string]any)
	if !ok {
		return r.redactDetail(detail) // not a receipt structure, fallback
	}

	// Redact sensitive fields that may contain secrets.
	var redactedFields []string
	for _, field := range []string{"target", "pattern"} {
		if val, exists := ar[field]; exists {
			valStr, isStr := val.(string)
			if !isStr || valStr == "" {
				continue
			}
			fieldResult := r.redactFn(context.Background(), valStr)
			if !fieldResult.Clean {
				ar[field] = "[REDACTED]"
				redactedFields = append(redactedFields, field)
			}
		}
	}

	// Fail-closed: if the quick-check found DLP matches but none were in
	// target/pattern, a secret is hiding in an unexpected field. Fall back
	// to full redaction rather than letting it through.
	if len(redactedFields) == 0 {
		return r.redactDetail(detail)
	}

	ar["redacted_fields"] = redactedFields
	m["action_record"] = ar

	// Re-scan after selective redaction: if a secret was in both target
	// AND an unexpected field (e.g., agent), the per-field loop caught
	// target but the other field survives. Fall back to full redaction
	// if the partially redacted receipt still has DLP matches.
	partialJSON, err := json.Marshal(m)
	if err != nil {
		return r.redactDetail(detail)
	}
	if rescan := r.redactFn(context.Background(), string(partialJSON)); !rescan.Clean {
		return r.redactDetail(detail)
	}

	return m
}

// writeEscrow encrypts raw detail JSON with X25519 NaCl box and writes to sidecar.
func (r *Recorder) writeEscrow(rawJSON []byte) (string, error) {
	ephPub, ephPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generating ephemeral key: %w", err)
	}

	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}

	// NaCl box: encrypt with ephemeral private + recipient public
	sealed := box.Seal(nonce[:], rawJSON, &nonce, r.escrowPub, ephPriv)

	// Prepend ephemeral public key so recipient can decrypt
	payload := make([]byte, 0, x25519KeySize+len(sealed))
	payload = append(payload, ephPub[:]...)
	payload = append(payload, sealed...)

	// filepath.Base as defense-in-depth: session ID is already validated
	// for path separators in Record(), but belt-and-suspenders for filenames.
	escrowName := fmt.Sprintf("evidence-%s-%d.raw.enc", filepath.Base(r.sessionID), r.seq)
	escrowPath := filepath.Join(filepath.Clean(r.cfg.Dir), escrowName)

	if err := os.WriteFile(escrowPath, payload, r.cfg.FileMode); err != nil {
		return "", fmt.Errorf("writing escrow file: %w", err)
	}
	if err := os.Chmod(escrowPath, r.cfg.FileMode); err != nil {
		return "", fmt.Errorf("setting escrow file permissions: %w", err)
	}

	return escrowPath, nil
}

func (r *Recorder) resumeSessionLocked(sessionID string) error {
	// Use local variables so r.* fields stay untouched if any I/O fails.
	resumedSeq := uint64(0)
	resumedPrevHash := GenesisHash
	resumedFirstSeqInSpan := uint64(0)

	// Matches the name ensureFile writes and sessionResumeCandidates filters on.
	wantSession := filepath.Base(sessionID)

	candidates, err := r.sessionResumeCandidates(sessionID)
	if err != nil {
		return err
	}
	for _, candidate := range candidates {
		entries, readErr := readEntriesForResume(candidate.path)
		if readErr != nil {
			return fmt.Errorf("reading existing evidence file %s: %w", candidate.base, readErr)
		}
		if len(entries) == 0 {
			continue
		}
		// Directional tail reads return newest-first. Resume explicitly from the
		// first entry so a future increase to the bounded window cannot select an
		// older sequence and fork the chain.
		last := entries[0]

		// NOTE: We do NOT recompute and verify the tail hash here because
		// ComputeHash is not round-trip stable for entries whose Detail was
		// stored as json.RawMessage (e.g., receipt entries). ReadEntries
		// deserializes Detail into map[string]interface{}, which re-marshals
		// with alphabetically sorted keys, producing a different hash than
		// the original struct-ordered JSON. Full chain verification (which
		// has the same limitation) is done by verify-receipt / VerifyChain.
		// The chain linkage (prevHash threading) is still enforced on each
		// new Record call.
		if last.Hash == "" {
			return fmt.Errorf("evidence file %s: tail entry seq %d has empty hash",
				candidate.base, last.Sequence)
		}

		// Filtering candidates by parsed filename settles which shard to read,
		// not what is inside it. A shard NAMED for this session but CONTAINING
		// another session's entries would still be adopted as this chain's
		// head, which is the same cross-session contamination the filename fix
		// closes, one layer down. A renamed, misplaced or tampered file reaches
		// exactly this path. Refuse rather than inherit a foreign tail.
		if last.SessionID != wantSession {
			return fmt.Errorf(
				"evidence file %s: tail entry seq %d belongs to session %q, not %q; refusing to adopt a foreign chain head",
				candidate.base, last.Sequence, last.SessionID, wantSession)
		}

		// A uint64 at its maximum wraps to zero on increment, which would
		// silently restart the sequence and reuse numbers already in the
		// chain. Refuse instead; an exhausted sequence needs a new session,
		// not a wrapped one.
		if last.Sequence == math.MaxUint64 {
			return fmt.Errorf(
				"evidence file %s: sequence space exhausted at %d; refusing to wrap and reuse sequence numbers",
				candidate.base, last.Sequence)
		}

		resumedSeq = last.Sequence + 1
		resumedPrevHash = last.Hash
		resumedFirstSeqInSpan = resumedSeq
		break
	}

	// Falling through to genesis is correct when this session has no entries on
	// disk. That includes empty shards left by a crash between file creation and
	// the first write. Existing entries with corrupt contents, oversized reads,
	// or empty tail hashes fail above before genesis can hide them.

	r.sessionID = sessionID
	r.seq = resumedSeq
	r.prevHash = resumedPrevHash
	r.sinceCheckpoint = 0
	r.firstSeqInSpan = resumedFirstSeqInSpan
	return nil
}

// resumeCandidate is filename-derived metadata for one shard. Resume needs to
// know which shard is newest, and that is answerable from the name alone, so
// candidates carry no file contents.
type resumeCandidate struct {
	path     string
	base     string
	seqStart uint64
}

// sessionResumeCandidates returns every shard belonging to sessionID, newest
// first.
//
// Two deliberate differences from the read paths in query.go:
//
// It filters on parsed session EQUALITY, not on an "evidence-<session>-"
// prefix. Prefix matching let a shard of session "s-evil" be adopted as the
// chain head of session "s".
//
// It applies NO MaxEvidenceReadDirectoryEntries ceiling. That bound exists so a
// truncated read cannot present partial evidence as complete, which is a real
// hazard for query, verification and the dashboard, and it stays enforced
// there. Resume is different: it consumes exactly one tail entry from one file
// and does not verify the chain, so a count ceiling here bought no integrity
// and instead permanently bricked receipt emission once a directory passed the
// limit. Only filename metadata is unbounded; every content read below is still
// bounded by readEntriesForResume.
func (r *Recorder) sessionResumeCandidates(sessionID string) ([]resumeCandidate, error) {
	dir := filepath.Clean(r.cfg.Dir)
	// Match ensureFile, which writes filepath.Base(sessionID) into the name.
	wantSession := filepath.Base(sessionID)

	directory, err := os.Open(dir)
	if err != nil {
		return nil, fmt.Errorf("reading evidence directory: %w", err)
	}
	defer func() { _ = directory.Close() }()

	candidates := make([]resumeCandidate, 0)
	for {
		dirEntries, readErr := directory.ReadDir(128)
		for _, de := range dirEntries {
			if de.IsDir() {
				continue
			}
			name := de.Name()
			if !strings.HasSuffix(name, ".jsonl") {
				continue
			}
			parsedSession, seqStart, ok := ParseEvidenceFilename(name)
			if !ok || parsedSession != wantSession {
				continue
			}
			candidates = append(candidates, resumeCandidate{
				path:     filepath.Join(dir, name),
				base:     name,
				seqStart: seqStart,
			})
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("reading evidence directory: %w", readErr)
		}
	}

	// Newest first, and total so the chosen head never depends on directory
	// order. sort.Slice is not stable, so basename breaks seqStart ties.
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].seqStart != candidates[j].seqStart {
			return candidates[i].seqStart > candidates[j].seqStart
		}
		return candidates[i].base > candidates[j].base
	})

	// One shared rule, applied identically by every consumer of this directory
	// contract. See evidencename.CheckNoDuplicateSeqStart for why refusing beats
	// each scanner tie-breaking its own way.
	names := make([]string, 0, len(candidates))
	for _, c := range candidates {
		names = append(names, c.base)
	}
	if err := evidencename.CheckNoDuplicateSeqStart(names); err != nil {
		return nil, fmt.Errorf("evidence session %s: %w", wantSession, err)
	}

	return candidates, nil
}

func readEntriesForResume(path string) ([]Entry, error) {
	entries, truncated, err := ReadTailEntriesBounded(path, 1, int64(maxEntryWireLineBytes))
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 && truncated {
		return nil, fmt.Errorf("%w: no complete evidence tail entry within %d bytes", ErrEvidenceReadLimitExceeded, maxEntryWireLineBytes)
	}
	return entries, nil
}

// ensureFile opens a JSONL file if none is open.
func (r *Recorder) ensureFile(sessionID string, seqStart uint64) error {
	// Detect evidence directory disappearance mid-run BEFORE the short-
	// circuit on an already-open r.file. Linux keeps the inode alive
	// through rm -rf as long as the fd is open; previous prerelease builds
	// guards only triggered when r.file was nil, so writes kept
	// succeeding against an unlinked file and the operator saw nothing
	// (the pre-tag gate rounds 3/4/5 - especially round 5's "recreation still
	// silent" repro). Statting the configured dir on every call catches
	// the disappearance while r.file is still the stale fd.
	dir := filepath.Clean(r.cfg.Dir)
	_, statErr := os.Stat(dir)
	if statErr != nil && !os.IsNotExist(statErr) {
		// Fail-closed: a non-NotExist stat error (permission denied,
		// transient I/O failure, mount unmapped) means we cannot trust
		// the directory's state. Returning the error here prevents the
		// short-circuit below from silently continuing to write to a
		// stale fd while the underlying directory may have been replaced.
		return fmt.Errorf("stat evidence directory %s: %w", r.cfg.Dir, statErr)
	}
	dirMissing := os.IsNotExist(statErr)
	if dirMissing {
		if mkErr := os.MkdirAll(dir, dirPermissions); mkErr != nil {
			return fmt.Errorf("evidence directory %s disappeared and could not be recreated: %w", r.cfg.Dir, mkErr)
		}
		_, _ = fmt.Fprintf(os.Stderr,
			"pipelock: recorder: evidence directory %s disappeared mid-run and was recreated; prior receipts are lost\n",
			r.cfg.Dir)
		// Drop the stale fd so the next OpenFile lands in the freshly
		// recreated directory. Ignore close errors - the fd was
		// already pointing at an unlinked inode.
		if r.file != nil {
			r.waitDurableForCurrentFileLocked()
			_ = r.file.Close()
			r.file = nil
			r.writer = nil
			r.fileEntryCount = 0
		}
	}

	if r.file != nil {
		return nil
	}

	// filepath.Base as defense-in-depth: session ID is already validated
	// for path separators in Record(), but belt-and-suspenders for filenames.
	name := fmt.Sprintf("evidence-%s-%d.jsonl", filepath.Base(sessionID), seqStart)
	path := filepath.Join(filepath.Clean(r.cfg.Dir), name)

	f, err := os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_WRONLY|os.O_APPEND, r.cfg.FileMode)
	if err != nil {
		return err
	}
	if err := lockEvidenceFileForWrite(f); err != nil {
		_ = f.Close()
		return fmt.Errorf("locking evidence file: %w", err)
	}
	if err := f.Chmod(r.cfg.FileMode); err != nil {
		_ = f.Close()
		return fmt.Errorf("setting evidence file permissions: %w", err)
	}

	r.file = f
	r.writer = bufio.NewWriter(f)
	r.fileEntryCount = 0
	r.fileSeqStart = seqStart
	r.fileGeneration++
	if r.sinceCheckpoint == 0 {
		r.firstSeqInSpan = seqStart
	}
	return nil
}

// writeEntryBounded serializes and writes a single entry as a JSONL line,
// rotating or rejecting before Pipelock can create a shard its bounded readers
// refuse to resume, hash, or verify.
func (r *Recorder) writeEntryBounded(e Entry, notify bool) error {
	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshaling entry: %w", err)
	}
	lineBytes := int64(len(data) + 1)
	if err := r.ensureEntryCapacityLocked(e.SessionID, e.Sequence, lineBytes); err != nil {
		return err
	}
	return r.writeEntryData(data, e, notify)
}

func (r *Recorder) writeEntryData(data []byte, e Entry, notify bool) error {
	if n, err := r.writer.Write(data); err != nil {
		return err
	} else if n != len(data) {
		return io.ErrShortWrite
	}
	if n, err := r.writer.Write([]byte("\n")); err != nil {
		return err
	} else if n != 1 {
		return io.ErrShortWrite
	}
	if err := r.writer.Flush(); err != nil {
		return err
	}
	if notify {
		r.notifyObserver(e)
	}
	return nil
}

func (r *Recorder) ensureEntryCapacityLocked(sessionID string, seq uint64, lineBytes int64) error {
	if lineBytes > MaxEvidenceReadFileBytes {
		return fmt.Errorf("%w: serialized evidence entry exceeds %d bytes", ErrEvidenceReadLimitExceeded, MaxEvidenceReadFileBytes)
	}
	if r.file == nil {
		if err := r.ensureFile(sessionID, seq); err != nil {
			return fmt.Errorf("opening evidence file: %w", err)
		}
	}
	info, err := r.file.Stat()
	if err != nil {
		return err
	}
	if info.Size()+lineBytes <= MaxEvidenceReadFileBytes {
		return nil
	}
	if err := r.rotateFile(); err != nil {
		return err
	}
	if err := r.ensureFile(sessionID, seq); err != nil {
		return fmt.Errorf("opening evidence file: %w", err)
	}
	info, err = r.file.Stat()
	if err != nil {
		return err
	}
	if info.Size()+lineBytes > MaxEvidenceReadFileBytes {
		return fmt.Errorf("%w: evidence file %s would exceed %d bytes", ErrEvidenceReadLimitExceeded, filepath.Base(r.file.Name()), MaxEvidenceReadFileBytes)
	}
	return nil
}

func (r *Recorder) lastEntryOffsetLocked(e Entry) int64 {
	if r.file == nil {
		return 0
	}
	info, err := r.file.Stat()
	if err != nil {
		return 0
	}
	data, err := json.Marshal(e)
	if err != nil {
		return 0
	}
	offset := info.Size() - int64(len(data)+1)
	if offset < 0 {
		return 0
	}
	return offset
}

func (r *Recorder) notifyObserver(e Entry) {
	if r.observer == nil {
		return
	}
	defer func() {
		_ = recover()
	}()
	r.observer.ObserveRecorderEntry(e)
}

// closeFile flushes and closes the current file.
func (r *Recorder) closeFile() error {
	if r.file == nil {
		return nil
	}
	r.waitDurableForCurrentFileLocked()
	if err := r.writer.Flush(); err != nil {
		_ = r.file.Close()
		r.file = nil
		r.writer = nil
		return err
	}
	unlockErr := unlockEvidenceFile(r.file)
	err := r.file.Close()
	r.file = nil
	r.writer = nil
	if unlockErr != nil {
		return fmt.Errorf("unlocking evidence file: %w", unlockErr)
	}
	return err
}

// rotateFile closes the current file so the next write opens a new one.
func (r *Recorder) rotateFile() error {
	return r.closeFile()
}

func (r *Recorder) waitDurableForCurrentFileLocked() {
	if r.durableCond == nil || r.file == nil {
		return
	}
	for r.durablePending[r.fileGeneration] > 0 {
		r.durableCond.Wait()
	}
}

// ExpireOldFiles removes age-expired raw escrow sidecars.
//
// JSONL shards are the hash-chain spine. Deleting an older shard while retaining
// a later shard preserves append continuity but breaks full-history offline
// verification and can strand external anchors that commit to the removed
// content. Until retention has a signed compaction/tombstone format, automatic
// expiry must not remove JSONL chain shards.
func (r *Recorder) ExpireOldFiles() (int, error) {
	if r.nop {
		return 0, nil
	}
	if r.cfg.RetentionDays <= 0 {
		return 0, nil
	}

	cutoff := time.Now().Add(-time.Duration(r.cfg.RetentionDays) * 24 * time.Hour)
	dir := filepath.Clean(r.cfg.Dir)

	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		return 0, fmt.Errorf("reading evidence directory: %w", err)
	}

	removed := 0
	var expiryErrs []error
	for _, de := range dirEntries {
		if de.IsDir() {
			continue
		}
		name := de.Name()
		if !isEvidenceFile(name) {
			continue
		}
		if strings.HasSuffix(name, ".jsonl") {
			continue
		}
		info, err := de.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			path := filepath.Join(dir, name)
			// Collect the failure and keep going. Returning here let a single
			// unremovable entry, such as one planted symlink or one sidecar the
			// service cannot read, stop retention for every remaining file in
			// the directory. The result was a directory that silently stopped
			// pruning and could only be recovered by hand, which is the failure
			// this whole change set exists to prevent.
			removedFile, removeErr := removeExpiredEvidenceFile(path, cutoff)
			switch {
			case removeErr != nil:
				expiryErrs = append(expiryErrs, fmt.Errorf("%s: %w", name, removeErr))
			case removedFile:
				removed++
			}
		}
	}
	return removed, errors.Join(expiryErrs...)
}

// removeExpiredEvidenceFile deletes one aged sidecar.
//
// The handle is opened first and re-stated after locking, so the file being
// removed is confirmed to be the same aged regular file that was selected. That
// narrows the window between selection and deletion; it does not close it,
// because os.Remove unlinks by name. If another principal can rename entries in
// the evidence directory, the name can be pointed at a different inode after
// the check. The remaining defense is the directory itself: evidence
// directories are created 0o750 and owned by the service, so no other
// unprivileged principal can rename entries within them.
func removeExpiredEvidenceFile(path string, cutoff time.Time) (bool, error) {
	file, info, err := openRegularEvidenceFile(path, validateEvidenceFileAccess())
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	defer func() { _ = file.Close() }()
	locked, err := tryLockEvidenceFileForExpiry(file)
	if err != nil {
		return false, fmt.Errorf("locking evidence file for expiry: %w", err)
	}
	if !locked {
		return false, nil
	}
	after, err := file.Stat()
	if err != nil {
		return false, err
	}
	if !after.Mode().IsRegular() || !os.SameFile(info, after) || !after.ModTime().Before(cutoff) {
		return false, nil
	}
	if err := os.Remove(filepath.Clean(path)); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// isEvidenceFile checks if a filename looks like an evidence file.
func isEvidenceFile(name string) bool {
	return strings.HasPrefix(name, "evidence-") &&
		(strings.HasSuffix(name, ".jsonl") || strings.HasSuffix(name, ".raw.enc"))
}

// EvidenceDirectoryHealth summarizes recorder file counts against bounded
// resume limits without parsing receipt contents.
type EvidenceDirectoryHealth struct {
	TotalEvidenceFiles     int
	MaxSessionFiles        int
	MaxSessionID           string
	WarningThreshold       int
	MaxFilesPerSession     int
	NearSessionFileLimit   bool
	OverSessionFileLimit   bool
	RetentionDays          int
	RetentionEnabled       bool
	RetentionEligibleFiles int
}

// EvidenceDirectoryHealthForDir returns file-count health for a recorder
// directory. retentionDays controls the eligible-old-file count for files the
// expirer is allowed to remove; zero preserves keep-forever semantics and
// reports no eligible files.
func EvidenceDirectoryHealthForDir(dir string, retentionDays int) (EvidenceDirectoryHealth, error) {
	health := EvidenceDirectoryHealth{
		WarningThreshold:   EvidenceFileWarningThreshold,
		MaxFilesPerSession: MaxEvidenceReadDirectoryEntries,
		RetentionDays:      retentionDays,
		RetentionEnabled:   retentionDays > 0,
	}
	dirEntries, err := os.ReadDir(filepath.Clean(dir))
	if err != nil {
		return health, fmt.Errorf("reading evidence directory: %w", err)
	}
	cutoff := time.Time{}
	if retentionDays > 0 {
		cutoff = time.Now().Add(-time.Duration(retentionDays) * 24 * time.Hour)
	}
	counts := make(map[string]int)
	for _, de := range dirEntries {
		if de.IsDir() {
			continue
		}
		name := de.Name()
		if !isEvidenceFile(name) {
			continue
		}
		health.TotalEvidenceFiles++
		if strings.HasSuffix(name, ".jsonl") {
			if sessionID, _, ok := ParseEvidenceFilename(name); ok {
				counts[sessionID]++
				if counts[sessionID] > health.MaxSessionFiles {
					health.MaxSessionFiles = counts[sessionID]
					health.MaxSessionID = sessionID
				}
			}
		}
		if retentionDays <= 0 {
			continue
		}
		if strings.HasSuffix(name, ".jsonl") {
			continue
		}
		info, infoErr := de.Info()
		if infoErr == nil && info.ModTime().Before(cutoff) {
			health.RetentionEligibleFiles++
		}
	}
	health.NearSessionFileLimit = health.MaxSessionFiles >= health.WarningThreshold
	health.OverSessionFileLimit = health.MaxSessionFiles > health.MaxFilesPerSession
	return health, nil
}

// ComputeFileHash computes SHA-256 of an evidence file for external verification.
func ComputeFileHash(path string) (string, error) {
	hash, err := computeEvidenceFileHashBounded(path, MaxEvidenceReadFileBytes)
	if err != nil {
		return "", fmt.Errorf("hashing file: %w", err)
	}
	return hash, nil
}

// maxCheckpointBound caps the checkpoint interval to a value that fits safely
// in uint64 on all platforms including 32-bit. Typed as uint64 to prevent
// overflow when compared against int on 32-bit architectures.
const maxCheckpointBound uint64 = 1 << 53

// safeUint64 converts a positive int to uint64, using fallback if non-positive.
func safeUint64(v, fallback int) uint64 {
	if v < 1 {
		v = fallback
	}
	uv := uint64(v) //nolint:gosec // G115: v is bounds-checked positive above
	if uv > maxCheckpointBound {
		return maxCheckpointBound
	}
	return uv
}

// FileCountVerdict renders the operator-facing sentence for an evidence
// directory's file-count health. Both the doctor and the runtime startup
// warning report the same contract, and formatting it in two places had already
// produced two different sentences pinned by two different tests. Returns an
// empty string when the count is below the warning threshold.
func (h EvidenceDirectoryHealth) FileCountVerdict() string {
	if !h.NearSessionFileLimit {
		return ""
	}
	if h.OverSessionFileLimit {
		return fmt.Sprintf(
			"evidence session %q has %d JSONL shard(s), over the %d-file evidence read cap; receipt emission is unaffected, but evidence view, serve and query refuse past this",
			h.MaxSessionID, h.MaxSessionFiles, h.MaxFilesPerSession)
	}
	return fmt.Sprintf(
		"evidence session %q has %d JSONL shard(s), near the %d-file evidence read cap; warning threshold is %d",
		h.MaxSessionID, h.MaxSessionFiles, h.MaxFilesPerSession, h.WarningThreshold)
}
