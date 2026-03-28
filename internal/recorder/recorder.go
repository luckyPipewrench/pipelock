// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/nacl/box"

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
)

// Config configures the flight recorder.
type Config struct {
	Enabled            bool   `yaml:"enabled"`
	Dir                string `yaml:"dir"`
	CheckpointInterval int    `yaml:"checkpoint_interval"`
	RetentionDays      int    `yaml:"retention_days"`
	Redact             bool   `yaml:"redact"`
	SignCheckpoints    bool   `yaml:"sign_checkpoints"`
	MaxEntriesPerFile  int    `yaml:"max_entries_per_file"`
	RawEscrow          bool   `yaml:"raw_escrow"`
	EscrowPublicKey    string `yaml:"escrow_public_key"`
}

// RedactFunc is the signature for DLP redaction. Matches scanner.ScanTextForDLP.
type RedactFunc func(ctx context.Context, text string) scanner.TextDLPResult

// Recorder writes hash-chained evidence entries to JSONL files.
type Recorder struct {
	cfg       Config
	redactFn  RedactFunc
	privKey   ed25519.PrivateKey
	escrowPub *[x25519KeySize]byte

	mu             sync.Mutex
	seq            uint64
	prevHash       string
	writer         *bufio.Writer
	file           *os.File
	fileEntryCount int
	fileSeqStart   uint64
	sessionID      string

	// Checkpoint tracking
	checkpointThreshold uint64
	sinceCheckpoint     uint64
	firstSeqInSpan      uint64
	closed              bool
	nop                 bool
}

// New creates a Recorder. The redactFn is used for DLP redaction (can be nil to skip).
// privKey is used for checkpoint signing (nil = unsigned checkpoints).
// When cfg.Enabled is false, returns a no-op recorder that discards all calls.
func New(cfg Config, redactFn RedactFunc, privKey ed25519.PrivateKey) (*Recorder, error) {
	if !cfg.Enabled {
		return &Recorder{nop: true}, nil
	}

	if cfg.CheckpointInterval <= 0 {
		cfg.CheckpointInterval = defaultCheckpointInterval
	}
	if cfg.MaxEntriesPerFile <= 0 {
		cfg.MaxEntriesPerFile = defaultMaxEntriesPerFile
	}

	if err := os.MkdirAll(filepath.Clean(cfg.Dir), dirPermissions); err != nil {
		return nil, fmt.Errorf("creating evidence directory: %w", err)
	}

	r := &Recorder{
		cfg:                 cfg,
		redactFn:            redactFn,
		privKey:             privKey,
		prevHash:            GenesisHash,
		checkpointThreshold: safeUint64(cfg.CheckpointInterval, 1),
	}

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

// Record writes an entry to the chain. Thread-safe. The caller provides the
// SessionID, Type, Transport, Summary, and Detail. Sequence, Timestamp,
// PrevHash, Hash, and Version are set by the recorder.
func (r *Recorder) Record(e Entry) error {
	if r.nop {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return fmt.Errorf("recorder is closed")
	}

	// Session ID validation: require non-empty, reject path separators
	// (defense against path traversal in filenames), and reject mismatches.
	if e.SessionID == "" {
		return errors.New("recorder: session_id required")
	}
	if strings.ContainsAny(e.SessionID, `/\`) {
		return fmt.Errorf("recorder: session_id contains path separator")
	}
	if r.sessionID == "" {
		r.sessionID = e.SessionID
	}
	if e.SessionID != r.sessionID {
		return fmt.Errorf("recorder: session_id mismatch (expected %q, got %q)", r.sessionID, e.SessionID)
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
			return fmt.Errorf("marshal raw escrow: %w", err)
		}
		escrowPath, err := r.writeEscrow(rawJSON)
		if err != nil {
			return fmt.Errorf("write raw escrow: %w", err)
		}
		e.RawRef = filepath.Base(escrowPath)
	}

	// DLP redaction
	if r.cfg.Redact && r.redactFn != nil {
		e.Detail = r.redactDetail(e.Detail)
	}

	e.Hash = ComputeHash(e)

	if err := r.ensureFile(e.SessionID, e.Sequence); err != nil {
		return fmt.Errorf("opening evidence file: %w", err)
	}

	if err := r.writeEntry(e); err != nil {
		return fmt.Errorf("writing entry: %w", err)
	}

	// Advance chain state AFTER successful write. If ensureFile or
	// writeEntry fails, the next entry must re-link to the same prevHash
	// so the chain stays consistent with what reached disk.
	r.prevHash = e.Hash
	r.seq++

	r.sinceCheckpoint++
	if r.sinceCheckpoint >= r.checkpointThreshold {
		if err := r.checkpointLocked(); err != nil {
			return fmt.Errorf("writing checkpoint: %w", err)
		}
	}

	// File rotation
	r.fileEntryCount++
	if r.fileEntryCount >= r.cfg.MaxEntriesPerFile {
		if err := r.rotateFile(); err != nil {
			return fmt.Errorf("rotating file: %w", err)
		}
	}

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
	} else if err := dr.Validate(); err != nil {
		return fmt.Errorf("invalid decision record: %w", err)
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
		Transport: dr.RequestContext.Transport,
		Summary:   summary,
		Detail:    detail,
	})
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
		PrevHash:  r.prevHash,
	}

	// Sign if we have a key — sign the hash of the chain up to this point
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
		if err := r.writeEntry(e); err != nil {
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

	if err := os.WriteFile(escrowPath, payload, filePermissions); err != nil {
		return "", fmt.Errorf("writing escrow file: %w", err)
	}

	return escrowPath, nil
}

// ensureFile opens a JSONL file if none is open.
func (r *Recorder) ensureFile(sessionID string, seqStart uint64) error {
	if r.file != nil {
		return nil
	}

	// filepath.Base as defense-in-depth: session ID is already validated
	// for path separators in Record(), but belt-and-suspenders for filenames.
	name := fmt.Sprintf("evidence-%s-%d.jsonl", filepath.Base(sessionID), seqStart)
	path := filepath.Join(filepath.Clean(r.cfg.Dir), name)

	f, err := os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_WRONLY|os.O_APPEND, filePermissions)
	if err != nil {
		return err
	}

	r.file = f
	r.writer = bufio.NewWriter(f)
	r.fileEntryCount = 0
	r.fileSeqStart = seqStart
	if r.sinceCheckpoint == 0 {
		r.firstSeqInSpan = seqStart
	}
	return nil
}

// writeEntry serializes and writes a single entry as a JSONL line.
func (r *Recorder) writeEntry(e Entry) error {
	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshaling entry: %w", err)
	}
	if _, err := r.writer.Write(data); err != nil {
		return err
	}
	if _, err := r.writer.Write([]byte("\n")); err != nil {
		return err
	}
	return r.writer.Flush()
}

// closeFile flushes and closes the current file.
func (r *Recorder) closeFile() error {
	if r.file == nil {
		return nil
	}
	if err := r.writer.Flush(); err != nil {
		_ = r.file.Close()
		r.file = nil
		r.writer = nil
		return err
	}
	err := r.file.Close()
	r.file = nil
	r.writer = nil
	return err
}

// rotateFile closes the current file so the next write opens a new one.
func (r *Recorder) rotateFile() error {
	return r.closeFile()
}

// ExpireOldFiles removes evidence files older than RetentionDays.
// Safe to call periodically. Returns the number of files removed.
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
	for _, de := range dirEntries {
		if de.IsDir() {
			continue
		}
		name := de.Name()
		if !isEvidenceFile(name) {
			continue
		}
		info, err := de.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			path := filepath.Join(dir, name)
			if err := os.Remove(path); err == nil {
				removed++
			}
		}
	}
	return removed, nil
}

// isEvidenceFile checks if a filename looks like an evidence file.
func isEvidenceFile(name string) bool {
	return strings.HasPrefix(name, "evidence-") &&
		(strings.HasSuffix(name, ".jsonl") || strings.HasSuffix(name, ".raw.enc"))
}

// ComputeFileHash computes SHA-256 of an evidence file for external verification.
func ComputeFileHash(path string) (string, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("opening file: %w", err)
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hashing file: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// maxCheckpointBound caps the checkpoint interval to a value that fits safely
// in uint64 on all platforms. The explicit bound satisfies gosec G115.
const maxCheckpointBound = 1 << 53

// safeUint64 converts a positive int to uint64, using fallback if non-positive.
func safeUint64(v, fallback int) uint64 {
	if v < 1 {
		v = fallback
	}
	if v > maxCheckpointBound {
		v = maxCheckpointBound
	}
	return uint64(v)
}
