// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/anchor"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const (
	evidenceHealthSchema    = "pipelock.evidencehealth.v1"
	evidenceAnchorStateFile = "anchor-state.json"
	maxTailReadBytes        = 64 * 1024
	anchorStateHashBytes    = 32
)

type evidenceHealthMonitor struct {
	recorder  *recorder.Recorder
	metrics   *metrics.Metrics
	emitterFn func() *receipt.Emitter
	configFn  func() *config.Config
	logW      io.Writer

	mu          sync.Mutex
	anchor      *metrics.EvidenceAnchorStats
	selfAuditOK atomic.Bool
	lastFsync   uint64
	lastBlocks  uint64
}

func newEvidenceHealthMonitor(
	rec *recorder.Recorder,
	m *metrics.Metrics,
	emitterFn func() *receipt.Emitter,
	configFn func() *config.Config,
	logW io.Writer,
) *evidenceHealthMonitor {
	h := &evidenceHealthMonitor{
		recorder:  rec,
		metrics:   m,
		emitterFn: emitterFn,
		configFn:  configFn,
		logW:      logW,
	}
	h.selfAuditOK.Store(true)
	return h
}

func (h *evidenceHealthMonitor) start(ctx context.Context, wg *sync.WaitGroup) {
	if h == nil || wg == nil {
		return
	}
	if h.metrics != nil {
		h.metrics.SetEvidenceHealthFunc(h.stats)
	}
	h.runPass()
	wg.Add(1)
	go func() {
		defer wg.Done()
		timer := time.NewTimer(h.interval())
		defer timer.Stop()
		for {
			select {
			case <-timer.C:
				h.runPass()
				timer.Reset(h.interval())
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (h *evidenceHealthMonitor) interval() time.Duration {
	if h == nil || h.configFn == nil {
		return config.DefaultEvidenceHealthSelfAuditInterval
	}
	cfg := h.configFn()
	if cfg == nil {
		return config.DefaultEvidenceHealthSelfAuditInterval
	}
	return cfg.FlightRecorder.EvidenceSelfAuditIntervalDuration()
}

func (h *evidenceHealthMonitor) runPass() {
	defer func() {
		if recovered := recover(); recovered != nil {
			h.fail("sampler_error", fmt.Errorf("panic in evidence self-audit: %v", recovered))
		}
	}()
	if h == nil {
		return
	}
	h.checkDurabilityInvariant()
	h.checkTail()
	h.refreshAnchor()
	h.updateRequirements()
}

func (h *evidenceHealthMonitor) checkDurabilityInvariant() {
	if h.metrics == nil {
		return
	}
	fsync, blocks := h.metrics.EvidenceCountersSnapshot()
	// The durability invariant: fsync_errors_gated (storage-layer durability
	// failures) and durability_blocks (decision-layer fail-closed blocks) must be
	// equal at quiescence; every gated fsync failure must become exactly one block.
	// Two consecutive reads with identical cumulative counters mean no activity
	// occurred in the interval (quiescent), so a non-zero gap that survives a
	// quiescent interval is a broken fail-closed path: a positive gap is an fsync
	// failure that never blocked (fail-open); a negative gap is a block not backed
	// by a durability failure. During activity the counters change every pass, so
	// judgment is deferred to the next quiet interval rather than false-alarming on
	// transient in-flight lag (a tighter activity-time check needs an in-flight gate
	// counter, tracked as a follow-up). Comparing cumulative totals rather than
	// per-pass deltas is deliberate: a standing gap must stay flagged at quiescence,
	// and a persistent divergence of varying magnitude must not escape.
	quiescent := fsync == h.lastFsync && blocks == h.lastBlocks
	h.lastFsync, h.lastBlocks = fsync, blocks
	if quiescent && fsync != blocks && h.selfAuditOK.Load() {
		h.fail("durability_invariant", fmt.Errorf("durability invariant mismatch at quiescence: fsync_errors_gated=%d durability_blocks=%d", fsync, blocks))
		h.emitViolation("durability_invariant")
	}
}

func (h *evidenceHealthMonitor) checkTail() {
	e := h.emitter()
	snap, ok := e.HealthSnapshot()
	if !ok || snap.ChainSeq == 0 || h.recorder == nil || h.recorder.Dir() == "" {
		return
	}
	tail, err := readLastReceiptTail(h.recorder.Dir(), transcriptRootSessionID)
	if err != nil {
		if !errors.Is(err, errNoReceiptTail) {
			h.fail("sampler_error", err)
		}
		return
	}
	stable, ok := e.HealthSnapshot()
	if !ok || stable.ChainSeq == 0 {
		return
	}
	if stable.ChainSeq != snap.ChainSeq || stable.PrevHash != snap.PrevHash {
		return
	}
	wantSeq := stable.ChainSeq - 1
	if tail.seq != wantSeq || tail.hash != stable.PrevHash {
		if h.metrics != nil {
			h.metrics.RecordEvidenceSequenceGap("self_audit")
		}
		h.fail("tail_divergence", fmt.Errorf("tail divergence: disk seq/hash=%d/%s memory seq/hash=%d/%s", tail.seq, tail.hash, wantSeq, stable.PrevHash))
	}
}

func (h *evidenceHealthMonitor) refreshAnchor() {
	if h.recorder == nil || h.recorder.Dir() == "" {
		h.setAnchor(nil)
		return
	}
	e := h.emitter()
	snap, ok := e.HealthSnapshot()
	if !ok {
		h.setAnchor(nil)
		return
	}
	state, found, err := readAnchorStateForSession(h.recorder.Dir(), transcriptRootSessionID)
	if err != nil {
		h.setAnchor(nil)
		h.fail("sampler_error", err)
		return
	}
	if !found {
		h.setAnchor(nil)
		return
	}
	if state.Schema != "pipelock.anchorstate.v1" {
		h.fail("sampler_error", fmt.Errorf("anchor-state schema %q is invalid", state.Schema))
		h.setAnchor(nil)
		return
	}
	if state.SessionID != transcriptRootSessionID {
		h.fail("sampler_error", fmt.Errorf("anchor-state session_id %q does not match %q", state.SessionID, transcriptRootSessionID))
		h.setAnchor(nil)
		return
	}
	if err := validateAnchorStateMarker(state, time.Now().UTC()); err != nil {
		h.fail("sampler_error", err)
		h.setAnchor(nil)
		return
	}
	if state.FinalSeq > snap.ChainSeq {
		h.fail("sampler_error", fmt.Errorf("anchor-state final_seq %d is ahead of chain_head_seq %d", state.FinalSeq, snap.ChainSeq))
		h.setAnchor(nil)
		return
	}
	if current := h.anchorSnapshot(); current != nil && state.FinalSeq < current.FinalSeq {
		return
	}
	lag := uint64(0)
	if snap.ChainSeq > state.FinalSeq {
		lag = snap.ChainSeq - state.FinalSeq
	}
	anchoredAt := state.AnchoredAt.UTC()
	anchor := &metrics.EvidenceAnchorStats{
		SessionID:            state.SessionID,
		FinalSeq:             state.FinalSeq,
		RootHash:             state.RootHash,
		Backend:              state.Backend,
		LogIndex:             state.LogIndex,
		AnchoredAt:           anchoredAt.Format(time.RFC3339Nano),
		BundleSHA256:         state.BundleSHA256,
		BundlePath:           state.BundlePath,
		LagReceipts:          lag,
		LastTimestampSeconds: float64(anchoredAt.UnixNano()) / 1e9,
	}
	h.setAnchor(anchor)
}

func (h *evidenceHealthMonitor) updateRequirements() {
	if h.metrics == nil {
		return
	}
	stats, ok := h.stats()
	if !ok {
		return
	}
	h.metrics.SetEvidenceRequirements(stats.Requirements)
	if stats.HeartbeatIntervalSeconds != nil {
		h.metrics.SetEvidenceHeartbeatInterval(*stats.HeartbeatIntervalSeconds, true)
	}
	h.metrics.SetEvidenceSelfAuditOK(h.selfAuditOK.Load())
	h.metrics.SetEvidenceAnchor(stats.LastAnchorTimestampSeconds, stats.AnchoredFinalSeq)
}

func (h *evidenceHealthMonitor) stats() (metrics.EvidenceHealthStats, bool) {
	if h == nil || h.recorder == nil || h.recorder.Dir() == "" {
		return metrics.EvidenceHealthStats{}, false
	}
	cfg := h.currentConfig()
	if cfg == nil || !cfg.FlightRecorder.EvidenceHealthEnabled() {
		return metrics.EvidenceHealthStats{}, false
	}
	e := h.emitter()
	snap, ok := e.HealthSnapshot()
	if !ok || snap.InitErr {
		return metrics.EvidenceHealthStats{}, false
	}
	requirements := map[string]bool{
		metrics.EvidenceRequirementRecorderEnabled: true,
		metrics.EvidenceRequirementEmitterHealthy:  ok && !snap.InitErr,
		metrics.EvidenceRequirementDurabilityGate:  cfg.FlightRecorder.RequireReceipts,
		metrics.EvidenceRequirementHeartbeats:      cfg.FlightRecorder.HeartbeatIntervalDuration() > 0,
		metrics.EvidenceRequirementAnchoringFresh:  false,
		metrics.EvidenceRequirementCPCActive:       false,
		metrics.EvidenceRequirementSelfAuditOK:     h.selfAuditOK.Load(),
	}
	anchor := h.anchorSnapshot()
	lastAnchor := 0.0
	var anchorLag uint64
	if anchor == nil {
		anchorLag = snap.ChainSeq + 1
	} else {
		anchorLag = anchor.LagReceipts
		lastAnchor = anchor.LastTimestampSeconds
		maxLag := cfg.FlightRecorder.EvidenceMaxAnchorLagDuration()
		if maxLag == 0 || time.Since(time.Unix(0, int64(anchor.LastTimestampSeconds*1e9))) <= maxLag {
			requirements[metrics.EvidenceRequirementAnchoringFresh] = true
		}
	}
	ageSeconds := (*float64)(nil)
	if !snap.LastEmit.IsZero() {
		age := time.Since(snap.LastEmit).Seconds()
		ageSeconds = &age
	}
	hbi := cfg.FlightRecorder.HeartbeatIntervalDuration().Seconds()
	gatedFsync, durabilityBlocks := h.metrics.EvidenceCountersSnapshot()
	fsyncStats := h.fsyncStats()
	gapStats := h.gapStats()
	in := metrics.EvidenceAELInput{
		RecorderEnabled:  requirements[metrics.EvidenceRequirementRecorderEnabled],
		EmitterHealthy:   requirements[metrics.EvidenceRequirementEmitterHealthy],
		DurabilityGate:   requirements[metrics.EvidenceRequirementDurabilityGate],
		Heartbeats:       requirements[metrics.EvidenceRequirementHeartbeats],
		AnchoringFresh:   requirements[metrics.EvidenceRequirementAnchoringFresh],
		CPCActive:        false,
		SelfAuditOK:      requirements[metrics.EvidenceRequirementSelfAuditOK],
		UnresolvedGaps:   gapStats.Resume+gapStats.SelfAudit > 0,
		UngatedFsyncFail: fsyncStats.Ungated > 0,
	}
	return metrics.EvidenceHealthStats{
		Schema:                     evidenceHealthSchema,
		CurrentAEL:                 metrics.EvidenceCurrentAEL(in),
		Requirements:               requirements,
		ChainHeadSeq:               snap.ChainSeq,
		ChainHeadAgeSeconds:        ageSeconds,
		HeartbeatIntervalSeconds:   &hbi,
		SequenceGaps:               gapStats,
		FsyncErrors:                fsyncStats,
		DurabilityBlocks:           durabilityBlocks,
		DurabilityInvariantOK:      h.selfAuditOK.Load() && gatedFsync >= durabilityBlocks,
		Anchor:                     anchor,
		CPC:                        nil,
		AnchoredFinalSeq:           anchoredFinalSeq(anchor),
		AnchorLagReceipts:          anchorLag,
		LastAnchorTimestampSeconds: lastAnchor,
	}, true
}

func (h *evidenceHealthMonitor) emitter() *receipt.Emitter {
	if h == nil || h.emitterFn == nil {
		return nil
	}
	return h.emitterFn()
}

func (h *evidenceHealthMonitor) currentConfig() *config.Config {
	if h == nil || h.configFn == nil {
		return nil
	}
	return h.configFn()
}

func (h *evidenceHealthMonitor) setAnchor(anchor *metrics.EvidenceAnchorStats) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.anchor = anchor
}

func (h *evidenceHealthMonitor) anchorSnapshot() *metrics.EvidenceAnchorStats {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.anchor == nil {
		return nil
	}
	cp := *h.anchor
	return &cp
}

func (h *evidenceHealthMonitor) fsyncStats() metrics.EvidenceFsyncStats {
	if h.metrics == nil {
		return metrics.EvidenceFsyncStats{}
	}
	_, fsync := h.metrics.EvidenceStatsCountersSnapshot()
	return fsync
}

func (h *evidenceHealthMonitor) gapStats() metrics.EvidenceGapStats {
	if h.metrics == nil {
		return metrics.EvidenceGapStats{}
	}
	gaps, _ := h.metrics.EvidenceStatsCountersSnapshot()
	return gaps
}

func (h *evidenceHealthMonitor) fail(check string, err error) {
	if !h.selfAuditOK.CompareAndSwap(true, false) {
		if h.metrics != nil {
			h.metrics.SetEvidenceSelfAuditOK(false)
		}
		return
	}
	if h.metrics != nil {
		h.metrics.SetEvidenceSelfAuditOK(false)
		h.metrics.RecordSelfAuditFailure(check)
	}
	if h.logW != nil && err != nil {
		_, _ = fmt.Fprintf(h.logW, "CRITICAL: evidence self-audit %s failed: %v\n", check, err)
	}
}

func (h *evidenceHealthMonitor) emitViolation(check string) {
	e := h.emitter()
	if e == nil {
		return
	}
	_ = e.Emit(receipt.EmitOpts{
		ActionID:  receipt.NewActionID(),
		Verdict:   config.ActionWarn,
		Transport: "evidence_selfaudit",
		Method:    "SELF_AUDIT",
		Target:    "pipelock://evidence/selfaudit",
		Layer:     "evidence_selfaudit_violation",
		Pattern:   check,
		Severity:  config.SeverityCritical,
	})
}

type receiptTail struct {
	seq  uint64
	hash string
}

var errNoReceiptTail = errors.New("no action receipt tail")

func readLastReceiptTail(dir, sessionID string) (receiptTail, error) {
	files, err := filepath.Glob(filepath.Join(filepath.Clean(dir), "evidence-"+filepath.Base(sessionID)+"-*.jsonl"))
	if err != nil {
		return receiptTail{}, err
	}
	sort.Slice(files, func(i, j int) bool {
		return evidenceFileStartSeq(files[i]) < evidenceFileStartSeq(files[j])
	})
	for i := len(files) - 1; i >= 0; i-- {
		tail, err := readLastReceiptTailFromFile(files[i])
		if err == nil {
			return tail, nil
		}
		if !errors.Is(err, errNoReceiptTail) {
			return receiptTail{}, err
		}
	}
	return receiptTail{}, errNoReceiptTail
}

func readLastReceiptTailFromFile(path string) (receiptTail, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return receiptTail{}, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return receiptTail{}, err
	}
	size := info.Size()
	start := int64(0)
	if size > maxTailReadBytes {
		start = size - maxTailReadBytes
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return receiptTail{}, err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return receiptTail{}, err
	}
	if start > 0 {
		if idx := bytes.IndexByte(data, '\n'); idx >= 0 && idx+1 < len(data) {
			data = data[idx+1:]
		}
	}
	lines := splitNonEmptyLines(data)
	for i := len(lines) - 1; i >= 0; i-- {
		tail, ok, err := parseReceiptTailLine(lines[i])
		if err != nil {
			return receiptTail{}, err
		}
		if ok {
			return tail, nil
		}
	}
	return receiptTail{}, errNoReceiptTail
}

func splitNonEmptyLines(data []byte) [][]byte {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), maxTailReadBytes)
	var lines [][]byte
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) > 0 {
			lines = append(lines, append([]byte(nil), line...))
		}
	}
	return lines
}

func parseReceiptTailLine(line []byte) (receiptTail, bool, error) {
	var entry struct {
		Type   string          `json:"type"`
		Detail json.RawMessage `json:"detail"`
	}
	if err := json.Unmarshal(line, &entry); err != nil {
		return receiptTail{}, false, err
	}
	if entry.Type != "action_receipt" {
		return receiptTail{}, false, nil
	}
	var rcpt receipt.Receipt
	if err := json.Unmarshal(entry.Detail, &rcpt); err != nil {
		return receiptTail{}, false, err
	}
	hash, err := receipt.ReceiptHash(rcpt)
	if err != nil {
		return receiptTail{}, false, err
	}
	return receiptTail{seq: rcpt.ActionRecord.ChainSeq, hash: hash}, true, nil
}

func evidenceFileStartSeq(path string) uint64 {
	name := strings.TrimSuffix(filepath.Base(path), ".jsonl")
	idx := strings.LastIndex(name, "-")
	if idx < 0 {
		return 0
	}
	n, err := strconv.ParseUint(name[idx+1:], 10, 64)
	if err != nil {
		return 0
	}
	return n
}

type anchorState struct {
	Schema       string    `json:"schema"`
	SessionID    string    `json:"session_id"`
	FinalSeq     uint64    `json:"final_seq"`
	RootHash     string    `json:"root_hash"`
	Backend      string    `json:"backend"`
	LogIndex     uint64    `json:"log_index"`
	AnchoredAt   time.Time `json:"anchored_at"`
	BundleSHA256 string    `json:"bundle_sha256"`
	BundlePath   string    `json:"bundle_path"`
}

const maxEvidenceAnchorStateBytes = 64 * 1024

func readAnchorState(path string) (anchorState, error) {
	marker, found, err := anchor.LoadStateMarkerFile(path)
	if err != nil {
		return anchorState{}, err
	}
	if !found {
		return anchorState{}, fmt.Errorf("read anchor-state: %w", os.ErrNotExist)
	}
	return anchorStateFromMarker(marker), nil
}

func readAnchorStateForSession(dir, sessionID string) (anchorState, bool, error) {
	legacy, err := readAnchorState(filepath.Join(dir, evidenceAnchorStateFile))
	if err == nil && legacy.SessionID != sessionID {
		return anchorState{}, false, fmt.Errorf("anchor-state session_id %q does not match %q", legacy.SessionID, sessionID)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return anchorState{}, false, err
	}
	markers, err := anchor.LoadStateMarkers(dir)
	if err != nil {
		return anchorState{}, false, err
	}
	var selected anchorState
	found := false
	seenSeq := map[uint64]string{}
	for _, marker := range markers {
		if marker.SessionID != sessionID {
			continue
		}
		state := anchorStateFromMarker(marker)
		if previousRoot, ok := seenSeq[state.FinalSeq]; ok && previousRoot != state.RootHash {
			return anchorState{}, false, fmt.Errorf("ambiguous anchor-state markers for session %q at final_seq %d", sessionID, state.FinalSeq)
		}
		seenSeq[state.FinalSeq] = state.RootHash
		if !found || state.FinalSeq > selected.FinalSeq {
			selected = state
			found = true
		}
	}
	return selected, found, nil
}

func anchorStateFromMarker(marker anchor.StateMarker) anchorState {
	return anchorState{
		Schema:       marker.Schema,
		SessionID:    marker.SessionID,
		FinalSeq:     marker.FinalSeq,
		RootHash:     marker.RootHash,
		Backend:      marker.Backend,
		LogIndex:     marker.LogIndex,
		AnchoredAt:   marker.AnchoredAt,
		BundleSHA256: marker.BundleSHA256,
		BundlePath:   marker.BundlePath,
	}
}

func validateAnchorStateMarker(state anchorState, now time.Time) error {
	if !isLowerHexBytes(state.RootHash, anchorStateHashBytes) {
		return fmt.Errorf("anchor-state root_hash is invalid")
	}
	if !isLowerHexBytes(state.BundleSHA256, anchorStateHashBytes) {
		return fmt.Errorf("anchor-state bundle_sha256 is invalid")
	}
	if state.Backend != "local" && state.Backend != "rekor" {
		return fmt.Errorf("anchor-state backend %q is invalid", state.Backend)
	}
	if state.AnchoredAt.IsZero() {
		return fmt.Errorf("anchor-state anchored_at is missing")
	}
	if state.AnchoredAt.After(now) {
		return fmt.Errorf("anchor-state anchored_at %s is in the future", state.AnchoredAt.UTC().Format(time.RFC3339Nano))
	}
	if strings.TrimSpace(state.BundlePath) == "" {
		return fmt.Errorf("anchor-state bundle_path is empty")
	}
	return nil
}

func isLowerHexBytes(value string, bytesLen int) bool {
	if len(value) != bytesLen*2 {
		return false
	}
	for _, ch := range value {
		if (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') {
			continue
		}
		return false
	}
	return true
}

func anchoredFinalSeq(anchor *metrics.EvidenceAnchorStats) uint64 {
	if anchor == nil {
		return 0
	}
	return anchor.FinalSeq
}
