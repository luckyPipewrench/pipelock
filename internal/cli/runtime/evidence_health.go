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
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/anchor"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/evidencename"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const (
	evidenceHealthSchema    = metrics.EvidenceHealthSchemaV2
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
	state, found, skipped, err := readAnchorStateForSessionWithSkipped(h.recorder.Dir(), transcriptRootSessionID)
	if skipped > 0 && h.metrics != nil {
		h.metrics.RecordEvidenceAnchorStateSkipped(skipped)
	}
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
	if (state.SignerKey == "" || state.SignerKey == e.SignerKeyHex()) && state.FinalSeq >= snap.ChainSeq {
		h.fail("sampler_error", fmt.Errorf("anchor-state final_seq %d is ahead of chain_head_seq %d", state.FinalSeq, snap.ChainSeq))
		h.setAnchor(nil)
		return
	}
	if current := h.anchorSnapshot(); current != nil && state.ReceiptCount == 0 && state.FinalSeq < current.FinalSeq {
		return
	}
	lag := uint64(0)
	if state.SignerKey != "" && state.SignerKey != e.SignerKeyHex() {
		lag = snap.ChainSeq
	} else if snap.ChainSeq > state.FinalSeq+1 {
		lag = snap.ChainSeq - state.FinalSeq - 1
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
	autoAnchor := h.metrics.EvidenceAutoAnchorStatsSnapshot()
	lastAnchor := 0.0
	var anchorLag uint64
	if anchor == nil {
		anchorLag = snap.ChainSeq
	} else {
		anchorLag = anchor.LagReceipts
		lastAnchor = anchor.LastTimestampSeconds
		maxLag := cfg.FlightRecorder.EvidenceMaxAnchorLagDuration()
		autoAnchorHealthy := !cfg.FlightRecorder.AnchorConfigured() || autoAnchor.LastError == ""
		if autoAnchorHealthy && (maxLag == 0 || time.Since(time.Unix(0, int64(anchor.LastTimestampSeconds*1e9))) <= maxLag) {
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
	fileStats := h.fileStats(cfg)
	operational := metrics.EvidenceOperationalInput{
		RecorderEnabled:  requirements[metrics.EvidenceRequirementRecorderEnabled],
		EmitterHealthy:   requirements[metrics.EvidenceRequirementEmitterHealthy],
		SelfAuditOK:      requirements[metrics.EvidenceRequirementSelfAuditOK],
		UnresolvedGaps:   gapStats.Resume+gapStats.SelfAudit > 0,
		UngatedFsyncFail: fsyncStats.Ungated > 0,
	}
	return metrics.EvidenceHealthStats{
		Schema:                     evidenceHealthSchema,
		CurrentAEL:                 metrics.EvidenceCurrentAELUnavailable,
		LocalRecorderOperational:   metrics.EvidenceLocalRecorderOperational(operational),
		RunState:                   metrics.EvidenceRunStateOpen,
		RunID:                      nil,
		AELArtifactCapability:      metrics.CurrentEvidenceArtifactCapability(),
		Requirements:               requirements,
		ChainHeadSeq:               snap.ChainSeq,
		ChainHeadAgeSeconds:        ageSeconds,
		HeartbeatIntervalSeconds:   &hbi,
		SequenceGaps:               gapStats,
		FsyncErrors:                fsyncStats,
		Files:                      fileStats,
		DurabilityBlocks:           durabilityBlocks,
		DurabilityInvariantOK:      h.selfAuditOK.Load() && gatedFsync >= durabilityBlocks,
		Anchor:                     anchor,
		AutoAnchor:                 autoAnchor,
		CPC:                        nil,
		AnchoredFinalSeq:           anchoredFinalSeq(anchor),
		AnchorLagReceipts:          anchorLag,
		LastAnchorTimestampSeconds: lastAnchor,
	}, true
}

func (h *evidenceHealthMonitor) fileStats(cfg *config.Config) metrics.EvidenceFileStats {
	if h == nil || h.recorder == nil || cfg == nil {
		return metrics.EvidenceFileStats{
			WarningThreshold:   recorder.EvidenceFileWarningThreshold,
			MaxFilesPerSession: recorder.MaxEvidenceReadDirectoryEntries,
		}
	}
	health, err := recorder.EvidenceDirectoryHealthForDir(h.recorder.Dir(), cfg.FlightRecorder.RetentionDays)
	if err != nil {
		// Deliberately NOT routed through fail(). That path latches
		// selfAuditOK off permanently with no re-arm, and this is a
		// metrics-only file-count scan: a transient directory read error would
		// otherwise masquerade as a permanent evidence-integrity failure and
		// never clear. Report zeroed counts alongside the real thresholds so a
		// dashboard cannot read the gap as a healthy empty directory.
		h.recordSamplerDegraded(err)
		return metrics.EvidenceFileStats{
			WarningThreshold:   recorder.EvidenceFileWarningThreshold,
			MaxFilesPerSession: recorder.MaxEvidenceReadDirectoryEntries,
		}
	}
	return metrics.EvidenceFileStats{
		TotalEvidenceFiles:     health.TotalEvidenceFiles,
		MaxSessionFiles:        health.MaxSessionFiles,
		MaxSessionID:           health.MaxSessionID,
		WarningThreshold:       health.WarningThreshold,
		MaxFilesPerSession:     health.MaxFilesPerSession,
		NearSessionFileLimit:   health.NearSessionFileLimit,
		OverSessionFileLimit:   health.OverSessionFileLimit,
		RetentionDays:          health.RetentionDays,
		RetentionEnabled:       health.RetentionEnabled,
		RetentionEligibleFiles: health.RetentionEligibleFiles,
	}
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

// recordSamplerDegraded reports that the file-count sampler could not read the
// evidence directory. This is a measurement failure, not an integrity finding,
// so it must stay off the latching self-audit path: conflating the two would
// leave a permanently degraded integrity signal behind a transient read error,
// and an operator cannot tell a real chain problem from a momentary EIO.
func (h *evidenceHealthMonitor) recordSamplerDegraded(err error) {
	if h.metrics != nil {
		h.metrics.RecordSelfAuditFailure("sampler_error")
	}
	if h.logW != nil && err != nil {
		_, _ = fmt.Fprintf(h.logW, "WARNING: evidence file-count sampler unavailable: %v\n", err)
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
	// A glob of "evidence-<session>-*.jsonl" has the same hole prefix matching
	// did: for session "s" it also matches "evidence-s-evil-999.jsonl", which
	// belongs to session "s-evil", and that file sorts highest so the reported
	// tail would come from another session. Enumerate and compare the parsed
	// session instead.
	clean := filepath.Clean(dir)
	wantSession := filepath.Base(sessionID)
	dirEntries, err := os.ReadDir(clean)
	if err != nil {
		// filepath.Glob, which this replaced, reported no matches and no error
		// for a directory that does not exist, and a caller relies on that: an
		// absent recorder directory means there is no tail yet, not a failure.
		// Preserve exactly that case. Every other error (permission denied, for
		// one) now surfaces instead of being silently reported as "no tail",
		// which Glob could not distinguish.
		if errors.Is(err, fs.ErrNotExist) {
			return receiptTail{}, errNoReceiptTail
		}
		return receiptTail{}, err
	}
	files := make([]string, 0, len(dirEntries))
	for _, de := range dirEntries {
		if de.IsDir() {
			continue
		}
		parsedSession, _, ok := recorder.ParseEvidenceFilename(de.Name())
		if !ok || parsedSession != wantSession {
			continue
		}
		files = append(files, filepath.Join(clean, de.Name()))
	}
	// Total order, for the same reason as the recorder's candidate sort:
	// sort.Slice is not stable and a non-numeric trailing segment parses to 0,
	// so ties must not be resolved by directory order.
	sort.Slice(files, func(i, j int) bool {
		si, sj := evidenceFileStartSeq(files[i]), evidenceFileStartSeq(files[j])
		if si != sj {
			return si < sj
		}
		return filepath.Base(files[i]) < filepath.Base(files[j])
	})
	// An ambiguous shard set makes "the tail" undefined, and this feeds the
	// self-audit divergence check, so guessing would produce either a false
	// alarm or a missed one.
	if err := evidencename.CheckNoDuplicateSeqStart(files); err != nil {
		return receiptTail{}, err
	}
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

// evidenceFileStartSeq delegates to the shared parser. Membership is decided
// with recorder.ParseEvidenceFilename, so deriving the ORDERING key from a
// second implementation would let the two drift apart on exactly the inputs
// that matter.
func evidenceFileStartSeq(path string) uint64 {
	_, seq, ok := recorder.ParseEvidenceFilename(path)
	if !ok {
		return 0
	}
	return seq
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
	ReceiptCount uint64    `json:"-"`
	SignerKey    string    `json:"-"`
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

func readAnchorStateForSession(dir string) (anchorState, bool, error) {
	state, found, _, err := readAnchorStateForSessionWithSkipped(dir, transcriptRootSessionID)
	return state, found, err
}

func readAnchorStateForSessionWithSkipped(dir, sessionID string) (anchorState, bool, int, error) {
	skipped := 0
	latestPath := filepath.Join(dir, evidenceAnchorStateFile)
	indexPath := filepath.Join(dir, "anchor-state.d")
	_, initialIndexErr := os.Lstat(indexPath)
	indexInitiallyMissing := errors.Is(initialIndexErr, os.ErrNotExist)
	latest, latestFound, latestErr := anchor.LoadStateMarkerFile(latestPath)
	var latestIssue error
	if latestErr != nil {
		skipped++
		latestIssue = latestErr
	} else if latestFound && latest.SessionID == sessionID && latest.ReceiptCount > 0 {
		indexed, indexedFound, indexErr := anchor.LoadIndexedStateMarker(dir, latest)
		if indexErr == nil && indexedFound && anchor.StateMarkersEqual(indexed, latest) {
			// Trust the O(1) pointer only after authenticating the single latest
			// bundle: hash it against BundleSHA256 and hydrate coverage/signer from
			// the verified checkpoint rather than the enriched JSON. This opens one
			// bundle (not the whole history), so it stays O(1) while a missing,
			// corrupt, or marker-mismatched bundle can no longer read as fresh.
			state := anchorStateFromMarker(latest)
			if checkpoint, verifyErr := loadAutoAnchorCheckpoint(dir, state); verifyErr == nil {
				state.ReceiptCount = checkpoint.ReceiptCount
				if len(checkpoint.SignerKeys) > 0 {
					state.SignerKey = checkpoint.SignerKeys[len(checkpoint.SignerKeys)-1]
				}
				return state, true, skipped, nil
			}
			skipped++
			latestIssue = errors.New("anchor-state latest bundle is missing or does not match its marker")
		} else {
			skipped++
			latestIssue = errors.New("anchor-state latest marker does not match its immutable index entry")
		}
	} else if latestFound && latest.SessionID != sessionID {
		if indexInitiallyMissing {
			latestIssue = fmt.Errorf("anchor-state session_id %q does not match %q", latest.SessionID, sessionID)
		}
	}

	markers, historicalSkipped, err := anchor.LoadStateMarkersResilient(dir)
	if err != nil {
		return anchorState{}, false, skipped, err
	}
	if latestErr != nil && indexInitiallyMissing && historicalSkipped > 0 {
		if _, indexErr := os.Lstat(indexPath); errors.Is(indexErr, os.ErrNotExist) {
			historicalSkipped--
		}
	}
	skipped += historicalSkipped
	candidates := make(map[uint64]anchorState)
	roots := make(map[uint64]string)
	ambiguous := make(map[uint64]bool)
	maxCoverage := uint64(0)
	for _, marker := range markers {
		if marker.SessionID != sessionID {
			continue
		}
		state := anchorStateFromMarker(marker)
		checkpoint, loadErr := loadAutoAnchorCheckpoint(dir, state)
		if loadErr != nil {
			skipped++
			continue
		}
		state.ReceiptCount = checkpoint.ReceiptCount
		if len(checkpoint.SignerKeys) > 0 {
			state.SignerKey = checkpoint.SignerKeys[len(checkpoint.SignerKeys)-1]
		}
		coverage := anchorStateCoverage(state)
		if coverage > maxCoverage {
			maxCoverage = coverage
		}
		if ambiguous[coverage] {
			skipped++
			continue
		}
		if previousRoot, ok := roots[coverage]; ok && previousRoot != state.RootHash {
			delete(candidates, coverage)
			ambiguous[coverage] = true
			skipped += 2
			continue
		}
		roots[coverage] = state.RootHash
		if previous, ok := candidates[coverage]; !ok || state.AnchoredAt.After(previous.AnchoredAt) {
			candidates[coverage] = state
		}
	}
	// Two bundle-verified markers at the SELECTED (highest) coverage with different
	// roots is forked or tampered history, not ordinary corruption to skip past.
	// Fail closed rather than silently degrading to an older anchor and hiding it.
	// A conflict only at a LOWER coverage does not affect a clean higher selection.
	if maxCoverage > 0 && ambiguous[maxCoverage] {
		return anchorState{}, false, skipped, fmt.Errorf("anchor-state has conflicting verified markers at the highest coverage %d", maxCoverage)
	}
	var selected anchorState
	var selectedCoverage uint64
	found := false
	for coverage, candidate := range candidates {
		if !found || coverage > selectedCoverage {
			selected = candidate
			selectedCoverage = coverage
			found = true
		}
	}
	if !found && latestIssue != nil {
		return anchorState{}, false, skipped, latestIssue
	}
	return selected, found, skipped, nil
}

func anchorStateCoverage(state anchorState) uint64 {
	if state.ReceiptCount > 0 {
		return state.ReceiptCount
	}
	if state.FinalSeq == math.MaxUint64 {
		return state.FinalSeq
	}
	return state.FinalSeq + 1
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
		ReceiptCount: marker.ReceiptCount,
		SignerKey:    marker.SignerKey,
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
