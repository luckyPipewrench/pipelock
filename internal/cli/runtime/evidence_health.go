// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
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
	// maxTailScanBytes bounds how far back the self-audit looks for a chain's
	// last action receipt. It must exceed one maximal recorder entry so a valid
	// large receipt is never mistaken for a missing one, and leaves room for
	// the paired v2 decision entries that share the session file.
	maxTailScanBytes     = 8 * int64(recorder.MaxEntryLineBytes)
	anchorStateHashBytes = 32
)

type evidenceHealthMonitor struct {
	recorder *recorder.Recorder
	metrics  *metrics.Metrics
	// emitterFn is the process emitter: the chain that carries lifecycle
	// records and self-audit violations, and whose head is reported as the
	// top-level chain_head_seq.
	emitterFn func() *receipt.Emitter
	// shardsFn returns every receipt chain this process writes, in signed
	// shard order. Nil means a single chain, the process emitter.
	shardsFn func() []*receipt.Emitter
	configFn func() *config.Config
	logW     io.Writer

	mu          sync.Mutex
	anchors     map[string]*metrics.EvidenceAnchorStats
	tails       map[string]shardTailState
	selfAuditOK atomic.Bool
	lastFsync   uint64
	lastBlocks  uint64
}

// shardTailState is the latest conclusive tail comparison for one chain. It
// is keyed by session and bound to the emitter instance that produced it, so
// a reload that swaps the emitter starts the chain over as unverified rather
// than inheriting a verdict about a different writer.
type shardTailState struct {
	emitter *receipt.Emitter
	state   string
	detail  string
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
		anchors:   make(map[string]*metrics.EvidenceAnchorStats),
		tails:     make(map[string]shardTailState),
	}
	h.selfAuditOK.Store(true)
	return h
}

// withShards makes the monitor observe every chain of a receipt group. Each
// chain is compared only with its own session's evidence.
func (h *evidenceHealthMonitor) withShards(shardsFn func() []*receipt.Emitter) *evidenceHealthMonitor {
	if h != nil {
		h.shardsFn = shardsFn
	}
	return h
}

// shardObservation is one chain's identity and state taken from that chain's
// own emitter. Health never joins one chain's head with another chain's
// session, disk tail or anchor marker.
type shardObservation struct {
	index     int
	emitter   *receipt.Emitter
	session   string
	snap      receipt.HealthSnapshot
	healthErr error
}

func (h *evidenceHealthMonitor) liveEmitters() []*receipt.Emitter {
	if h.shardsFn != nil {
		return h.shardsFn()
	}
	if e := h.emitter(); e != nil {
		return []*receipt.Emitter{e}
	}
	return nil
}

// stillCurrent reports whether obs's emitter is still the live writer of its
// chain. A hot reload or signer rotation can replace the writer while a pass
// is reading disk; a comparison that spans that replacement is about two
// writers and decides nothing.
func (h *evidenceHealthMonitor) stillCurrent(obs shardObservation) (receipt.HealthSnapshot, bool) {
	live := h.liveEmitters()
	if obs.index >= len(live) || live[obs.index] != obs.emitter {
		return receipt.HealthSnapshot{}, false
	}
	snap, ok := obs.emitter.HealthSnapshot()
	if !ok || snap.InitErr || snap.RunNonce != obs.snap.RunNonce || snap.ChainSeq < obs.snap.ChainSeq {
		return receipt.HealthSnapshot{}, false
	}
	return snap, true
}

func (h *evidenceHealthMonitor) observeShards() []shardObservation {
	if h == nil {
		return nil
	}
	emitters := h.liveEmitters()
	out := make([]shardObservation, 0, len(emitters))
	for i, e := range emitters {
		snap, ok := e.HealthSnapshot()
		if !ok {
			continue
		}
		session := h.sessionFor(e)
		out = append(out, shardObservation{index: i, emitter: e, session: session, snap: snap, healthErr: e.HealthError()})
	}
	return out
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
	if h.recorder == nil || h.recorder.Dir() == "" {
		return
	}
	for _, obs := range h.observeShards() {
		h.checkShardTail(obs)
	}
}

// afterSelfAuditTailRead is a test seam between the disk read and the second
// snapshot in checkShardTail. Production leaves it a no-op.
var afterSelfAuditTailRead = func() {}

// checkShardTail compares one chain's disk tail with that chain's in-memory
// head. Receipts are written and flushed while the emitter holds its chain
// lock, and HealthSnapshot takes the same lock, so at a snapshot the session's
// last action receipt on disk is exactly ChainSeq-1. The disk is read between
// two snapshots of the same live writer, so its last receipt must have a
// sequence between the two heads. At either end its hash must equal that
// head; strictly between them it must carry this writer's valid signature.
// Anything outside that is a proven fault. A pass that cannot make the
// comparison (writer replaced, file replaced) leaves the chain pending rather
// than keeping an earlier verdict.
func (h *evidenceHealthMonitor) checkShardTail(obs shardObservation) {
	first := obs.snap
	if first.InitErr {
		h.setTail(obs, metrics.EvidenceSelfAuditPending, "receipt chain failed to initialize")
		return
	}
	if first.ChainSeq == 0 {
		// Nothing is claimed in this segment yet, so there is nothing to
		// compare.
		h.setTail(obs, metrics.EvidenceSelfAuditVerified, "")
		return
	}
	tail, err := readLastReceiptTail(h.recorder.Dir(), obs.session)
	if err != nil {
		h.applyTailReadError(obs, err)
		return
	}
	afterSelfAuditTailRead()
	second, current := h.stillCurrent(obs)
	if !current {
		// Keyed by emitter: the replacement starts unverified on its own.
		return
	}
	low, high := first.ChainSeq-1, second.ChainSeq-1
	var divergence error
	switch {
	case tail.seq < low:
		divergence = fmt.Errorf("disk tail seq %d is behind chain head %d", tail.seq, low)
	case tail.seq > high:
		divergence = fmt.Errorf("disk tail seq %d is ahead of chain head %d", tail.seq, high)
	case tail.seq == low && tail.hash != first.PrevHash:
		divergence = fmt.Errorf("disk seq/hash=%d/%s memory seq/hash=%d/%s", tail.seq, tail.hash, low, first.PrevHash)
	case tail.seq == high && tail.hash != second.PrevHash:
		divergence = fmt.Errorf("disk seq/hash=%d/%s memory seq/hash=%d/%s", tail.seq, tail.hash, high, second.PrevHash)
	case tail.seq != low && tail.seq != high:
		if err := receipt.VerifyWithKey(tail.receipt, obs.emitter.SignerKeyHex()); err != nil {
			divergence = fmt.Errorf("disk tail seq %d does not verify against this chain's signer: %w", tail.seq, err)
		}
	}
	if divergence != nil {
		if h.metrics != nil {
			h.metrics.RecordEvidenceSequenceGap("self_audit")
		}
		h.setTail(obs, metrics.EvidenceSelfAuditFailed, divergence.Error())
		h.fail("tail_divergence", fmt.Errorf("tail divergence on chain %s: %w", obs.session, divergence))
		return
	}
	h.setTail(obs, metrics.EvidenceSelfAuditVerified, "")
}

// applyTailReadError classifies a failed tail read. Only provably malformed
// evidence is a finding; everything else leaves the chain unverified.
func (h *evidenceHealthMonitor) applyTailReadError(obs shardObservation, err error) {
	switch {
	case errors.Is(err, errNoReceiptTail):
		h.setTail(obs, metrics.EvidenceSelfAuditPending, fmt.Sprintf("no action receipt on disk for chain head %d", obs.snap.ChainSeq-1))
	case errors.Is(err, errReceiptTailCorrupt):
		h.setTail(obs, metrics.EvidenceSelfAuditFailed, err.Error())
		h.fail("sampler_error", fmt.Errorf("chain %s: %w", obs.session, err))
	case errors.Is(err, errReceiptTailBeyondBound):
		h.setTail(obs, metrics.EvidenceSelfAuditPending, err.Error())
	case errors.Is(err, errReceiptTailChanged):
		// The file shrank during the read (appends are tolerated). Not
		// proof of corruption, but the chain is unverified.
		h.setTail(obs, metrics.EvidenceSelfAuditPending, err.Error())
	default:
		h.setTail(obs, metrics.EvidenceSelfAuditPending, err.Error())
		h.recordSamplerDegraded(fmt.Errorf("chain %s: %w", obs.session, err))
	}
}

// setTail records a conclusive state. A failed chain stays failed for the
// process lifetime, matching the selfaudit_ok latch.
func (h *evidenceHealthMonitor) setTail(obs shardObservation, state, detail string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if prev, ok := h.tails[obs.session]; ok && prev.state == metrics.EvidenceSelfAuditFailed {
		return
	}
	h.tails[obs.session] = shardTailState{emitter: obs.emitter, state: state, detail: detail}
}

func (h *evidenceHealthMonitor) tailState(obs shardObservation) shardTailState {
	h.mu.Lock()
	defer h.mu.Unlock()
	state, ok := h.tails[obs.session]
	if !ok || (state.emitter != obs.emitter && state.state != metrics.EvidenceSelfAuditFailed) {
		return shardTailState{state: metrics.EvidenceSelfAuditPending, detail: "chain not yet verified"}
	}
	return state
}

func (h *evidenceHealthMonitor) refreshAnchor() {
	if h.recorder == nil || h.recorder.Dir() == "" {
		h.clearAnchors()
		return
	}
	shards := h.observeShards()
	live := make(map[string]bool, len(shards))
	for _, obs := range shards {
		live[obs.session] = true
		h.refreshShardAnchor(obs)
	}
	h.mu.Lock()
	for session := range h.anchors {
		if !live[session] {
			delete(h.anchors, session)
		}
	}
	h.mu.Unlock()
}

// refreshShardAnchor reads the anchor marker for one chain's own session and
// measures lag against that chain's own head and signer.
func (h *evidenceHealthMonitor) refreshShardAnchor(obs shardObservation) {
	e, snap, session := obs.emitter, obs.snap, obs.session
	state, found, skipped, err := readAnchorStateForSessionWithSkipped(h.recorder.Dir(), session)
	if skipped > 0 && h.metrics != nil {
		h.metrics.RecordEvidenceAnchorStateSkipped(skipped)
	}
	if err != nil {
		h.setAnchor(session, nil)
		var pathErr *fs.PathError
		if errors.As(err, &pathErr) {
			// Reading the markers failed (permissions, a transient I/O
			// error). That is a measurement gap, not evidence of a forged
			// or conflicting anchor, so it must not latch.
			h.recordSamplerDegraded(fmt.Errorf("chain %s anchor state: %w", session, err))
			return
		}
		h.fail("sampler_error", err)
		return
	}
	if !found {
		h.setAnchor(session, nil)
		return
	}
	// The anchor loop runs independently and may have anchored receipts
	// written after obs was taken. Judge the marker against the current head
	// of the same writer.
	if fresh, current := h.stillCurrent(obs); current {
		snap = fresh
	} else {
		return
	}
	if state.Schema != "pipelock.anchorstate.v1" {
		h.fail("sampler_error", fmt.Errorf("anchor-state schema %q is invalid", state.Schema))
		h.setAnchor(session, nil)
		return
	}
	if state.SessionID != session {
		h.fail("sampler_error", fmt.Errorf("anchor-state session_id %q does not match %q", state.SessionID, session))
		h.setAnchor(session, nil)
		return
	}
	if err := validateAnchorStateMarker(state, time.Now().UTC()); err != nil {
		h.fail("sampler_error", err)
		h.setAnchor(session, nil)
		return
	}
	if (state.SignerKey == "" || state.SignerKey == e.SignerKeyHex()) && state.FinalSeq >= snap.ChainSeq {
		h.fail("sampler_error", fmt.Errorf("anchor-state final_seq %d is ahead of chain_head_seq %d", state.FinalSeq, snap.ChainSeq))
		h.setAnchor(session, nil)
		return
	}
	if current := h.anchorFor(session); current != nil && state.ReceiptCount == 0 && state.FinalSeq < current.FinalSeq {
		return
	}
	lag := uint64(0)
	if state.SignerKey != "" && state.SignerKey != e.SignerKeyHex() {
		lag = snap.ChainSeq
	} else if snap.ChainSeq > state.FinalSeq+1 {
		lag = snap.ChainSeq - state.FinalSeq - 1
	}
	anchoredAt := state.AnchoredAt.UTC()
	h.setAnchor(session, &metrics.EvidenceAnchorStats{
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
	})
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
	shards := h.observeShards()
	if len(shards) == 0 {
		return metrics.EvidenceHealthStats{}, false
	}
	head := shards[0]
	if process := h.emitter(); process != nil {
		for _, obs := range shards {
			if obs.emitter == process {
				head = obs
				break
			}
		}
	}
	autoAnchor := h.metrics.EvidenceAutoAnchorStatsSnapshot()
	maxLag := cfg.FlightRecorder.EvidenceMaxAnchorLagDuration()
	autoAnchorHealthy := !cfg.FlightRecorder.AnchorConfigured() || autoAnchor.LastError == ""
	selfAuditOK := h.selfAuditOK.Load()

	emitterHealthy, heartbeats, anchoringFresh := true, true, true
	selfAuditState := metrics.EvidenceSelfAuditVerified
	var newestEmit time.Time
	var stalest *metrics.EvidenceAnchorStats
	var anchorLag uint64
	shardHealth := make([]metrics.EvidenceShardHealth, 0, len(shards))
	for _, obs := range shards {
		healthy := !obs.snap.InitErr && obs.healthErr == nil
		emitterHealthy = emitterHealthy && healthy
		heartbeats = heartbeats && obs.snap.HeartbeatObserved
		if obs.snap.LastEmit.After(newestEmit) {
			newestEmit = obs.snap.LastEmit
		}
		tail := h.tailState(obs)
		selfAuditState = worseSelfAuditState(selfAuditState, tail.state)
		anchor := h.anchorFor(obs.session)
		lag := obs.snap.ChainSeq
		var anchoredSeq *uint64
		if anchor == nil {
			anchoringFresh = false
		} else {
			lag = anchor.LagReceipts
			seq := anchor.FinalSeq
			anchoredSeq = &seq
			if !autoAnchorHealthy || (maxLag != 0 && time.Since(time.Unix(0, int64(anchor.LastTimestampSeconds*1e9))) > maxLag) {
				anchoringFresh = false
			}
			if stalest == nil || anchor.LastTimestampSeconds < stalest.LastTimestampSeconds {
				stalest = anchor
			}
		}
		if lag > anchorLag {
			anchorLag = lag
		}
		shardHealth = append(shardHealth, metrics.EvidenceShardHealth{
			ShardIndex: obs.index, SessionID: obs.session, ChainHeadSeq: obs.snap.ChainSeq,
			EmitterHealthy: healthy, TailState: tail.state, TailDetail: tail.detail,
			AnchoredFinalSeq: anchoredSeq, AnchorLagReceipts: lag,
		})
	}
	if !selfAuditOK {
		selfAuditState = metrics.EvidenceSelfAuditFailed
	}
	// A chain without any anchor makes the set unanchored; report no single
	// chain's marker as if it covered the others.
	var anchor *metrics.EvidenceAnchorStats
	if allShardsAnchored(shardHealth) {
		anchor = stalest
	}
	lastAnchor := 0.0
	if anchor != nil {
		lastAnchor = anchor.LastTimestampSeconds
	}
	requirements := map[string]bool{
		metrics.EvidenceRequirementRecorderEnabled: true,
		metrics.EvidenceRequirementEmitterHealthy:  emitterHealthy,
		metrics.EvidenceRequirementDurabilityGate:  cfg.FlightRecorder.RequireReceipts,
		// This is an observation, not a statement about the configured cadence.
		// A fresh process remains pending (false) until its first heartbeat is
		// recorded on every chain. No runtime alert consumes this deprecated
		// diagnostic requirement, so cold start cannot page solely because its
		// first timer tick has not happened yet.
		metrics.EvidenceRequirementHeartbeats:     heartbeats,
		metrics.EvidenceRequirementAnchoringFresh: anchoringFresh,
		metrics.EvidenceRequirementCPCActive:      false,
		metrics.EvidenceRequirementSelfAuditOK:    selfAuditOK,
	}
	ageSeconds := (*float64)(nil)
	if !newestEmit.IsZero() {
		age := time.Since(newestEmit).Seconds()
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
		SelfAuditPending: selfAuditState == metrics.EvidenceSelfAuditPending,
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
		ChainHeadSeq:               head.snap.ChainSeq,
		ChainHeadAgeSeconds:        ageSeconds,
		HeartbeatIntervalSeconds:   &hbi,
		SequenceGaps:               gapStats,
		FsyncErrors:                fsyncStats,
		Files:                      fileStats,
		DurabilityBlocks:           durabilityBlocks,
		DurabilityInvariantOK:      selfAuditOK && gatedFsync >= durabilityBlocks,
		Anchor:                     anchor,
		AutoAnchor:                 autoAnchor,
		TornTails:                  h.metrics.EvidenceTornTailSnapshot(),
		SelfAudit:                  metrics.EvidenceSelfAuditStats{State: selfAuditState, Shards: shardHealth},
		CPC:                        nil,
		AnchoredFinalSeq:           anchoredFinalSeq(anchor),
		AnchorLagReceipts:          anchorLag,
		LastAnchorTimestampSeconds: lastAnchor,
	}, true
}

func allShardsAnchored(shards []metrics.EvidenceShardHealth) bool {
	for _, shard := range shards {
		if shard.AnchoredFinalSeq == nil {
			return false
		}
	}
	return true
}

var selfAuditStateRank = map[string]int{
	metrics.EvidenceSelfAuditVerified: 0,
	metrics.EvidenceSelfAuditPending:  1,
	metrics.EvidenceSelfAuditFailed:   2,
}

func worseSelfAuditState(a, b string) string {
	if selfAuditStateRank[b] > selfAuditStateRank[a] {
		return b
	}
	return a
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

func (h *evidenceHealthMonitor) setAnchor(session string, anchor *metrics.EvidenceAnchorStats) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if anchor == nil {
		delete(h.anchors, session)
		return
	}
	h.anchors[session] = anchor
}

func (h *evidenceHealthMonitor) clearAnchors() {
	h.mu.Lock()
	defer h.mu.Unlock()
	clear(h.anchors)
}

func (h *evidenceHealthMonitor) anchorFor(session string) *metrics.EvidenceAnchorStats {
	h.mu.Lock()
	defer h.mu.Unlock()
	anchor := h.anchors[session]
	if anchor == nil {
		return nil
	}
	cp := *anchor
	return &cp
}

// anchorSnapshot returns the anchor reported for the process chain.
func (h *evidenceHealthMonitor) anchorSnapshot() *metrics.EvidenceAnchorStats {
	return h.anchorFor(h.sessionFor(h.emitter()))
}

// sessionFor names the recorder session a chain writes. An emitter built
// without an explicit session records under the recorder's own binding.
func (h *evidenceHealthMonitor) sessionFor(e *receipt.Emitter) string {
	if session := e.Session(); session != "" {
		return session
	}
	return recorderSessionOf(h.recorder)
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
	seq     uint64
	hash    string
	receipt receipt.Receipt
}

var (
	errNoReceiptTail = errors.New("no action receipt tail")
	// errReceiptTailCorrupt marks evidence that is provably malformed: a
	// complete line that does not parse, a receipt that cannot be hashed, or
	// an ambiguous shard set. It is a finding, not a measurement failure.
	errReceiptTailCorrupt = errors.New("receipt tail is malformed")
	// errReceiptTailChanged is a concurrent append to the file being read.
	errReceiptTailChanged = errors.New("receipt tail changed during read")
	// errReceiptTailBeyondBound means the last action receipt lies further
	// back than the self-audit reads. The chain is unverified, not broken.
	errReceiptTailBeyondBound = errors.New("receipt tail is beyond the self-audit read bound")
)

func readLastReceiptTail(dir, sessionID string) (receiptTail, error) {
	// A glob of "evidence-<session>-*.jsonl" has the same hole prefix matching
	// did: for session "s" it also matches "evidence-s-evil-999.jsonl", which
	// belongs to session "s-evil", and that file sorts highest so the reported
	// tail would come from another session. Enumerate and compare the parsed
	// session instead.
	clean := filepath.Clean(dir)
	wantSession := filepath.Base(sessionID)
	if _, statErr := os.Stat(clean); statErr != nil {
		if errors.Is(statErr, fs.ErrNotExist) {
			return receiptTail{}, errNoReceiptTail
		}
		return receiptTail{}, fmt.Errorf("stat evidence directory: %w", statErr)
	}
	location, resolveErr := recorder.ResolveEvidenceLocation(dir, "")
	if resolveErr != nil {
		return receiptTail{}, fmt.Errorf("resolve evidence location: %w", resolveErr)
	}
	dirEntries, err := recorder.ReadEvidenceLocationEntries(location)
	if err != nil {
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
		files = append(files, de.Name())
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
		return receiptTail{}, fmt.Errorf("%w: %w", errReceiptTailCorrupt, err)
	}
	// Fall back to an older file only when the newer file was read whole and
	// holds no action receipt (a rotation can open a file holding only paired
	// decision entries). readLastReceiptTailFromFile returns errNoReceiptTail
	// only after reading a file whole, so a partially read newer file never
	// lets its predecessor's last receipt pose as the chain head.
	for i := len(files) - 1; i >= 0; i-- {
		tail, err := readLastReceiptTailFromFile(location, files[i])
		if err == nil {
			return tail, nil
		}
		if !errors.Is(err, errNoReceiptTail) {
			return receiptTail{}, err
		}
	}
	return receiptTail{}, errNoReceiptTail
}

// readLastReceiptTailFromFile finds the file's last action receipt, widening
// the read from maxTailReadBytes up to maxTailScanBytes so a valid receipt as
// large as the recorder's entry limit is still found.
func readLastReceiptTailFromFile(location recorder.EvidenceLocation, name string) (receiptTail, error) {
	for window := int64(maxTailReadBytes); ; window *= 2 {
		window = min(window, maxTailScanBytes)
		data, truncated, err := recorder.ReadEvidenceLocationAppendTail(location, name, window)
		if err != nil {
			if errors.Is(err, recorder.ErrEvidenceFileChanged) {
				return receiptTail{}, fmt.Errorf("%w: %s", errReceiptTailChanged, name)
			}
			return receiptTail{}, err
		}
		tail, found, err := lastReceiptInTail(data, truncated)
		if err != nil || found {
			return tail, err
		}
		if !truncated {
			return receiptTail{}, errNoReceiptTail
		}
		if window == maxTailScanBytes {
			return receiptTail{}, fmt.Errorf("%w: no action receipt in the last %d bytes of %s", errReceiptTailBeyondBound, maxTailScanBytes, name)
		}
	}
}

// lastReceiptInTail scans complete lines newest first. When the read began
// mid-file the first segment may be a fragment and is dropped; a final
// segment without its newline is an append still in progress and is dropped
// too, so neither is reported as corrupt evidence.
func lastReceiptInTail(data []byte, truncated bool) (receiptTail, bool, error) {
	if truncated {
		idx := bytes.IndexByte(data, '\n')
		if idx < 0 {
			return receiptTail{}, false, nil
		}
		data = data[idx+1:]
	}
	end := bytes.LastIndexByte(data, '\n')
	if end < 0 {
		return receiptTail{}, false, nil
	}
	lines := splitNonEmptyLines(data[:end])
	for i := len(lines) - 1; i >= 0; i-- {
		tail, ok, err := parseReceiptTailLine(lines[i])
		if err != nil {
			return receiptTail{}, false, fmt.Errorf("%w: %w", errReceiptTailCorrupt, err)
		}
		if ok {
			return tail, true, nil
		}
	}
	return receiptTail{}, false, nil
}

func splitNonEmptyLines(data []byte) [][]byte {
	var lines [][]byte
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) > 0 {
			lines = append(lines, line)
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
	return receiptTail{seq: rcpt.ActionRecord.ChainSeq, hash: hash, receipt: rcpt}, true, nil
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
