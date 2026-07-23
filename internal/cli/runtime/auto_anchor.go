// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	anchorpkg "github.com/luckyPipewrench/pipelock/internal/anchor"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const (
	autoAnchorPollCadence = 30 * time.Second
	autoAnchorBundleDir   = "anchor-bundles"
)

var autoAnchorPollCadenceOverride atomic.Int64

type autoAnchorMonitor struct {
	recorder  *recorder.Recorder
	metrics   *metrics.Metrics
	emitterFn func() *receipt.Emitter
	configFn  func() *config.Config
	logW      io.Writer
	nowFn     func() time.Time
	backendFn func(config.FlightRecorderAnchor) (anchorpkg.Backend, error)
	extractFn func(string, string) ([]receipt.Receipt, error)
	sessionID string

	mu                   sync.Mutex
	seeded               bool
	hasLastAnchor        bool
	lastAnchoredAt       time.Time
	lastFinalSeq         uint64
	lastReceiptCount     uint64
	observedChainSeq     uint64
	observedReceiptCount uint64
	forceAnchor          bool

	// pending retains a checkpoint that was accepted by the backend but whose
	// local bundle/marker persistence has not yet completed. It lets a later
	// pass retry only the local write for the identical head instead of
	// resubmitting to the transparency log, which would spam the log, burn
	// rate limits, and create duplicate anchors.
	pending           bool
	pendingCheckpoint anchorpkg.Checkpoint
	pendingProof      anchorpkg.Proof

	// anchorInFlight serializes the submit/reuse decision so the pending-dedup
	// check-then-act cannot be split by a second caller. The production loop is
	// single-goroutine, so this is uncontended today; it keeps the dedup correct
	// by construction if a future change ever runs anchor passes concurrently,
	// without holding mu across the backend network call.
	anchorInFlight bool
}

func newAutoAnchorMonitor(
	rec *recorder.Recorder,
	m *metrics.Metrics,
	emitterFn func() *receipt.Emitter,
	configFn func() *config.Config,
	logW io.Writer,
) *autoAnchorMonitor {
	return &autoAnchorMonitor{
		recorder:  rec,
		metrics:   m,
		emitterFn: emitterFn,
		configFn:  configFn,
		logW:      logW,
		nowFn:     func() time.Time { return time.Now().UTC() },
		backendFn: autoAnchorBackend,
		extractFn: receipt.ExtractReceiptsFromSessionDir,
		sessionID: transcriptRootSessionID,
	}
}

func (m *autoAnchorMonitor) start(ctx context.Context, wg *sync.WaitGroup) {
	if m == nil || wg == nil {
		return
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.runPass()
		timer := time.NewTimer(autoAnchorPollInterval())
		defer timer.Stop()
		for {
			select {
			case <-timer.C:
				m.runPass()
				timer.Reset(autoAnchorPollInterval())
			case <-ctx.Done():
				return
			}
		}
	}()
}

func autoAnchorPollInterval() time.Duration {
	if override := time.Duration(autoAnchorPollCadenceOverride.Load()); override > 0 {
		return override
	}
	return autoAnchorPollCadence
}

// setAutoAnchorPollIntervalForTest replaces the fixed production cadence and
// returns a restore function. It is process-global and must not be used from
// parallel tests.
func setAutoAnchorPollIntervalForTest(interval time.Duration) (restore func()) {
	previous := autoAnchorPollCadenceOverride.Swap(int64(interval))
	return func() { autoAnchorPollCadenceOverride.Store(previous) }
}

func (m *autoAnchorMonitor) runPass() {
	defer func() {
		if recovered := recover(); recovered != nil {
			m.fail(fmt.Errorf("panic in auto-anchor pass: %v", recovered))
		}
	}()
	if m == nil || m.configFn == nil || m.recorder == nil || m.recorder.Dir() == "" {
		return
	}
	cfg := m.configFn()
	if cfg == nil || !cfg.FlightRecorder.AnchorConfigured() {
		return
	}
	emitter := m.emitter()
	snapshot, ok := emitter.HealthSnapshot()
	if !ok || snapshot.InitErr || snapshot.ChainSeq == 0 {
		return
	}
	now := m.now()
	if err := m.seed(now, snapshot, emitter.SignerKeyHex()); err != nil {
		m.fail(err)
		return
	}
	currentReceiptCount, err := m.observe(snapshot.ChainSeq)
	if err != nil {
		m.fail(err)
		return
	}
	shouldAnchor, newReceipts, err := m.triggered(cfg.FlightRecorder, currentReceiptCount, now)
	if err != nil {
		m.fail(err)
		return
	}
	if !shouldAnchor || newReceipts == 0 {
		return
	}
	if m.metrics != nil {
		m.metrics.RecordEvidenceAutoAnchorAttempt()
	}
	if err := m.anchor(cfg.FlightRecorder.Anchor, emitter); err != nil {
		m.fail(err)
	}
}

func (m *autoAnchorMonitor) seed(now time.Time, snapshot receipt.HealthSnapshot, currentSignerKey string) error {
	m.mu.Lock()
	if m.seeded {
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()

	state, found, skipped, err := readAnchorStateForSessionWithSkipped(m.recorder.Dir(), m.sessionID)
	if skipped > 0 && m.metrics != nil {
		m.metrics.RecordEvidenceAnchorStateSkipped(skipped)
	}
	if err != nil {
		return fmt.Errorf("seed auto-anchor state: %w", err)
	}
	if found {
		if state.Schema != "pipelock.anchorstate.v1" {
			return fmt.Errorf("seed auto-anchor state: schema %q is invalid", state.Schema)
		}
		if err := validateAnchorStateMarker(state, now); err != nil {
			return fmt.Errorf("seed auto-anchor state: %w", err)
		}
		checkpoint, loadErr := loadAutoAnchorCheckpoint(m.recorder.Dir(), state)
		if loadErr != nil {
			return fmt.Errorf("seed auto-anchor state: %w", loadErr)
		}
		if len(checkpoint.SignerKeys) == 0 {
			return errors.New("seed auto-anchor state: anchor checkpoint has no signer keys")
		}
		state.ReceiptCount = checkpoint.ReceiptCount
		state.SignerKey = checkpoint.SignerKeys[len(checkpoint.SignerKeys)-1]
		receipts, extractErr := m.extractFn(m.recorder.Dir(), m.sessionID)
		if extractErr != nil {
			return fmt.Errorf("seed auto-anchor state: extract receipt chain: %w", extractErr)
		}
		if err := validateAutoAnchorSeedState(state, receipts, currentSignerKey); err != nil {
			return fmt.Errorf("seed auto-anchor state: %w", err)
		}
		if state.SignerKey == "" || state.SignerKey == currentSignerKey {
			if state.FinalSeq >= snapshot.ChainSeq {
				return fmt.Errorf("seed auto-anchor state: final_seq %d is ahead of chain sequence %d", state.FinalSeq, snapshot.ChainSeq)
			}
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seeded {
		return nil
	}
	m.seeded = true
	m.observedChainSeq = snapshot.ChainSeq
	m.observedReceiptCount = snapshot.ChainSeq
	if found {
		m.hasLastAnchor = true
		m.lastFinalSeq = state.FinalSeq
		m.lastAnchoredAt = state.AnchoredAt.UTC()
		if state.ReceiptCount > 0 {
			m.lastReceiptCount = state.ReceiptCount
			m.observedReceiptCount = state.ReceiptCount
			if state.SignerKey == currentSignerKey {
				m.observedReceiptCount, err = addAutoAnchorReceiptCount(m.observedReceiptCount, snapshot.ChainSeq-state.FinalSeq-1)
			} else {
				// Receipt sequence numbers restart at zero after a signer rotation.
				// The exact total is recovered from the checkpoint built below; force
				// one immediate anchor so intermediate rotated segments cannot be
				// undercounted by a threshold trigger.
				m.observedReceiptCount, err = addAutoAnchorReceiptCount(m.observedReceiptCount, snapshot.ChainSeq)
				m.forceAnchor = true
			}
			if err != nil {
				m.seeded = false
				return fmt.Errorf("seed auto-anchor state: %w", err)
			}
		} else {
			m.lastReceiptCount, err = addAutoAnchorReceiptCount(state.FinalSeq, 1)
			if err != nil {
				m.seeded = false
				return fmt.Errorf("seed auto-anchor state: %w", err)
			}
		}
	}
	return nil
}

func (m *autoAnchorMonitor) observe(chainSeq uint64) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if chainSeq < m.observedChainSeq {
		return 0, fmt.Errorf("live receipt chain sequence regressed from %d to %d", m.observedChainSeq, chainSeq)
	}
	observed, err := addAutoAnchorReceiptCount(m.observedReceiptCount, chainSeq-m.observedChainSeq)
	if err != nil {
		return 0, err
	}
	m.observedReceiptCount = observed
	m.observedChainSeq = chainSeq
	return m.observedReceiptCount, nil
}

func addAutoAnchorReceiptCount(current, delta uint64) (uint64, error) {
	if delta > math.MaxUint64-current {
		return 0, errors.New("auto-anchor receipt count overflow")
	}
	return current + delta, nil
}

func (m *autoAnchorMonitor) triggered(fr config.FlightRecorder, receiptCount uint64, now time.Time) (bool, uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	newReceipts := receiptCount
	if m.hasLastAnchor {
		if m.lastReceiptCount > receiptCount {
			return false, 0, fmt.Errorf("auto-anchor in-memory receipt count %d is ahead of observed count %d", m.lastReceiptCount, receiptCount)
		}
		if m.lastReceiptCount == receiptCount {
			return false, 0, nil
		}
		newReceipts = receiptCount - m.lastReceiptCount
	}
	if newReceipts == 0 {
		return false, 0, nil
	}
	if !m.hasLastAnchor {
		return true, newReceipts, nil
	}
	if m.forceAnchor {
		return true, newReceipts, nil
	}
	interval := fr.AnchorIntervalDuration()
	intervalDue := interval > 0 && !now.Before(m.lastAnchoredAt.Add(interval))
	threshold := fr.AnchorReceiptThreshold()
	thresholdDue := threshold > 0 && newReceipts >= threshold
	return intervalDue || thresholdDue, newReceipts, nil
}

func (m *autoAnchorMonitor) anchor(anchorCfg config.FlightRecorderAnchor, emitter *receipt.Emitter) error {
	receipts, err := m.extractFn(m.recorder.Dir(), m.sessionID)
	if err != nil {
		return fmt.Errorf("extract live receipt chain: %w", err)
	}
	trustedKeys, err := autoAnchorTrustedKeys(receipts, emitter.SignerKeyHex())
	if err != nil {
		return err
	}
	checkpoint, err := anchorpkg.BuildCheckpoint(m.sessionID, receipts, trustedKeys)
	if err != nil {
		return fmt.Errorf("build live receipt checkpoint: %w", err)
	}
	if len(checkpoint.SignerKeys) == 0 {
		return errors.New("live receipt checkpoint has no signer keys")
	}
	if !m.checkpointAdvanced(checkpoint.ReceiptCount) {
		return errors.New("live receipt checkpoint did not advance beyond the last anchored sequence")
	}
	proof, skipped, err := m.submitOrReusePending(anchorCfg, checkpoint)
	if err != nil {
		return err
	}
	if skipped {
		// Another submission for this monitor is already in flight; a concurrent
		// pass must not submit or persist the same head a second time.
		return nil
	}
	bundleRel := filepath.ToSlash(filepath.Join(autoAnchorBundleDir, fmt.Sprintf("anchor-proxy-%d-%d-%.12s.json", checkpoint.ReceiptCount, checkpoint.FinalSeq, checkpoint.RootHash)))
	bundleBytes, err := anchorpkg.WriteBundleUnderDir(m.recorder.Dir(), bundleRel, anchorpkg.NewBundle(checkpoint, proof))
	if err != nil {
		return fmt.Errorf("write live anchor bundle: %w", err)
	}
	bundleSum := sha256.Sum256(bundleBytes)
	anchoredAt := m.now()
	if err := anchorpkg.WriteStateMarker(m.recorder.Dir(), anchorpkg.StateMarker{
		SessionID:    checkpoint.SessionID,
		FinalSeq:     checkpoint.FinalSeq,
		RootHash:     checkpoint.RootHash,
		Backend:      proof.Backend,
		LogIndex:     proof.LogIndex,
		AnchoredAt:   anchoredAt,
		BundleSHA256: hex.EncodeToString(bundleSum[:]),
		BundlePath:   bundleRel,
		ReceiptCount: checkpoint.ReceiptCount,
		SignerKey:    checkpoint.SignerKeys[len(checkpoint.SignerKeys)-1],
	}); err != nil {
		return fmt.Errorf("write live anchor state: %w", err)
	}
	m.mu.Lock()
	m.pending = false
	m.pendingCheckpoint = anchorpkg.Checkpoint{}
	m.pendingProof = anchorpkg.Proof{}
	m.seeded = true
	m.hasLastAnchor = true
	m.lastFinalSeq = checkpoint.FinalSeq
	m.lastReceiptCount = checkpoint.ReceiptCount
	m.observedChainSeq = checkpoint.FinalSeq + 1
	m.observedReceiptCount = checkpoint.ReceiptCount
	m.forceAnchor = false
	m.lastAnchoredAt = anchoredAt
	m.mu.Unlock()
	if m.metrics != nil {
		m.metrics.RecordEvidenceAutoAnchorSuccess()
	}
	return nil
}

// submitOrReusePending submits the checkpoint to the anchor backend, or reuses
// the proof from a prior pass whose backend submission succeeded but whose local
// bundle/marker persistence failed. Reuse prevents a persistence failure from
// resubmitting an identical head to the transparency log, which would spam the
// log and create duplicate anchors. The freshly returned proof is verified
// before it is retained.
func (m *autoAnchorMonitor) submitOrReusePending(anchorCfg config.FlightRecorderAnchor, checkpoint anchorpkg.Checkpoint) (anchorpkg.Proof, bool, error) {
	m.mu.Lock()
	if m.pending &&
		m.pendingCheckpoint.ReceiptCount == checkpoint.ReceiptCount &&
		m.pendingCheckpoint.RootHash == checkpoint.RootHash &&
		m.pendingCheckpoint.FinalSeq == checkpoint.FinalSeq {
		proof := m.pendingProof
		m.mu.Unlock()
		return proof, false, nil
	}
	if m.anchorInFlight {
		m.mu.Unlock()
		return anchorpkg.Proof{}, true, nil
	}
	m.anchorInFlight = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.anchorInFlight = false
		m.mu.Unlock()
	}()

	backend, err := m.backendFn(anchorCfg)
	if err != nil {
		return anchorpkg.Proof{}, false, fmt.Errorf("configure auto-anchor backend: %w", err)
	}
	proof, err := backend.Submit(checkpoint)
	if err != nil {
		return anchorpkg.Proof{}, false, fmt.Errorf("submit live receipt checkpoint: %w", err)
	}
	if err := verifyAutoAnchorProof(backend, proof, checkpoint); err != nil {
		return anchorpkg.Proof{}, false, fmt.Errorf("verify live receipt anchor proof: %w", err)
	}
	m.mu.Lock()
	m.pending = true
	m.pendingCheckpoint = checkpoint
	m.pendingProof = proof
	m.mu.Unlock()
	return proof, false, nil
}

// verifyAutoAnchorProof checks a freshly returned anchor proof before it is
// persisted, so a misconfigured or buggy backend that returns a syntactically
// accepted but invalid proof cannot make the chain look anchored. The local
// backend verifies deterministically. A Rekor submission is witnessed
// independently by the offline verifier against the log's public key, which the
// runtime does not hold, so it is recorded without an immediate
// self-verification (the documented submit-and-audit-offline model).
func verifyAutoAnchorProof(backend anchorpkg.Backend, proof anchorpkg.Proof, checkpoint anchorpkg.Checkpoint) error {
	if local, ok := backend.(anchorpkg.LocalLog); ok {
		return local.Verify(proof, checkpoint)
	}
	return nil
}

func (m *autoAnchorMonitor) checkpointAdvanced(receiptCount uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return !m.hasLastAnchor || receiptCount > m.lastReceiptCount
}

func loadAutoAnchorCheckpoint(dir string, state anchorState) (anchorpkg.Checkpoint, error) {
	return anchorpkg.LoadStateMarkerCheckpoint(dir, anchorpkg.StateMarker{
		Schema:       state.Schema,
		SessionID:    state.SessionID,
		FinalSeq:     state.FinalSeq,
		RootHash:     state.RootHash,
		Backend:      state.Backend,
		LogIndex:     state.LogIndex,
		AnchoredAt:   state.AnchoredAt,
		BundleSHA256: state.BundleSHA256,
		BundlePath:   state.BundlePath,
		ReceiptCount: state.ReceiptCount,
		SignerKey:    state.SignerKey,
	})
}

func validateAutoAnchorSeedState(state anchorState, receipts []receipt.Receipt, currentSignerKey string) error {
	if state.ReceiptCount == 0 {
		return errors.New("auto-anchor checkpoint receipt_count is zero")
	}
	if state.ReceiptCount > uint64(len(receipts)) {
		return fmt.Errorf("auto-anchor checkpoint receipt_count %d is ahead of live chain count %d", state.ReceiptCount, len(receipts))
	}
	trustedKeys, err := autoAnchorTrustedKeys(receipts, currentSignerKey)
	if err != nil {
		return err
	}
	checkpoint, err := anchorpkg.BuildCheckpoint(state.SessionID, receipts[:state.ReceiptCount], trustedKeys)
	if err != nil {
		return fmt.Errorf("rebuild auto-anchor checkpoint: %w", err)
	}
	if checkpoint.FinalSeq != state.FinalSeq || checkpoint.RootHash != state.RootHash || checkpoint.ReceiptCount != state.ReceiptCount {
		return errors.New("auto-anchor checkpoint does not match the live receipt chain")
	}
	return nil
}

func (m *autoAnchorMonitor) emitter() *receipt.Emitter {
	if m == nil || m.emitterFn == nil {
		return nil
	}
	return m.emitterFn()
}

func (m *autoAnchorMonitor) now() time.Time {
	if m != nil && m.nowFn != nil {
		return m.nowFn().UTC()
	}
	return time.Now().UTC()
}

func (m *autoAnchorMonitor) fail(err error) {
	if err == nil {
		return
	}
	if m != nil && m.metrics != nil {
		m.metrics.RecordEvidenceAutoAnchorFailure(err.Error())
	}
	if m != nil && m.logW != nil {
		_, _ = fmt.Fprintf(m.logW, "CRITICAL: evidence auto-anchor failed: %v\n", err)
	}
}

func autoAnchorTrustedKeys(receipts []receipt.Receipt, currentSignerKey string) ([]string, error) {
	if len(receipts) == 0 {
		return nil, errors.New("refuse auto-anchor: live receipt chain is empty")
	}
	if currentSignerKey == "" {
		return nil, errors.New("refuse auto-anchor: live receipt emitter signer key is unavailable")
	}
	finalSignerKey := receipts[len(receipts)-1].SignerKey
	if finalSignerKey != currentSignerKey {
		return nil, fmt.Errorf("refuse auto-anchor: receipt chain head signer %q does not match live emitter signer", finalSignerKey)
	}
	// The live emitter key is the only out-of-band trust anchor available to
	// the runtime. Walk the chain backward and admit a predecessor only when a
	// receipt signed by the already-trusted successor carries the transition.
	// Promoting every key merely present in the file would let a forged or
	// grafted segment enter the trusted set before structural verification.
	seen := map[string]struct{}{currentSignerKey: {}}
	trustedKeys := make([]string, 0, 1)
	trustedKeys = append(trustedKeys, currentSignerKey)
	expectedKey := currentSignerKey
	for i := len(receipts) - 1; i >= 0; i-- {
		rcpt := receipts[i]
		if rcpt.SignerKey != expectedKey {
			return nil, fmt.Errorf("refuse auto-anchor: receipt signer %q is not authorized by the live head", rcpt.SignerKey)
		}
		if err := receipt.VerifyWithKey(rcpt, expectedKey); err != nil {
			return nil, fmt.Errorf("refuse auto-anchor: verify receipt under backward trust: %w", err)
		}
		transition := rcpt.ActionRecord.KeyTransition
		if transition == nil {
			continue
		}
		expectedKey = transition.PriorSignerKey
		if _, ok := seen[expectedKey]; ok {
			continue
		}
		seen[expectedKey] = struct{}{}
		trustedKeys = append(trustedKeys, expectedKey)
	}
	return trustedKeys, nil
}

func autoAnchorBackend(anchorCfg config.FlightRecorderAnchor) (anchorpkg.Backend, error) {
	rekorURL := strings.TrimSpace(anchorCfg.RekorURL)
	localLog := strings.TrimSpace(anchorCfg.LocalLog)
	switch {
	case rekorURL != "" && localLog != "":
		return nil, errors.New("rekor_url and local_log are mutually exclusive")
	case rekorURL != "":
		key, err := anchorpkg.LoadRekorPrivateKey(strings.TrimSpace(anchorCfg.RekorKeyPath))
		if err != nil {
			return nil, err
		}
		return anchorpkg.RekorLog{
			URL:           rekorURL,
			Signer:        key,
			HashAlgorithm: anchorpkg.DefaultRekorHashAlgorithm,
		}, nil
	case localLog != "":
		return anchorpkg.LocalLog{Path: localLog, LogID: strings.TrimSpace(anchorCfg.LogID)}, nil
	default:
		return nil, errors.New("anchor point is not configured")
	}
}
