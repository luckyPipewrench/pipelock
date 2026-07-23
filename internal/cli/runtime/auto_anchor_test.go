// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	anchorpkg "github.com/luckyPipewrench/pipelock/internal/anchor"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

type countingAnchorBackend struct {
	submits  atomic.Int64
	onSubmit func()
}

func (b *countingAnchorBackend) Submit(anchorpkg.Checkpoint) (anchorpkg.Proof, error) {
	b.submits.Add(1)
	if b.onSubmit != nil {
		b.onSubmit()
	}
	return anchorpkg.Proof{Backend: anchorpkg.LocalBackend, LogID: "runtime-test-log"}, nil
}

func (*countingAnchorBackend) Verify(anchorpkg.Proof, anchorpkg.Checkpoint) error { return nil }

type errorAnchorBackend struct{ err error }

func (b errorAnchorBackend) Submit(anchorpkg.Checkpoint) (anchorpkg.Proof, error) {
	return anchorpkg.Proof{}, b.err
}

func (errorAnchorBackend) Verify(anchorpkg.Proof, anchorpkg.Checkpoint) error { return nil }

type autoAnchorTestRig struct {
	monitor  *autoAnchorMonitor
	metrics  *metrics.Metrics
	emitter  *receipt.Emitter
	recorder *recorder.Recorder
	cfg      *config.Config
	logs     *bytes.Buffer
	priv     ed25519.PrivateKey
}

func TestAutoAnchorFirstReceiptPersistsBundleMarkerAndMetrics(t *testing.T) {
	trig := newAutoAnchorTestRig(t)
	emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/first")

	trig.monitor.runPass()

	entries, err := anchorpkg.ReadLocalLog(trig.cfg.FlightRecorder.Anchor.LocalLog)
	if err != nil {
		t.Fatalf("ReadLocalLog: %v; stats=%+v stderr=%q", err, trig.metrics.EvidenceAutoAnchorStatsSnapshot(), trig.logs.String())
	}
	if len(entries) != 1 || entries[0].Checkpoint.ReceiptCount != 2 || entries[0].Checkpoint.FinalSeq != 1 {
		t.Fatalf("local anchor entries = %+v, want one first-receipt checkpoint", entries)
	}
	state, found, err := readAnchorStateForSession(trig.recorder.Dir())
	if err != nil || !found {
		t.Fatalf("readAnchorStateForSession = (%+v, %v, %v), want marker", state, found, err)
	}
	if state.FinalSeq != 1 || state.Backend != anchorpkg.LocalBackend {
		t.Fatalf("anchor state = %+v, want local final_seq 1", state)
	}
	if _, err := os.Stat(filepath.Join(trig.recorder.Dir(), filepath.FromSlash(state.BundlePath))); err != nil {
		t.Fatalf("anchor bundle missing: %v", err)
	}
	assertAutoAnchorStats(t, trig.metrics, 1, 1, 0, "")
	if trig.logs.Len() != 0 {
		t.Fatalf("unexpected auto-anchor stderr: %q", trig.logs.String())
	}
}

func TestAutoAnchorInertWithoutAnchorPoint(t *testing.T) {
	trig := newAutoAnchorTestRig(t)
	trig.cfg.FlightRecorder.Anchor = config.FlightRecorderAnchor{}
	emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/inert")

	trig.monitor.runPass()

	assertAutoAnchorStats(t, trig.metrics, 0, 0, 0, "")
	if matches, err := filepath.Glob(filepath.Join(trig.recorder.Dir(), "anchor-*")); err != nil || len(matches) != 0 {
		t.Fatalf("inert auto-anchor artifacts = %v, err=%v", matches, err)
	}
}

func TestAutoAnchorTriggersAreORedAndNeverRepeatAHead(t *testing.T) {
	trig := newAutoAnchorTestRig(t)
	trig.cfg.FlightRecorder.Anchor.Interval = "0"
	trig.cfg.FlightRecorder.Anchor.ReceiptThreshold = uint64Pointer(2)
	emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/one")
	trig.monitor.runPass()
	trig.monitor.runPass()
	emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/two")
	trig.monitor.runPass()
	emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/three")
	trig.monitor.runPass()
	trig.monitor.runPass()

	entries, err := anchorpkg.ReadLocalLog(trig.cfg.FlightRecorder.Anchor.LocalLog)
	if err != nil {
		t.Fatalf("ReadLocalLog: %v", err)
	}
	if len(entries) != 2 || entries[0].Checkpoint.FinalSeq != 1 || entries[1].Checkpoint.FinalSeq != 3 {
		t.Fatalf("threshold anchors = %+v, want final_seq 1 then 3", entries)
	}
	assertAutoAnchorStats(t, trig.metrics, 2, 2, 0, "")
}

func TestAutoAnchorSeedsStaleMarkerAcrossRestart(t *testing.T) {
	trig := newAutoAnchorTestRig(t)
	base := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	trig.monitor.nowFn = func() time.Time { return base }
	emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/before-restart")
	trig.monitor.runPass()
	emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/after-restart")

	restarted := newAutoAnchorMonitor(trig.recorder, trig.metrics, func() *receipt.Emitter { return trig.emitter }, func() *config.Config { return trig.cfg }, trig.logs)
	restarted.nowFn = func() time.Time { return base.Add(2 * time.Hour) }
	trig.cfg.FlightRecorder.Anchor.Interval = time.Hour.String()
	trig.cfg.FlightRecorder.Anchor.ReceiptThreshold = uint64Pointer(0)
	restarted.runPass()

	entries, err := anchorpkg.ReadLocalLog(trig.cfg.FlightRecorder.Anchor.LocalLog)
	if err != nil {
		t.Fatalf("ReadLocalLog: %v", err)
	}
	if len(entries) != 2 || entries[1].Checkpoint.FinalSeq != 2 {
		t.Fatalf("restart anchors = %+v, want stale marker followed by final_seq 2", entries)
	}
}

func TestAutoAnchorSkipsUnbackedMarkerAtNextUnwrittenSequence(t *testing.T) {
	trig := newAutoAnchorTestRig(t)
	emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/current-head")
	snapshot, ok := trig.emitter.HealthSnapshot()
	if !ok {
		t.Fatal("emitter health snapshot unavailable")
	}
	if err := anchorpkg.WriteStateMarker(trig.recorder.Dir(), anchorpkg.StateMarker{
		SessionID:    transcriptRootSessionID,
		FinalSeq:     snapshot.ChainSeq,
		RootHash:     strings.Repeat("a", 64),
		Backend:      anchorpkg.LocalBackend,
		AnchoredAt:   time.Now().UTC().Add(-time.Second),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   "manual-forged-ahead.json",
	}); err != nil {
		t.Fatalf("WriteStateMarker: %v", err)
	}

	trig.monitor.runPass()

	assertAutoAnchorStats(t, trig.metrics, 1, 1, 0, "")
}

func TestAutoAnchorRestartAfterKeyRotationUsesReceiptCountAndPreservesBundles(t *testing.T) {
	dir := t.TempDir()
	_, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey A: %v", err)
	}
	recA, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, MaxEntriesPerFile: 100, FileMode: 0o600}, nil, nil)
	if err != nil {
		t.Fatalf("recorder.New A: %v", err)
	}
	emitterA := receipt.NewEmitter(receipt.EmitterConfig{Recorder: recA, PrivKey: privA, ConfigHash: "rotation-a", Principal: "tester", Actor: "runtime-test"})
	if err := emitterA.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen A: %v", err)
	}
	for i := range 3 {
		emitAutoAnchorReceipt(t, emitterA, fmt.Sprintf("https://api.vendor.example/a-%d", i))
	}
	cfg := config.Defaults()
	cfg.FlightRecorder.Dir = dir
	cfg.FlightRecorder.Anchor.LocalLog = filepath.Join(dir, "rotated-restart-anchor-log.jsonl")
	cfg.FlightRecorder.Anchor.Interval = "0"
	cfg.FlightRecorder.Anchor.ReceiptThreshold = uint64Pointer(1)
	m := metrics.New()
	logs := &bytes.Buffer{}
	first := newAutoAnchorMonitor(recA, m, func() *receipt.Emitter { return emitterA }, func() *config.Config { return cfg }, logs)
	first.runPass()
	stateA, found, err := readAnchorStateForSession(dir)
	if err != nil || !found {
		t.Fatalf("read first anchor state = (%+v, %v, %v)", stateA, found, err)
	}
	bundleAPath := filepath.Join(dir, filepath.FromSlash(stateA.BundlePath))
	bundleA, err := os.ReadFile(filepath.Clean(bundleAPath))
	if err != nil {
		t.Fatalf("ReadFile first bundle: %v", err)
	}
	if err := recA.Close(); err != nil {
		t.Fatalf("Close recorder A: %v", err)
	}

	_, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey B: %v", err)
	}
	recB, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, MaxEntriesPerFile: 100, FileMode: 0o600}, nil, nil)
	if err != nil {
		t.Fatalf("recorder.New B: %v", err)
	}
	t.Cleanup(func() { _ = recB.Close() })
	emitterB := receipt.NewEmitter(receipt.EmitterConfig{Recorder: recB, PrivKey: privB, ConfigHash: "rotation-b", Principal: "tester", Actor: "runtime-test", Metrics: m})
	if emitterB == nil || emitterB.InitError() != nil {
		t.Fatalf("NewEmitter B = %v, init err = %v", emitterB, emitterB.InitError())
	}
	if err := emitterB.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen B: %v", err)
	}
	for i := range 3 {
		emitAutoAnchorReceipt(t, emitterB, fmt.Sprintf("https://api.vendor.example/b-%d", i))
	}
	restarted := newAutoAnchorMonitor(recB, m, func() *receipt.Emitter { return emitterB }, func() *config.Config { return cfg }, logs)

	restarted.runPass()

	entries, err := anchorpkg.ReadLocalLog(cfg.FlightRecorder.Anchor.LocalLog)
	if err != nil {
		t.Fatalf("ReadLocalLog: %v", err)
	}
	if len(entries) != 2 || entries[0].Checkpoint.ReceiptCount != 4 || entries[1].Checkpoint.ReceiptCount != 8 {
		t.Fatalf("rotation anchors = %+v, want receipt counts 4 then 8", entries)
	}
	stateB, found, err := readAnchorStateForSession(dir)
	if err != nil || !found {
		t.Fatalf("read second anchor state = (%+v, %v, %v)", stateB, found, err)
	}
	if stateA.BundlePath == stateB.BundlePath {
		t.Fatalf("rotated anchors reused bundle path %q", stateA.BundlePath)
	}
	gotBundleA, err := os.ReadFile(filepath.Clean(bundleAPath))
	if err != nil {
		t.Fatalf("ReadFile preserved first bundle: %v", err)
	}
	if !bytes.Equal(gotBundleA, bundleA) {
		t.Fatal("second rotated anchor overwrote the first anchor bundle")
	}
}

func TestAutoAnchorRotatedChainTrustDerivation(t *testing.T) {
	t.Run("valid_transition", func(t *testing.T) {
		rec, emitter, _, cfg, m, logs, receipts := newRotatedAutoAnchorChain(t)
		monitor := newAutoAnchorMonitor(rec, m, func() *receipt.Emitter { return emitter }, func() *config.Config { return cfg }, logs)
		monitor.runPass()

		entries, err := anchorpkg.ReadLocalLog(cfg.FlightRecorder.Anchor.LocalLog)
		if err != nil {
			t.Fatalf("ReadLocalLog: %v", err)
		}
		if len(entries) != 1 || entries[0].Checkpoint.ReceiptCount != uint64(len(receipts)) || len(entries[0].Checkpoint.SignerKeys) != 2 {
			t.Fatalf("rotated-chain anchor = %+v, want all receipts and both signer keys", entries)
		}
		assertAutoAnchorStats(t, m, 1, 1, 0, "")
	})

	t.Run("foreign_head_refused_before_submit", func(t *testing.T) {
		foreign := newAutoAnchorTestRig(t)
		emitAutoAnchorReceipt(t, foreign.emitter, "https://api.vendor.example/foreign")
		foreignReceipts, err := receipt.ExtractReceiptsFromSessionDir(foreign.recorder.Dir(), transcriptRootSessionID)
		if err != nil {
			t.Fatalf("ExtractReceiptsFromSessionDir: %v", err)
		}
		live := newAutoAnchorTestRig(t)
		emitAutoAnchorReceipt(t, live.emitter, "https://api.vendor.example/live")
		backend := &countingAnchorBackend{}
		live.monitor.extractFn = func(string, string) ([]receipt.Receipt, error) { return foreignReceipts, nil }
		live.monitor.backendFn = func(config.FlightRecorderAnchor) (anchorpkg.Backend, error) { return backend, nil }

		live.monitor.runPass()

		if backend.submits.Load() != 0 {
			t.Fatalf("foreign head submit calls = %d, want 0", backend.submits.Load())
		}
		assertAutoAnchorStats(t, live.metrics, 1, 0, 1, "does not match live emitter signer")
	})

	t.Run("tampered_transition_refused_before_submit", func(t *testing.T) {
		rec, emitter, privB, cfg, m, logs, receipts := newRotatedAutoAnchorChain(t)
		transitionIndex := -1
		for i := range receipts {
			if receipts[i].ActionRecord.KeyTransition != nil {
				transitionIndex = i
				break
			}
		}
		if transitionIndex < 0 {
			t.Fatal("rotated receipt has no transition marker")
		}
		tamperedRecord := receipts[transitionIndex].ActionRecord
		tamperedRecord.KeyTransition.PriorChainHash = strings.Repeat("0", 64)
		tampered, err := receipt.Sign(tamperedRecord, privB)
		if err != nil {
			t.Fatalf("Sign tampered transition: %v", err)
		}
		receipts[transitionIndex] = tampered
		backend := &countingAnchorBackend{}
		monitor := newAutoAnchorMonitor(rec, m, func() *receipt.Emitter { return emitter }, func() *config.Config { return cfg }, logs)
		monitor.extractFn = func(string, string) ([]receipt.Receipt, error) { return receipts, nil }
		monitor.backendFn = func(config.FlightRecorderAnchor) (anchorpkg.Backend, error) { return backend, nil }

		monitor.runPass()

		if backend.submits.Load() != 0 {
			t.Fatalf("tampered transition submit calls = %d, want 0", backend.submits.Load())
		}
		assertAutoAnchorStats(t, m, 1, 0, 1, "invalid receipt chain")
	})

	t.Run("grafted_foreign_prefix_is_not_promoted_to_trust", func(t *testing.T) {
		foreign := newAutoAnchorTestRig(t)
		emitAutoAnchorReceipt(t, foreign.emitter, "https://api.vendor.example/graft")
		foreignReceipts, err := receipt.ExtractReceiptsFromSessionDir(foreign.recorder.Dir(), transcriptRootSessionID)
		if err != nil {
			t.Fatalf("ExtractReceiptsFromSessionDir foreign: %v", err)
		}
		_, emitter, _, _, _, _, receipts := newRotatedAutoAnchorChain(t)
		grafted := append(append([]receipt.Receipt(nil), foreignReceipts...), receipts...)

		if _, err := autoAnchorTrustedKeys(grafted, emitter.SignerKeyHex()); err == nil || !strings.Contains(err.Error(), "not authorized by the live head") {
			t.Fatalf("grafted prefix trust derivation err = %v, want backward-trust rejection", err)
		}
	})

	t.Run("spliced_foreign_segment_refused_before_submit", func(t *testing.T) {
		rec, emitter, _, cfg, m, logs, receipts := newRotatedAutoAnchorChain(t)
		foreign := newAutoAnchorTestRig(t)
		emitAutoAnchorReceipt(t, foreign.emitter, "https://api.vendor.example/splice")
		foreignReceipts, err := receipt.ExtractReceiptsFromSessionDir(foreign.recorder.Dir(), transcriptRootSessionID)
		if err != nil {
			t.Fatalf("ExtractReceiptsFromSessionDir foreign: %v", err)
		}
		boundary := autoAnchorRotationBoundary(t, receipts)
		spliced := append(append([]receipt.Receipt(nil), receipts[:boundary]...), foreignReceipts[0])
		spliced = append(spliced, receipts[boundary:]...)
		backend := &countingAnchorBackend{}
		monitor := newAutoAnchorMonitor(rec, m, func() *receipt.Emitter { return emitter }, func() *config.Config { return cfg }, logs)
		monitor.extractFn = func(string, string) ([]receipt.Receipt, error) { return spliced, nil }
		monitor.backendFn = func(config.FlightRecorderAnchor) (anchorpkg.Backend, error) { return backend, nil }

		monitor.runPass()

		if backend.submits.Load() != 0 {
			t.Fatalf("spliced chain submit calls = %d, want 0", backend.submits.Load())
		}
		assertAutoAnchorStats(t, m, 1, 0, 1, "not authorized by the live head")
	})

	t.Run("truncated_rotated_prefix_refused_before_submit", func(t *testing.T) {
		rec, emitter, _, cfg, m, logs, receipts := newRotatedAutoAnchorChain(t)
		truncated := append([]receipt.Receipt(nil), receipts[autoAnchorRotationBoundary(t, receipts):]...)
		backend := &countingAnchorBackend{}
		monitor := newAutoAnchorMonitor(rec, m, func() *receipt.Emitter { return emitter }, func() *config.Config { return cfg }, logs)
		monitor.extractFn = func(string, string) ([]receipt.Receipt, error) { return truncated, nil }
		monitor.backendFn = func(config.FlightRecorderAnchor) (anchorpkg.Backend, error) { return backend, nil }

		monitor.runPass()

		if backend.submits.Load() != 0 {
			t.Fatalf("truncated chain submit calls = %d, want 0", backend.submits.Load())
		}
		assertAutoAnchorStats(t, m, 1, 0, 1, "chain starts at a key_transition segment")
	})
}

func TestAutoAnchorObserveRejectsReceiptCountOverflow(t *testing.T) {
	monitor := &autoAnchorMonitor{
		observedChainSeq:     math.MaxUint64 - 1,
		observedReceiptCount: math.MaxUint64,
	}
	if got, err := monitor.observe(math.MaxUint64); err == nil || !strings.Contains(err.Error(), "receipt count overflow") {
		t.Fatalf("observe overflow = (%d, %v), want fail-closed overflow error", got, err)
	}
	monitor.hasLastAnchor = true
	monitor.lastReceiptCount = 10
	if _, _, err := monitor.triggered(config.FlightRecorder{}, 9, time.Now().UTC()); err == nil || !strings.Contains(err.Error(), "ahead of observed count") {
		t.Fatalf("trigger with in-memory state ahead err = %v, want explicit failure", err)
	}
}

func TestAutoAnchorTriggeredUint64Boundaries(t *testing.T) {
	threshold := uint64(1)
	fr := config.FlightRecorder{Anchor: config.FlightRecorderAnchor{
		Interval:         "0",
		ReceiptThreshold: &threshold,
	}}
	monitor := &autoAnchorMonitor{
		hasLastAnchor:    true,
		lastReceiptCount: math.MaxUint64 - 1,
	}
	triggered, newReceipts, err := monitor.triggered(fr, math.MaxUint64, time.Now().UTC())
	if err != nil || !triggered || newReceipts != 1 {
		t.Fatalf("max uint64 trigger = (%v, %d, %v), want true, 1, nil", triggered, newReceipts, err)
	}
	monitor.lastReceiptCount = math.MaxUint64
	triggered, newReceipts, err = monitor.triggered(fr, math.MaxUint64, time.Now().UTC())
	if err != nil || triggered || newReceipts != 0 {
		t.Fatalf("same max uint64 head trigger = (%v, %d, %v), want false, 0, nil", triggered, newReceipts, err)
	}
}

func TestAutoAnchorSeedRejectsForgedReceiptCountOverflow(t *testing.T) {
	trig := newAutoAnchorTestRig(t)
	emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/current")
	writeForgedAutoAnchorState(t, trig, "anchor-proxy-forged-overflow.json", anchorpkg.Checkpoint{
		SessionID:    transcriptRootSessionID,
		FinalSeq:     0,
		RootHash:     strings.Repeat("a", 64),
		ReceiptCount: math.MaxUint64,
		StartTime:    time.Now().UTC().Add(-time.Minute),
		EndTime:      time.Now().UTC().Add(-time.Second),
		SignerKeys:   []string{trig.emitter.SignerKeyHex()},
	})

	trig.monitor.runPass()

	assertAutoAnchorStats(t, trig.metrics, 0, 0, 1, "ahead of live chain count")
}

func TestAutoAnchorSeedRejectsForgedCheckpointMatchingMarkerAndBundle(t *testing.T) {
	trig := newAutoAnchorTestRig(t)
	emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/current")
	writeForgedAutoAnchorState(t, trig, "anchor-proxy-forged-checkpoint.json", anchorpkg.Checkpoint{
		SessionID:    transcriptRootSessionID,
		FinalSeq:     0,
		RootHash:     strings.Repeat("a", 64),
		ReceiptCount: 1,
		StartTime:    time.Now().UTC().Add(-time.Minute),
		EndTime:      time.Now().UTC().Add(-time.Second),
		SignerKeys:   []string{trig.emitter.SignerKeyHex()},
	})

	trig.monitor.runPass()

	assertAutoAnchorStats(t, trig.metrics, 0, 0, 1, "does not match the live receipt chain")
}

func TestLoadAutoAnchorCheckpointRejectsUnsafePaths(t *testing.T) {
	if _, err := loadAutoAnchorCheckpoint(t.TempDir(), anchorState{BundlePath: "../outside.json"}); err == nil || !strings.Contains(err.Error(), "stay under receipt directory") {
		t.Fatalf("traversal bundle path err = %v, want containment rejection", err)
	}

	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside-bundle.json")
	checkpoint := anchorpkg.Checkpoint{
		SessionID:    transcriptRootSessionID,
		RootHash:     strings.Repeat("a", 64),
		ReceiptCount: 1,
		SignerKeys:   []string{strings.Repeat("b", 64)},
	}
	proof := anchorpkg.Proof{Backend: anchorpkg.LocalBackend, LogID: "path-test"}
	if err := anchorpkg.WriteBundle(outside, anchorpkg.NewBundle(checkpoint, proof)); err != nil {
		t.Fatalf("WriteBundle outside: %v", err)
	}
	data, err := os.ReadFile(filepath.Clean(outside))
	if err != nil {
		t.Fatalf("ReadFile outside: %v", err)
	}
	bundleDir := filepath.Join(root, autoAnchorBundleDir)
	if err := os.Mkdir(bundleDir, 0o750); err != nil {
		t.Fatalf("Mkdir bundle dir: %v", err)
	}
	link := filepath.Join(bundleDir, "anchor-proxy-link.json")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	sum := sha256.Sum256(data)
	state := anchorState{
		SessionID:    checkpoint.SessionID,
		FinalSeq:     checkpoint.FinalSeq,
		RootHash:     checkpoint.RootHash,
		Backend:      proof.Backend,
		BundleSHA256: hex.EncodeToString(sum[:]),
		BundlePath:   filepath.ToSlash(filepath.Join(autoAnchorBundleDir, filepath.Base(link))),
	}
	if _, err := loadAutoAnchorCheckpoint(root, state); err == nil || !strings.Contains(err.Error(), "open anchor-state bundle") {
		t.Fatalf("symlink escape bundle err = %v, want rooted-open rejection", err)
	}
}

func TestAutoAnchorRekorBackendLoadsKeyPerAttempt(t *testing.T) {
	trig := newAutoAnchorTestRig(t)
	emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/rekor")
	keyPath := filepath.Join(t.TempDir(), "rekor-entry.key")
	if err := signing.SavePrivateKey(trig.priv, keyPath); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/log/entries" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		var body json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		encoded := base64.StdEncoding.EncodeToString(body)
		response := map[string]any{
			"fake-uuid": map[string]any{
				"logID": "fake-log", "logIndex": 0, "integratedTime": 1, "body": encoded,
				"verification": map[string]any{
					"signedEntryTimestamp": "test-set",
					"inclusionProof": map[string]any{
						"rootHash": strings.Repeat("0", 64), "logIndex": 0, "treeSize": 1,
						"hashes": []string{}, "checkpoint": "test-checkpoint",
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	t.Cleanup(server.Close)
	trig.cfg.FlightRecorder.Anchor = config.FlightRecorderAnchor{
		RekorURL:         server.URL,
		RekorKeyPath:     keyPath,
		Interval:         time.Hour.String(),
		ReceiptThreshold: uint64Pointer(1000),
	}

	trig.monitor.runPass()
	if requests.Load() != 1 {
		t.Fatalf("Rekor requests = %d, want 1", requests.Load())
	}
	assertAutoAnchorStats(t, trig.metrics, 1, 1, 0, "")
	if err := os.Remove(keyPath); err != nil {
		t.Fatalf("Remove key: %v", err)
	}
	emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/rekor-retry")
	trig.cfg.FlightRecorder.Anchor.Interval = "0"
	trig.cfg.FlightRecorder.Anchor.ReceiptThreshold = uint64Pointer(1)
	trig.monitor.runPass()
	if requests.Load() != 1 {
		t.Fatalf("Rekor request occurred with missing reloaded key: %d", requests.Load())
	}
	assertAutoAnchorStats(t, trig.metrics, 2, 1, 1, "load rekor signing key")
}

func TestAutoAnchorFailureDegradesEvidenceHealthUntilRecovery(t *testing.T) {
	trig := newAutoAnchorTestRig(t)
	emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/healthy-anchor")
	trig.monitor.runPass()
	originalLog := trig.cfg.FlightRecorder.Anchor.LocalLog
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("block"), 0o600); err != nil {
		t.Fatalf("WriteFile blocker: %v", err)
	}
	trig.cfg.FlightRecorder.Anchor.LocalLog = filepath.Join(blocker, "anchor.jsonl")
	trig.cfg.FlightRecorder.Anchor.Interval = "0"
	trig.cfg.FlightRecorder.Anchor.ReceiptThreshold = uint64Pointer(1)
	emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/failed-anchor")
	trig.monitor.runPass()

	health := newEvidenceHealthMonitor(trig.recorder, trig.metrics, func() *receipt.Emitter { return trig.emitter }, func() *config.Config { return trig.cfg }, trig.logs)
	health.runPass()
	stats, ok := health.stats()
	if !ok {
		t.Fatal("evidence health stats unavailable")
	}
	if stats.AutoAnchor.LastError == "" || stats.Requirements[metrics.EvidenceRequirementAnchoringFresh] {
		t.Fatalf("failed auto-anchor health = %+v, want last error and anchoring_fresh=false", stats)
	}

	trig.cfg.FlightRecorder.Anchor = config.FlightRecorderAnchor{}
	health.runPass()
	stats, ok = health.stats()
	if !ok || stats.AutoAnchor.LastError == "" || !stats.Requirements[metrics.EvidenceRequirementAnchoringFresh] {
		t.Fatalf("disabled auto-anchor health = %+v, ok=%v; stale runtime error must remain visible without gating marker freshness", stats, ok)
	}

	trig.cfg.FlightRecorder.Anchor = config.FlightRecorderAnchor{
		LocalLog:         originalLog,
		Interval:         "0",
		ReceiptThreshold: uint64Pointer(1),
	}
	trig.monitor.runPass()
	health.runPass()
	stats, ok = health.stats()
	if !ok || stats.AutoAnchor.LastError != "" || !stats.Requirements[metrics.EvidenceRequirementAnchoringFresh] {
		t.Fatalf("recovered auto-anchor health = %+v, ok=%v", stats, ok)
	}
}

func TestAutoAnchorPersistentMarkerFailureDoesNotBlockReceiptEmission(t *testing.T) {
	trig := newAutoAnchorTestRig(t)
	blocker := filepath.Join(trig.recorder.Dir(), "anchor-state.d")
	if err := os.WriteFile(blocker, []byte("block"), 0o600); err != nil {
		t.Fatalf("WriteFile blocker: %v", err)
	}
	backend := &countingAnchorBackend{}
	trig.monitor.seeded = true
	trig.monitor.backendFn = func(config.FlightRecorderAnchor) (anchorpkg.Backend, error) { return backend, nil }
	emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/before-marker-failure")

	trig.monitor.runPass()
	emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/after-marker-failure")
	trig.monitor.runPass()

	if backend.submits.Load() != 2 {
		t.Fatalf("persistent marker failure submits = %d, want retry on both heads", backend.submits.Load())
	}
	if snapshot, ok := trig.emitter.HealthSnapshot(); !ok || snapshot.InitErr || snapshot.ChainSeq != 3 {
		t.Fatalf("emitter after persistent anchor failure = (%+v, %v), want healthy chain_seq 3", snapshot, ok)
	}
	bundles, err := filepath.Glob(filepath.Join(trig.recorder.Dir(), autoAnchorBundleDir, "*.json"))
	if err != nil || len(bundles) != 2 {
		t.Fatalf("bundles surviving marker failures = %v, err=%v, want two", bundles, err)
	}
	assertAutoAnchorStats(t, trig.metrics, 2, 0, 2, "write live anchor state")
}

func TestAutoAnchorReusesPendingProofOnPersistRetry(t *testing.T) {
	trig := newAutoAnchorTestRig(t)
	// Block the marker directory so bundle+marker persistence fails while the
	// backend submission succeeds, leaving a pending unpersisted checkpoint.
	blocker := filepath.Join(trig.recorder.Dir(), "anchor-state.d")
	if err := os.WriteFile(blocker, []byte("block"), 0o600); err != nil {
		t.Fatalf("WriteFile blocker: %v", err)
	}
	backend := &countingAnchorBackend{}
	trig.monitor.seeded = true
	trig.monitor.backendFn = func(config.FlightRecorderAnchor) (anchorpkg.Backend, error) { return backend, nil }
	emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/pending-head")

	// Two passes over the SAME head: the first submits, the second must reuse the
	// pending proof and retry only local persistence — never a second submit.
	trig.monitor.runPass()
	trig.monitor.runPass()

	if got := backend.submits.Load(); got != 1 {
		t.Fatalf("submits for a single unchanged head = %d, want 1 (pending reuse, no resubmit)", got)
	}
	if !trig.monitor.pending {
		t.Fatal("monitor must retain the pending checkpoint while persistence keeps failing")
	}
	assertAutoAnchorStats(t, trig.metrics, 2, 0, 2, "write live anchor state")

	// Clearing the blocker lets the retry persist with the SAME pending proof and
	// still no additional submit.
	if err := os.Remove(blocker); err != nil {
		t.Fatalf("remove blocker: %v", err)
	}
	trig.monitor.runPass()
	if got := backend.submits.Load(); got != 1 {
		t.Fatalf("submits after successful persist retry = %d, want 1", got)
	}
	if trig.monitor.pending {
		t.Fatal("pending must clear after the marker is durable")
	}
	assertAutoAnchorStats(t, trig.metrics, 3, 1, 2, "")
}

func TestAutoAnchorConcurrentPassesSubmitHeadOnce(t *testing.T) {
	trig := newAutoAnchorTestRig(t)
	trig.monitor.seeded = true
	trig.cfg.FlightRecorder.Anchor.Interval = "0"
	trig.cfg.FlightRecorder.Anchor.ReceiptThreshold = uint64Pointer(1)
	emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/concurrent-head")

	// Block inside the first submit so a second pass runs while the first is
	// mid-submission. The in-flight guard must keep the second pass from
	// submitting the same head again.
	submitEntered := make(chan struct{})
	releaseSubmit := make(chan struct{})
	var once sync.Once
	backend := &countingAnchorBackend{onSubmit: func() {
		once.Do(func() {
			close(submitEntered)
			<-releaseSubmit
		})
	}}
	trig.monitor.backendFn = func(config.FlightRecorderAnchor) (anchorpkg.Backend, error) { return backend, nil }

	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		trig.monitor.runPass()
	}()
	select {
	case <-submitEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("first submit did not start")
	}
	// Second pass while the first submit is blocked: it must observe the
	// in-flight guard and skip without a second submit.
	trig.monitor.runPass()
	if got := backend.submits.Load(); got != 1 {
		t.Fatalf("submits while first is in flight = %d, want 1", got)
	}
	close(releaseSubmit)
	select {
	case <-firstDone:
	case <-time.After(2 * time.Second):
		t.Fatal("first pass did not finish")
	}
	if got := backend.submits.Load(); got != 1 {
		t.Fatalf("total submits for one head = %d, want exactly 1", got)
	}
	if trig.monitor.anchorInFlight {
		t.Fatal("in-flight guard must clear after the pass returns")
	}
}

func TestVerifyAutoAnchorProof(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "local-anchor-log.jsonl")
	local := anchorpkg.LocalLog{Path: logPath, LogID: "verify-test-log"}
	checkpoint := anchorpkg.Checkpoint{SessionID: "proxy", FinalSeq: 1, RootHash: strings.Repeat("a", 64), ReceiptCount: 1}
	goodProof, err := local.Submit(checkpoint)
	if err != nil {
		t.Fatalf("local submit: %v", err)
	}

	t.Run("local accepts its own proof", func(t *testing.T) {
		if err := verifyAutoAnchorProof(local, goodProof, checkpoint); err != nil {
			t.Fatalf("verifyAutoAnchorProof(local, good) = %v, want nil", err)
		}
	})
	t.Run("local rejects a tampered proof", func(t *testing.T) {
		bad := goodProof
		bad.EntryHash = strings.Repeat("b", 64)
		if err := verifyAutoAnchorProof(local, bad, checkpoint); err == nil {
			t.Fatal("verifyAutoAnchorProof(local, tampered) = nil, want error")
		}
	})
	t.Run("rekor records without immediate self-verification", func(t *testing.T) {
		if err := verifyAutoAnchorProof(anchorpkg.RekorLog{URL: "https://rekor.internal.example"}, anchorpkg.Proof{Backend: anchorpkg.RekorBackend}, checkpoint); err != nil {
			t.Fatalf("verifyAutoAnchorProof(rekor) = %v, want nil", err)
		}
	})
}

func TestReadAnchorStateForSessionRejectsCorruptAndAmbiguousAutoMarkers(t *testing.T) {
	t.Run("corrupt current bundle is caught at the health read", func(t *testing.T) {
		trig := newAutoAnchorTestRig(t)
		emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/corrupt-bundle")
		trig.monitor.runPass()
		bundles, err := filepath.Glob(filepath.Join(trig.recorder.Dir(), autoAnchorBundleDir, "*.json"))
		if err != nil || len(bundles) != 1 {
			t.Fatalf("bundles = %v err=%v, want exactly one", bundles, err)
		}
		if err := os.WriteFile(bundles[0], []byte("{ not a bundle"), 0o600); err != nil {
			t.Fatalf("corrupt bundle: %v", err)
		}
		// The fast path authenticates the latest bundle, so a corrupt current
		// bundle can no longer read as a trusted enriched marker; the read must not
		// return it as valid state.
		if state, found, err := readAnchorStateForSession(trig.recorder.Dir()); found && err == nil && state.ReceiptCount > 0 {
			t.Fatalf("health read with corrupt bundle = (found=%v, err=%v, state=%+v), want the corrupt bundle rejected", found, err, state)
		}
		restarted := newAutoAnchorMonitor(trig.recorder, trig.metrics, func() *receipt.Emitter { return trig.emitter }, func() *config.Config { return trig.cfg }, trig.logs)
		restarted.runPass()
		if got := trig.metrics.EvidenceAutoAnchorStatsSnapshot().LastError; !strings.Contains(got, "bundle") {
			t.Fatalf("seed error = %q, want bundle failure", got)
		}
	})
	t.Run("writer rejects ambiguous same-receipt-count marker", func(t *testing.T) {
		trig := newAutoAnchorTestRig(t)
		emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/ambiguous")
		trig.monitor.runPass()
		state, found, err := readAnchorStateForSession(trig.recorder.Dir())
		if err != nil || !found {
			t.Fatalf("baseline read = (%+v, %v, %v)", state, found, err)
		}
		// A second auto marker at the same receipt count but a different root
		// must not replace the authoritative latest pointer.
		conflictRel := filepath.ToSlash(filepath.Join(autoAnchorBundleDir, "anchor-proxy-conflict.json"))
		conflictCP := anchorpkg.Checkpoint{
			SessionID: state.SessionID, FinalSeq: state.FinalSeq, ReceiptCount: state.ReceiptCount,
			RootHash: strings.Repeat("c", 64), SignerKeys: []string{trig.emitter.SignerKeyHex()},
		}
		bundleBytes, werr := anchorpkg.WriteBundleUnderDir(trig.recorder.Dir(), conflictRel, anchorpkg.NewBundle(conflictCP, anchorpkg.Proof{Backend: anchorpkg.LocalBackend, LogID: "conflict"}))
		if werr != nil {
			t.Fatalf("write conflict bundle: %v", werr)
		}
		sum := sha256.Sum256(bundleBytes)
		werr = anchorpkg.WriteStateMarker(trig.recorder.Dir(), anchorpkg.StateMarker{
			SessionID: conflictCP.SessionID, FinalSeq: conflictCP.FinalSeq, RootHash: conflictCP.RootHash,
			Backend: anchorpkg.LocalBackend, AnchoredAt: time.Now().UTC(),
			BundleSHA256: hex.EncodeToString(sum[:]), BundlePath: conflictRel,
			ReceiptCount: conflictCP.ReceiptCount, SignerKey: trig.emitter.SignerKeyHex(),
		})
		if werr == nil || !strings.Contains(werr.Error(), "conflicts with latest marker") {
			t.Fatalf("write conflict marker err = %v, want latest conflict", werr)
		}
		selected, found, readErr := readAnchorStateForSession(trig.recorder.Dir())
		if readErr != nil || !found || selected.RootHash != state.RootHash {
			t.Fatalf("read after rejected conflict = (%+v, %v, %v), want original pointer", selected, found, readErr)
		}
	})
}

func TestReadAnchorStateForSessionManualHigherCoverageBeatsAuto(t *testing.T) {
	trig := newAutoAnchorTestRig(t)
	emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/auto")
	trig.monitor.runPass()
	emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/manual")
	receipts, err := receipt.ExtractReceiptsFromSessionDir(trig.recorder.Dir(), transcriptRootSessionID)
	if err != nil {
		t.Fatalf("ExtractReceiptsFromSessionDir: %v", err)
	}
	checkpoint, err := anchorpkg.BuildCheckpoint(transcriptRootSessionID, receipts, []string{trig.emitter.SignerKeyHex()})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	bundleRel := "manual-anchor.json"
	bundleBytes, err := anchorpkg.WriteBundleUnderDir(trig.recorder.Dir(), bundleRel, anchorpkg.NewBundle(checkpoint, anchorpkg.Proof{
		Backend: anchorpkg.LocalBackend,
		LogID:   "manual-test-log",
	}))
	if err != nil {
		t.Fatalf("WriteBundleUnderDir: %v", err)
	}
	bundleSum := sha256.Sum256(bundleBytes)
	if err := anchorpkg.WriteStateMarker(trig.recorder.Dir(), anchorpkg.StateMarker{
		SessionID:    transcriptRootSessionID,
		FinalSeq:     checkpoint.FinalSeq,
		RootHash:     checkpoint.RootHash,
		Backend:      anchorpkg.LocalBackend,
		AnchoredAt:   time.Now().UTC().Add(-time.Second),
		BundleSHA256: hex.EncodeToString(bundleSum[:]),
		BundlePath:   bundleRel,
	}); err != nil {
		t.Fatalf("WriteStateMarker manual: %v", err)
	}

	state, found, err := readAnchorStateForSession(trig.recorder.Dir())
	if err != nil || !found {
		t.Fatalf("readAnchorStateForSession = (%+v, %v, %v), want manual marker", state, found, err)
	}
	if state.FinalSeq != checkpoint.FinalSeq || state.ReceiptCount != checkpoint.ReceiptCount || state.BundlePath != bundleRel {
		t.Fatalf("selected anchor state = %+v, want higher-coverage manual marker", state)
	}
}

func TestAutoAnchorSeedRejectsUnbackedManualMarkerOutrankingAuto(t *testing.T) {
	trig := newAutoAnchorTestRig(t)
	emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/anchored")
	trig.monitor.runPass()
	anchored, found, err := readAnchorStateForSession(trig.recorder.Dir())
	if err != nil || !found {
		t.Fatalf("read anchored state = (%+v, %v, %v)", anchored, found, err)
	}
	emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/unanchored")
	snapshot, ok := trig.emitter.HealthSnapshot()
	if !ok || snapshot.ChainSeq == 0 {
		t.Fatalf("HealthSnapshot = (%+v, %v), want live chain", snapshot, ok)
	}
	if err := anchorpkg.WriteStateMarker(trig.recorder.Dir(), anchorpkg.StateMarker{
		SessionID:    transcriptRootSessionID,
		FinalSeq:     snapshot.ChainSeq - 1,
		RootHash:     strings.Repeat("c", 64),
		Backend:      anchorpkg.LocalBackend,
		AnchoredAt:   time.Now().UTC().Add(-time.Second),
		BundleSHA256: strings.Repeat("d", 64),
		BundlePath:   "manual-forged.json",
	}); err != nil {
		t.Fatalf("WriteStateMarker forged manual marker: %v", err)
	}

	restarted := newAutoAnchorMonitor(trig.recorder, trig.metrics, func() *receipt.Emitter { return trig.emitter }, func() *config.Config { return trig.cfg }, trig.logs)
	if err := restarted.seed(time.Now().UTC(), snapshot, trig.emitter.SignerKeyHex()); err != nil {
		t.Fatalf("seed with forged manual marker: %v", err)
	}
	if restarted.lastReceiptCount != anchored.ReceiptCount || restarted.lastFinalSeq != anchored.FinalSeq {
		t.Fatalf("seeded anchor = (count=%d, final_seq=%d), want authentic auto marker (count=%d, final_seq=%d)",
			restarted.lastReceiptCount, restarted.lastFinalSeq, anchored.ReceiptCount, anchored.FinalSeq)
	}
}

func TestReadAnchorStateForSessionSkipsCorruptHistoricalState(t *testing.T) {
	t.Run("marker", func(t *testing.T) {
		trig := newAutoAnchorTestRig(t)
		emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/valid")
		trig.monitor.runPass()
		if err := os.WriteFile(filepath.Join(trig.recorder.Dir(), "anchor-state.d", "corrupt.json"), []byte(`{"schema":`), 0o600); err != nil {
			t.Fatalf("WriteFile corrupt marker: %v", err)
		}
		if err := os.Remove(filepath.Join(trig.recorder.Dir(), evidenceAnchorStateFile)); err != nil {
			t.Fatalf("Remove latest pointer: %v", err)
		}

		state, found, skipped, err := readAnchorStateForSessionWithSkipped(trig.recorder.Dir(), transcriptRootSessionID)
		if err != nil || !found {
			t.Fatalf("readAnchorStateForSession = (%+v, %v, %v), want valid marker despite corrupt history", state, found, err)
		}
		if skipped != 1 {
			t.Fatalf("skipped historical markers = %d, want 1", skipped)
		}
	})

	t.Run("bundle", func(t *testing.T) {
		trig := newAutoAnchorTestRig(t)
		trig.cfg.FlightRecorder.Anchor.Interval = "0"
		trig.cfg.FlightRecorder.Anchor.ReceiptThreshold = uint64Pointer(1)
		emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/older")
		trig.monitor.runPass()
		older, found, err := readAnchorStateForSession(trig.recorder.Dir())
		if err != nil || !found {
			t.Fatalf("read older state = (%+v, %v, %v)", older, found, err)
		}
		emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/newer")
		trig.monitor.runPass()
		olderMarkerPath, err := anchorpkg.StateMarkerPath(trig.recorder.Dir(), anchorpkg.StateMarker{
			SessionID: older.SessionID,
			FinalSeq:  older.FinalSeq,
			RootHash:  older.RootHash,
		})
		if err != nil {
			t.Fatalf("StateMarkerPath older: %v", err)
		}
		olderData, err := os.ReadFile(filepath.Clean(olderMarkerPath))
		if err != nil {
			t.Fatalf("ReadFile older marker: %v", err)
		}
		var legacy map[string]any
		if err := json.Unmarshal(olderData, &legacy); err != nil {
			t.Fatalf("Unmarshal older marker: %v", err)
		}
		delete(legacy, "receipt_count")
		delete(legacy, "signer_key")
		olderData, err = json.Marshal(legacy)
		if err != nil {
			t.Fatalf("Marshal legacy marker: %v", err)
		}
		if err := os.WriteFile(filepath.Clean(olderMarkerPath), append(olderData, '\n'), 0o600); err != nil {
			t.Fatalf("WriteFile legacy marker: %v", err)
		}
		if err := os.WriteFile(filepath.Join(trig.recorder.Dir(), filepath.FromSlash(older.BundlePath)), []byte(`{"corrupt":true}`), 0o600); err != nil {
			t.Fatalf("WriteFile corrupt historical bundle: %v", err)
		}
		if err := os.Remove(filepath.Join(trig.recorder.Dir(), evidenceAnchorStateFile)); err != nil {
			t.Fatalf("Remove latest pointer: %v", err)
		}

		state, found, skipped, err := readAnchorStateForSessionWithSkipped(trig.recorder.Dir(), transcriptRootSessionID)
		if err != nil || !found {
			t.Fatalf("readAnchorStateForSession = (%+v, %v, %v), want latest marker despite corrupt old bundle", state, found, err)
		}
		if skipped != 1 {
			t.Fatalf("skipped historical bundles = %d, want 1", skipped)
		}
		if state.FinalSeq <= older.FinalSeq {
			t.Fatalf("selected state = %+v, want marker newer than final_seq %d", state, older.FinalSeq)
		}
	})
}

func TestReadAnchorStateForSessionFastPathRequiresLatestBundle(t *testing.T) {
	trig := newAutoAnchorTestRig(t)
	emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/fast-path-bundle")
	trig.monitor.runPass()
	state, found, err := readAnchorStateForSession(trig.recorder.Dir())
	if err != nil || !found {
		t.Fatalf("read initial state = (%+v, %v, %v)", state, found, err)
	}
	// The O(1) fast path authenticates the single latest bundle before trusting
	// the pointer, so removing it must stop the read from returning the enriched
	// marker as valid state. (The gain over the old scan is that only the latest
	// bundle is opened, not every historical one.)
	if err := os.Remove(filepath.Join(trig.recorder.Dir(), filepath.FromSlash(state.BundlePath))); err != nil {
		t.Fatalf("Remove bundle: %v", err)
	}
	got, found, err := readAnchorStateForSession(trig.recorder.Dir())
	if found && err == nil && got.ReceiptCount > 0 {
		t.Fatalf("read without the latest bundle = (%+v, %v, %v), want the unverifiable pointer rejected", got, found, err)
	}
}

func TestReadAnchorStateForSessionFallbackRejectsUnbackedEnrichedMarker(t *testing.T) {
	trig := newAutoAnchorTestRig(t)
	emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/backed-anchor")
	trig.monitor.runPass()
	backed, found, err := readAnchorStateForSession(trig.recorder.Dir())
	if err != nil || !found {
		t.Fatalf("read backed state = (%+v, %v, %v)", backed, found, err)
	}
	forgedCoverage := backed.ReceiptCount + 100
	forgedRoot := sha256.Sum256([]byte("unbacked-enriched-history"))
	if err := anchorpkg.WriteStateMarker(trig.recorder.Dir(), anchorpkg.StateMarker{
		SessionID:    transcriptRootSessionID,
		FinalSeq:     forgedCoverage - 1,
		RootHash:     hex.EncodeToString(forgedRoot[:]),
		Backend:      anchorpkg.LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("d", 64),
		BundlePath:   "missing-forged-bundle.json",
		ReceiptCount: forgedCoverage,
		SignerKey:    trig.emitter.SignerKeyHex(),
	}); err != nil {
		t.Fatalf("WriteStateMarker forged history: %v", err)
	}
	if err := os.WriteFile(filepath.Join(trig.recorder.Dir(), evidenceAnchorStateFile), []byte(`{"schema":`), 0o600); err != nil {
		t.Fatalf("WriteFile torn pointer: %v", err)
	}

	got, found, skipped, err := readAnchorStateForSessionWithSkipped(trig.recorder.Dir(), transcriptRootSessionID)
	if err != nil || !found {
		t.Fatalf("fallback read = (%+v, %v, %d, %v), want backed state", got, found, skipped, err)
	}
	if got.RootHash != backed.RootHash || got.ReceiptCount != backed.ReceiptCount {
		t.Fatalf("fallback selected unbacked state %+v, want backed state %+v", got, backed)
	}
	if skipped != 2 {
		t.Fatalf("skipped pointer/marker count = %d, want 2", skipped)
	}
}

func TestReadAnchorStateForSessionFallsBackFromTornLatestPointer(t *testing.T) {
	trig := newAutoAnchorTestRig(t)
	emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/torn-pointer")
	trig.monitor.runPass()
	if err := os.WriteFile(filepath.Join(trig.recorder.Dir(), evidenceAnchorStateFile), []byte(`{"schema":`), 0o600); err != nil {
		t.Fatalf("WriteFile torn pointer: %v", err)
	}

	state, found, err := readAnchorStateForSession(trig.recorder.Dir())
	if err != nil || !found {
		t.Fatalf("readAnchorStateForSession = (%+v, %v, %v), want indexed fallback", state, found, err)
	}
	snapshot, ok := trig.emitter.HealthSnapshot()
	if !ok {
		t.Fatal("emitter health snapshot unavailable")
	}
	restarted := newAutoAnchorMonitor(trig.recorder, trig.metrics, func() *receipt.Emitter { return trig.emitter }, func() *config.Config { return trig.cfg }, trig.logs)
	if err := restarted.seed(time.Now().UTC(), snapshot, trig.emitter.SignerKeyHex()); err != nil {
		t.Fatalf("seed with torn-pointer fallback: %v", err)
	}
}

func TestReadAnchorStateForSessionFallsBackFromDisagreeingLatestPointer(t *testing.T) {
	trig := newAutoAnchorTestRig(t)
	emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/disagreeing-pointer")
	trig.monitor.runPass()
	want, found, err := readAnchorStateForSession(trig.recorder.Dir())
	if err != nil || !found {
		t.Fatalf("read initial state = (%+v, %v, %v)", want, found, err)
	}
	pointerPath := filepath.Join(trig.recorder.Dir(), evidenceAnchorStateFile)
	data, err := os.ReadFile(filepath.Clean(pointerPath))
	if err != nil {
		t.Fatalf("ReadFile pointer: %v", err)
	}
	var forged map[string]any
	if err := json.Unmarshal(data, &forged); err != nil {
		t.Fatalf("Unmarshal pointer: %v", err)
	}
	forged["root_hash"] = strings.Repeat("f", 64)
	data, err = json.Marshal(forged)
	if err != nil {
		t.Fatalf("Marshal pointer: %v", err)
	}
	if err := os.WriteFile(filepath.Clean(pointerPath), append(data, '\n'), 0o600); err != nil {
		t.Fatalf("WriteFile pointer: %v", err)
	}

	got, found, skipped, err := readAnchorStateForSessionWithSkipped(trig.recorder.Dir(), transcriptRootSessionID)
	if err != nil || !found || got.RootHash != want.RootHash {
		t.Fatalf("fallback state = (%+v, %v, %v), want indexed root %q", got, found, err, want.RootHash)
	}
	if skipped != 1 {
		t.Fatalf("skipped pointer count = %d, want 1", skipped)
	}
}

func TestReadAnchorStateForSessionOtherSessionPointerOnlyForcesFallback(t *testing.T) {
	trig := newAutoAnchorTestRig(t)
	emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/proxy-session")
	trig.monitor.runPass()
	want, found, err := readAnchorStateForSession(trig.recorder.Dir())
	if err != nil || !found {
		t.Fatalf("read proxy state = (%+v, %v, %v)", want, found, err)
	}
	if err := anchorpkg.WriteStateMarker(trig.recorder.Dir(), anchorpkg.StateMarker{
		SessionID:    "other-session",
		FinalSeq:     99,
		RootHash:     strings.Repeat("c", 64),
		Backend:      anchorpkg.LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("d", 64),
		BundlePath:   "other-session-bundle.json",
		ReceiptCount: 100,
		SignerKey:    strings.Repeat("e", 64),
	}); err != nil {
		t.Fatalf("WriteStateMarker other session: %v", err)
	}

	got, found, skipped, err := readAnchorStateForSessionWithSkipped(trig.recorder.Dir(), transcriptRootSessionID)
	if err != nil || !found || got.RootHash != want.RootHash || got.ReceiptCount != want.ReceiptCount {
		t.Fatalf("proxy fallback = (%+v, %v, %d, %v), want %+v", got, found, skipped, err, want)
	}
	if skipped != 0 {
		t.Fatalf("cross-session pointer skipped count = %d, want 0", skipped)
	}
}

func TestReadAnchorStateForSessionRejectsPointerContentForgedFromIndex(t *testing.T) {
	// A pointer whose identity (session, final_seq, root) still matches its index
	// entry but whose non-identity content (receipt_count) is forged, with the
	// immutable index entry left untouched, must not be trusted by the O(1) fast
	// path: the content-equality check must reject it and fall back to the index.
	trig := newAutoAnchorTestRig(t)
	emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/pointer-content-forge")
	trig.monitor.runPass()
	want, found, err := readAnchorStateForSession(trig.recorder.Dir())
	if err != nil || !found || want.ReceiptCount == 0 {
		t.Fatalf("read initial state = (%+v, %v, %v)", want, found, err)
	}
	pointerPath := filepath.Join(trig.recorder.Dir(), evidenceAnchorStateFile)
	data, err := os.ReadFile(filepath.Clean(pointerPath))
	if err != nil {
		t.Fatalf("ReadFile pointer: %v", err)
	}
	var forged map[string]any
	if err := json.Unmarshal(data, &forged); err != nil {
		t.Fatalf("Unmarshal pointer: %v", err)
	}
	// Keep the identity fields; forge only the coverage count. The index entry on
	// disk is NOT modified.
	forged["receipt_count"] = float64(want.ReceiptCount + 999)
	data, err = json.Marshal(forged)
	if err != nil {
		t.Fatalf("Marshal forged pointer: %v", err)
	}
	if err := os.WriteFile(filepath.Clean(pointerPath), append(data, '\n'), 0o600); err != nil {
		t.Fatalf("WriteFile forged pointer: %v", err)
	}

	got, found, skipped, err := readAnchorStateForSessionWithSkipped(trig.recorder.Dir(), transcriptRootSessionID)
	if err != nil || !found {
		t.Fatalf("fallback read = (%+v, %v, %v)", got, found, err)
	}
	if got.ReceiptCount != want.ReceiptCount {
		t.Fatalf("selected receipt_count = %d, want the untouched index value %d (forged pointer content must be rejected)", got.ReceiptCount, want.ReceiptCount)
	}
	if skipped != 1 {
		t.Fatalf("skipped pointer count = %d, want 1", skipped)
	}
}

func TestReadAnchorStateForSessionCorruptHighestMarkerFallsBackLower(t *testing.T) {
	trig := newAutoAnchorTestRig(t)
	trig.cfg.FlightRecorder.Anchor.Interval = "0"
	trig.cfg.FlightRecorder.Anchor.ReceiptThreshold = uint64Pointer(1)
	emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/lower-anchor")
	trig.monitor.runPass()
	lower, found, err := readAnchorStateForSession(trig.recorder.Dir())
	if err != nil || !found {
		t.Fatalf("read lower state = (%+v, %v, %v)", lower, found, err)
	}
	emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/higher-anchor")
	trig.monitor.runPass()
	higher, found, err := readAnchorStateForSession(trig.recorder.Dir())
	if err != nil || !found || higher.ReceiptCount <= lower.ReceiptCount {
		t.Fatalf("read higher state = (%+v, %v, %v), want coverage above %d", higher, found, err, lower.ReceiptCount)
	}
	higherPath, err := anchorpkg.StateMarkerPath(trig.recorder.Dir(), anchorpkg.StateMarker{
		SessionID: higher.SessionID,
		FinalSeq:  higher.FinalSeq,
		RootHash:  higher.RootHash,
	})
	if err != nil {
		t.Fatalf("StateMarkerPath higher: %v", err)
	}
	if err := os.WriteFile(filepath.Clean(higherPath), []byte(`{"schema":`), 0o600); err != nil {
		t.Fatalf("corrupt higher marker: %v", err)
	}
	if err := os.Remove(filepath.Join(trig.recorder.Dir(), evidenceAnchorStateFile)); err != nil {
		t.Fatalf("Remove latest pointer: %v", err)
	}

	got, found, skipped, err := readAnchorStateForSessionWithSkipped(trig.recorder.Dir(), transcriptRootSessionID)
	if err != nil || !found || got.RootHash != lower.RootHash || got.ReceiptCount != lower.ReceiptCount {
		t.Fatalf("fallback from corrupt highest = (%+v, %v, %d, %v), want lower %+v", got, found, skipped, err, lower)
	}
	if skipped != 1 {
		t.Fatalf("corrupt highest skipped count = %d, want 1", skipped)
	}
}

func TestAutoAnchorSeedRejectsForgedEnrichedMarker(t *testing.T) {
	trig := newAutoAnchorTestRig(t)
	emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/forged-marker")
	trig.monitor.runPass()
	state, found, err := readAnchorStateForSession(trig.recorder.Dir())
	if err != nil || !found {
		t.Fatalf("read initial state = (%+v, %v, %v)", state, found, err)
	}
	markerPath, err := anchorpkg.StateMarkerPath(trig.recorder.Dir(), anchorpkg.StateMarker{
		SessionID: state.SessionID,
		FinalSeq:  state.FinalSeq,
		RootHash:  state.RootHash,
	})
	if err != nil {
		t.Fatalf("StateMarkerPath: %v", err)
	}
	data, err := os.ReadFile(filepath.Clean(markerPath))
	if err != nil {
		t.Fatalf("ReadFile marker: %v", err)
	}
	var forged map[string]any
	if err := json.Unmarshal(data, &forged); err != nil {
		t.Fatalf("Unmarshal marker: %v", err)
	}
	forged["receipt_count"] = float64(999)
	forged["signer_key"] = trig.emitter.SignerKeyHex()
	forged["anchored_at"] = time.Now().UTC().Add(-(config.DefaultEvidenceHealthMaxAnchorLag + time.Second)).Format(time.RFC3339Nano)
	data, err = json.Marshal(forged)
	if err != nil {
		t.Fatalf("Marshal forged marker: %v", err)
	}
	for _, path := range []string{markerPath, filepath.Join(trig.recorder.Dir(), evidenceAnchorStateFile)} {
		if err := os.WriteFile(filepath.Clean(path), append(data, '\n'), 0o600); err != nil {
			t.Fatalf("WriteFile forged marker %s: %v", filepath.Base(path), err)
		}
	}
	health := newEvidenceHealthMonitor(trig.recorder, trig.metrics, func() *receipt.Emitter { return trig.emitter }, func() *config.Config { return trig.cfg }, trig.logs)
	health.runPass()
	healthStats, ok := health.stats()
	if !ok {
		t.Fatal("evidence health stats unavailable")
	}
	if healthStats.Requirements[metrics.EvidenceRequirementAnchoringFresh] {
		t.Fatal("inflated receipt_count fabricated anchor freshness")
	}

	restarted := newAutoAnchorMonitor(trig.recorder, trig.metrics, func() *receipt.Emitter { return trig.emitter }, func() *config.Config { return trig.cfg }, trig.logs)
	restarted.runPass()

	stats := trig.metrics.EvidenceAutoAnchorStatsSnapshot()
	if stats.Failures == 0 || !strings.Contains(stats.LastError, "bundle") {
		t.Fatalf("forged marker auto-anchor stats = %+v, want a bundle-authenticity failure", stats)
	}
}

func TestLoadAutoAnchorCheckpointRejectsForgedSignerKey(t *testing.T) {
	trig := newAutoAnchorTestRig(t)
	emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/forged-signer")
	trig.monitor.runPass()
	state, found, err := readAnchorStateForSession(trig.recorder.Dir())
	if err != nil || !found {
		t.Fatalf("read anchor state = (%+v, %v, %v)", state, found, err)
	}
	state.SignerKey = strings.Repeat("f", 64)
	if _, err := loadAutoAnchorCheckpoint(trig.recorder.Dir(), state); err == nil || !strings.Contains(err.Error(), "signer_key does not match") {
		t.Fatalf("loadAutoAnchorCheckpoint err = %v, want signer-key mismatch", err)
	}
}

func TestAutoAnchorConcurrentEmitterAndEvidenceHealth(t *testing.T) {
	trig := newAutoAnchorTestRig(t)
	trig.cfg.FlightRecorder.Anchor.Interval = "0"
	trig.cfg.FlightRecorder.Anchor.ReceiptThreshold = uint64Pointer(1)
	emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/before-concurrency")
	submitStarted := make(chan struct{})
	releaseSubmit := make(chan struct{})
	var blockOnce sync.Once
	backend := &countingAnchorBackend{onSubmit: func() {
		blockOnce.Do(func() {
			close(submitStarted)
			<-releaseSubmit
		})
	}}
	trig.monitor.backendFn = func(config.FlightRecorderAnchor) (anchorpkg.Backend, error) { return backend, nil }
	health := newEvidenceHealthMonitor(trig.recorder, trig.metrics, func() *receipt.Emitter { return trig.emitter }, func() *config.Config { return trig.cfg }, trig.logs)
	anchorDone := make(chan struct{})
	go func() {
		defer close(anchorDone)
		trig.monitor.runPass()
	}()
	select {
	case <-submitStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("auto-anchor submit did not start")
	}
	healthDone := make(chan struct{})
	go func() {
		defer close(healthDone)
		health.runPass()
	}()
	emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/during-anchor")
	close(releaseSubmit)
	select {
	case <-anchorDone:
	case <-time.After(2 * time.Second):
		t.Fatal("auto-anchor pass did not finish")
	}
	select {
	case <-healthDone:
	case <-time.After(2 * time.Second):
		t.Fatal("evidence-health pass did not finish")
	}

	trig.monitor.runPass()
	state, found, err := readAnchorStateForSession(trig.recorder.Dir())
	if err != nil || !found {
		t.Fatalf("read final concurrent anchor state = (%+v, %v, %v)", state, found, err)
	}
	receipts, err := receipt.ExtractReceiptsFromSessionDir(trig.recorder.Dir(), transcriptRootSessionID)
	if err != nil {
		t.Fatalf("ExtractReceiptsFromSessionDir: %v", err)
	}
	if state.ReceiptCount != uint64(len(receipts)) {
		t.Fatalf("concurrent anchor receipt count = %d, want complete live count %d", state.ReceiptCount, len(receipts))
	}
	assertAutoAnchorStats(t, trig.metrics, 2, 2, 0, "")
}

func TestAutoAnchorPassRecoversPanicAndRetriesOnCadence(t *testing.T) {
	t.Run("panic", func(t *testing.T) {
		trig := newAutoAnchorTestRig(t)
		trig.monitor.configFn = func() *config.Config { panic("test panic") }
		trig.monitor.runPass()
		assertAutoAnchorStats(t, trig.metrics, 0, 0, 1, "panic in auto-anchor pass")
		if !strings.Contains(trig.logs.String(), "CRITICAL: evidence auto-anchor failed") {
			t.Fatalf("panic stderr = %q, want CRITICAL", trig.logs.String())
		}
	})

	t.Run("reload_activation", func(t *testing.T) {
		trig := newAutoAnchorTestRig(t)
		emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/reload")
		inactive := *trig.cfg
		inactive.FlightRecorder.Anchor = config.FlightRecorderAnchor{}
		var configCalls atomic.Int64
		firstPass := make(chan struct{})
		trig.monitor.configFn = func() *config.Config {
			if configCalls.Add(1) == 1 {
				close(firstPass)
				return &inactive
			}
			return trig.cfg
		}
		submitted := make(chan struct{}, 1)
		backend := &countingAnchorBackend{onSubmit: func() { submitted <- struct{}{} }}
		trig.monitor.backendFn = func(config.FlightRecorderAnchor) (anchorpkg.Backend, error) { return backend, nil }
		restore := setAutoAnchorPollIntervalForTest(time.Millisecond)
		defer restore()
		ctx, cancel := context.WithCancel(t.Context())
		var wg sync.WaitGroup
		trig.monitor.start(ctx, &wg)
		select {
		case <-firstPass:
		case <-time.After(2 * time.Second):
			t.Fatal("initial inactive auto-anchor pass did not run")
		}
		select {
		case <-submitted:
		case <-time.After(2 * time.Second):
			t.Fatal("auto-anchor did not activate from live config on next cadence")
		}
		cancel()
		wg.Wait()
		if backend.submits.Load() != 1 {
			t.Fatalf("reload activation submits = %d, want 1", backend.submits.Load())
		}
	})

	t.Run("reload_add_then_remove", func(t *testing.T) {
		trig := newAutoAnchorTestRig(t)
		emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/reload-add-remove")
		active := trig.cfg.Clone()
		inactive := trig.cfg.Clone()
		inactive.FlightRecorder.Anchor = config.FlightRecorderAnchor{}
		var live atomic.Pointer[config.Config]
		live.Store(inactive)
		inactiveObserved := make(chan struct{}, 4)
		trig.monitor.configFn = func() *config.Config {
			cfg := live.Load()
			if !cfg.FlightRecorder.AnchorConfigured() {
				select {
				case inactiveObserved <- struct{}{}:
				default:
				}
			}
			return cfg
		}
		submitted := make(chan struct{}, 1)
		backend := &countingAnchorBackend{onSubmit: func() { submitted <- struct{}{} }}
		trig.monitor.backendFn = func(config.FlightRecorderAnchor) (anchorpkg.Backend, error) { return backend, nil }
		restore := setAutoAnchorPollIntervalForTest(time.Millisecond)
		defer restore()
		ctx, cancel := context.WithCancel(t.Context())
		var wg sync.WaitGroup
		trig.monitor.start(ctx, &wg)
		select {
		case <-inactiveObserved:
		case <-time.After(2 * time.Second):
			t.Fatal("inactive auto-anchor pass did not run")
		}
		live.Store(active)
		select {
		case <-submitted:
		case <-time.After(2 * time.Second):
			t.Fatal("auto-anchor did not activate after anchor-point addition")
		}
		live.Store(inactive)
		emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/after-anchor-removal")
		for range 2 {
			select {
			case <-inactiveObserved:
			case <-time.After(2 * time.Second):
				t.Fatal("auto-anchor did not observe anchor-point removal")
			}
		}
		cancel()
		wg.Wait()
		if backend.submits.Load() != 1 {
			t.Fatalf("reload add/remove submits = %d, want no submit after removal", backend.submits.Load())
		}
	})
}

func TestServerReloadAppliesOnlyFlightRecorderAnchorSubsection(t *testing.T) {
	s, stderr := newTestServer(t, nil)
	oldLive := s.proxy.CurrentConfig()
	oldLive.Mode = config.ModeBalanced
	updated := oldLive.Clone()
	updated.FlightRecorder.Anchor = config.FlightRecorderAnchor{
		LocalLog:         "/tmp/runtime-anchor-log.jsonl",
		LogID:            "reload-test-log",
		Interval:         "2h",
		ReceiptThreshold: uint64Pointer(25),
	}
	if err := s.Reload(updated); err != nil {
		t.Fatalf("Reload anchor addition: %v", err)
	}
	live := s.proxy.CurrentConfig()
	if !live.FlightRecorder.AnchorConfigured() || live.FlightRecorder.AnchorReceiptThreshold() != 25 {
		t.Fatalf("live anchor after addition = %+v, want active threshold 25", live.FlightRecorder.Anchor)
	}
	if stderr.contains("flight_recorder settings changed") {
		t.Fatalf("reload treated anchor subsection as restart-only:\n%s", stderr.String())
	}

	unchanged := live.Clone()
	if err := s.Reload(unchanged); err != nil {
		t.Fatalf("Reload unchanged anchor: %v", err)
	}
	removed := live.Clone()
	removed.FlightRecorder.Anchor = config.FlightRecorderAnchor{}
	if err := s.Reload(removed); err != nil {
		t.Fatalf("Reload anchor removal: %v", err)
	}
	if s.proxy.CurrentConfig().FlightRecorder.AnchorConfigured() {
		t.Fatalf("live anchor after removal = %+v, want inactive", s.proxy.CurrentConfig().FlightRecorder.Anchor)
	}
}

func TestAutoAnchorHelperBoundaries(t *testing.T) {
	if got := autoAnchorPollInterval(); got != autoAnchorPollCadence {
		t.Fatalf("default poll interval = %s, want %s", got, autoAnchorPollCadence)
	}
	restore := setAutoAnchorPollIntervalForTest(5 * time.Millisecond)
	if got := autoAnchorPollInterval(); got != 5*time.Millisecond {
		t.Fatalf("overridden poll interval = %s, want 5ms", got)
	}
	restore()

	var nilMonitor *autoAnchorMonitor
	nilMonitor.start(t.Context(), &sync.WaitGroup{})
	nilMonitor.runPass()
	nilMonitor.fail(nil)
	nilMonitor.fail(errors.New("ignored without sinks"))
	if nilMonitor.emitter() != nil {
		t.Fatal("nil monitor returned an emitter")
	}
	if nilMonitor.now().IsZero() {
		t.Fatal("nil monitor returned a zero current time")
	}
	(&autoAnchorMonitor{}).start(t.Context(), nil)
	(&autoAnchorMonitor{}).runPass()

	if _, err := autoAnchorTrustedKeys(nil, "key"); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty trusted-key derivation err = %v", err)
	}
	if _, err := autoAnchorTrustedKeys([]receipt.Receipt{{}}, ""); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("missing current signer err = %v", err)
	}
	trig := newAutoAnchorTestRig(t)
	emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/duplicate-key")
	receipts, err := receipt.ExtractReceiptsFromSessionDir(trig.recorder.Dir(), transcriptRootSessionID)
	if err != nil {
		t.Fatalf("ExtractReceiptsFromSessionDir: %v", err)
	}
	keys, err := autoAnchorTrustedKeys(receipts, trig.emitter.SignerKeyHex())
	if err != nil || len(keys) != 1 {
		t.Fatalf("trusted keys = %v, err=%v, want one distinct key", keys, err)
	}

	local, err := autoAnchorBackend(config.FlightRecorderAnchor{LocalLog: "/tmp/local-anchor.jsonl"})
	if err != nil {
		t.Fatalf("local backend: %v", err)
	}
	if _, ok := local.(anchorpkg.LocalLog); !ok {
		t.Fatalf("local backend type = %T", local)
	}
	for _, tc := range []struct {
		name string
		cfg  config.FlightRecorderAnchor
		want string
	}{
		{name: "none", want: "not configured"},
		{name: "both", cfg: config.FlightRecorderAnchor{RekorURL: "https://rekor.internal.example", LocalLog: "/tmp/log"}, want: "mutually exclusive"},
		{name: "missing_rekor_key", cfg: config.FlightRecorderAnchor{RekorURL: "https://rekor.internal.example", RekorKeyPath: "/definitely/missing"}, want: "load rekor signing key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := autoAnchorBackend(tc.cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("autoAnchorBackend err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestAutoAnchorAttemptFailurePaths(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*testing.T, *autoAnchorTestRig)
		want    string
	}{
		{name: "extract", prepare: func(_ *testing.T, trig *autoAnchorTestRig) {
			trig.monitor.extractFn = func(string, string) ([]receipt.Receipt, error) { return nil, errors.New("torn tail") }
		}, want: "extract live receipt chain"},
		{name: "backend_config", prepare: func(_ *testing.T, trig *autoAnchorTestRig) {
			trig.monitor.backendFn = func(config.FlightRecorderAnchor) (anchorpkg.Backend, error) {
				return nil, errors.New("backend unavailable")
			}
		}, want: "configure auto-anchor backend"},
		{name: "submit", prepare: func(_ *testing.T, trig *autoAnchorTestRig) {
			trig.monitor.backendFn = func(config.FlightRecorderAnchor) (anchorpkg.Backend, error) {
				return errorAnchorBackend{err: errors.New("log unavailable")}, nil
			}
		}, want: "submit live receipt checkpoint"},
		{name: "bundle", prepare: func(t *testing.T, trig *autoAnchorTestRig) {
			if err := os.WriteFile(filepath.Join(trig.recorder.Dir(), autoAnchorBundleDir), []byte("block"), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			trig.monitor.backendFn = func(config.FlightRecorderAnchor) (anchorpkg.Backend, error) { return &countingAnchorBackend{}, nil }
		}, want: "write live anchor bundle"},
		{name: "state_marker", prepare: func(t *testing.T, trig *autoAnchorTestRig) {
			if err := os.WriteFile(filepath.Join(trig.recorder.Dir(), "anchor-state.d"), []byte("block"), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			trig.monitor.seeded = true
			trig.monitor.backendFn = func(config.FlightRecorderAnchor) (anchorpkg.Backend, error) { return &countingAnchorBackend{}, nil }
		}, want: "write live anchor state"},
		{name: "checkpoint_not_advanced", prepare: func(t *testing.T, trig *autoAnchorTestRig) {
			receipts, err := receipt.ExtractReceiptsFromSessionDir(trig.recorder.Dir(), transcriptRootSessionID)
			if err != nil {
				t.Fatalf("ExtractReceiptsFromSessionDir: %v", err)
			}
			trig.monitor.seeded = true
			trig.monitor.hasLastAnchor = true
			trig.monitor.lastFinalSeq = 0
			trig.monitor.lastReceiptCount = 1
			trig.monitor.extractFn = func(string, string) ([]receipt.Receipt, error) { return receipts[:1], nil }
		}, want: "did not advance"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trig := newAutoAnchorTestRig(t)
			emitAutoAnchorReceipt(t, trig.emitter, "https://api.vendor.example/failure")
			tt.prepare(t, trig)
			trig.monitor.runPass()
			assertAutoAnchorStats(t, trig.metrics, 1, 0, 1, tt.want)
		})
	}
}

func newAutoAnchorTestRig(t *testing.T) *autoAnchorTestRig {
	t.Helper()
	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, MaxEntriesPerFile: 100, FileMode: 0o600}, nil, nil)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	m := metrics.New()
	emitter := receipt.NewEmitter(receipt.EmitterConfig{
		Recorder: rec, PrivKey: priv, ConfigHash: "runtime-auto-anchor-test",
		Principal: "tester", Actor: "runtime-test", Metrics: m,
	})
	if emitter == nil || emitter.InitError() != nil {
		t.Fatalf("NewEmitter = %v, init err = %v", emitter, emitter.InitError())
	}
	if err := emitter.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen: %v", err)
	}
	cfg := config.Defaults()
	cfg.FlightRecorder.Dir = dir
	cfg.FlightRecorder.Anchor.LocalLog = filepath.Join(dir, "local-anchor-log.jsonl")
	logs := &bytes.Buffer{}
	monitor := newAutoAnchorMonitor(rec, m, func() *receipt.Emitter { return emitter }, func() *config.Config { return cfg }, logs)
	return &autoAnchorTestRig{monitor: monitor, metrics: m, emitter: emitter, recorder: rec, cfg: cfg, logs: logs, priv: priv}
}

func newRotatedAutoAnchorChain(t *testing.T) (*recorder.Recorder, *receipt.Emitter, ed25519.PrivateKey, *config.Config, *metrics.Metrics, *bytes.Buffer, []receipt.Receipt) {
	t.Helper()
	dir := t.TempDir()
	_, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey A: %v", err)
	}
	recA, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, MaxEntriesPerFile: 100, FileMode: 0o600}, nil, nil)
	if err != nil {
		t.Fatalf("recorder.New A: %v", err)
	}
	emitterA := receipt.NewEmitter(receipt.EmitterConfig{Recorder: recA, PrivKey: privA, ConfigHash: "rotation-a", Principal: "tester", Actor: "runtime-test"})
	if err := emitterA.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen A: %v", err)
	}
	emitAutoAnchorReceipt(t, emitterA, "https://api.vendor.example/old-one")
	emitAutoAnchorReceipt(t, emitterA, "https://api.vendor.example/old-two")
	if err := recA.Close(); err != nil {
		t.Fatalf("Close recorder A: %v", err)
	}

	_, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey B: %v", err)
	}
	recB, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, MaxEntriesPerFile: 100, FileMode: 0o600}, nil, nil)
	if err != nil {
		t.Fatalf("recorder.New B: %v", err)
	}
	t.Cleanup(func() { _ = recB.Close() })
	m := metrics.New()
	emitterB := receipt.NewEmitter(receipt.EmitterConfig{Recorder: recB, PrivKey: privB, ConfigHash: "rotation-b", Principal: "tester", Actor: "runtime-test", Metrics: m})
	if emitterB == nil || emitterB.InitError() != nil {
		t.Fatalf("rotated NewEmitter = %v, init err = %v", emitterB, emitterB.InitError())
	}
	if err := emitterB.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen B: %v", err)
	}
	emitAutoAnchorReceipt(t, emitterB, "https://api.vendor.example/new")
	receipts, err := receipt.ExtractReceiptsFromSessionDir(dir, transcriptRootSessionID)
	if err != nil {
		t.Fatalf("ExtractReceiptsFromSessionDir: %v", err)
	}
	cfg := config.Defaults()
	cfg.FlightRecorder.Dir = dir
	cfg.FlightRecorder.Anchor.LocalLog = filepath.Join(dir, "rotated-anchor-log.jsonl")
	return recB, emitterB, privB, cfg, m, &bytes.Buffer{}, receipts
}

func autoAnchorRotationBoundary(t *testing.T, receipts []receipt.Receipt) int {
	t.Helper()
	for i := range receipts {
		if receipts[i].ActionRecord.KeyTransition != nil {
			return i
		}
	}
	t.Fatal("rotated receipt chain has no transition boundary")
	return -1
}

func writeForgedAutoAnchorState(t *testing.T, trig *autoAnchorTestRig, name string, checkpoint anchorpkg.Checkpoint) {
	t.Helper()
	bundleRel := filepath.ToSlash(filepath.Join(autoAnchorBundleDir, name))
	bundleBytes, err := anchorpkg.WriteBundleUnderDir(trig.recorder.Dir(), bundleRel, anchorpkg.NewBundle(checkpoint, anchorpkg.Proof{
		Backend: anchorpkg.LocalBackend,
		LogID:   "forged",
	}))
	if err != nil {
		t.Fatalf("WriteBundleUnderDir: %v", err)
	}
	bundleSum := sha256.Sum256(bundleBytes)
	if err := anchorpkg.WriteStateMarker(trig.recorder.Dir(), anchorpkg.StateMarker{
		SessionID:    checkpoint.SessionID,
		FinalSeq:     checkpoint.FinalSeq,
		RootHash:     checkpoint.RootHash,
		Backend:      anchorpkg.LocalBackend,
		AnchoredAt:   time.Now().UTC().Add(-time.Second),
		BundleSHA256: hex.EncodeToString(bundleSum[:]),
		BundlePath:   bundleRel,
	}); err != nil {
		t.Fatalf("WriteStateMarker: %v", err)
	}
}

func emitAutoAnchorReceipt(t *testing.T, emitter *receipt.Emitter, target string) {
	t.Helper()
	if err := emitter.Emit(receipt.EmitOpts{
		ActionID: receipt.NewActionID(), Verdict: config.ActionAllow,
		Transport: "fetch", Method: http.MethodGet, Target: target,
	}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
}

func assertAutoAnchorStats(t *testing.T, m *metrics.Metrics, attempts, successes, failures uint64, lastErrorContains string) {
	t.Helper()
	stats := m.EvidenceAutoAnchorStatsSnapshot()
	if stats.Attempts != attempts || stats.Successes != successes || stats.Failures != failures {
		t.Fatalf("auto-anchor stats = %+v, want attempts=%d successes=%d failures=%d", stats, attempts, successes, failures)
	}
	if !strings.Contains(stats.LastError, lastErrorContains) {
		t.Fatalf("auto-anchor last error = %q, want contains %q", stats.LastError, lastErrorContains)
	}
}

func uint64Pointer(value uint64) *uint64 { return &value }
