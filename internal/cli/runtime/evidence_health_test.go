// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestEvidenceHealthSelfAuditDurabilityInvariantLatchesAndEmits(t *testing.T) {
	t.Run("positive_divergence", func(t *testing.T) {
		h, m, e, _ := newEvidenceHealthTestMonitor(t, func(cfg *config.Config) {
			cfg.FlightRecorder.RequireReceipts = true
		})
		emitEvidenceHealthTestReceipt(t, e, "https://api.vendor.example/baseline")
		before, ok := e.HealthSnapshot()
		if !ok {
			t.Fatal("HealthSnapshot unavailable")
		}

		// Establish a standing fsync>blocks gap. The first pass sees the counters
		// change (not quiescent) and must not latch; the next pass sees them
		// unchanged (quiescent) with the gap surviving and must latch.
		recordEvidenceHealthDeltas(m, 2, 1)
		h.runPass()
		if !h.selfAuditOK.Load() {
			t.Fatal("durability pass latched selfaudit_ok before a quiescent interval")
		}
		h.runPass()

		assertEvidenceHealthLatched(t, h)
		assertSelfAuditFailures(t, m, "durability_invariant", 1)
		after, ok := e.HealthSnapshot()
		if !ok {
			t.Fatal("HealthSnapshot unavailable after violation")
		}
		if after.ChainSeq <= before.ChainSeq {
			t.Fatalf("violation was not emitted: chain seq before=%d after=%d", before.ChainSeq, after.ChainSeq)
		}

		// Latch is permanent and the violation does not re-fire on further
		// quiescent passes.
		h.runPass()
		assertEvidenceHealthLatched(t, h)
		assertSelfAuditFailures(t, m, "durability_invariant", 1)
	})

	t.Run("negative_divergence", func(t *testing.T) {
		h, m, e, _ := newEvidenceHealthTestMonitor(t, nil)
		emitEvidenceHealthTestReceipt(t, e, "https://api.vendor.example/baseline")

		// blocks > fsync is a durability block not backed by a storage failure.
		recordEvidenceHealthDeltas(m, 1, 2)
		h.runPass()
		h.runPass()

		assertEvidenceHealthLatched(t, h)
		assertSelfAuditFailures(t, m, "durability_invariant", 1)
	})

	t.Run("varying_magnitude_then_quiescent", func(t *testing.T) {
		h, m, e, _ := newEvidenceHealthTestMonitor(t, nil)
		emitEvidenceHealthTestReceipt(t, e, "https://api.vendor.example/baseline")

		// A persistent divergence whose per-pass magnitude varies never repeats an
		// identical delta, yet the standing gap must still latch once activity
		// stops. A per-pass-delta detector would miss this; the cumulative-gap
		// check does not.
		recordEvidenceHealthDeltas(m, 2, 0)
		h.runPass()
		recordEvidenceHealthDeltas(m, 3, 0)
		h.runPass()
		recordEvidenceHealthDeltas(m, 1, 0)
		h.runPass()
		if !h.selfAuditOK.Load() {
			t.Fatal("latched during active divergence before a quiescent interval")
		}
		h.runPass()
		assertEvidenceHealthLatched(t, h)
	})
}

func TestEvidenceHealthSelfAuditDurabilityInvariantNoFalsePositive(t *testing.T) {
	h, m, e, _ := newEvidenceHealthTestMonitor(t, nil)
	emitEvidenceHealthTestReceipt(t, e, "https://api.vendor.example/baseline")

	// Transient in-flight lag: fsync leads blocks during activity, then blocks
	// catch up so the counters are EQUAL at quiescence. This must not latch --
	// the invariant only fires on a gap that survives a quiet interval.
	recordEvidenceHealthDeltas(m, 2, 1)
	h.runPass()
	recordEvidenceHealthDeltas(m, 1, 2)
	h.runPass()
	h.runPass()

	if !h.selfAuditOK.Load() {
		t.Fatal("a divergence that resolved before quiescence latched selfaudit_ok")
	}
	assertSelfAuditFailures(t, m, "durability_invariant", 0)
}

func TestEvidenceHealthSelfAuditTailDivergenceLatches(t *testing.T) {
	h, m, e, priv := newEvidenceHealthTestMonitor(t, nil)
	emitEvidenceHealthTestReceipt(t, e, "https://api.vendor.example/alpha")
	staleDiskEmitter := receipt.NewEmitter(receipt.EmitterConfig{
		Recorder:   h.recorder,
		PrivKey:    priv,
		ConfigHash: "test-config-hash",
		Principal:  "tester",
		Actor:      "runtime-test",
		Metrics:    m,
	})
	if staleDiskEmitter == nil {
		t.Fatal("receipt.NewEmitter returned nil")
	}
	emitEvidenceHealthTestReceipt(t, staleDiskEmitter, "https://api.vendor.example/bravo")

	h.runPass()

	assertEvidenceHealthLatched(t, h)
	gaps, _ := m.EvidenceStatsCountersSnapshot()
	if gaps.SelfAudit != 1 {
		t.Fatalf("self-audit sequence gaps = %d, want 1", gaps.SelfAudit)
	}
	assertSelfAuditFailures(t, m, "tail_divergence", 1)
}

func TestEvidenceHealthSelfAuditSamplerErrorFailsClosedWithoutPanic(t *testing.T) {
	h, m, e, _ := newEvidenceHealthTestMonitor(t, nil)
	emitEvidenceHealthTestReceipt(t, e, "https://api.vendor.example/baseline")
	overwriteEvidenceHealthFile(t, h.recorder.Dir(), []byte("{not-json}\n"))

	h.runPass()

	assertEvidenceHealthLatched(t, h)
	assertSelfAuditFailures(t, m, "sampler_error", 1)
	stats, ok := h.stats()
	if !ok {
		t.Fatal("stats unavailable after sampler error")
	}
	if stats.Requirements[metrics.EvidenceRequirementSelfAuditOK] {
		t.Fatal("selfaudit_ok requirement = true after sampler error")
	}
	if stats.CurrentAEL != 0 {
		t.Fatalf("current AEL = %d, want 0 after sampler error", stats.CurrentAEL)
	}
	if stats.DurabilityBlocks != 0 {
		t.Fatalf("durability blocks = %d, want 0; self-audit must not gate traffic", stats.DurabilityBlocks)
	}
}

func TestEvidenceHealthSelfAuditUnavailableSnapshotIsUnmeasured(t *testing.T) {
	h, _, _, _ := newEvidenceHealthTestMonitor(t, nil)
	h.emitterFn = func() *receipt.Emitter { return nil }

	h.runPass()

	if _, ok := h.stats(); ok {
		t.Fatal("stats measured evidence health with unavailable emitter snapshot")
	}
	if !h.selfAuditOK.Load() {
		t.Fatal("unavailable emitter snapshot latched selfaudit_ok")
	}
}

func TestEvidenceHealthAnchorStateMalformedMarkersFailClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(anchorState) anchorState
	}{
		{
			name: "wrong_schema",
			mutate: func(state anchorState) anchorState {
				state.Schema = "pipelock.anchorstate.v0"
				return state
			},
		},
		{
			name: "wrong_session",
			mutate: func(state anchorState) anchorState {
				state.SessionID = "other"
				return state
			},
		},
		{
			name: "future_final_seq",
			mutate: func(state anchorState) anchorState {
				state.FinalSeq = 2
				return state
			},
		},
		{
			name: "future_anchored_at",
			mutate: func(state anchorState) anchorState {
				state.AnchoredAt = time.Now().UTC().Add(time.Hour)
				return state
			},
		},
		{
			name: "wrong_root_hash_shape",
			mutate: func(state anchorState) anchorState {
				state.RootHash = "not-a-hash"
				return state
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, m, e, _ := newEvidenceHealthTestMonitor(t, func(cfg *config.Config) {
				cfg.FlightRecorder.RequireReceipts = true
			})
			emitEvidenceHealthTestReceipt(t, e, "https://api.vendor.example/baseline")
			writeEvidenceHealthAnchorState(t, h.recorder.Dir(), tt.mutate(validEvidenceHealthAnchorState()))

			h.runPass()

			assertEvidenceHealthLatched(t, h)
			assertSelfAuditFailures(t, m, "sampler_error", 1)
			h.runPass()
			assertSelfAuditFailures(t, m, "sampler_error", 1)
			stats, ok := h.stats()
			if !ok {
				t.Fatal("stats unavailable")
			}
			if stats.Anchor != nil {
				t.Fatalf("malformed marker produced anchor stats: %+v", stats.Anchor)
			}
			if stats.Requirements[metrics.EvidenceRequirementAnchoringFresh] {
				t.Fatal("malformed marker made anchoring_fresh true")
			}
			if stats.CurrentAEL != 0 {
				t.Fatalf("current AEL = %d, want 0 after malformed marker", stats.CurrentAEL)
			}
		})
	}
}

func TestValidateAnchorStateMarkerRejectsMalformedFields(t *testing.T) {
	now := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)
	valid := anchorState{
		Schema:       "pipelock.anchorstate.v1",
		SessionID:    transcriptRootSessionID,
		FinalSeq:     1,
		RootHash:     strings.Repeat("a", 64),
		Backend:      "local",
		LogIndex:     1,
		AnchoredAt:   now.Add(-time.Second),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   "/tmp/pipelock-anchor-bundle.json",
	}
	tests := []struct {
		name   string
		mutate func(anchorState) anchorState
		want   string
	}{
		{
			name: "bad_root_hash_shape",
			mutate: func(state anchorState) anchorState {
				state.RootHash = strings.Repeat("A", 64)
				return state
			},
			want: "root_hash is invalid",
		},
		{
			name: "bad_bundle_hash_shape",
			mutate: func(state anchorState) anchorState {
				state.BundleSHA256 = "not-a-sha256"
				return state
			},
			want: "bundle_sha256 is invalid",
		},
		{
			name: "unsupported_backend",
			mutate: func(state anchorState) anchorState {
				state.Backend = "attacker-log"
				return state
			},
			want: "backend",
		},
		{
			name: "missing_anchored_at",
			mutate: func(state anchorState) anchorState {
				state.AnchoredAt = time.Time{}
				return state
			},
			want: "anchored_at is missing",
		},
		{
			name: "future_anchored_at",
			mutate: func(state anchorState) anchorState {
				state.AnchoredAt = now.Add(time.Second)
				return state
			},
			want: "in the future",
		},
		{
			name: "empty_bundle_path",
			mutate: func(state anchorState) anchorState {
				state.BundlePath = " \t"
				return state
			},
			want: "bundle_path is empty",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAnchorStateMarker(tt.mutate(valid), now)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validateAnchorStateMarker err = %v, want %q", err, tt.want)
			}
		})
	}
	if err := validateAnchorStateMarker(valid, now); err != nil {
		t.Fatalf("valid marker rejected: %v", err)
	}
}

func TestEvidenceHealthParserHelpersRejectMalformedInputs(t *testing.T) {
	for _, tt := range []struct {
		path string
		want uint64
	}{
		{path: "/tmp/evidence-proxy-42.jsonl", want: 42},
		{path: "/tmp/evidence-proxy-nope.jsonl", want: 0},
		{path: "/tmp/evidence-proxy.jsonl", want: 0},
		{path: "/tmp/evidence-proxy-7.txt", want: 0},
	} {
		if got := evidenceFileStartSeq(tt.path); got != tt.want {
			t.Fatalf("evidenceFileStartSeq(%q) = %d, want %d", tt.path, got, tt.want)
		}
	}

	dir := t.TempDir()
	noAction := filepath.Join(dir, "no-action.jsonl")
	if err := os.WriteFile(noAction, []byte("{\"type\":\"heartbeat\"}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile noAction: %v", err)
	}
	if _, err := readLastReceiptTailFromFile(noAction); !errors.Is(err, errNoReceiptTail) {
		t.Fatalf("readLastReceiptTailFromFile no-action err = %v, want errNoReceiptTail", err)
	}
	malformedOuter := filepath.Join(dir, "malformed-outer.jsonl")
	if err := os.WriteFile(malformedOuter, []byte("{not-json}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile malformedOuter: %v", err)
	}
	if _, err := readLastReceiptTailFromFile(malformedOuter); err == nil {
		t.Fatal("readLastReceiptTailFromFile malformed outer err = nil, want failure")
	}
	malformedDetail := filepath.Join(dir, "malformed-detail.jsonl")
	if err := os.WriteFile(malformedDetail, []byte(`{"type":"action_receipt","detail":"not-an-object"}`+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile malformedDetail: %v", err)
	}
	if _, err := readLastReceiptTailFromFile(malformedDetail); err == nil {
		t.Fatal("readLastReceiptTailFromFile malformed detail err = nil, want failure")
	}
	if _, err := readLastReceiptTailFromFile(filepath.Join(dir, "missing.jsonl")); err == nil {
		t.Fatal("readLastReceiptTailFromFile missing file err = nil, want failure")
	}
	if _, err := readLastReceiptTail(filepath.Join(dir, "missing-dir"), transcriptRootSessionID); !errors.Is(err, errNoReceiptTail) {
		t.Fatalf("readLastReceiptTail missing dir err = %v, want errNoReceiptTail", err)
	}
}

func TestReadLastReceiptTailFromFileLargeTailWindow(t *testing.T) {
	h, _, e, _ := newEvidenceHealthTestMonitor(t, nil)
	emitEvidenceHealthTestReceipt(t, e, "https://api.vendor.example/large-tail")
	source := evidenceHealthFile(t, h.recorder.Dir())
	data, err := os.ReadFile(filepath.Clean(source))
	if err != nil {
		t.Fatalf("ReadFile source evidence: %v", err)
	}

	path := filepath.Join(t.TempDir(), "large.jsonl")
	var big bytes.Buffer
	for big.Len() <= maxTailReadBytes+1024 {
		big.WriteString(`{"type":"heartbeat"}` + "\n")
	}
	big.Write(data)
	if err := os.WriteFile(path, big.Bytes(), 0o600); err != nil {
		t.Fatalf("WriteFile large tail: %v", err)
	}
	tail, err := readLastReceiptTailFromFile(path)
	if err != nil {
		t.Fatalf("readLastReceiptTailFromFile large tail: %v", err)
	}
	if tail.hash == "" {
		t.Fatalf("large tail hash is empty: %+v", tail)
	}
}

func TestReadAnchorStateStrictJSON(t *testing.T) {
	valid := validEvidenceHealthAnchorState()
	valid.AnchoredAt = time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)
	validData, err := json.Marshal(valid)
	if err != nil {
		t.Fatalf("Marshal valid anchor state: %v", err)
	}
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{name: "valid", data: append(validData, '\n')},
		{name: "duplicate", data: []byte(`{"schema":"pipelock.anchorstate.v1","schema":"pipelock.anchorstate.v1"}`), wantErr: true},
		{name: "unknown", data: []byte(`{"schema":"pipelock.anchorstate.v1","extra":true}`), wantErr: true},
		{name: "trailing", data: []byte(`{"schema":"pipelock.anchorstate.v1"} {"schema":"pipelock.anchorstate.v1"}`), wantErr: true},
		{name: "malformed", data: []byte(`{not-json}`), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "anchor-state.json")
			if err := os.WriteFile(path, tt.data, 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			got, err := readAnchorState(path)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("readAnchorState err = nil, want failure for %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("readAnchorState: %v", err)
			}
			if got.Schema != valid.Schema || got.BundleSHA256 != valid.BundleSHA256 {
				t.Fatalf("readAnchorState = %+v, want valid marker", got)
			}
		})
	}
	if _, err := readAnchorState(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("readAnchorState missing file err = nil, want failure")
	}
}

func TestEvidenceHealthNilGuardHelpers(t *testing.T) {
	var nilMonitor *evidenceHealthMonitor
	if got := nilMonitor.interval(); got != config.DefaultEvidenceHealthSelfAuditInterval {
		t.Fatalf("nil interval = %s, want default", got)
	}
	if got := nilMonitor.emitter(); got != nil {
		t.Fatalf("nil emitter = %+v, want nil", got)
	}
	if got := nilMonitor.currentConfig(); got != nil {
		t.Fatalf("nil currentConfig = %+v, want nil", got)
	}
	nilMonitor.emitViolation("durability_invariant")

	h := &evidenceHealthMonitor{}
	if got := h.interval(); got != config.DefaultEvidenceHealthSelfAuditInterval {
		t.Fatalf("missing config interval = %s, want default", got)
	}
	if got := h.fsyncStats(); got != (metrics.EvidenceFsyncStats{}) {
		t.Fatalf("nil metrics fsyncStats = %+v, want zero", got)
	}
	if got := h.gapStats(); got != (metrics.EvidenceGapStats{}) {
		t.Fatalf("nil metrics gapStats = %+v, want zero", got)
	}
	if _, ok := h.stats(); ok {
		t.Fatal("stats measured with missing recorder/config/emitter")
	}

	cfg := config.Defaults()
	cfg.FlightRecorder.EvidenceHealth.SelfAuditInterval = "2s"
	h.configFn = func() *config.Config { return cfg }
	if got := h.interval(); got != 5*time.Second {
		t.Fatalf("clamped interval = %s, want 5s", got)
	}
	h.configFn = func() *config.Config { return nil }
	if got := h.interval(); got != config.DefaultEvidenceHealthSelfAuditInterval {
		t.Fatalf("nil config interval = %s, want default", got)
	}
}

func TestEvidenceHealthAnchorStateValidMarkerCanOnlyUseAcceptedFreshness(t *testing.T) {
	h, _, e, _ := newEvidenceHealthTestMonitor(t, func(cfg *config.Config) {
		cfg.FlightRecorder.RequireReceipts = true
	})
	emitEvidenceHealthTestReceipt(t, e, "https://api.vendor.example/baseline")
	newer := validEvidenceHealthAnchorState()
	newer.FinalSeq = 1
	writeEvidenceHealthAnchorState(t, h.recorder.Dir(), newer)

	h.runPass()

	stats, ok := h.stats()
	if !ok {
		t.Fatal("stats unavailable")
	}
	if stats.Anchor == nil {
		t.Fatal("valid marker did not produce anchor stats")
	}
	if !stats.Requirements[metrics.EvidenceRequirementAnchoringFresh] {
		t.Fatal("valid fresh marker did not set anchoring_fresh")
	}
	if stats.CurrentAEL != 3 {
		t.Fatalf("current AEL = %d, want 3 for accepted fresh marker", stats.CurrentAEL)
	}

	older := validEvidenceHealthAnchorState()
	older.FinalSeq = 0
	older.AnchoredAt = time.Now().UTC().Add(-time.Hour)
	writeEvidenceHealthAnchorState(t, h.recorder.Dir(), older)
	h.runPass()
	afterOlder, ok := h.stats()
	if !ok {
		t.Fatal("stats unavailable after older marker")
	}
	if afterOlder.Anchor == nil || afterOlder.Anchor.LastTimestampSeconds != stats.Anchor.LastTimestampSeconds {
		t.Fatalf("older marker replaced newer anchor: before=%+v after=%+v", stats.Anchor, afterOlder.Anchor)
	}

	stale := validEvidenceHealthAnchorState()
	stale.FinalSeq = 1
	stale.AnchoredAt = time.Now().UTC().Add(-(config.DefaultEvidenceHealthMaxAnchorLag + time.Second))
	writeEvidenceHealthAnchorState(t, h.recorder.Dir(), stale)
	h.runPass()
	afterStale, ok := h.stats()
	if !ok {
		t.Fatal("stats unavailable after stale marker")
	}
	if afterStale.Anchor == nil {
		t.Fatal("valid stale marker did not produce anchor stats")
	}
	if afterStale.Requirements[metrics.EvidenceRequirementAnchoringFresh] {
		t.Fatal("valid stale marker set anchoring_fresh")
	}
	if afterStale.CurrentAEL != 2 {
		t.Fatalf("current AEL = %d, want 2 for stale marker", afterStale.CurrentAEL)
	}
}

func newEvidenceHealthTestMonitor(
	t *testing.T,
	mutate func(*config.Config),
) (*evidenceHealthMonitor, *metrics.Metrics, *receipt.Emitter, ed25519.PrivateKey) {
	t.Helper()
	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{
		Enabled:           true,
		Dir:               dir,
		MaxEntriesPerFile: 100,
		FileMode:          0o600,
	}, nil, nil)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	m := metrics.New()
	e := receipt.NewEmitter(receipt.EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: "test-config-hash",
		Principal:  "tester",
		Actor:      "runtime-test",
		Metrics:    m,
	})
	if e == nil {
		t.Fatal("receipt.NewEmitter returned nil")
	}
	cfg := config.Defaults()
	cfg.FlightRecorder.Dir = dir
	cfg.FlightRecorder.EvidenceHealth.SelfAuditInterval = "5s"
	if mutate != nil {
		mutate(cfg)
	}
	var logs bytes.Buffer
	h := newEvidenceHealthMonitor(rec, m, func() *receipt.Emitter { return e }, func() *config.Config { return cfg }, &logs)
	m.SetEvidenceHealthFunc(h.stats)
	return h, m, e, priv
}

func emitEvidenceHealthTestReceipt(t *testing.T, e *receipt.Emitter, target string) {
	t.Helper()
	if err := e.Emit(receipt.EmitOpts{
		ActionID:  receipt.NewActionID(),
		Verdict:   config.ActionAllow,
		Transport: "fetch",
		Method:    "GET",
		Target:    target,
	}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
}

func recordEvidenceHealthDeltas(m *metrics.Metrics, fsync, blocks int) {
	m.RecordFsyncError(true, fsync)
	for i := 0; i < blocks; i++ {
		m.RecordRequiredReceiptBlock("durability", "fetch")
	}
}

func overwriteEvidenceHealthFile(t *testing.T, dir string, data []byte) {
	t.Helper()
	if err := os.WriteFile(evidenceHealthFile(t, dir), data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func evidenceHealthFile(t *testing.T, dir string) string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "evidence-proxy-*.jsonl"))
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("evidence files = %v, want exactly one", matches)
	}
	return matches[0]
}

func validEvidenceHealthAnchorState() anchorState {
	return anchorState{
		Schema:       "pipelock.anchorstate.v1",
		SessionID:    transcriptRootSessionID,
		FinalSeq:     0,
		RootHash:     strings.Repeat("a", 64),
		Backend:      "local",
		LogIndex:     1,
		AnchoredAt:   time.Now().UTC().Add(-time.Second),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   "/tmp/pipelock-anchor-bundle.json",
	}
}

func writeEvidenceHealthAnchorState(t *testing.T, dir string, state anchorState) {
	t.Helper()
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, evidenceAnchorStateFile), append(data, '\n'), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func assertEvidenceHealthLatched(t *testing.T, h *evidenceHealthMonitor) {
	t.Helper()
	if h.selfAuditOK.Load() {
		t.Fatal("selfaudit_ok = true, want latched false")
	}
	stats, ok := h.stats()
	if !ok {
		t.Fatal("stats unavailable")
	}
	if stats.Requirements[metrics.EvidenceRequirementSelfAuditOK] {
		t.Fatal("selfaudit_ok requirement = true, want false")
	}
	if stats.CurrentAEL != 0 {
		t.Fatalf("current AEL = %d, want 0", stats.CurrentAEL)
	}
}

func assertSelfAuditFailures(t *testing.T, m *metrics.Metrics, check string, want float64) {
	t.Helper()
	if got := evidenceMetricValue(t, m, "pipelock_evidence_selfaudit_failures_total", map[string]string{"check": check}); got != want {
		t.Fatalf("selfaudit_failures_total{check=%q} = %v, want %v", check, got, want)
	}
}

func evidenceMetricValue(t *testing.T, m *metrics.Metrics, name string, labels map[string]string) float64 {
	t.Helper()
	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			if metricLabelsMatch(metric, labels) {
				switch family.GetType() {
				case dto.MetricType_COUNTER:
					return metric.GetCounter().GetValue()
				case dto.MetricType_GAUGE:
					return metric.GetGauge().GetValue()
				default:
					t.Fatalf("unsupported metric type for %s: %s", name, family.GetType())
				}
			}
		}
		return 0
	}
	return 0
}

func metricLabelsMatch(metric *dto.Metric, labels map[string]string) bool {
	for wantName, wantValue := range labels {
		found := false
		for _, label := range metric.GetLabel() {
			if label.GetName() == wantName && label.GetValue() == wantValue {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
