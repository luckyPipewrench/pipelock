// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	anchorpkg "github.com/luckyPipewrench/pipelock/internal/anchor"
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
			state := tt.mutate(validEvidenceHealthAnchorState())
			state.SignerKey = e.SignerKeyHex()
			writeEvidenceHealthAnchorState(t, h.recorder.Dir(), state)

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

func TestReadAnchorStateFilesystemGuards(t *testing.T) {
	valid := validEvidenceHealthAnchorState()
	valid.AnchoredAt = time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)
	validData, err := json.Marshal(valid)
	if err != nil {
		t.Fatalf("Marshal valid anchor state: %v", err)
	}

	tests := []struct {
		name    string
		setup   func(t *testing.T, dir string) string
		wantErr string
	}{
		{
			name: "symlink",
			setup: func(t *testing.T, dir string) string {
				t.Helper()
				if runtime.GOOS == "windows" {
					t.Skip("symlink creation needs privileges on Windows")
				}
				target := filepath.Join(dir, "target-anchor-state.json")
				if err := os.WriteFile(target, append(validData, '\n'), 0o600); err != nil {
					t.Fatalf("WriteFile target: %v", err)
				}
				link := filepath.Join(dir, evidenceAnchorStateFile)
				if err := os.Symlink(filepath.Base(target), link); err != nil {
					t.Fatalf("Symlink anchor state: %v", err)
				}
				return link
			},
			wantErr: "not a regular file",
		},
		{
			name: "non regular",
			setup: func(t *testing.T, dir string) string {
				t.Helper()
				path := filepath.Join(dir, evidenceAnchorStateFile)
				if err := os.Mkdir(path, 0o750); err != nil {
					t.Fatalf("Mkdir anchor state: %v", err)
				}
				return path
			},
			wantErr: "not a regular file",
		},
		{
			name: "oversized",
			setup: func(t *testing.T, dir string) string {
				t.Helper()
				path := filepath.Join(dir, evidenceAnchorStateFile)
				if err := os.WriteFile(path, make([]byte, maxEvidenceAnchorStateBytes+1), 0o600); err != nil {
					t.Fatalf("WriteFile oversized anchor state: %v", err)
				}
				return path
			},
			wantErr: "exceeds size limit",
		},
		{
			name: "valid",
			setup: func(t *testing.T, dir string) string {
				t.Helper()
				path := filepath.Join(dir, evidenceAnchorStateFile)
				if err := os.WriteFile(path, append(validData, '\n'), 0o600); err != nil {
					t.Fatalf("WriteFile valid anchor state: %v", err)
				}
				return path
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readAnchorState(tc.setup(t, t.TempDir()))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("readAnchorState err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("readAnchorState: %v", err)
			}
			if got.SessionID != valid.SessionID || got.BundleSHA256 != valid.BundleSHA256 {
				t.Fatalf("readAnchorState = %+v, want valid marker", got)
			}
		})
	}
}

func TestReadAnchorStateForSessionHandlesConflicts(t *testing.T) {
	t.Run("legacy session mismatch fails closed", func(t *testing.T) {
		dir := t.TempDir()
		state := validEvidenceHealthAnchorState()
		state.SessionID = "different-session"
		writeEvidenceHealthAnchorState(t, dir, state)
		if _, found, err := readAnchorStateForSession(dir); err == nil || found || !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("readAnchorStateForSession found=%v err=%v, want session mismatch", found, err)
		}
	})

	t.Run("corrupt legacy pointer is counted once", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, evidenceAnchorStateFile), []byte(`{"schema":`), 0o600); err != nil {
			t.Fatalf("WriteFile corrupt legacy pointer: %v", err)
		}
		if _, found, skipped, err := readAnchorStateForSessionWithSkipped(dir, transcriptRootSessionID); err == nil || found || skipped != 1 {
			t.Fatalf("corrupt legacy pointer = (found=%v, skipped=%d, err=%v), want one skipped file and error", found, skipped, err)
		}
	})

	t.Run("ambiguous lower history does not wedge latest", func(t *testing.T) {
		dir := t.TempDir()
		firstState := validEvidenceHealthAnchorState()
		firstState.FinalSeq = 1
		first := anchorStateToMarker(writeEvidenceHealthAnchorBundle(t, dir, firstState))
		if err := anchorpkg.WriteStateMarker(dir, first); err != nil {
			t.Fatalf("WriteStateMarker first: %v", err)
		}
		higherState := firstState
		higherState.FinalSeq = 2
		higherState.RootHash = strings.Repeat("c", 64)
		higher := anchorStateToMarker(writeEvidenceHealthAnchorBundle(t, dir, higherState))
		if err := anchorpkg.WriteStateMarker(dir, higher); err != nil {
			t.Fatalf("WriteStateMarker higher: %v", err)
		}
		conflictingLowerState := firstState
		conflictingLowerState.RootHash = strings.Repeat("e", 64)
		conflictingLower := anchorStateToMarker(writeEvidenceHealthAnchorBundle(t, dir, conflictingLowerState))
		if err := anchorpkg.WriteStateMarker(dir, conflictingLower); err != nil {
			t.Fatalf("WriteStateMarker conflicting lower: %v", err)
		}

		got, found, err := readAnchorStateForSession(dir)
		if err != nil || !found || got.FinalSeq != higher.FinalSeq || got.RootHash != higher.RootHash {
			t.Fatalf("readAnchorStateForSession = (%+v, %v, %v), want unaffected higher pointer", got, found, err)
		}
	})

	t.Run("verified conflict at the highest coverage fails closed", func(t *testing.T) {
		dir := t.TempDir()
		// Two bundle-backed markers at the same highest coverage with different
		// roots. The write path blocks this, so plant the index entries directly to
		// exercise the read. There is no valid pointer, so the resilient scan runs.
		for _, rootByte := range []string{"c", "e"} {
			s := validEvidenceHealthAnchorState()
			s.FinalSeq = 2
			s.RootHash = strings.Repeat(rootByte, 64)
			marker := anchorStateToMarker(writeEvidenceHealthAnchorBundle(t, dir, s))
			marker.Schema = "pipelock.anchorstate.v1"
			path, err := anchorpkg.StateMarkerPath(dir, marker)
			if err != nil {
				t.Fatalf("StateMarkerPath: %v", err)
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
				t.Fatalf("MkdirAll index: %v", err)
			}
			data, err := json.Marshal(marker)
			if err != nil {
				t.Fatalf("Marshal marker: %v", err)
			}
			if err := os.WriteFile(filepath.Clean(path), append(data, '\n'), 0o600); err != nil {
				t.Fatalf("WriteFile marker: %v", err)
			}
		}
		if state, found, _, err := readAnchorStateForSessionWithSkipped(dir, transcriptRootSessionID); err == nil || found {
			t.Fatalf("verified max-coverage conflict = (%+v, found=%v, err=%v), want fail closed", state, found, err)
		}
	})

	t.Run("ambiguous recovery candidates are all skipped", func(t *testing.T) {
		dir := t.TempDir()
		indexDir := filepath.Join(dir, "anchor-state.d")
		if err := os.Mkdir(indexDir, 0o750); err != nil {
			t.Fatalf("Mkdir index: %v", err)
		}
		for i, rootByte := range []string{"a", "b", "c"} {
			marker := anchorStateToMarker(validEvidenceHealthAnchorState())
			marker.FinalSeq = 1
			marker.RootHash = strings.Repeat(rootByte, 64)
			marker.BundleSHA256 = strings.Repeat(string(rune('d'+i)), 64)
			path, err := anchorpkg.StateMarkerPath(dir, marker)
			if err != nil {
				t.Fatalf("StateMarkerPath: %v", err)
			}
			marker.Schema = "pipelock.anchorstate.v1"
			data, err := json.Marshal(marker)
			if err != nil {
				t.Fatalf("Marshal marker: %v", err)
			}
			if err := os.WriteFile(filepath.Clean(path), append(data, '\n'), 0o600); err != nil {
				t.Fatalf("WriteFile marker: %v", err)
			}
		}
		state, found, skipped, err := readAnchorStateForSessionWithSkipped(dir, transcriptRootSessionID)
		if err != nil || found || skipped != 3 {
			t.Fatalf("ambiguous recovery = (%+v, %v, %d, %v), want no selection and three skipped", state, found, skipped, err)
		}
	})

	t.Run("hostile index structure fails closed", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Symlink(t.TempDir(), filepath.Join(dir, "anchor-state.d")); err != nil {
			t.Fatalf("Symlink index: %v", err)
		}
		if _, found, _, err := readAnchorStateForSessionWithSkipped(dir, transcriptRootSessionID); err == nil || found {
			t.Fatalf("readAnchorStateForSessionWithSkipped found=%v err=%v, want structural failure", found, err)
		}
	})

	t.Run("maximum sequence coverage does not overflow", func(t *testing.T) {
		if got := anchorStateCoverage(anchorState{FinalSeq: math.MaxUint64}); got != math.MaxUint64 {
			t.Fatalf("anchorStateCoverage = %d, want MaxUint64", got)
		}
	})
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
	emitEvidenceHealthTestReceipt(t, e, "https://api.vendor.example/current-head")
	newer := validEvidenceHealthAnchorState()
	newer.FinalSeq = 1
	newer.SignerKey = e.SignerKeyHex()
	writeEvidenceHealthAnchorState(t, h.recorder.Dir(), newer)

	h.runPass()

	stats, ok := h.stats()
	if !ok {
		t.Fatal("stats unavailable")
	}
	if stats.Anchor == nil {
		t.Fatal("valid marker did not produce anchor stats")
	}
	if stats.AnchorLagReceipts != 0 || stats.Anchor.LagReceipts != 0 {
		t.Fatalf("fully covered chain anchor lag = %d/%d, want zero", stats.AnchorLagReceipts, stats.Anchor.LagReceipts)
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
	older.SignerKey = e.SignerKeyHex()
	older = writeEvidenceHealthAnchorBundle(t, h.recorder.Dir(), older)
	if err := anchorpkg.WriteStateMarker(h.recorder.Dir(), anchorStateToMarker(older)); err != nil {
		t.Fatalf("WriteStateMarker older: %v", err)
	}
	h.runPass()
	afterOlder, ok := h.stats()
	if !ok {
		t.Fatal("stats unavailable after older marker")
	}
	if afterOlder.Anchor == nil || afterOlder.Anchor.LastTimestampSeconds != stats.Anchor.LastTimestampSeconds {
		t.Fatalf("older marker replaced newer anchor: before=%+v after=%+v", stats.Anchor, afterOlder.Anchor)
	}

	staleMonitor, _, staleEmitter, _ := newEvidenceHealthTestMonitor(t, func(cfg *config.Config) {
		cfg.FlightRecorder.RequireReceipts = true
	})
	emitEvidenceHealthTestReceipt(t, staleEmitter, "https://api.vendor.example/stale-baseline")
	emitEvidenceHealthTestReceipt(t, staleEmitter, "https://api.vendor.example/stale-current-head")
	stale := validEvidenceHealthAnchorState()
	stale.FinalSeq = 1
	stale.AnchoredAt = time.Now().UTC().Add(-(config.DefaultEvidenceHealthMaxAnchorLag + time.Second))
	stale.SignerKey = staleEmitter.SignerKeyHex()
	writeEvidenceHealthAnchorState(t, staleMonitor.recorder.Dir(), stale)
	staleMonitor.runPass()
	afterStale, ok := staleMonitor.stats()
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

func TestEvidenceHealthReadsIndexedAnchorStateMarkers(t *testing.T) {
	h, _, e, _ := newEvidenceHealthTestMonitor(t, func(cfg *config.Config) {
		cfg.FlightRecorder.RequireReceipts = true
	})
	emitEvidenceHealthTestReceipt(t, e, "https://api.vendor.example/baseline")
	emitEvidenceHealthTestReceipt(t, e, "https://api.vendor.example/current-head")
	if _, err := os.Stat(filepath.Join(h.recorder.Dir(), evidenceAnchorStateFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy anchor-state presence err = %v, want absent legacy marker", err)
	}

	older := validEvidenceHealthAnchorState()
	older.FinalSeq = 0
	older.SignerKey = e.SignerKeyHex()
	older = writeEvidenceHealthAnchorBundle(t, h.recorder.Dir(), older)
	if err := anchorpkg.WriteStateMarker(h.recorder.Dir(), anchorStateToMarker(older)); err != nil {
		t.Fatalf("WriteStateMarker older: %v", err)
	}
	newer := validEvidenceHealthAnchorState()
	newer.FinalSeq = 1
	newer.RootHash = strings.Repeat("c", 64)
	newer.SignerKey = e.SignerKeyHex()
	newer = writeEvidenceHealthAnchorBundle(t, h.recorder.Dir(), newer)
	if err := anchorpkg.WriteStateMarker(h.recorder.Dir(), anchorStateToMarker(newer)); err != nil {
		t.Fatalf("WriteStateMarker newer: %v", err)
	}

	h.runPass()

	stats, ok := h.stats()
	if !ok {
		t.Fatal("stats unavailable")
	}
	if stats.Anchor == nil {
		t.Fatal("indexed anchor-state marker did not produce anchor stats")
	}
	if stats.Anchor.FinalSeq != newer.FinalSeq || stats.Anchor.RootHash != newer.RootHash {
		t.Fatalf("anchor stats = %+v, want latest indexed marker final_seq/root", stats.Anchor)
	}
	if !stats.Requirements[metrics.EvidenceRequirementAnchoringFresh] {
		t.Fatal("fresh indexed marker did not set anchoring_fresh")
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
	state = writeEvidenceHealthAnchorBundle(t, dir, state)
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, evidenceAnchorStateFile), append(data, '\n'), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func writeEvidenceHealthAnchorBundle(t *testing.T, dir string, state anchorState) anchorState {
	t.Helper()
	identity := sha256.Sum256([]byte(state.SessionID + "\x00" + strconv.FormatUint(state.FinalSeq, 10) + "\x00" + state.RootHash + "\x00" + state.AnchoredAt.String()))
	state.BundlePath = filepath.ToSlash(filepath.Join("test-anchor-bundles", hex.EncodeToString(identity[:])+".json"))
	checkpoint := anchorpkg.Checkpoint{
		SessionID:    state.SessionID,
		FinalSeq:     state.FinalSeq,
		RootHash:     state.RootHash,
		ReceiptCount: state.FinalSeq + 1,
		SignerKeys:   []string{state.SignerKey},
	}
	if state.SignerKey == "" {
		checkpoint.SignerKeys[0] = strings.Repeat("c", 64)
	}
	data, err := anchorpkg.WriteBundleUnderDir(dir, state.BundlePath, anchorpkg.NewBundle(checkpoint, anchorpkg.Proof{
		Backend:  state.Backend,
		LogIndex: state.LogIndex,
	}))
	if err != nil {
		t.Fatalf("WriteBundleUnderDir: %v", err)
	}
	sum := sha256.Sum256(data)
	state.BundleSHA256 = hex.EncodeToString(sum[:])
	return state
}

func anchorStateToMarker(state anchorState) anchorpkg.StateMarker {
	return anchorpkg.StateMarker{
		Schema:       state.Schema,
		SessionID:    state.SessionID,
		FinalSeq:     state.FinalSeq,
		RootHash:     state.RootHash,
		Backend:      state.Backend,
		LogIndex:     state.LogIndex,
		AnchoredAt:   state.AnchoredAt,
		BundleSHA256: state.BundleSHA256,
		BundlePath:   state.BundlePath,
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

// TestEvidenceHealthFileStatsDegradesSafely covers the file-count sampler's
// defensive paths. The sampler feeds metrics, not enforcement, so a nil monitor
// or an unreadable evidence directory must still return well-formed stats
// carrying the real thresholds. Returning zeroed thresholds would make a
// dashboard read "0 of 0 files" and look healthy while the sampler is blind.
func TestEvidenceHealthFileStatsDegradesSafely(t *testing.T) {
	t.Parallel()

	t.Run("nil_monitor_returns_thresholds", func(t *testing.T) {
		t.Parallel()
		var h *evidenceHealthMonitor
		got := h.fileStats(config.Defaults())
		if got.MaxFilesPerSession != recorder.MaxEvidenceReadDirectoryEntries {
			t.Fatalf("MaxFilesPerSession = %d, want %d",
				got.MaxFilesPerSession, recorder.MaxEvidenceReadDirectoryEntries)
		}
		if got.WarningThreshold != recorder.EvidenceFileWarningThreshold {
			t.Fatalf("WarningThreshold = %d, want %d",
				got.WarningThreshold, recorder.EvidenceFileWarningThreshold)
		}
	})

	t.Run("nil_config_returns_thresholds", func(t *testing.T) {
		t.Parallel()
		h := &evidenceHealthMonitor{}
		got := h.fileStats(nil)
		if got.MaxFilesPerSession != recorder.MaxEvidenceReadDirectoryEntries {
			t.Fatalf("MaxFilesPerSession = %d, want %d",
				got.MaxFilesPerSession, recorder.MaxEvidenceReadDirectoryEntries)
		}
	})

	t.Run("unreadable_dir_degrades_sampler_without_latching_self_audit", func(t *testing.T) {
		t.Parallel()
		// A regular file where a directory is expected makes the scan fail.
		// Build the recorder against a real directory, then remove it so the
		// later sampler read fails. recorder.New validates the directory up
		// front, so the failure has to be introduced after construction.
		dir := filepath.Join(t.TempDir(), "recorder")
		if err := os.Mkdir(dir, 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir}, nil, nil)
		if err != nil {
			t.Fatalf("recorder.New: %v", err)
		}
		defer func() { _ = rec.Close() }()
		if err := os.RemoveAll(dir); err != nil {
			t.Fatalf("remove dir: %v", err)
		}

		// Real sinks, so a regression that drops the warning or the metric is
		// caught rather than passing on a nil-sink no-op.
		var logBuf bytes.Buffer
		m := metrics.New()
		h := &evidenceHealthMonitor{recorder: rec, metrics: m, logW: &logBuf}
		h.selfAuditOK.Store(true)
		got := h.fileStats(config.Defaults())
		if got.MaxFilesPerSession != recorder.MaxEvidenceReadDirectoryEntries {
			t.Fatalf("thresholds lost on sampler error: %+v", got)
		}
		if got.TotalEvidenceFiles != 0 {
			t.Fatalf("TotalEvidenceFiles = %d, want 0 on sampler error", got.TotalEvidenceFiles)
		}
		// The decision this test exists to pin: a metrics-only file-count scan
		// failure must not latch the integrity self-audit off. Conflating the
		// two would leave a permanently degraded integrity signal behind a
		// transient read error, with no way to tell it from a real chain fault.
		if !h.selfAuditOK.Load() {
			t.Fatal("a sampler read failure latched selfAuditOK off; it is a measurement failure, not an integrity finding")
		}
		if !strings.Contains(logBuf.String(), "file-count sampler unavailable") {
			t.Fatalf("operator was not warned about the sampler failure: %q", logBuf.String())
		}
		if got := samplerErrorCount(t, m); got != 1 {
			t.Fatalf("selfaudit_failures_total{check=sampler_error} = %v, want 1", got)
		}
	})
}

// samplerErrorCount reads the sampler_error self-audit counter out of the
// metrics registry. The counter fields are unexported, so this gathers from the
// registry the same way a scrape would.
func samplerErrorCount(t *testing.T, m *metrics.Metrics) float64 {
	t.Helper()
	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, f := range families {
		if !strings.Contains(f.GetName(), "selfaudit_failures") {
			continue
		}
		for _, metric := range f.GetMetric() {
			for _, label := range metric.GetLabel() {
				if label.GetValue() == "sampler_error" {
					return metric.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}
