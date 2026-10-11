// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"

	anchorpkg "github.com/luckyPipewrench/pipelock/internal/anchor"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// shardedHealthRig is a live recorder with one or more receipt chains and an
// evidence health monitor wired the way server startup wires it.
type shardedHealthRig struct {
	h        *evidenceHealthMonitor
	m        *metrics.Metrics
	rec      *recorder.Recorder
	key      ed25519.PrivateKey
	shards   *receipt.ReceiptShardSet
	emitters []*receipt.Emitter
	logs     *bytes.Buffer
	cfg      *config.Config
}

func newShardedHealthRig(t *testing.T, chains int) *shardedHealthRig {
	t.Helper()
	return newShardedHealthRigWithProcess(t, chains, 0)
}

func newShardedHealthRigWithProcess(t *testing.T, chains, processIndex int) *shardedHealthRig {
	t.Helper()
	return newShardedHealthRigFull(t, chains, processIndex, 40)
}

func newShardedHealthRigWithLimit(t *testing.T, chains, maxEntries int) *shardedHealthRig {
	t.Helper()
	return newShardedHealthRigFull(t, chains, 0, maxEntries)
}

func newShardedHealthRigFull(t *testing.T, chains, processIndex, maxEntries int) *shardedHealthRig {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{
		Enabled:           true,
		Dir:               dir,
		MaxEntriesPerFile: maxEntries,
		FileMode:          0o600,
		SignCheckpoints:   true,
	}, nil, key)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	m := metrics.New()
	rig := &shardedHealthRig{m: m, rec: rec, key: key, logs: &bytes.Buffer{}}
	var process func() *receipt.Emitter
	if chains == 1 {
		session, err := acquireRunSession(rec)
		if err != nil {
			t.Fatal(err)
		}
		e := receipt.NewEmitter(receipt.EmitterConfig{
			Recorder: rec, PrivKey: key, ConfigHash: strings.Repeat("a", 64),
			Principal: "local", Actor: "pipelock", Metrics: m, Session: session,
		})
		if e == nil {
			t.Fatal("receipt.NewEmitter returned nil")
		}
		rig.emitters = []*receipt.Emitter{e}
		process = func() *receipt.Emitter { return e }
	} else {
		shards, err := receipt.OpenInitialReceiptShardSet(receipt.EmitterConfig{
			Recorder: rec, PrivKey: key, ConfigHash: strings.Repeat("a", 64),
			Principal: "local", Actor: "pipelock", Metrics: m,
		}, recorder.DefaultSessionBase, chains, processIndex)
		if err != nil {
			t.Fatalf("OpenInitialReceiptShardSet: %v", err)
		}
		rig.shards = shards
		rig.emitters = shards.Emitters()
		process = shards.ProcessEmitter
	}
	cfg := config.Defaults()
	cfg.FlightRecorder.Dir = dir
	cfg.FlightRecorder.EvidenceHealth.SelfAuditInterval = "5s"
	rig.cfg = cfg
	rig.h = newEvidenceHealthMonitor(rec, m, process, func() *config.Config { return cfg }, rig.logs)
	if rig.shards != nil {
		rig.h.withShards(rig.shards.Emitters)
	}
	m.SetEvidenceHealthFunc(rig.h.stats)
	return rig
}

// emit writes one action receipt through the production admission path: a
// group selects the shard once, a single chain writes directly.
func (r *shardedHealthRig) emit(t *testing.T, target string) {
	t.Helper()
	opts := receipt.EmitOpts{
		ActionID: receipt.NewActionID(), Verdict: config.ActionAllow,
		Transport: "fetch", Method: "GET", Target: target,
	}
	var err error
	if r.shards != nil {
		err = r.shards.Emit(r.shards.Admit(opts))
	} else {
		err = r.emitters[0].Emit(opts)
	}
	if err != nil {
		t.Errorf("emit %s: %v", target, err)
	}
}

func (r *shardedHealthRig) assertNotLatched(t *testing.T) {
	t.Helper()
	if !r.h.selfAuditOK.Load() {
		t.Fatalf("self-audit latched a false failure; log:\n%s", r.logs.String())
	}
	if got := evidenceMetricValue(t, r.m, "pipelock_evidence_selfaudit_failures_total", map[string]string{"check": "tail_divergence"}); got != 0 {
		t.Fatalf("tail_divergence failures = %v, want 0; log:\n%s", got, r.logs.String())
	}
}

func (r *shardedHealthRig) stats(t *testing.T) metrics.EvidenceHealthStats {
	t.Helper()
	stats, ok := r.h.stats()
	if !ok {
		t.Fatal("evidence health stats unavailable")
	}
	return stats
}

// TestEvidenceHealthEachChainComparedWithItsOwnSession reproduces the
// multi-chain false CRITICAL deterministically. The recorder's own session
// binding is not the identity of any one chain: between writes it rests on
// the first shard, and during a write it names whichever shard is writing.
// Joining the process chain's head with that binding compared one chain's
// head with another chain's tail and latched selfaudit_ok for the process
// lifetime. Here the process chain is shard 1 while the binding rests on
// shard 0, so the old join fails on every pass rather than only when a pass
// lands inside another shard's write.
func TestEvidenceHealthEachChainComparedWithItsOwnSession(t *testing.T) {
	rig := newShardedHealthRigWithProcess(t, 2, 1)
	rig.emit(t, "https://api.vendor.example/first")
	rig.emit(t, "https://api.vendor.example/second")
	rig.emit(t, "https://api.vendor.example/third")
	if rig.rec.SessionID() == rig.shards.ProcessEmitter().Session() {
		t.Fatal("fixture: recorder binding already names the process chain")
	}

	rig.h.runPass()

	rig.assertNotLatched(t)
	stats := rig.stats(t)
	if stats.SelfAudit.State != metrics.EvidenceSelfAuditVerified {
		t.Fatalf("self-audit state = %q, want verified: %+v", stats.SelfAudit.State, stats.SelfAudit.Shards)
	}
	if len(stats.SelfAudit.Shards) != 2 {
		t.Fatalf("shard observations = %d, want 2", len(stats.SelfAudit.Shards))
	}
	for i, shard := range stats.SelfAudit.Shards {
		if shard.SessionID != rig.emitters[i].Session() || shard.ShardIndex != i {
			t.Fatalf("shard %d observation = %+v, want its own session %q", i, shard, rig.emitters[i].Session())
		}
	}
	if !stats.LocalRecorderOperational {
		t.Fatal("healthy multi-chain recorder reported non-operational")
	}
}

// TestEvidenceHealthConcurrentLoadNeverFalselyLatches runs the self-audit
// continuously while every chain is being written, at 1, 2 and 8 chains.
func TestEvidenceHealthConcurrentLoadNeverFalselyLatches(t *testing.T) {
	for _, chains := range []int{1, 2, 8} {
		t.Run(fmt.Sprintf("chains=%d", chains), func(t *testing.T) {
			rig := newShardedHealthRig(t, chains)
			const writers, perWriter = 4, 60
			var wg sync.WaitGroup
			done := make(chan struct{})
			for w := 0; w < writers; w++ {
				wg.Add(1)
				go func(w int) {
					defer wg.Done()
					for i := 0; i < perWriter; i++ {
						rig.emit(t, fmt.Sprintf("https://api.vendor.example/w%d/%d", w, i))
					}
				}(w)
			}
			auditDone := make(chan struct{})
			go func() {
				defer close(auditDone)
				for {
					select {
					case <-done:
						return
					default:
						rig.h.runPass()
						_, _ = rig.h.stats()
					}
				}
			}()
			wg.Wait()
			close(done)
			<-auditDone

			rig.h.runPass()
			rig.assertNotLatched(t)
			stats := rig.stats(t)
			if stats.SelfAudit.State != metrics.EvidenceSelfAuditVerified {
				t.Fatalf("quiescent self-audit state = %q, want verified: %+v", stats.SelfAudit.State, stats.SelfAudit.Shards)
			}
			var total uint64
			for _, shard := range stats.SelfAudit.Shards {
				total += shard.ChainHeadSeq
			}
			if want := uint64(writers * perWriter); total < want {
				t.Fatalf("receipts across chains = %d, want at least %d", total, want)
			}
		})
	}
}

// TestEvidenceHealthMissingTailIsPendingNotGreen deletes a chain's evidence
// after it claimed receipts. That is not proof of corruption (and must not
// latch), but it is not healthy either.
func TestEvidenceHealthMissingTailIsPendingNotGreen(t *testing.T) {
	rig := newShardedHealthRig(t, 1)
	rig.emit(t, "https://api.vendor.example/one")
	rig.h.runPass()
	if state := rig.stats(t).SelfAudit.State; state != metrics.EvidenceSelfAuditVerified {
		t.Fatalf("baseline state = %q, want verified", state)
	}
	removeSessionEvidence(t, rig.rec.Dir(), rig.emitters[0].Session())

	rig.h.runPass()

	rig.assertNotLatched(t)
	stats := rig.stats(t)
	if stats.SelfAudit.State != metrics.EvidenceSelfAuditPending {
		t.Fatalf("state after evidence removal = %q, want pending", stats.SelfAudit.State)
	}
	if stats.LocalRecorderOperational {
		t.Fatal("missing evidence reported as operational")
	}
	if detail := stats.SelfAudit.Shards[0].TailDetail; !strings.Contains(detail, "no action receipt") && !strings.Contains(detail, "missing") {
		t.Fatalf("tail detail = %q, want missing receipt explanation", stats.SelfAudit.Shards[0].TailDetail)
	}
}

// TestEvidenceHealthUnverifiedChainIsPending covers the window before the
// first pass: stats are not green until the chain was compared with disk.
func TestEvidenceHealthUnverifiedChainIsPending(t *testing.T) {
	rig := newShardedHealthRig(t, 2)
	rig.emit(t, "https://api.vendor.example/one")
	stats := rig.stats(t)
	if stats.SelfAudit.State != metrics.EvidenceSelfAuditPending || stats.LocalRecorderOperational {
		t.Fatalf("pre-audit state = %q operational=%v, want pending and not operational", stats.SelfAudit.State, stats.LocalRecorderOperational)
	}
}

// TestEvidenceHealthUnhealthyNonProcessShard: a runtime health failure on any
// chain, not only the process chain, is part of health.
func TestEvidenceHealthUnhealthyNonProcessShard(t *testing.T) {
	rig := newShardedHealthRig(t, 2)
	rig.emit(t, "https://api.vendor.example/one")
	rig.h.runPass()
	rig.emitters[1].MarkUnhealthy(errors.New("shard storage failed"))

	stats := rig.stats(t)
	if stats.Requirements[metrics.EvidenceRequirementEmitterHealthy] {
		t.Fatal("emitter_healthy = true with an unhealthy shard")
	}
	if stats.LocalRecorderOperational {
		t.Fatal("recorder operational with an unhealthy shard")
	}
	if stats.SelfAudit.Shards[1].EmitterHealthy || !stats.SelfAudit.Shards[0].EmitterHealthy {
		t.Fatalf("per-shard emitter health = %+v, want only shard 1 unhealthy", stats.SelfAudit.Shards)
	}
}

// TestEvidenceHealthPoisonedSingleChainIsReported: the single-chain path had
// the same gap; HealthError was ignored entirely.
func TestEvidenceHealthPoisonedSingleChainIsReported(t *testing.T) {
	rig := newShardedHealthRig(t, 1)
	rig.emit(t, "https://api.vendor.example/one")
	rig.h.runPass()
	rig.emitters[0].MarkUnhealthy(errors.New("heartbeat failed"))
	if rig.stats(t).LocalRecorderOperational {
		t.Fatal("poisoned emitter reported operational")
	}
}

func TestEvidenceHealthEqualSeqDifferentHashLatches(t *testing.T) {
	rig := newShardedHealthRig(t, 2)
	rig.emit(t, "https://api.vendor.example/one")
	rig.emit(t, "https://api.vendor.example/two")
	rewriteLastReceipt(t, rig.rec.Dir(), rig.emitters[1].Session(), func(r *receipt.Receipt) {
		r.ActionRecord.Target = "https://api.vendor.example/altered"
	})

	rig.h.runPass()

	assertEvidenceHealthLatched(t, rig.h)
	assertSelfAuditFailures(t, rig.m, "tail_divergence", 1)
	stats := rig.stats(t)
	if stats.SelfAudit.State != metrics.EvidenceSelfAuditFailed || stats.SelfAudit.Shards[1].TailState != metrics.EvidenceSelfAuditFailed {
		t.Fatalf("self-audit = %+v, want shard 1 failed", stats.SelfAudit)
	}
	if stats.SelfAudit.Shards[0].TailState != metrics.EvidenceSelfAuditVerified {
		t.Fatalf("intact shard 0 tail state = %q, want verified", stats.SelfAudit.Shards[0].TailState)
	}
}

func TestEvidenceHealthDiskBehindHeadLatches(t *testing.T) {
	rig := newShardedHealthRig(t, 1)
	rig.emit(t, "https://api.vendor.example/one")
	rig.emit(t, "https://api.vendor.example/two")
	dropLastReceiptLine(t, rig.rec.Dir(), rig.emitters[0].Session())

	rig.h.runPass()

	assertEvidenceHealthLatched(t, rig.h)
	assertSelfAuditFailures(t, rig.m, "tail_divergence", 1)
	if detail := rig.stats(t).SelfAudit.Shards[0].TailDetail; !strings.Contains(detail, "does not match the newest written receipt") {
		t.Fatalf("tail detail = %q, want the disk/written mismatch", detail)
	}
}

// TestEvidenceHealthLargeReceiptIsVerified writes a receipt well beyond the
// old 64 KiB tail window; the self-audit must still find and verify it.
func TestEvidenceHealthLargeReceiptIsVerified(t *testing.T) {
	rig := newShardedHealthRig(t, 1)
	rig.emit(t, "https://api.vendor.example/"+strings.Repeat("a", 100_000))

	rig.h.runPass()

	rig.assertNotLatched(t)
	if state := rig.stats(t).SelfAudit.State; state != metrics.EvidenceSelfAuditVerified {
		t.Fatalf("state with a 100k-character receipt = %q, want verified", state)
	}
}

// TestEvidenceHealthReloadSwapRestartsVerification: a new emitter instance for
// the same chain (hot reload) is not covered by the old instance's verdict.
func TestEvidenceHealthReloadSwapRestartsVerification(t *testing.T) {
	rig := newShardedHealthRig(t, 1)
	rig.emit(t, "https://api.vendor.example/one")
	rig.h.runPass()
	reloaded := receipt.NewEmitter(receipt.EmitterConfig{
		Recorder: rig.rec, PrivKey: rig.key, ConfigHash: strings.Repeat("b", 64),
		Principal: "local", Actor: "pipelock", Metrics: rig.m, Session: rig.emitters[0].Session(),
	})
	if reloaded == nil || reloaded.InitError() != nil {
		t.Fatalf("reloaded emitter failed to resume: %v", reloaded.InitError())
	}
	rig.h.emitterFn = func() *receipt.Emitter { return reloaded }
	if state := rig.stats(t).SelfAudit.State; state != metrics.EvidenceSelfAuditPending {
		t.Fatalf("state for a swapped emitter before audit = %q, want pending", state)
	}
	if err := reloaded.Emit(receipt.EmitOpts{ActionID: receipt.NewActionID(), Verdict: config.ActionAllow, Transport: "fetch", Method: "GET", Target: "https://api.vendor.example/two"}); err != nil {
		t.Fatal(err)
	}
	rig.h.runPass()
	rig.assertNotLatched(t)
	if state := rig.stats(t).SelfAudit.State; state != metrics.EvidenceSelfAuditVerified {
		t.Fatalf("state after audit of reloaded emitter = %q, want verified", state)
	}
}

// TestEvidenceHealthAnchorFreshnessCoversEveryChain: one chain's anchor does
// not make the set anchored.
func TestEvidenceHealthAnchorFreshnessCoversEveryChain(t *testing.T) {
	rig := newShardedHealthRig(t, 2)
	rig.emit(t, "https://api.vendor.example/one")
	rig.emit(t, "https://api.vendor.example/two")
	state := validEvidenceHealthAnchorState()
	state.SessionID = rig.emitters[0].Session()
	state.FinalSeq = 0
	state = writeEvidenceHealthAnchorBundle(t, rig.rec.Dir(), state)
	writeEvidenceHealthAnchorState(t, rig.rec.Dir(), state)

	rig.h.runPass()

	stats := rig.stats(t)
	if stats.Requirements[metrics.EvidenceRequirementAnchoringFresh] {
		t.Fatal("anchoring_fresh = true while shard 1 has no anchor")
	}
	if stats.Anchor != nil {
		t.Fatalf("top-level anchor = %+v, want nil while a chain is unanchored", stats.Anchor)
	}
	if stats.SelfAudit.Shards[0].AnchoredFinalSeq == nil || stats.SelfAudit.Shards[1].AnchoredFinalSeq != nil {
		t.Fatalf("per-shard anchors = %+v, want only shard 0 anchored", stats.SelfAudit.Shards)
	}
	if stats.AnchorLagReceipts < stats.SelfAudit.Shards[1].ChainHeadSeq {
		t.Fatalf("anchor lag = %d, want at least unanchored shard 1 head %d", stats.AnchorLagReceipts, stats.SelfAudit.Shards[1].ChainHeadSeq)
	}
}

func TestLastReceiptInTailIgnoresFragments(t *testing.T) {
	rig := newShardedHealthRig(t, 1)
	rig.emit(t, "https://api.vendor.example/one")
	file := sessionEvidenceFiles(t, rig.rec.Dir(), rig.emitters[0].Session())
	data, err := os.ReadFile(file[len(file)-1])
	if err != nil {
		t.Fatal(err)
	}
	want, ok, err := lastReceiptInTail(data, false)
	if err != nil || !ok {
		t.Fatalf("complete tail: ok=%v err=%v", ok, err)
	}

	t.Run("append in progress", func(t *testing.T) {
		withPartial := append(append([]byte(nil), data...), []byte(`{"type":"action_receipt","detail":{"trunc`)...)
		got, ok, err := lastReceiptInTail(withPartial, false)
		if err != nil || !ok || got.seq != want.seq || got.hash != want.hash {
			t.Fatalf("partial trailing line: got=%+v ok=%v err=%v, want %+v", got, ok, err, want)
		}
	})
	t.Run("read began mid-line", func(t *testing.T) {
		got, ok, err := lastReceiptInTail(append([]byte(`ragment-of-a-line"}`+"\n"), data...), true)
		if err != nil || !ok || got.seq != want.seq || got.hash != want.hash {
			t.Fatalf("leading fragment: got=%+v ok=%v err=%v, want %+v", got, ok, err, want)
		}
	})
	t.Run("no complete line", func(t *testing.T) {
		if _, ok, err := lastReceiptInTail([]byte(`{"type":"action_rec`), false); ok || err != nil {
			t.Fatalf("lone fragment: ok=%v err=%v, want nothing found", ok, err)
		}
	})
	t.Run("complete malformed line", func(t *testing.T) {
		_, _, err := lastReceiptInTail(append(append([]byte(nil), data...), []byte("{not-json}\n")...), false)
		if !errors.Is(err, errReceiptTailCorrupt) {
			t.Fatalf("malformed complete line err = %v, want errReceiptTailCorrupt", err)
		}
	})
}

// TestReadLastReceiptTailNewerFileWithoutReceipt: after rotation the newest
// file may hold only paired decision entries; the tail is the previous file's
// last receipt, found only after the newer file was read whole.
func TestReadLastReceiptTailNewerFileWithoutReceipt(t *testing.T) {
	rig := newShardedHealthRig(t, 1)
	rig.emit(t, "https://api.vendor.example/one")
	session := rig.emitters[0].Session()
	want, err := readLastReceiptTail(rig.rec.Dir(), session)
	if err != nil {
		t.Fatal(err)
	}
	newer := filepath.Join(rig.rec.Dir(), fmt.Sprintf("evidence-%s-%d.jsonl", session, 1_000_000))
	if err := os.WriteFile(newer, []byte(`{"type":"proxy_decision","detail":{}}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readLastReceiptTail(rig.rec.Dir(), session)
	if err != nil || got.seq != want.seq || got.hash != want.hash {
		t.Fatalf("tail with decision-only newer file = %+v err=%v, want %+v", got, err, want)
	}
}

// TestReadLastReceiptTailBeyondBoundIsPending: when the newest receipt lies
// further back than the self-audit reads, the chain is unverified rather than
// scanned without limit.
func TestReadLastReceiptTailBeyondBoundIsPending(t *testing.T) {
	rig := newShardedHealthRigWithLimit(t, 1, 3)
	rig.emit(t, "https://api.vendor.example/one")
	for i := 0; i < 6*maxTailFallbackFiles; i++ {
		if err := rig.rec.Record(recorder.Entry{SessionID: rig.emitters[0].Session(), Type: "test_padding", Summary: fmt.Sprintf("pad %d", i)}); err != nil {
			t.Fatalf("padding entry: %v", err)
		}
	}

	rig.h.runPass()

	rig.assertNotLatched(t)
	stats := rig.stats(t)
	if stats.SelfAudit.State != metrics.EvidenceSelfAuditPending || !strings.Contains(stats.SelfAudit.Shards[0].TailDetail, "read bound") {
		t.Fatalf("self-audit = %+v, want pending beyond the read bound", stats.SelfAudit)
	}
}

// TestReadLastReceiptTailChangedFileIsPending: a file that shrank or was
// replaced during the read leaves the chain unverified rather than keeping an
// earlier verdict, and does not latch.
func TestReadLastReceiptTailChangedFileIsPending(t *testing.T) {
	rig := newShardedHealthRig(t, 1)
	rig.emit(t, "https://api.vendor.example/one")
	rig.h.runPass()
	obs := rig.h.observeShards()[0]
	if before := rig.h.tailState(obs); before.state != metrics.EvidenceSelfAuditVerified {
		t.Fatalf("baseline = %+v, want verified", before)
	}
	rig.h.applyTailReadError(obs, fmt.Errorf("%w: x", errReceiptTailChanged))
	if after := rig.h.tailState(obs); after.state != metrics.EvidenceSelfAuditPending {
		t.Fatalf("after changed-file read = %+v, want pending", after)
	}
	rig.assertNotLatched(t)
}

func sessionEvidenceFiles(t *testing.T, dir, session string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, entry := range entries {
		if parsed, _, ok := recorder.ParseEvidenceFilename(entry.Name()); ok && parsed == session {
			files = append(files, filepath.Join(dir, entry.Name()))
		}
	}
	sort.Slice(files, func(i, j int) bool { return evidenceFileStartSeq(files[i]) < evidenceFileStartSeq(files[j]) })
	if len(files) == 0 {
		t.Fatalf("no evidence files for session %q", session)
	}
	return files
}

func removeSessionEvidence(t *testing.T, dir, session string) {
	t.Helper()
	for _, file := range sessionEvidenceFiles(t, dir, session) {
		if err := os.Remove(file); err != nil {
			t.Fatal(err)
		}
	}
}

// lastReceiptLine returns the newest session file and the index of its last
// action_receipt line.
func lastReceiptLine(t *testing.T, dir, session string) (string, [][]byte, int) {
	t.Helper()
	files := sessionEvidenceFiles(t, dir, session)
	for f := len(files) - 1; f >= 0; f-- {
		data, err := os.ReadFile(files[f])
		if err != nil {
			t.Fatal(err)
		}
		lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n"))
		for i := len(lines) - 1; i >= 0; i-- {
			if bytes.Contains(lines[i], []byte(`"type":"action_receipt"`)) {
				return files[f], lines, i
			}
		}
	}
	t.Fatalf("no action receipt for session %q", session)
	return "", nil, 0
}

func writeLines(t *testing.T, path string, lines [][]byte) {
	t.Helper()
	if err := os.WriteFile(path, append(bytes.Join(lines, []byte("\n")), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func rewriteLastReceipt(t *testing.T, dir, session string, mutate func(*receipt.Receipt)) {
	t.Helper()
	path, lines, idx := lastReceiptLine(t, dir, session)
	var entry map[string]json.RawMessage
	if err := json.Unmarshal(lines[idx], &entry); err != nil {
		t.Fatal(err)
	}
	var rcpt receipt.Receipt
	if err := json.Unmarshal(entry["detail"], &rcpt); err != nil {
		t.Fatal(err)
	}
	mutate(&rcpt)
	detail, err := json.Marshal(rcpt)
	if err != nil {
		t.Fatal(err)
	}
	entry["detail"] = detail
	if lines[idx], err = json.Marshal(entry); err != nil {
		t.Fatal(err)
	}
	writeLines(t, path, lines)
}

func dropLastReceiptLine(t *testing.T, dir, session string) {
	t.Helper()
	path, lines, idx := lastReceiptLine(t, dir, session)
	writeLines(t, path, append(lines[:idx:idx], lines[idx+1:]...))
}

// TestServerEvidenceMonitorsCoverEveryChain checks the startup wiring: the
// self-audit observes every chain, and a receipt group gets no anchor loop
// because config validation refuses auto-anchoring with several chains.
func TestServerEvidenceMonitorsCoverEveryChain(t *testing.T) {
	for _, chains := range []int{1, 4} {
		t.Run(fmt.Sprintf("chains=%d", chains), func(t *testing.T) {
			rig := newShardedHealthRig(t, chains)
			rig.emit(t, "https://api.vendor.example/one")
			s := &Server{recorder: rig.rec, metrics: rig.m, cfg: rig.cfg, receiptShardSet: rig.shards, receiptEmitter: rig.h.emitter()}
			s.opts.Stderr = rig.logs
			health, anchor := s.evidenceMonitors(rig.cfg)
			if health == nil {
				t.Fatal("evidence health monitor not built")
			}
			observed := health.observeShards()
			if len(observed) != chains {
				t.Fatalf("observed chains=%d, want %d", len(observed), chains)
			}
			for i, obs := range observed {
				if obs.session != rig.emitters[i].Session() {
					t.Fatalf("chain %d audit session %q, want %q", i, obs.session, rig.emitters[i].Session())
				}
			}
			if (anchor != nil) != (chains == 1) {
				t.Fatalf("anchor loop built=%v for %d chains, want only for one chain", anchor != nil, chains)
			}
		})
	}
}

// TestServerStartEvidenceMonitorsRunsSelfAudit drives the startup entry point
// itself: the self-audit must have run over every chain and published its
// stats, not merely been constructed.
func TestServerStartEvidenceMonitorsRunsSelfAudit(t *testing.T) {
	rig := newShardedHealthRig(t, 4)
	for i := 0; i < 8; i++ {
		rig.emit(t, fmt.Sprintf("https://api.vendor.example/%d", i))
	}
	m := metrics.New()
	s := &Server{recorder: rig.rec, metrics: m, cfg: rig.cfg, receiptShardSet: rig.shards, receiptEmitter: rig.h.emitter()}
	s.opts.Stderr = rig.logs
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	s.startEvidenceMonitors(ctx, &wg, rig.cfg)
	cancel()
	wg.Wait()
	stats, ok := m.EvidenceHealthStatsSnapshot()
	if !ok {
		t.Fatal("startup published no evidence health")
	}
	if stats.SelfAudit.State != metrics.EvidenceSelfAuditVerified || len(stats.SelfAudit.Shards) != 4 {
		t.Fatalf("startup self-audit = %+v, want 4 verified chains", stats.SelfAudit)
	}
}

// TestEvidenceHealthWriterReplacedMidPassDoesNotLatch: a hot reload or signer
// rotation can replace a chain's writer between the first snapshot and the
// disk read. The comparison spans two writers and must decide nothing.
func TestEvidenceHealthWriterReplacedMidPassDoesNotLatch(t *testing.T) {
	rig := newShardedHealthRig(t, 1)
	rig.emit(t, "https://api.vendor.example/one")
	obs := rig.h.observeShards()[0]
	replacement := receipt.NewEmitter(receipt.EmitterConfig{
		Recorder: rig.rec, PrivKey: rig.key, ConfigHash: strings.Repeat("b", 64),
		Principal: "local", Actor: "pipelock", Metrics: rig.m, Session: rig.emitters[0].Session(),
	})
	if replacement == nil || replacement.InitError() != nil {
		t.Fatal("replacement emitter failed to resume")
	}
	for i := 0; i < 3; i++ {
		if err := replacement.Emit(receipt.EmitOpts{ActionID: receipt.NewActionID(), Verdict: config.ActionAllow, Transport: "fetch", Method: "GET", Target: "https://api.vendor.example/next"}); err != nil {
			t.Fatal(err)
		}
	}
	rig.h.emitterFn = func() *receipt.Emitter { return replacement }

	rig.h.checkShardTail(obs)
	rig.h.refreshShardAnchor(obs)

	rig.assertNotLatched(t)
	rig.h.runPass()
	rig.assertNotLatched(t)
	if state := rig.stats(t).SelfAudit.State; state != metrics.EvidenceSelfAuditVerified {
		t.Fatalf("state after auditing the replacement = %q, want verified", state)
	}
}

// TestEvidenceHealthAuthenticReplayAtTailFails: a receipt with a valid
// signature is not the chain's head unless it is exactly the receipt the
// chain last wrote. Replaying an earlier authentic receipt over the newest one
// is a divergence, however it is signed.
func TestEvidenceHealthAuthenticReplayAtTailFails(t *testing.T) {
	rig := newShardedHealthRig(t, 1)
	rig.emit(t, "https://api.vendor.example/one")
	rig.emit(t, "https://api.vendor.example/two")
	session := rig.emitters[0].Session()
	path, lines, idx := lastReceiptLine(t, rig.rec.Dir(), session)
	earlier := -1
	for i := idx - 1; i >= 0; i-- {
		if bytes.Contains(lines[i], []byte(`"type":"action_receipt"`)) {
			earlier = i
			break
		}
	}
	if earlier < 0 {
		t.Fatal("fixture: no earlier receipt to replay")
	}
	lines[idx] = append([]byte(nil), lines[earlier]...)
	writeLines(t, path, lines)

	rig.h.runPass()

	assertEvidenceHealthLatched(t, rig.h)
	if state := rig.stats(t).SelfAudit.State; state != metrics.EvidenceSelfAuditFailed {
		t.Fatalf("state with a replayed authentic tail = %q, want failed", state)
	}
}

// TestEvidenceHealthUnconfirmedWriteIsAGap: a receipt whose position was
// assigned but whose write was not confirmed leaves the chain head ahead of
// what was written, and the next check reports it. The check covers the
// newest receipt only: a later successful receipt moves the comparison past
// the gap, which offline verification of the whole chain still finds.
func TestEvidenceHealthUnconfirmedWriteIsAGap(t *testing.T) {
	rig := newShardedHealthRig(t, 1)
	rig.emit(t, "https://api.vendor.example/one")
	rig.h.runPass()
	rig.rec.SetSyncForTest(func(*os.File) error { return errors.New("injected sync failure") })
	if err := rig.emitters[0].EmitDurable(receipt.EmitOpts{
		ActionID: receipt.NewActionID(), Verdict: config.ActionAllow,
		Transport: "fetch", Method: "GET", Target: "https://api.vendor.example/lost",
	}); !errors.Is(err, receipt.ErrReceiptPostAdvance) {
		t.Fatalf("EmitDurable = %v, want a post-advance failure", err)
	}
	rig.rec.SetSyncForTest(nil)

	rig.h.runPass()

	assertEvidenceHealthLatched(t, rig.h)
	stats := rig.stats(t)
	if stats.SelfAudit.State != metrics.EvidenceSelfAuditFailed || !strings.Contains(stats.SelfAudit.Shards[0].TailDetail, "not confirmed") {
		t.Fatalf("self-audit = %+v, want failed for the unconfirmed receipt", stats.SelfAudit)
	}
}

// TestEvidenceHealthAppendDuringReadStillVerifies: the comparison reads only
// the evidence written before the observation, so a receipt appended while
// the tail is read cannot move it.
func TestEvidenceHealthAppendDuringReadStillVerifies(t *testing.T) {
	rig := newShardedHealthRig(t, 1)
	rig.emit(t, "https://api.vendor.example/one")
	obs := rig.h.observeShards()[0]
	view, err := obs.emitter.TailObservation()
	if err != nil {
		t.Fatal(err)
	}
	rig.emit(t, "https://api.vendor.example/two")
	tail, err := readLastReceiptTailBefore(rig.rec.Dir(), obs.session, view.WriteFile, view.WriteEnd)
	if err != nil {
		t.Fatal(err)
	}
	if tail.seq != view.PersistedSeq || tail.hash != view.PersistedHash {
		t.Fatalf("prefix tail = %d/%s, want the observed receipt %d/%s", tail.seq, tail.hash, view.PersistedSeq, view.PersistedHash)
	}
	rig.h.checkShardTail(obs)
	rig.assertNotLatched(t)
}

// TestEvidenceHealthConcurrentAnchorIsJudgedAgainstCurrentHead: the anchor
// loop can anchor receipts written after the health pass took its snapshot.
// That marker is ahead of the old snapshot, not of the chain.
func TestEvidenceHealthConcurrentAnchorIsJudgedAgainstCurrentHead(t *testing.T) {
	rig := newShardedHealthRig(t, 1)
	rig.emit(t, "https://api.vendor.example/one")
	obs := rig.h.observeShards()[0]
	rig.emit(t, "https://api.vendor.example/two")
	rig.emit(t, "https://api.vendor.example/three")
	state := validEvidenceHealthAnchorState()
	state.SessionID = obs.session
	state.FinalSeq = 2
	state.SignerKey = rig.emitters[0].SignerKeyHex()
	state = writeEvidenceHealthAnchorBundle(t, rig.rec.Dir(), state)
	writeEvidenceHealthAnchorState(t, rig.rec.Dir(), state)

	rig.h.refreshShardAnchor(obs)

	rig.assertNotLatched(t)
	if anchor := rig.h.anchorFor(obs.session); anchor == nil || anchor.FinalSeq != 2 {
		t.Fatalf("anchor = %+v, want the concurrent marker at final_seq 2", anchor)
	}
}

// TestEvidenceHealthUnreadableAnchorStateIsRecoverable: losing read access to
// the anchor markers is a measurement gap. It must not latch, and health
// recovers when access returns.
func TestEvidenceHealthUnreadableAnchorStateIsRecoverable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission denial does not apply to root")
	}
	rig := newShardedHealthRig(t, 1)
	rig.emit(t, "https://api.vendor.example/one")
	state := validEvidenceHealthAnchorState()
	state.SessionID = rig.emitters[0].Session()
	state.SignerKey = rig.emitters[0].SignerKeyHex()
	state = writeEvidenceHealthAnchorBundle(t, rig.rec.Dir(), state)
	marker := anchorStateToMarker(state)
	marker.ReceiptCount = state.FinalSeq + 1
	marker.SignerKey = state.SignerKey
	if err := anchorpkg.WriteStateMarker(rig.rec.Dir(), marker); err != nil {
		t.Fatalf("WriteStateMarker: %v", err)
	}
	rig.h.runPass()
	if rig.h.anchorFor(rig.emitters[0].Session()) == nil {
		t.Fatal("fixture: anchor not read before access was removed")
	}
	index := filepath.Join(rig.rec.Dir(), "anchor-state.d")
	if err := os.Chmod(index, 0); err != nil {
		t.Fatal(err)
	}
	rig.h.runPass()
	if err := syscall.Chmod(index, 0o750); err != nil {
		t.Fatal(err)
	}
	rig.assertNotLatched(t)
	rig.h.runPass()
	rig.assertNotLatched(t)
	if rig.h.anchorFor(rig.emitters[0].Session()) == nil {
		t.Fatal("anchor not recovered after access returned")
	}
}

// TestEvidenceHealthForeignCountIsPerWriter: each reload's replacement writes
// its opening receipt before it goes live, so each live writer can see one
// foreign newest receipt. Successive writers must not add their single
// checks up into a divergence.
func TestEvidenceHealthForeignCountIsPerWriter(t *testing.T) {
	rig := newShardedHealthRig(t, 1)
	rig.emit(t, "https://api.vendor.example/one")
	rig.h.runPass()
	live := rig.emitters[0]
	for i := 0; i < 2*maxForeignTailPasses; i++ {
		next := receipt.NewEmitter(receipt.EmitterConfig{
			Recorder: rig.rec, PrivKey: rig.key, ConfigHash: strings.Repeat("c", 64),
			Principal: "local", Actor: "pipelock", Metrics: rig.m, Session: live.Session(),
		})
		if next == nil || next.InitError() != nil {
			t.Fatal("replacement writer failed to resume")
		}
		if err := next.EmitSessionOpen(); err != nil {
			t.Fatalf("replacement %d open: %v", i, err)
		}
		current := live
		rig.h.emitterFn = func() *receipt.Emitter { return current }
		rig.h.runPass() // the old writer is live; the newest receipt is the replacement's
		rig.assertNotLatched(t)
		live = next
	}
	final := live
	rig.h.emitterFn = func() *receipt.Emitter { return final }
	rig.h.runPass()
	rig.assertNotLatched(t)
	if state := rig.stats(t).SelfAudit.State; state != metrics.EvidenceSelfAuditVerified {
		t.Fatalf("state for the last writer = %q, want verified", state)
	}
}

// TestEvidenceHealthReplacedWriterFailureDoesNotLatchSuccessor: a check that
// observed a writer before it was replaced reaches no irreversible verdict
// about the chain, even when that writer's last write was not confirmed.
func TestEvidenceHealthReplacedWriterFailureDoesNotLatchSuccessor(t *testing.T) {
	rig := newShardedHealthRig(t, 1)
	rig.emit(t, "https://api.vendor.example/one")
	old := rig.emitters[0]
	rig.rec.SetSyncForTest(func(*os.File) error { return errors.New("injected sync failure") })
	if err := old.EmitDurable(receipt.EmitOpts{
		ActionID: receipt.NewActionID(), Verdict: config.ActionAllow,
		Transport: "fetch", Method: "GET", Target: "https://api.vendor.example/lost",
	}); !errors.Is(err, receipt.ErrReceiptPostAdvance) {
		t.Fatalf("EmitDurable = %v, want a post-advance failure", err)
	}
	rig.rec.SetSyncForTest(nil)
	obs := rig.h.observeShards()[0]
	successor := receipt.NewEmitter(receipt.EmitterConfig{
		Recorder: rig.rec, PrivKey: rig.key, ConfigHash: strings.Repeat("d", 64),
		Principal: "local", Actor: "pipelock", Metrics: rig.m, Session: old.Session(),
	})
	if successor == nil || successor.InitError() != nil {
		t.Fatal("successor failed to resume")
	}
	rig.h.emitterFn = func() *receipt.Emitter { return successor }

	rig.h.checkShardTail(obs)

	rig.assertNotLatched(t)
	rig.h.runPass()
	rig.assertNotLatched(t)
}
