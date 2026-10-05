// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// pendingGap drives an anchorWalker through one receipt gap: a receipt by
// keyA, then waiting checkpoints that keyA did not sign, each over a 64-byte
// prev_hash like the recorder's, then a receipt by keyB. sign returns the
// signature for checkpoint n.
type pendingGap struct {
	t    *testing.T
	a    *anchorWalker
	seq  uint64
	i    int
	keyA string
	keyB string
}

const pendingTestHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func newPendingGap(t *testing.T) (*pendingGap, ed25519.PrivateKey) {
	t.Helper()
	pubA, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	g := &pendingGap{t: t, a: &anchorWalker{anchor: checkpointAnchor{lastSignedIndex: -1}}, keyA: hex.EncodeToString(pubA), keyB: hex.EncodeToString(pubB)}
	t.Cleanup(g.a.close)
	g.add(recorder.Entry{Type: "action_receipt"}, &receipt.Receipt{SignerKey: g.keyA})
	return g, privB
}

func (g *pendingGap) add(e recorder.Entry, r *receipt.Receipt) {
	e.Sequence = g.seq
	g.seq++
	if r != nil {
		g.a.addReceipt(*r)
	}
	g.a.addEntry(g.i, e)
	g.i++
}

// checkpoint adds one decision entry and a checkpoint over it carrying sig.
func (g *pendingGap) checkpoint(sig string) {
	g.add(recorder.Entry{Type: "decision"}, nil)
	// A fresh copy, as a parsed entry would hold, so the test measures what
	// the walker retains rather than one shared string.
	prevHash := strings.Clone(pendingTestHash)
	g.add(recorder.Entry{Type: "checkpoint", PrevHash: prevHash, Detail: map[string]any{
		"first_seq": float64(g.seq - 1), "last_seq": float64(g.seq - 1), "entry_count": float64(1), "signature": sig,
	}}, nil)
}

// TestAnchorWalkerSpillsPendingCheckpointsInBoundedMemory pins that a gap of
// 20,000 waiting checkpoints, which a recorder signing a checkpoint after
// every entry writes before a new writer's first receipt, is held in bounded
// memory and every checkpoint still verifies.
func TestAnchorWalkerSpillsPendingCheckpointsInBoundedMemory(t *testing.T) {
	const waiting = 20000
	g, privB := newPendingGap(t)
	sig := hex.EncodeToString(ed25519.Sign(privB, []byte(pendingTestHash)))
	runtime.GC()
	base := liveHeapPeak(t, func() {})
	peak := liveHeapPeak(t, func() {
		for range waiting {
			g.checkpoint(sig)
		}
	})
	if got := g.a.pending.len(); got != waiting {
		t.Fatalf("pending = %d, want %d", got, waiting)
	}
	if len(g.a.pending.mem) > pendingInMemory {
		t.Fatalf("in-memory pending = %d, bound %d", len(g.a.pending.mem), pendingInMemory)
	}
	var growth uint64
	if peak > base {
		growth = peak - base
	}
	// Held in memory, 20,000 checkpoints are about five megabytes.
	const allowance = 2 << 20
	t.Logf("live heap growth holding %d pending checkpoints: %d KiB", waiting, growth>>10)
	if growth > allowance {
		t.Fatalf("live heap grew %d KiB holding %d pending checkpoints (allowance %d KiB)", growth>>10, waiting, allowance>>10)
	}
	g.add(recorder.Entry{Type: "action_receipt"}, &receipt.Receipt{SignerKey: g.keyB})
	anchor, err := g.a.finish()
	if err != nil {
		t.Fatalf("honest gap failed: %v", err)
	}
	if anchor.signed != waiting {
		t.Fatalf("signed = %d, want %d", anchor.signed, waiting)
	}
}

// TestAnchorWalkerSpillChangedFailsClosed pins that a spilled checkpoint
// rewritten on disk between being held and being verified fails verification,
// including when the rewrite turns a forged signature into a valid one.
func TestAnchorWalkerSpillChangedFailsClosed(t *testing.T) {
	g, privB := newPendingGap(t)
	_, privC, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	good := ed25519.Sign(privB, []byte(pendingTestHash))
	forged := ed25519.Sign(privC, []byte(pendingTestHash))
	const waiting = pendingInMemory + 10
	const forgedAt = pendingInMemory + 3 // the fourth spilled checkpoint
	for n := range waiting {
		s := good
		if n == forgedAt {
			s = forged
		}
		g.checkpoint(hex.EncodeToString(s))
	}
	p := &g.a.pending
	if p.spilled != waiting-pendingInMemory {
		t.Fatalf("spilled = %d, want %d", p.spilled, waiting-pendingInMemory)
	}
	if err := p.w.Flush(); err != nil {
		t.Fatal(err)
	}
	record := int64(pendingSpillHeader + len(pendingTestHash) + ed25519.SignatureSize)
	at := int64(forgedAt-pendingInMemory)*record + int64(pendingSpillHeader+len(pendingTestHash))
	held := make([]byte, ed25519.SignatureSize)
	if _, err := p.file.ReadAt(held, at); err != nil {
		t.Fatal(err)
	}
	if string(held) != string(forged) {
		t.Fatal("spill layout differs from the test's offsets")
	}
	if _, err := p.file.WriteAt(good, at); err != nil {
		t.Fatal(err)
	}
	g.add(recorder.Entry{Type: "action_receipt"}, &receipt.Receipt{SignerKey: g.keyB})
	_, err = g.a.finish()
	if !errors.Is(err, errPendingSpillChanged) {
		t.Fatalf("rewritten spill: err = %v, want errPendingSpillChanged", err)
	}
}

// TestAnchorWalkerSpillForgedStillFails is the positive control for the
// spill: a forged checkpoint that is held on disk, and not rewritten, fails
// as a bad signature at its own sequence.
func TestAnchorWalkerSpillForgedStillFails(t *testing.T) {
	g, privB := newPendingGap(t)
	_, privC, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	good := hex.EncodeToString(ed25519.Sign(privB, []byte(pendingTestHash)))
	forged := hex.EncodeToString(ed25519.Sign(privC, []byte(pendingTestHash)))
	for n := range pendingInMemory + 10 {
		s := good
		if n == pendingInMemory+3 {
			s = forged
		}
		g.checkpoint(s)
	}
	g.add(recorder.Entry{Type: "action_receipt"}, &receipt.Receipt{SignerKey: g.keyB})
	anchor, err := g.a.finish()
	if err == nil || !strings.Contains(err.Error(), "does not verify under the signer of its receipt segment") {
		t.Fatalf("forged spilled checkpoint: err = %v", err)
	}
	if anchor.signed != pendingInMemory+9 {
		t.Fatalf("signed = %d, want %d", anchor.signed, pendingInMemory+9)
	}
}

// TestAnchorWalkerReusesSpillAcrossGaps pins that a second gap after a
// spilled one is held and verified from a reset spill file.
func TestAnchorWalkerReusesSpillAcrossGaps(t *testing.T) {
	g, privB := newPendingGap(t)
	pubC, privC, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyC := hex.EncodeToString(pubC)
	sigB := hex.EncodeToString(ed25519.Sign(privB, []byte(pendingTestHash)))
	sigC := hex.EncodeToString(ed25519.Sign(privC, []byte(pendingTestHash)))
	for range pendingInMemory + 5 {
		g.checkpoint(sigB)
	}
	g.add(recorder.Entry{Type: "action_receipt"}, &receipt.Receipt{SignerKey: g.keyB})
	for range pendingInMemory + 7 {
		g.checkpoint(sigC)
	}
	g.add(recorder.Entry{Type: "action_receipt"}, &receipt.Receipt{SignerKey: keyC})
	anchor, err := g.a.finish()
	if err != nil {
		t.Fatalf("two spilled gaps: %v", err)
	}
	if want := 2*pendingInMemory + 12; anchor.signed != want {
		t.Fatalf("signed = %d, want %d", anchor.signed, want)
	}
}

// writeIntervalOneRecorder writes, through the real recorder and emitter with
// a signed checkpoint after every entry, decisions entries before the
// writer's first receipt, then a receipt, and, when sealed, the
// transcript_root. It returns the directory and signer key.
func writeIntervalOneRecorder(t *testing.T, decisions int, sealed bool) (string, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := physicalTempDir(t)
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, CheckpointInterval: 1, SignCheckpoints: true}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	for range decisions {
		if err := rec.Record(recorder.Entry{SessionID: "proxy", Type: "decision", Transport: "fetch", Summary: "before the first receipt"}); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	emitter := receipt.NewEmitter(receipt.EmitterConfig{Recorder: rec, PrivKey: priv, Principal: "test", Actor: "test"})
	if err := emitter.InitError(); err != nil {
		t.Fatalf("emitter init error: %v", err)
	}
	if err := emitter.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen: %v", err)
	}
	if sealed {
		if err := emitter.EmitTranscriptRoot("proxy"); err != nil {
			t.Fatalf("EmitTranscriptRoot: %v", err)
		}
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}
	return dir, hex.EncodeToString(pub)
}

// TestVerifyReceiptCmd_IntervalOneRecorderVerifies pins that a recorder
// configured with checkpoint_interval: 1, which signs more checkpoints before
// its first receipt than the old in-memory cap held, verifies.
func TestVerifyReceiptCmd_IntervalOneRecorderVerifies(t *testing.T) {
	if testing.Short() {
		t.Skip("writes a recorder with thousands of signed checkpoints")
	}
	t.Parallel()
	const decisions = 4200
	dir, key := writeIntervalOneRecorder(t, decisions, true)
	out, err := runVerifyReceipt(t, "--chain", dir, "--whole-recorder", "--require-seal", "--key", key)
	if err != nil {
		t.Fatalf("interval-1 recorder failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "signed checkpoints verified") {
		t.Fatalf("no checkpoint anchor reported:\n%s", out)
	}
}

// TestVerifyReceiptCmd_UnsealedSpillReleased pins that an unsealed recorder,
// which never reaches the checkpoint anchor check, is still reported as
// incomplete rather than passing, and that the spill file it held is closed.
func TestVerifyReceiptCmd_UnsealedSpillReleased(t *testing.T) {
	if testing.Short() {
		t.Skip("writes a recorder with thousands of signed checkpoints")
	}
	if _, err := os.Stat("/proc/self/fd"); err != nil {
		t.Skip("needs /proc to list open files")
	}
	dir, key := writeIntervalOneRecorder(t, pendingInMemory+200, false)
	out, err := runVerifyReceipt(t, "--chain", dir, "--whole-recorder", "--require-seal", "--key", key)
	if err == nil || !strings.Contains(out, "INCOMPLETE") {
		t.Fatalf("unsealed recorder: err = %v\n%s", err, out)
	}
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range fds {
		target, _ := os.Readlink(filepath.Join("/proc/self/fd", fd.Name()))
		if strings.Contains(target, "pipelock-verify-checkpoints") {
			t.Fatalf("spill file still open after verification: %s", target)
		}
	}
}
