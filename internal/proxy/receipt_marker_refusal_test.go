// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const (
	refusalSentinel     = "REFUSALSENTINELTEXT"
	refusalTargetPrefix = "https://api.vendor.example/"
)

type markerGroup struct {
	proxy    *Proxy
	shards   *receipt.ReceiptShardSet
	rec      *recorder.Recorder
	pubHex   string
	failures *int
}

// newMarkerGroup builds a required receipt group whose shard-0 v2 writer is
// supplied by mkV2, so a test can inject its failure.
func newMarkerGroup(t *testing.T, mkV2 func(*recorder.Recorder) proxydecision.Recorder) markerGroup {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: t.TempDir(), SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	shards, err := receipt.OpenInitialReceiptShardSet(receipt.EmitterConfig{
		Recorder: rec, PrivKey: key, ConfigHash: strings.Repeat("a", 64), Principal: "local", Actor: "pipelock",
	}, "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	open, _ := shards.Opening()
	v2 := make([]*proxydecision.Emitter, 2)
	for i, shard := range open.Shards {
		var r proxydecision.Recorder = rec
		if i == 0 && mkV2 != nil {
			r = mkV2(rec)
		}
		v2[i] = proxydecision.NewEmitter(proxydecision.EmitterConfig{Recorder: r, Signer: proxydecision.NewKeyedSigner(key), Principal: "local", Actor: "pipelock", Session: shard.SessionID})
	}
	failures := 0
	option, err := WithReceiptShardSet(shards, v2, func(error) { failures++ })
	if err != nil {
		t.Fatal(err)
	}
	p := &Proxy{logger: audit.NewNop(), metrics: metrics.New()}
	option(p)
	return markerGroup{proxy: p, shards: shards, rec: rec, pubHex: hex.EncodeToString(key.Public().(ed25519.PublicKey)), failures: &failures}
}

func (g markerGroup) intent(target string) error {
	opts := receipt.EmitOpts{
		ActionID: receipt.NewActionID(), Verdict: config.ActionAllow,
		Transport: "forward", Method: "GET", Target: target,
		PolicyHash: strings.Repeat("a", 64), ShardSelected: true, ShardIndex: 0,
	}
	return g.proxy.emitRequiredReceiptWithEmitter(opts, g.proxy.receiptEmitterPtr.Load())
}

func (g markerGroup) unhealthy() int {
	n := 0
	for _, s := range g.shards.Emitters() {
		if s.HealthError() != nil {
			n++
		}
	}
	return n
}

// persisted reads shard 0's raw recorder entries, counts v1 intents and
// failure markers, and checks signatures, sequence and hash links. Lifecycle
// rules are not applied: these sessions are left open on purpose.
func (g markerGroup) persisted(t *testing.T) (intents, markers int, linked bool) {
	t.Helper()
	session := g.shards.Emitters()[0].Session()
	paths, err := filepath.Glob(filepath.Join(g.rec.Dir(), "evidence-"+session+"-*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(paths)
	var rs []receipt.Receipt
	for _, path := range paths {
		entries, err := recorder.ReadEntries(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, e := range entries {
			if e.Type != "action_receipt" {
				continue
			}
			raw, err := json.Marshal(e.Detail)
			if err != nil {
				t.Fatal(err)
			}
			r, err := receipt.Unmarshal(raw)
			if err != nil {
				t.Fatalf("unmarshal receipt: %v", err)
			}
			rs = append(rs, r)
		}
	}
	for _, r := range rs {
		if r.ActionRecord.SessionControl != nil {
			continue
		}
		switch r.ActionRecord.Layer {
		case receiptEmissionFailedLayer:
			markers++
		case "":
			intents++
		}
	}
	return intents, markers, receipt.VerifyChain(rs, g.pubHex).IntegrityVerified
}

func intentOpts(target string) receipt.EmitOpts {
	return receipt.EmitOpts{
		ActionID: receipt.NewActionID(), Verdict: config.ActionAllow,
		Transport: "forward", Method: "GET", Target: target,
		PolicyHash: strings.Repeat("a", 64), ShardSelected: true, ShardIndex: 0,
		DecisionPhase: receipt.DecisionPhaseIntent,
	}
}

// largestFittingTarget returns a target whose v1 intent receipt fits the
// recorder's line limit while the failure marker for the same action does
// not. It finds the largest fitting length for each and takes the midpoint:
// an entry's length varies by a few bytes between runs (timestamps trim
// trailing zeros), so neither edge is used.
func largestFittingTarget(t *testing.T) string {
	t.Helper()
	target := func(n int) string { return refusalTargetPrefix + strings.Repeat("a", n) }
	marker := func(n int) receipt.EmitOpts {
		return receiptEmissionFailureMarkerOpts(intentOpts(target(n)), "proxydecision receipt emission failed", config.ActionBlock)
	}
	fits := func(opts receipt.EmitOpts) bool {
		g := newMarkerGroup(t, nil)
		return g.shards.EmitDurable(opts) == nil
	}
	largest := func(build func(int) receipt.EmitOpts) int {
		lo, hi := 1, recorder.MaxEntryLineBytes
		if !fits(build(lo)) || fits(build(hi)) {
			t.Fatal("calibration bounds do not bracket the line limit")
		}
		for hi-lo > 1 {
			mid := lo + (hi-lo)/2
			if fits(build(mid)) {
				lo = mid
			} else {
				hi = mid
			}
		}
		return lo
	}
	intentMax := largest(func(n int) receipt.EmitOpts { return intentOpts(target(n)) })
	markerMax := largest(marker)
	const minGap = 64
	if intentMax-markerMax < minGap {
		t.Fatalf("calibration: intent fits up to %d and marker up to %d; want a gap of at least %d bytes", intentMax, markerMax, minGap)
	}
	return target(markerMax + (intentMax-markerMax)/2)
}

// A failure marker refused before it is written is a deterministic input
// rejection. The action is still refused and no marker is recorded, but the
// group stays healthy and the next required action proceeds.
func TestRequiredGroupPreWriteMarkerRefusalStaysLocal(t *testing.T) {
	target := largestFittingTarget(t)
	// The real v2 writer refuses the oversized proxy_decision before writing,
	// and the v1 failure marker is then over the line limit too.
	g := newMarkerGroup(t, nil)

	first := g.intent(target)
	if !errors.Is(first, recorder.ErrSerializedEntryTooLarge) {
		t.Fatalf("first intent = %v, want a deterministic pre-write refusal", first)
	}
	if *g.failures != 0 || g.unhealthy() != 0 {
		t.Fatalf("pre-write marker refusal latched the group: failRequired=%d unhealthy=%d/2", *g.failures, g.unhealthy())
	}
	if err := g.intent(refusalTargetPrefix + "next"); err != nil {
		t.Fatalf("healthy group refused the next intent: %v", err)
	}
	intents, markers, linked := g.persisted(t)
	if intents != 2 || markers != 0 || !linked {
		t.Fatalf("persisted intents=%d markers=%d linked=%v, want 2/0/true", intents, markers, linked)
	}
}

// syncBreakingDecisionRecorder refuses the v2 write deterministically, and on
// the way out breaks the v1 recorder's sync, so the failure marker that
// follows is an uncertain write.
type syncBreakingDecisionRecorder struct{ rec *recorder.Recorder }

func (r syncBreakingDecisionRecorder) Record(recorder.Entry) error {
	r.rec.SetSyncForTest(func(*os.File) error { return errors.New("injected sync failure") })
	return recorder.ErrSerializedEntryTooLarge
}

func (r syncBreakingDecisionRecorder) RecordDurable(e recorder.Entry) error { return r.Record(e) }

// Negative control: a marker whose write may have reached the disk is not a
// deterministic refusal. The group still latches and later actions block.
func TestRequiredGroupUncertainMarkerWriteStillLatches(t *testing.T) {
	g := newMarkerGroup(t, func(rec *recorder.Recorder) proxydecision.Recorder { return syncBreakingDecisionRecorder{rec: rec} })

	first := g.intent(refusalTargetPrefix + "data")
	if first == nil || !errors.Is(first, recorder.ErrSerializedEntryTooLarge) {
		t.Fatalf("first intent = %v, want the v2 refusal joined with the marker failure", first)
	}
	if got := receiptFailureClass(first); got != "durability" && got != "post_advance" {
		t.Fatalf("failure class = %q, want the uncertain write to outrank the size refusal", got)
	}
	if *g.failures != 1 || g.unhealthy() != 2 {
		t.Fatalf("uncertain marker write: failRequired=%d unhealthy=%d/2, want 1 and 2", *g.failures, g.unhealthy())
	}
	g.rec.SetSyncForTest(nil)
	if err := g.intent(refusalTargetPrefix + "next"); err == nil {
		t.Fatal("latched group accepted the next required intent")
	}
}

func TestReceiptFailureClass(t *testing.T) {
	size := fmt.Errorf("record: %w", recorder.ErrSerializedEntryTooLarge)
	durable := fmt.Errorf("%w: sync: %w", receipt.ErrReceiptPostAdvance, recorder.ErrDurability)
	postAdvance := fmt.Errorf("%w: write", receipt.ErrReceiptPostAdvance)
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, "none"},
		{"size refusal", size, "entry_too_large"},
		{"durability", durable, "durability"},
		{"post-advance", postAdvance, "post_advance"},
		{"size joined with durability", errors.Join(size, durable), "durability"},
		{"size joined with post-advance", errors.Join(size, postAdvance), "post_advance"},
		{"emitter unavailable", errReceiptEmitterUnavailable, "emitter_unavailable"},
		{"chain sealed", fmt.Errorf("emit: %w", receipt.ErrChainSealed), "chain_sealed"},
		{"v2 emit", fmt.Errorf("%w: x", errV2ReceiptEmit), "v2_emit"},
		{"unknown", errors.New(refusalSentinel), receiptLabelOther},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := receiptFailureClass(tc.err); got != tc.want {
				t.Fatalf("receiptFailureClass = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestReceiptDiagnosticLabelsAreBounded(t *testing.T) {
	for _, tc := range []struct {
		name, got, want string
	}{
		{"known verdict", receiptVerdictLabel(config.ActionBlock), config.ActionBlock},
		{"unknown verdict", receiptVerdictLabel(refusalSentinel), receiptLabelOther},
		{"known phase", receiptPhaseLabel(receipt.DecisionPhaseOutcome), receipt.DecisionPhaseOutcome},
		{"empty phase", receiptPhaseLabel(""), "none"},
		{"unknown phase", receiptPhaseLabel(refusalSentinel), receiptLabelOther},
		{"owned layer", receiptLayerLabel(receiptOutcomeLayer), receiptOutcomeLayer},
		{"unknown layer", receiptLayerLabel(refusalSentinel), receiptLabelOther},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Fatalf("label = %q, want %q", tc.got, tc.want)
			}
		})
	}
}

type refusalLogCapture struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *refusalLogCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

func (c *refusalLogCapture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

// A refused required receipt logs an audit-gap line with bounded labels and
// none of the request text that was in its options.
func TestReceiptRefusalLogOmitsRequestText(t *testing.T) {
	capture := &refusalLogCapture{}
	logger, err := audit.NewWithStream("json", "stdout", "", true, true, capture)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(logger.Close)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: t.TempDir(), SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	e := receipt.NewEmitter(receipt.EmitterConfig{Recorder: rec, PrivKey: key, ConfigHash: strings.Repeat("a", 64), Principal: "local", Actor: "pipelock"})
	if e == nil || e.InitError() != nil {
		t.Fatalf("emitter: %v", e.InitError())
	}
	p := &Proxy{logger: logger, metrics: metrics.New()}
	p.receiptEmitterPtr.Store(e)
	opts := receipt.EmitOpts{
		ActionID: refusalSentinel + "-action", Verdict: config.ActionAllow,
		Transport: refusalSentinel + "-transport", Method: refusalSentinel + "-method",
		Layer: refusalSentinel + "-layer", Pattern: refusalSentinel + "-pattern",
		// Over the recorder's line limit, so the receipt is refused before it is written.
		Target:     refusalTargetPrefix + refusalSentinel + strings.Repeat("a", recorder.MaxEntryLineBytes),
		PolicyHash: strings.Repeat("a", 64),
	}
	refused := p.emitRequiredReceiptWithEmitter(opts, e)
	logger.Close()
	if !errors.Is(refused, recorder.ErrSerializedEntryTooLarge) {
		t.Fatalf("refused = %v, want a pre-write size refusal", refused)
	}
	out := capture.String()
	if strings.Contains(out, refusalSentinel) {
		t.Fatalf("refusal log echoes request text:\n%s", out)
	}
	for _, want := range []string{"event=receipt_channel_broken", "audit_gap=true", "phase=intent", "layer=other", "failure=entry_too_large"} {
		if !strings.Contains(out, want) {
			t.Fatalf("refusal log missing %q:\n%s", want, out)
		}
	}
}

func TestReceiptEmissionBlockedDetailOmitsErrorText(t *testing.T) {
	err := fmt.Errorf("recording %s: %w", refusalSentinel, recorder.ErrSerializedEntryTooLarge)
	blocked := newReceiptEmissionBlockedRequest(err)
	if strings.Contains(blocked.detail, refusalSentinel) {
		t.Fatalf("block detail echoes error text: %q", blocked.detail)
	}
	if !strings.Contains(blocked.detail, "failure=entry_too_large") || blocked.reason != receiptEmissionBlockReason {
		t.Fatalf("block detail=%q reason=%q", blocked.detail, blocked.reason)
	}
}
