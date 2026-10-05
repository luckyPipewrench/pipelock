// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func newFragmentMemoScanner(t *testing.T) *Scanner {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	return sc
}

func TestFragmentCleanMemoIdenticalContinuity(t *testing.T) {
	sc := newFragmentMemoScanner(t)
	fb := NewFragmentBuffer(65536, 10, 300)
	owner := testCEEIdentity("memo-owner")
	stream := owner.Stream("json-bucket")
	app := func(path, text string) (FragmentAppendResult, [][]DLPMatch) {
		return fb.AppendAndScanOwnedBatch(context.Background(), owner, []FragmentAppend{{Group: stream, Stream: stream, Pieces: []FragmentPiece{{Continuity: []byte(path), Data: []byte(text)}}}}, sc)
	}
	_, _ = app("big", strings.Repeat("ordinary ", 2000))
	_, _ = app("big", strings.Repeat("ordinary ", 2000))
	before := fb.cleanMemo.hits
	_, _ = app("small", "abc")
	_, _ = app("small", "def")
	if fb.cleanMemo.hits-before != 2 {
		t.Fatalf("untouched big continuity not reused: hits=%d", fb.cleanMemo.hits-before)
	}
	other := newFragmentMemoScanner(t)
	fs := fb.activeFragmentsLocked(fb.sessions[stream.Key()].fragments)
	before = fb.cleanMemo.hits
	_ = fb.scanBatchWithCleanMemo(context.Background(), other, fs, stream.Key())
	if fb.cleanMemo.hits != before {
		t.Fatal("scanner generation reused")
	}
	t.Logf("untouched continuity hit delta=2; replacement scanner missed")
}

func TestFragmentCleanMemoDifferential(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "fixture warn", Regex: `fixturewarn-[a-z]+`, Action: config.ActionWarn, Severity: config.SeverityHigh}, config.DLPPattern{Name: "boundary", Regex: `CTOK[A-Z]{12}`, Severity: config.SeverityHigh})
	sc := MustNew(cfg)
	defer sc.Close()
	warns := []string{}
	sc.SetDLPWarnHook(func(_ context.Context, p, s string) { warns = append(warns, p+":"+s) })
	fb := NewFragmentBuffer(256, 20, 300)
	owner := testCEEIdentity("differential")
	stream := owner.Stream("bucket")
	rng := rand.New(rand.NewSource(724)) // #nosec G404 -- deterministic parity corpus.
	inputs := []string{"ordinary", "ordinary", "CTOKBBBB", "BBBBBBBB", "fixturewarn-", "sample", "fixturewarn-sample", base64.StdEncoding.EncodeToString([]byte("CTOKBBBBBBBBBBBB")), strings.Repeat("x", 300), "Ａ\u200b", `%2543TOKBBBB`, "BBBBBBBB"}
	for i := 0; i < 120; i++ {
		b := make([]byte, rng.Intn(45))
		_, _ = rng.Read(b)
		inputs = append(inputs, string(b))
	}
	comparisons, blocks, warnCases := 0, 0, 0
	for i, text := range inputs {
		continuity := fmt.Sprintf("leaf-%d", i%4)
		item := FragmentAppend{Group: stream, Stream: stream, SourceRequestID: []byte(fmt.Sprint(i)), Pieces: []FragmentPiece{{Continuity: []byte(continuity), Data: []byte(text)}}}
		// Build the exact pre-retention snapshot, then compare its entire result and warning stream.
		fb.mu.Lock()
		var fs []fragment
		res := fb.appendPiecesSnapshotLocked(owner.Key(), stream.Key(), stream.Key(), item.Pieces, item.SourceRequestID, &fs)
		fb.retainStreamLocked(owner.Key(), stream.Key())
		fb.mu.Unlock()
		if res != (FragmentAppendResult{}) {
			t.Fatal(res)
		}
		for repeat := 0; repeat < 2; repeat++ {
			warns = nil
			want := scanFragmentsForSecrets(context.Background(), sc, fs)
			ww := append([]string(nil), warns...)
			warns = nil
			got := fb.scanBatchWithCleanMemo(context.Background(), sc, fs, stream.Key())
			gw := append([]string(nil), warns...)
			if !reflect.DeepEqual(want, got) || !reflect.DeepEqual(ww, gw) {
				t.Fatalf("full result/warning parity request=%d repeat=%d want=%v got=%v warns=%v/%v", i, repeat, want, got, ww, gw)
			}
			comparisons++
			blocks += len(got)
			warnCases += len(gw)
		}
	}
	// Guaranteed boundary/provenance controls, independent of rolling random traffic.
	for _, payload := range []string{"CTOKBBBBBBBBBBBB", base64.StdEncoding.EncodeToString([]byte("CTOKBBBBBBBBBBBB")), "fixturewarn-sample"} {
		cut := len(payload) / 2
		fs := []fragment{{data: []byte(payload[:cut]), sourceRequestID: []byte("first")}, {data: []byte(payload[cut:]), sourceRequestID: []byte("second")}}
		for repeat := 0; repeat < 2; repeat++ {
			warns = nil
			want := scanFragmentsForSecrets(context.Background(), sc, fs)
			ww := append([]string(nil), warns...)
			warns = nil
			got := fb.scanBatchWithCleanMemo(context.Background(), sc, fs, "control")
			gw := append([]string(nil), warns...)
			if !reflect.DeepEqual(want, got) || !reflect.DeepEqual(ww, gw) {
				t.Fatal("control parity")
			}
			blocks += len(got)
			warnCases += len(gw)
			comparisons++
		}
	}
	if blocks == 0 || warnCases == 0 || fb.cleanMemo.hits == 0 {
		t.Fatalf("vacuous blocks=%d warns=%d hits=%d", blocks, warnCases, fb.cleanMemo.hits)
	}
	t.Logf("full DLPMatch/contributor and emitted-warning parity comparisons=%d blocks=%d warns=%d hits=%d misses=%d", comparisons, blocks, warnCases, fb.cleanMemo.hits, fb.cleanMemo.misses)
}

func TestFragmentCleanMemoConcurrent(t *testing.T) {
	sc := newFragmentMemoScanner(t)
	fb := NewFragmentBuffer(65536, 20, 300)
	fs := []fragment{{data: []byte("hello")}, {data: []byte("world")}}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Go(func() {
			for j := 0; j < 50; j++ {
				if got := fb.scanBatchWithCleanMemo(context.Background(), sc, fs, "same"); len(got) > 0 {
					t.Error(got)
				}
			}
		})
	}
	wg.Wait()
	t.Logf("concurrent identical clean scans hits=%d misses=%d", fb.cleanMemo.hits, fb.cleanMemo.misses)
}

func TestFragmentCleanMemoGenerationChangesDetection(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	old := MustNew(cfg)
	defer old.Close()
	fb := NewFragmentBuffer(65536, 10, 300)
	fs := []fragment{{data: []byte("CTOKBBBB"), sourceRequestID: []byte("first")}, {data: []byte("BBBBBBBB"), sourceRequestID: []byte("second")}}
	if got := fb.scanBatchWithCleanMemo(context.Background(), old, fs, "policy"); len(got) != 0 {
		t.Fatal("old policy control", got)
	}
	if got := fb.scanBatchWithCleanMemo(context.Background(), old, fs, "policy"); len(got) != 0 || fb.cleanMemo.hits != 1 {
		t.Fatal("clean cache control")
	}
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "new boundary", Regex: `CTOK[A-Z]{12}`, Severity: config.SeverityHigh})
	fresh := MustNew(cfg)
	defer fresh.Close()
	got := fb.scanBatchWithCleanMemo(context.Background(), fresh, fs, "policy")
	want := scanFragmentsForSecrets(context.Background(), fresh, fs)
	if len(got) != 1 || !reflect.DeepEqual(got, want) || len(got[0].Contributors) != 2 {
		t.Fatalf("replacement policy failed closed/provenance control: %v", got)
	}
	fb.Close()
	if len(fb.cleanMemo.entries) != 0 {
		t.Fatal("Close retained cache")
	}
	t.Log("new scanner policy blocks previously clean identical text with exact two-request attribution; Close clears memo")
}

func TestFragmentCleanMemoBoundsAndIdentity(t *testing.T) {
	sc := newFragmentMemoScanner(t)
	other := newFragmentMemoScanner(t)
	key := fragmentCleanKey{scanner: sc, stream: "data-owner", continuity: "leaf"}
	m := fragmentCleanMemo{limit: 128}
	m.store(key, "ordinary")
	if !m.lookup(key, "ordinary") {
		t.Fatal("clean positive control missed")
	}
	for _, k := range []fragmentCleanKey{
		{scanner: other, stream: key.stream, continuity: key.continuity},
		{scanner: sc, stream: "other-owner", continuity: key.continuity},
		{scanner: sc, stream: key.stream, continuity: "sibling"},
	} {
		if m.lookup(k, "ordinary") {
			t.Fatal("identity crossed memo boundary")
		}
	}
	if m.lookup(key, "changed") {
		t.Fatal("changed input reused clean result")
	}
	m.store(key, strings.Repeat("x", 129))
	if !m.lookup(key, "ordinary") {
		t.Fatal("oversized entry removed valid resident")
	}
	for i := range 50 {
		m.store(fragmentCleanKey{scanner: sc, stream: fmt.Sprint(i)}, "ordinary")
		if m.bytes > m.limit {
			t.Fatal("memo budget exceeded")
		}
	}
	// Replacement accounts for both old and new represented input.
	m.store(key, "ordinary")
	m.store(key, "ordinary again")
	total := 0
	for k, text := range m.entries {
		total += len(text) + len(k.stream) + len(k.continuity)
	}
	if m.bytes != total {
		t.Fatalf("bytes=%d want%d", m.bytes, total)
	}
	m.limit = 0
	m.store(fragmentCleanKey{scanner: sc, stream: "disabled"}, "ordinary")
	if m.lookup(fragmentCleanKey{scanner: sc, stream: "disabled"}, "ordinary") {
		t.Fatal("disabled memo admitted entry")
	}
}
