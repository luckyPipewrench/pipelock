// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receiptcontent

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// countingDetector judges listed texts dirty and counts every call.
type countingDetector struct {
	calls atomic.Int64
	dirty map[string]scanner.TextDLPResult
}

func (c *countingDetector) detect(_ context.Context, text string) scanner.TextDLPResult {
	c.calls.Add(1)
	if res, ok := c.dirty[text]; ok {
		return res
	}
	return scanner.TextDLPResult{Clean: true}
}

func cacheProducer() *Producer {
	return (&Producer{schema: &Schema{Kind: "test.clean_cache", Fields: map[string]Class{"a": Content, "b": Content, "c": Content, "d": Content}}}).
		WithFixedValues(map[string][]string{"d": {"fixed"}})
}

// TestCachedDetectorSkipsRepeatedCleanTexts proves the cache is used: a second
// scan of the same receipt makes no detector call, and a receipt that changes
// one atom only scans the texts that contain it.
func TestCachedDetectorSkipsRepeatedCleanTexts(t *testing.T) {
	inner := &countingDetector{}
	cached, err := NewCachedDetector(inner.detect, 1<<10)
	if err != nil {
		t.Fatal(err)
	}
	prod := cacheProducer()
	first, err := prod.Project([]byte(`{"a":"alpha","b":"beta","c":"request-1","d":"fixed"}`))
	if err != nil {
		t.Fatal(err)
	}
	if rep, err := Scan(t.Context(), cached.Detect, first); err != nil || !rep.Clean() {
		t.Fatalf("first scan: %+v %v", rep.Findings, err)
	}
	cold := inner.calls.Load()
	if cold == 0 {
		t.Fatal("first scan made no detector call")
	}
	if rep, err := Scan(t.Context(), cached.Detect, first); err != nil || !rep.Clean() {
		t.Fatalf("repeat scan: %+v %v", rep.Findings, err)
	}
	if n := inner.calls.Load() - cold; n != 0 {
		t.Fatalf("repeat scan made %d detector calls, want 0", n)
	}

	second, err := prod.Project([]byte(`{"a":"alpha","b":"beta","c":"request-2","d":"fixed"}`))
	if err != nil {
		t.Fatal(err)
	}
	var texts []string
	record := func(ctx context.Context, text string) scanner.TextDLPResult {
		texts = append(texts, text)
		return scanner.TextDLPResult{Clean: true}
	}
	if _, err := Scan(t.Context(), record, second); err != nil {
		t.Fatal(err)
	}
	// Equal texts built by different views are one detector call.
	holding := map[string]struct{}{}
	for _, text := range texts {
		if strings.Contains(text, "request-2") {
			holding[text] = struct{}{}
		}
	}
	want := len(holding)
	before := inner.calls.Load()
	if rep, err := Scan(t.Context(), cached.Detect, second); err != nil || !rep.Clean() {
		t.Fatalf("second receipt: %+v %v", rep.Findings, err)
	}
	if got := int(inner.calls.Load() - before); got != want || want == 0 || want == len(texts) {
		t.Fatalf("second receipt made %d detector calls, want only the %d of %d texts holding the new atom", got, want, len(texts))
	}
}

// TestCachedDetectorNeverRemembersFindings keeps every non-empty result out of
// the cache: a dirty text and a warn-only clean text are rescanned each time
// and returned exactly as the detector returned them.
func TestCachedDetectorNeverRemembersFindings(t *testing.T) {
	dirty := scanner.TextDLPResult{Clean: false, Matches: []scanner.TextDLPMatch{{PatternName: "Test Token"}}}
	warn := scanner.TextDLPResult{Clean: true, InformationalMatches: []scanner.TextDLPMatch{{PatternName: "Test Warn", Warn: true}}}
	inner := &countingDetector{dirty: map[string]scanner.TextDLPResult{"dirty": dirty, "warn": warn}}
	cached, err := NewCachedDetector(inner.detect, 1<<10)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		text string
		want scanner.TextDLPResult
	}{{"dirty", dirty}, {"warn", warn}} {
		for range 3 {
			before := inner.calls.Load()
			if got := cached.Detect(t.Context(), tc.text); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("%s: got %+v, want %+v", tc.text, got, tc.want)
			}
			if inner.calls.Load() != before+1 {
				t.Fatalf("%s was answered from the cache", tc.text)
			}
		}
	}
	if cached.Len() != 0 {
		t.Fatalf("cache remembered %d non-empty results", cached.Len())
	}
	// The same text under a different cache is a different key: one cache's
	// memory never answers for another detector.
	other, err := NewCachedDetector(inner.detect, 1<<10)
	if err != nil {
		t.Fatal(err)
	}
	cached.Detect(t.Context(), "shared")
	if cached.cache.key == other.cache.key {
		t.Fatal("two caches share a digest key")
	}
	before := inner.calls.Load()
	other.Detect(t.Context(), "shared")
	if inner.calls.Load() != before+1 {
		t.Fatal("a second cache answered from the first one's memory")
	}
}

// TestCachedDetectorBoundsMemory keeps at most two generations per shard.
func TestCachedDetectorBoundsMemory(t *testing.T) {
	inner := &countingDetector{}
	cached, err := NewCachedDetector(inner.detect, cleanCacheShards*4)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 5000 {
		cached.Detect(t.Context(), fmt.Sprintf("text-%d", i))
	}
	for i := range cached.cache.shards {
		s := &cached.cache.shards[i]
		if len(s.cur) > 4 || len(s.prev) > 4 {
			t.Fatalf("shard %d holds %d+%d digests, limit 4 each", i, len(s.cur), len(s.prev))
		}
	}
	if n := cached.Len(); n > 2*cleanCacheShards*4 {
		t.Fatalf("cache holds %d digests", n)
	}
	// A text used again across a rollover is kept.
	cached.Detect(t.Context(), "hot")
	for i := range 200 {
		cached.Detect(t.Context(), fmt.Sprintf("cold-%d", i))
		cached.Detect(t.Context(), "hot")
	}
	before := inner.calls.Load()
	cached.Detect(t.Context(), "hot")
	if inner.calls.Load() != before {
		t.Fatal("a text in steady use was evicted")
	}
}

func TestCachedDetectorRefusesInvalidConstruction(t *testing.T) {
	if _, err := NewCachedDetector(nil, 1<<10); err == nil {
		t.Fatal("nil detector accepted")
	}
	inner := &countingDetector{}
	if _, err := NewCachedDetector(inner.detect, cleanCacheShards-1); err == nil {
		t.Fatal("cache smaller than its shard count accepted")
	}
}

// TestCachedDetectorConcurrentScans runs receipts from many goroutines, as the
// chains of one recorder do, and checks every report against the scalar one.
func TestCachedDetectorConcurrentScans(t *testing.T) {
	inner := &countingDetector{dirty: map[string]scanner.TextDLPResult{
		"beta3request-3": {Clean: false, Matches: []scanner.TextDLPMatch{{PatternName: "Split Token"}}},
	}}
	cached, err := NewCachedDetector(inner.detect, cleanCacheShards*8)
	if err != nil {
		t.Fatal(err)
	}
	prod := cacheProducer()
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for g := range 8 {
		wg.Go(func() {
			for i := range 40 {
				n := (g + i) % 6
				p, err := prod.Project(fmt.Appendf(nil, `{"a":"alpha","b":"beta%d","c":"request-%d","d":"fixed"}`, n, n))
				if err != nil {
					errs <- err
					return
				}
				want, _ := Scan(context.Background(), inner.detect, p)
				got, _ := Scan(context.Background(), cached.Detect, p)
				if !reflect.DeepEqual(want.Findings, got.Findings) {
					errs <- fmt.Errorf("receipt %d: scalar %+v, cached %+v", n, want.Findings, got.Findings)
					return
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}
