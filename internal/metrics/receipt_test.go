// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestRecordEmitFailure_CanonicalReasons(t *testing.T) {
	m := New()
	m.RecordEmitFailure("chain_init")
	m.RecordEmitFailure("chain_init")
	m.RecordEmitFailure("record")
	m.RecordEmitFailure("unavailable")

	if got := testutil.ToFloat64(m.receiptEmitFailures.WithLabelValues("chain_init")); got != 2 {
		t.Errorf("chain_init = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.receiptEmitFailures.WithLabelValues("record")); got != 1 {
		t.Errorf("record = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.receiptEmitFailures.WithLabelValues("unavailable")); got != 1 {
		t.Errorf("unavailable = %v, want 1", got)
	}
}

func TestRecordEmitFailure_NonCanonicalMappedToUnknown(t *testing.T) {
	m := New()
	m.RecordEmitFailure("arbitrary attacker controlled text")
	m.RecordEmitFailure("another one")

	if got := testutil.ToFloat64(m.receiptEmitFailures.WithLabelValues("unknown")); got != 2 {
		t.Errorf("unknown = %v, want 2 (non-canonical reasons collapsed)", got)
	}
}

func TestRecordEmitFailure_NilSafe(t *testing.T) {
	var m *Metrics
	m.RecordEmitFailure("chain_init") // must not panic
}

func TestRecordEmitFailure_ZeroValueSafe(t *testing.T) {
	var m Metrics
	m.RecordEmitFailure("record") // must not panic
}

func TestRecordRequiredReceiptBlock_BoundedLabels(t *testing.T) {
	m := New()
	m.RecordRequiredReceiptBlock("unavailable", "fetch")
	m.RecordRequiredReceiptBlock("emit_error", "websocket")
	m.RecordRequiredReceiptBlock("attacker-controlled", "CONNECT /evil")

	if got := testutil.ToFloat64(m.requiredReceiptBlockings.WithLabelValues("unavailable", "fetch")); got != 1 {
		t.Errorf("unavailable/fetch = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.requiredReceiptBlockings.WithLabelValues("emit_error", "websocket")); got != 1 {
		t.Errorf("emit_error/websocket = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.requiredReceiptBlockings.WithLabelValues("unknown", "other")); got != 1 {
		t.Errorf("unknown/other = %v, want 1 (unbounded labels collapsed)", got)
	}
}

func TestRecordRequiredReceiptBlock_NilSafe(t *testing.T) {
	var m *Metrics
	m.RecordRequiredReceiptBlock("unavailable", "fetch") // must not panic
}

func TestRecordRequiredReceiptBlock_ZeroValueSafe(t *testing.T) {
	var m Metrics
	m.RecordRequiredReceiptBlock("unavailable", "fetch") // must not panic
}

func TestNormalizeReceiptTransport(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		transport string
		want      string
	}{
		{"fetch", "fetch", "fetch"},
		{"forward", "forward", "forward"},
		{"connect", "connect", "connect"},
		{"websocket", "websocket", "websocket"},
		{"intercept", "intercept", "intercept"},
		{"reverse", "reverse", "reverse"},
		{"mcp", "mcp", "mcp"},
		{"empty", "", "other"},
		{"uppercase", "FETCH", "other"},
		{"attacker string", "fetch,reason=record", "other"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := normalizeReceiptTransport(tt.transport); got != tt.want {
				t.Fatalf("normalizeReceiptTransport(%q) = %q, want %q", tt.transport, got, tt.want)
			}
		})
	}
}

func TestStatsHandler_IncludesReceiptHealth(t *testing.T) {
	m := New()
	m.RecordEmitFailure("record")
	m.RecordEmitFailure("record")
	m.RecordEmitFailure("unavailable")
	m.RecordRequiredReceiptBlock("emit_error", "fetch")
	m.RecordRequiredReceiptBlock("unavailable", "websocket")

	rec := httptest.NewRecorder()
	m.StatsHandler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/stats", nil))

	var got struct {
		Receipts struct {
			EmitFailures   []rankedEntry                 `json:"emit_failures"`
			RequiredBlocks []requiredReceiptBlockSummary `json:"required_blocks"`
		} `json:"receipts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal stats: %v", err)
	}
	if len(got.Receipts.EmitFailures) < 2 {
		t.Fatalf("emit_failures = %+v, want record and unavailable", got.Receipts.EmitFailures)
	}
	if got.Receipts.EmitFailures[0] != (rankedEntry{Name: "record", Count: 2}) {
		t.Fatalf("top emit failure = %+v, want record=2", got.Receipts.EmitFailures[0])
	}
	if got.Receipts.EmitFailures[1] != (rankedEntry{Name: "unavailable", Count: 1}) {
		t.Fatalf("second emit failure = %+v, want unavailable=1", got.Receipts.EmitFailures[1])
	}
	wantBlocks := map[requiredReceiptBlockSummary]bool{
		{Reason: "emit_error", Transport: "fetch", Count: 1}:      true,
		{Reason: "unavailable", Transport: "websocket", Count: 1}: true,
	}
	for _, block := range got.Receipts.RequiredBlocks {
		delete(wantBlocks, block)
	}
	if len(wantBlocks) != 0 {
		t.Fatalf("required_blocks missing entries: %+v; got %+v", wantBlocks, got.Receipts.RequiredBlocks)
	}
}

func TestStatsHandler_ReceiptHealthEmptyByDefault(t *testing.T) {
	m := New()

	rec := httptest.NewRecorder()
	m.StatsHandler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/stats", nil))

	var got struct {
		Receipts struct {
			EmitFailures   []rankedEntry                 `json:"emit_failures"`
			RequiredBlocks []requiredReceiptBlockSummary `json:"required_blocks"`
		} `json:"receipts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal stats: %v", err)
	}
	if len(got.Receipts.EmitFailures) != 0 {
		t.Fatalf("default emit_failures = %+v, want empty", got.Receipts.EmitFailures)
	}
	if len(got.Receipts.RequiredBlocks) != 0 {
		t.Fatalf("default required_blocks = %+v, want empty", got.Receipts.RequiredBlocks)
	}
}

func TestStatsHandler_ReceiptHealthUsesBoundedLabels(t *testing.T) {
	m := New()
	m.RecordEmitFailure("client supplied reason")
	m.RecordRequiredReceiptBlock("client supplied reason", "client supplied transport")

	rec := httptest.NewRecorder()
	m.StatsHandler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/stats", nil))

	var got struct {
		Receipts struct {
			EmitFailures   []rankedEntry                 `json:"emit_failures"`
			RequiredBlocks []requiredReceiptBlockSummary `json:"required_blocks"`
		} `json:"receipts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal stats: %v", err)
	}
	if len(got.Receipts.EmitFailures) != 1 || got.Receipts.EmitFailures[0] != (rankedEntry{Name: "unknown", Count: 1}) {
		t.Fatalf("emit_failures = %+v, want bounded unknown=1", got.Receipts.EmitFailures)
	}
	wantBlock := requiredReceiptBlockSummary{Reason: "unknown", Transport: "other", Count: 1}
	if len(got.Receipts.RequiredBlocks) != 1 || got.Receipts.RequiredBlocks[0] != wantBlock {
		t.Fatalf("required_blocks = %+v, want %+v", got.Receipts.RequiredBlocks, wantBlock)
	}
}

func TestReceiptHealthMetricsConcurrent(t *testing.T) {
	m := New()
	var wg sync.WaitGroup
	const workers = 8
	const perWorker = 25
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for j := 0; j < perWorker; j++ {
				if worker%2 == 0 {
					m.RecordEmitFailure("record")
					m.RecordRequiredReceiptBlock("emit_error", "fetch")
				} else {
					m.RecordEmitFailure("unavailable")
					m.RecordRequiredReceiptBlock("unavailable", "websocket")
				}
			}
		}(i)
	}
	wg.Wait()

	rec := httptest.NewRecorder()
	m.StatsHandler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/stats", nil))

	var got struct {
		Receipts struct {
			EmitFailures   []rankedEntry                 `json:"emit_failures"`
			RequiredBlocks []requiredReceiptBlockSummary `json:"required_blocks"`
		} `json:"receipts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal stats: %v", err)
	}
	wantEach := int64(workers / 2 * perWorker)
	wantFailures := map[string]int64{
		"record":      wantEach,
		"unavailable": wantEach,
	}
	for _, entry := range got.Receipts.EmitFailures {
		if want, ok := wantFailures[entry.Name]; ok {
			if entry.Count != want {
				t.Fatalf("emit failure %s = %d, want %d", entry.Name, entry.Count, want)
			}
			delete(wantFailures, entry.Name)
		}
	}
	if len(wantFailures) != 0 {
		t.Fatalf("missing emit failure counts: %+v; got %+v", wantFailures, got.Receipts.EmitFailures)
	}

	wantBlocks := map[requiredReceiptBlockSummary]bool{
		{Reason: "emit_error", Transport: "fetch", Count: wantEach}:      true,
		{Reason: "unavailable", Transport: "websocket", Count: wantEach}: true,
	}
	for _, block := range got.Receipts.RequiredBlocks {
		delete(wantBlocks, block)
	}
	if len(wantBlocks) != 0 {
		t.Fatalf("missing required block counts: %+v; got %+v", wantBlocks, got.Receipts.RequiredBlocks)
	}
}

func TestTopRequiredReceiptBlocksSortsAndCaps(t *testing.T) {
	counts := map[string]int64{
		requiredReceiptBlockKey("emit_error", "fetch"):      7,
		requiredReceiptBlockKey("emit_error", "websocket"):  7,
		requiredReceiptBlockKey("unavailable", "connect"):   9,
		requiredReceiptBlockKey("unavailable", "forward"):   3,
		requiredReceiptBlockKey("unavailable", "websocket"): 9,
		requiredReceiptBlockKey("malformed-key", "ignored"): 1,
		"not-delimited": 2,
	}
	got := topRequiredReceiptBlocks(counts)
	wantPrefix := []requiredReceiptBlockSummary{
		{Reason: "unavailable", Transport: "connect", Count: 9},
		{Reason: "unavailable", Transport: "websocket", Count: 9},
		{Reason: "emit_error", Transport: "fetch", Count: 7},
		{Reason: "emit_error", Transport: "websocket", Count: 7},
		{Reason: "unavailable", Transport: "forward", Count: 3},
		{Reason: "unknown", Transport: "other", Count: 2},
	}
	if len(got) != len(counts) {
		t.Fatalf("entry count = %d, want %d: %+v", len(got), len(counts), got)
	}
	for i, want := range wantPrefix {
		if got[i] != want {
			t.Fatalf("entry %d = %+v, want %+v (all: %+v)", i, got[i], want, got)
		}
	}

	large := make(map[string]int64, maxTopEntries+25)
	for i := 0; i < maxTopEntries+25; i++ {
		large[requiredReceiptBlockKey("emit_error", fmt.Sprintf("transport-%03d", i))] = int64(i)
	}
	capped := topRequiredReceiptBlocks(large)
	if len(capped) != maxTopEntries {
		t.Fatalf("capped length = %d, want %d", len(capped), maxTopEntries)
	}
	if capped[0].Count != int64(maxTopEntries+24) {
		t.Fatalf("top count = %d, want %d", capped[0].Count, maxTopEntries+24)
	}
	if capped[len(capped)-1].Count != 25 {
		t.Fatalf("last retained count = %d, want 25", capped[len(capped)-1].Count)
	}
}

func TestRequiredReceiptBlockKeyRoundTrip(t *testing.T) {
	t.Parallel()

	key := requiredReceiptBlockKey("emit_error", "websocket")
	reason, transport := splitRequiredReceiptBlockKey(key)
	if reason != "emit_error" || transport != "websocket" {
		t.Fatalf("splitRequiredReceiptBlockKey(%q) = (%q, %q), want (emit_error, websocket)",
			key, reason, transport)
	}

	reason, transport = splitRequiredReceiptBlockKey("malformed")
	if reason != "unknown" || transport != "other" {
		t.Fatalf("malformed key split = (%q, %q), want bounded fallback (unknown, other)",
			reason, transport)
	}
}
