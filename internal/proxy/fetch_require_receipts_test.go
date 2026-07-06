// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// fetchRequireReceiptsProxy builds a fetch-capable proxy with a receipt
// emitter whose recorder is already closed (every emit fails), so the test
// exercises the emit-failure branch deterministically.
func fetchRequireReceiptsProxy(t *testing.T, require bool) *Proxy {
	t.Helper()
	cfg := testScannerConfig()
	cfg.Internal = nil // disable SSRF so the loopback upstream is reachable
	cfg.ResponseScanning.Enabled = false
	cfg.FlightRecorder.RequireReceipts = require

	sc := scanner.New(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	rph := newReceiptProxyHelperWithMetrics(t, p.metrics)
	if err := rph.rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}
	p.receiptEmitterPtr.Store(rph.emitter)
	return p
}

func fetchRequireReceiptsLiveProxy(t *testing.T, cfgMod func(*config.Config)) (*Proxy, *receiptProxyHelper) {
	t.Helper()
	cfg := testScannerConfig()
	cfg.Internal = nil
	cfg.FlightRecorder.RequireReceipts = true
	if cfgMod != nil {
		cfgMod(cfg)
	}

	sc := scanner.New(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	rph := newReceiptProxyHelperWithMetrics(t, p.metrics)
	p.receiptEmitterPtr.Store(rph.emitter)
	return p, rph
}

// TestHandleFetch_RequireReceiptsBlocksEmissionFailure proves fetch transport
// parity: with require_receipts on, a failed allow-receipt emission blocks the
// fetch BEFORE egress (0 upstream hits) with the receipt_emission_failed
// reason — matching forward / CONNECT / WebSocket / MCP.
func TestHandleFetch_RequireReceiptsBlocksEmissionFailure(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	p := fetchRequireReceiptsProxy(t, true)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+upstream.URL, nil)
	rec := httptest.NewRecorder()
	p.handleFetch(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if got := rec.Header().Get(blockreason.HeaderReason); got != string(blockreason.ReceiptEmissionFailed) {
		t.Fatalf("block reason header = %q, want %s", got, blockreason.ReceiptEmissionFailed)
	}
	var resp FetchResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode FetchResponse: %v", err)
	}
	if !resp.Blocked {
		t.Fatalf("FetchResponse.Blocked = false, want true: %+v", resp)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("upstream hits = %d, want 0 (must block before egress)", got)
	}
	assertMetricsContain(t, p.metrics, `pipelock_receipt_emit_failures_total{reason="record"} 1`)
	assertMetricsContain(t, p.metrics, `pipelock_required_receipt_blocks_total{reason="emit_error",transport="fetch"} 1`)
}

func TestHandleFetch_RequireReceiptsSyncFailureBlocksBeforeEgress(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	p, rph := fetchRequireReceiptsLiveProxy(t, func(cfg *config.Config) {
		cfg.ResponseScanning.Enabled = false
	})
	syncErr := errors.New("injected durable sync failure")
	rph.rec.SetSyncForTest(func(*os.File) error {
		return syncErr
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+upstream.URL, nil)
	rec := httptest.NewRecorder()
	p.handleFetch(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("upstream hits = %d, want 0 (durable intent sync failure must block before egress)", got)
	}
	assertMetricsContain(t, p.metrics, `pipelock_receipt_emit_failures_total{reason="sync"} 1`)
	assertMetricsContain(t, p.metrics, `pipelock_required_receipt_blocks_total{reason="durability",transport="fetch"} 1`)
}

func TestHandleFetch_RequireReceiptsSuccessEmitsIntentOutcomePair(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	p, rph := fetchRequireReceiptsLiveProxy(t, func(cfg *config.Config) {
		cfg.ResponseScanning.Enabled = false
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+upstream.URL, nil)
	p.handleFetch(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("fetch status = %d, want 200", rec.Code)
	}

	receipts := rph.findReceipts(t)
	if len(receipts) != 2 {
		t.Fatalf("receipt count = %d, want intent/outcome pair", len(receipts))
	}
	if receipts[0].ActionRecord.DecisionPhase != receipt.DecisionPhaseIntent {
		t.Fatalf("intent phase = %q, want %q", receipts[0].ActionRecord.DecisionPhase, receipt.DecisionPhaseIntent)
	}
	if receipts[1].ActionRecord.DecisionPhase != receipt.DecisionPhaseOutcome {
		t.Fatalf("outcome phase = %q, want %q", receipts[1].ActionRecord.DecisionPhase, receipt.DecisionPhaseOutcome)
	}
	if receipts[1].ActionRecord.ActionID != receipts[0].ActionRecord.ActionID {
		t.Fatalf("outcome action_id = %s, want %s", receipts[1].ActionRecord.ActionID, receipts[0].ActionRecord.ActionID)
	}
	if !strings.Contains(receipts[1].ActionRecord.Pattern, "status=202") {
		t.Fatalf("outcome pattern = %q, want status=202", receipts[1].ActionRecord.Pattern)
	}
}

func TestHandleFetch_RequireReceiptsOutcomeEmitFailureDoesNotFailRequest(t *testing.T) {
	var rph *receiptProxyHelper
	var closed atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if closed.CompareAndSwap(false, true) {
			if err := rph.rec.Close(); err != nil {
				t.Errorf("recorder.Close: %v", err)
			}
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	var p *Proxy
	p, rph = fetchRequireReceiptsLiveProxy(t, func(cfg *config.Config) {
		cfg.ResponseScanning.Enabled = false
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+upstream.URL, nil)
	p.handleFetch(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("fetch status = %d, want 200", rec.Code)
	}
	receipts := extractReceiptsFromDir(t, rph.dir)
	if len(receipts) != 1 {
		t.Fatalf("receipt count after outcome failure = %d, want durable intent only", len(receipts))
	}
	if receipts[0].ActionRecord.DecisionPhase != receipt.DecisionPhaseIntent {
		t.Fatalf("receipt phase = %q, want %q", receipts[0].ActionRecord.DecisionPhase, receipt.DecisionPhaseIntent)
	}
}

func TestHandleFetch_RequireReceiptsUnavailableEmitterBlocksAndRecordsMetrics(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	cfg := testScannerConfig()
	cfg.Internal = nil
	cfg.ResponseScanning.Enabled = false
	cfg.FlightRecorder.RequireReceipts = true
	sc := scanner.New(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+upstream.URL, nil)
	rec := httptest.NewRecorder()
	p.handleFetch(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if got := rec.Header().Get(blockreason.HeaderReason); got != string(blockreason.ReceiptEmissionFailed) {
		t.Fatalf("block reason header = %q, want %s", got, blockreason.ReceiptEmissionFailed)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("upstream hits = %d, want 0 (must block before egress)", got)
	}
	assertMetricsContain(t, p.metrics, `pipelock_receipt_emit_failures_total{reason="unavailable"} 1`)
	assertMetricsContain(t, p.metrics, `pipelock_required_receipt_blocks_total{reason="unavailable",transport="fetch"} 1`)
}

// TestHandleFetch_ReceiptFailureWithoutRequireStillForwards pins the default:
// with require_receipts off, a receipt-emit failure stays best-effort and the
// fetch still egresses and returns 200.
func TestHandleFetch_ReceiptFailureWithoutRequireStillForwards(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	p := fetchRequireReceiptsProxy(t, false)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+upstream.URL, nil)
	rec := httptest.NewRecorder()
	p.handleFetch(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", rec.Code, rec.Body.String())
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("upstream hits = %d, want 1", got)
	}
	assertMetricsContain(t, p.metrics, `pipelock_receipt_emit_failures_total{reason="record"} 1`)
	assertMetricsNotContain(t, p.metrics, `pipelock_required_receipt_blocks_total{reason="emit_error",transport="fetch"} 1`)
}

func TestHandleFetch_RequireReceiptsResponseBlockReusesActionID(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write([]byte("compressed bytes"))
	}))
	defer upstream.Close()

	p, rph := fetchRequireReceiptsLiveProxy(t, func(cfg *config.Config) {
		cfg.ResponseScanning.Enabled = false
	})
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+upstream.URL, nil)
	rec := httptest.NewRecorder()
	p.handleFetch(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get(blockreason.HeaderReason); got != string(blockreason.CompressedResponse) {
		t.Fatalf("block reason header = %q, want %s", got, blockreason.CompressedResponse)
	}
	if err := rph.rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	var actionReceipts []receipt.Receipt
	for _, entry := range readAllEntries(t, rph.dir) {
		if entry.Type != receiptEntryType {
			continue
		}
		detail, err := json.Marshal(entry.Detail)
		if err != nil {
			t.Fatalf("json.Marshal detail: %v", err)
		}
		rcpt, err := receipt.Unmarshal(detail)
		if err != nil {
			t.Fatalf("receipt.Unmarshal: %v", err)
		}
		actionReceipts = append(actionReceipts, rcpt)
	}
	if len(actionReceipts) != 3 {
		t.Fatalf("action receipt count = %d, want 3", len(actionReceipts))
	}
	if actionReceipts[0].ActionRecord.Verdict != config.ActionAllow {
		t.Fatalf("first verdict = %q, want allow", actionReceipts[0].ActionRecord.Verdict)
	}
	if actionReceipts[0].ActionRecord.DecisionPhase != receipt.DecisionPhaseIntent {
		t.Fatalf("allow decision_phase = %q, want %q", actionReceipts[0].ActionRecord.DecisionPhase, receipt.DecisionPhaseIntent)
	}
	if actionReceipts[1].ActionRecord.Verdict != config.ActionBlock {
		t.Fatalf("second verdict = %q, want block", actionReceipts[1].ActionRecord.Verdict)
	}
	if actionReceipts[2].ActionRecord.DecisionPhase != receipt.DecisionPhaseOutcome {
		t.Fatalf("outcome decision_phase = %q, want %q", actionReceipts[2].ActionRecord.DecisionPhase, receipt.DecisionPhaseOutcome)
	}
	if !strings.Contains(actionReceipts[2].ActionRecord.Pattern, "status=403") {
		t.Fatalf("outcome pattern = %q, want status=403", actionReceipts[2].ActionRecord.Pattern)
	}
	for i, rcpt := range actionReceipts[1:] {
		if actionReceipts[0].ActionRecord.ActionID != rcpt.ActionRecord.ActionID {
			t.Fatalf("action receipt %d action_id = %s, want %s",
				i+1, rcpt.ActionRecord.ActionID, actionReceipts[0].ActionRecord.ActionID)
		}
	}
}
