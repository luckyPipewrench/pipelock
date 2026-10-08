// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestReceiptGroupWSFrameRequestPolicyUsesConnectionShard(t *testing.T) {
	_, shards, p, _ := newReceiptFailureGroup(t)
	cfg := reqPolicyConfig(wsDiscriminatorRule("api.vendor.example"))
	cfg.FlightRecorder.RequireReceipts = true
	p.cfgPtr.Store(cfg)
	if err := p.setupRequestPolicy(cfg); err != nil {
		t.Fatal(err)
	}
	_ = p.admitReceiptShard() // Choose the non-process shard for the relay.
	selected := p.admitReceiptShard()
	if selected.ShardIndex != 1 {
		t.Fatalf("relay shard = %d, want 1", selected.ShardIndex)
	}
	relay := &wsRelay{
		proxy: p, cfg: cfg, receiptShard: selected,
		clientConn: discardConn{}, upstreamConn: discardConn{},
		hostname: "api.vendor.example", reqPolicyPath: "/socket",
		targetURL: "wss://api.vendor.example/socket", requestID: "frame-policy",
	}
	before0, _ := shards.Emitters()[0].HealthSnapshot()
	before1, _ := shards.Emitters()[1].HealthSnapshot()
	if !relay.applyFrameRequestPolicy(audit.NewNop(), []byte(`{"action":"deleteAll"}`)) {
		t.Fatal("matching frame forwarded")
	}
	after0, _ := shards.Emitters()[0].HealthSnapshot()
	after1, _ := shards.Emitters()[1].HealthSnapshot()
	if after0.ChainSeq != before0.ChainSeq || after1.ChainSeq != before1.ChainSeq+1 {
		t.Fatalf("frame receipt advanced process/selected shards %d/%d -> %d/%d", before0.ChainSeq, before1.ChainSeq, after0.ChainSeq, after1.ChainSeq)
	}

	shards.Emitters()[1].MarkUnhealthy(errors.New("injected receipt failure"))
	if !relay.applyFrameRequestPolicy(audit.NewNop(), []byte(`{"action":"deleteAll"}`)) {
		t.Fatal("required-mode receipt failure forwarded frame")
	}
	failed, _ := shards.Emitters()[1].HealthSnapshot()
	if failed.ChainSeq != after1.ChainSeq {
		t.Fatal("failed frame emission advanced the shard")
	}
	relay.receiptShard = receipt.EmitOpts{}
	if !relay.applyFrameRequestPolicy(audit.NewNop(), []byte(`{"action":"deleteAll"}`)) {
		t.Fatal("unselected-shard error forwarded frame")
	}
	assertMetricsContain(t, p.metrics, `pipelock_receipt_emit_failures_total{reason="unavailable"} 2`)
}

func TestReceiptGroupInterceptRequestPolicyAndOtherReceiptShareShard(t *testing.T) {
	_, shards, groupProxy, _ := newReceiptFailureGroup(t)
	cfg := reqPolicyConfig(blockRule(http.MethodDelete))
	cfg.FlightRecorder.RequireReceipts = true
	p := newTestProxyWithConfig(t, cfg)
	p.receiptEmitterPtr.Store(shards.ProcessEmitter())
	p.v2EmitterPtr.Store(groupProxy.v2EmitterPtr.Load())
	p.receiptGroupPtr.Store(groupProxy.receiptGroupPtr.Load())
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	ic := &InterceptContext{
		TargetHost: rpTestHost, TargetPort: "443", Config: cfg, Scanner: sc,
		Logger: audit.NewNop(), Metrics: p.metrics, Proxy: p, RequestID: "intercept-policy",
	}
	handler := newInterceptHandler(ic, &interceptMockRT{body: "ok", contentType: "text/plain"})
	request := func() *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "https://"+rpTestHost+"/v1/jobs/1", nil)
		r.Host = rpTestHost + ":443"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("request_policy status = %d, want 403: %s", w.Code, w.Body.String())
		}
		return w
	}
	before0, _ := shards.Emitters()[0].HealthSnapshot()
	before1, _ := shards.Emitters()[1].HealthSnapshot()
	w := request()
	if w.Header().Get(blockreason.HeaderReceipt) == "" {
		t.Fatal("request_policy block lacks recorded receipt reference")
	}
	after0, _ := shards.Emitters()[0].HealthSnapshot()
	after1, _ := shards.Emitters()[1].HealthSnapshot()
	if after0.ChainSeq != before0.ChainSeq+1 || after1.ChainSeq != before1.ChainSeq {
		t.Fatalf("first intercept request advanced shards %d/%d -> %d/%d", before0.ChainSeq, before1.ChainSeq, after0.ChainSeq, after1.ChainSeq)
	}

	selected := p.admitReceiptShard() // A second request's other receipts use this admission.
	if selected.ShardIndex != 1 {
		t.Fatalf("second admission shard = %d, want 1", selected.ShardIndex)
	}
	requestContext := *ic
	requestContext.receiptShard = selected
	if err := interceptEmitReceipt(&requestContext, receipt.EmitOpts{
		ActionID: receipt.NewActionID(), Verdict: config.ActionBlock,
		Layer: "test_block", Transport: "intercept", Method: http.MethodDelete,
		Target: "https://" + rpTestHost + "/v1/jobs/1",
	}); err != nil {
		t.Fatalf("other intercept receipt: %v", err)
	}
	if err := p.emitRequestPolicyReceipt(withReceiptShard(receipt.EmitOpts{
		ActionID: receipt.NewActionID(), Verdict: config.ActionBlock,
		Layer: blockLayerRequestPolicy, Transport: "intercept", Method: http.MethodDelete,
		Target: "https://" + rpTestHost + "/v1/jobs/1", PolicyHash: cfg.CanonicalPolicyHash(),
	}, selected)); err != nil {
		t.Fatalf("intercept request_policy receipt: %v", err)
	}
	paired, _ := shards.Emitters()[1].HealthSnapshot()
	if paired.ChainSeq != after1.ChainSeq+2 {
		t.Fatalf("intercept pair advanced shard 1 by %d, want 2", paired.ChainSeq-after1.ChainSeq)
	}

	shards.Emitters()[0].MarkUnhealthy(errors.New("injected receipt failure"))
	w = request() // The third admission wraps to shard 0.
	if w.Header().Get(blockreason.HeaderReceipt) != "" {
		t.Fatal("failed required-mode block advertised a receipt")
	}
	if w.Header().Get(blockreason.HeaderReason) != string(blockreason.RequestPolicyDeny) {
		t.Fatal("receipt failure weakened the request_policy denial")
	}
	requestContext.receiptShard = receipt.EmitOpts{ShardSelected: true, ShardIndex: 0}
	allowResponse := httptest.NewRecorder()
	if !interceptEmitReceiptOrBlock(&requestContext, allowResponse, audit.LogContext{}, receipt.EmitOpts{
		ActionID: receipt.NewActionID(), Verdict: config.ActionAllow,
		Transport: "intercept", Method: http.MethodGet,
		Target: "https://" + rpTestHost + "/v1/jobs/1",
	}) {
		t.Fatal("required-mode intercept allow forwarded after receipt failure")
	}
	if allowResponse.Header().Get(blockreason.HeaderReason) != string(blockreason.ReceiptEmissionFailed) {
		t.Fatal("required-mode intercept failure lacks receipt_emission_failed reason")
	}
}
