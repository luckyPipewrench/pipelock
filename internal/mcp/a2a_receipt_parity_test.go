// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// A2A (agent-to-agent) decision points block traffic on multiple paths. Every
// block must leave a policy-hash-bearing receipt, the same as the other
// applicable transports (forward/CONNECT/WS/MCP tools-call). These tests lock
// in the A2A listener/header and non-tools/call body paths that previously
// returned without evidence.
//
// Transport-attribution note: the receipt convention is Transport = the wire
// (forward / mcp_http / mcp_http_listener) and Layer = the A2A scanner
// (mcp_a2a_scanning), mirroring the forward A2A path which already ships
// Transport="forward" + Layer="a2a_header". A2A is a protocol that rides over a
// transport, so it is attributed via Layer/method, not by overloading
// Transport. See internal/proxy/receipt_coverage_test.go for the established
// shape.

const (
	a2aReceiptListenerTrans = "mcp_http_listener"
	// fakeGHTokenA2A is a synthetic GitHub PAT (prefix + 36 chars) kept split
	// across literals so gitleaks/gosec G101 do not flag it. It trips the DLP
	// scanner the same way a real leaked token would.
	fakeGHTokenA2A = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
	// a2aEmitterConfigHash is the configHash the test emitter stamps onto every
	// v1 receipt. In production this is cfg.CanonicalPolicyHash(); pinning it
	// lets the tests assert the receipt is bound to a non-empty policy hash.
	a2aEmitterConfigHash = "test-config-hash"
)

// a2aBlockReceipts returns the v1 action receipts in dir whose verdict is block.
func a2aBlockReceipts(t *testing.T, dir string) []receipt.Receipt {
	t.Helper()
	var out []receipt.Receipt
	for _, r := range decisionReceiptLogFor(t, dir) {
		if r.ActionRecord.Verdict == config.ActionBlock {
			out = append(out, r)
		}
	}
	return out
}

// a2aSendMessageWithToken builds an A2A SendMessage frame whose text part
// carries a leaked token, tripping the DLP scanner.
func a2aSendMessageWithToken(id int) string {
	return makeRequest(id, "SendMessage", map[string]any{
		"message": map[string]any{
			"parts": []map[string]any{{"text": "exfil " + fakeGHTokenA2A}},
		},
	})
}

// startA2AReceiptListener boots RunHTTPListenerProxy wired with the supplied
// opts (carrying a capturing receipt emitter), returning the base URL.
func startA2AReceiptListener(t *testing.T, upstreamURL string, opts MCPProxyOpts) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()

	var logBuf lockedHTTPBuffer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- RunHTTPListenerProxy(ctx, ln, upstreamURL, &logBuf, opts)
	}()

	baseURL := "http://" + addr
	waitForHTTPHealth(t, baseURL)

	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("RunHTTPListenerProxy: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("timeout waiting for listener proxy to stop")
		}
	})
	return baseURL
}

func postA2A(t *testing.T, baseURL, body string, headers map[string]string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/", strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req) //nolint:gosec // test
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

// 5a: a blocked A2A *header* request (an A2A-Extensions URI the URL scanner
// rejects) must emit a signed block receipt bound to the policy hash. Pre-fix
// the header block wrote the JSON-RPC error and returned with no receipt.
func TestA2AHeaderBlock_EmitsReceiptWithPolicyHash(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("upstream called: A2A header block must prevent forwarding")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	h := newMCPDecisionReceiptHarness(t)
	sc := testScannerForHTTP(t)

	baseURL := startA2AReceiptListener(t, upstream.URL, MCPProxyOpts{
		Scanner:          sc,
		A2ACfg:           &config.A2AScanning{Enabled: true, Action: config.ActionBlock},
		ReceiptEmitter:   h.v1,
		V2ReceiptEmitter: h.v2,
		PolicyHash:       mcpTestPolicyHash,
	})

	// Benign body; the malicious signal is in the A2A-Extensions header. The
	// ftp:// scheme is rejected by the URL scanner without needing DNS.
	postA2A(t, baseURL, jsonToolsList, map[string]string{
		"A2A-Extensions": "ftp://evil.example.com/exfil",
	})

	blocks := a2aBlockReceipts(t, h.dir)
	if len(blocks) != 1 {
		t.Fatalf("expected exactly 1 block receipt for A2A header block, got %d", len(blocks))
	}
	r := blocks[0]
	if err := receipt.VerifyWithKey(r, hex.EncodeToString(h.pub)); err != nil {
		t.Fatalf("receipt verify: %v", err)
	}
	ar := r.ActionRecord
	if ar.PolicyHash != a2aEmitterConfigHash {
		t.Errorf("PolicyHash = %q, want non-empty %q", ar.PolicyHash, a2aEmitterConfigHash)
	}
	if ar.Transport != a2aReceiptListenerTrans {
		t.Errorf("Transport = %q, want %q", ar.Transport, a2aReceiptListenerTrans)
	}
	if ar.Layer != mcpReceiptLayerA2A {
		t.Errorf("Layer = %q, want %q", ar.Layer, mcpReceiptLayerA2A)
	}
	if ar.Target != mcpReceiptA2AHeaderTarget {
		t.Errorf("Target = %q, want %q", ar.Target, mcpReceiptA2AHeaderTarget)
	}

	// The listener header path uses the same decision helper as body blocks, so
	// it should also produce a signed v2 decision when a v2 emitter is present.
	v2s := mcpV2Receipts(t, h)
	if len(v2s) != 1 {
		t.Fatalf("expected exactly 1 v2 decision for A2A header block, got %d", len(v2s))
	}
	if err := contractreceipt.VerifyWithKey(v2s[0], h.pub, h.kid); err != nil {
		t.Fatalf("v2 verify: %v", err)
	}
	if v2s[0].PolicyHash != mcpTestPolicyHash {
		t.Errorf("v2 PolicyHash = %q, want %q", v2s[0].PolicyHash, mcpTestPolicyHash)
	}
}

// 5b (A2A body gate): a non-tools/call A2A method whose A2A body scan finds a
// secret (Action=block) short-circuits via blockingGateA2ABody. That block must
// emit BOTH a v1 receipt and a v2 decision, policy-hash bound. Pre-fix actionID
// was empty (not a tools/call) so the deferred emitter suppressed both.
func TestA2ABodyBlock_A2AGate_DualEmitsWithPolicyHash(t *testing.T) {
	sc := testScannerForHTTP(t)
	h := newMCPDecisionReceiptHarness(t)

	opts := MCPProxyOpts{
		Scanner:          sc,
		InputCfg:         &InputScanConfig{Enabled: true, Action: config.ActionBlock, OnParseError: config.ActionBlock},
		A2ACfg:           &config.A2AScanning{Enabled: true, Action: config.ActionBlock},
		ReceiptEmitter:   h.v1,
		V2ReceiptEmitter: h.v2,
		PolicyHash:       mcpTestPolicyHash,
		Transport:        a2aReceiptListenerTrans,
	}
	var logBuf bytes.Buffer
	decision := scanHTTPInputDecision([]byte(a2aSendMessageWithToken(7)), &logBuf, "s", "s", opts)
	if decision.Blocked == nil {
		t.Fatalf("expected A2A body block, got forward; log=%s", logBuf.String())
	}

	// v1 receipt: signed, block, A2A layer, target = the A2A method.
	v1s := a2aBlockReceipts(t, h.dir)
	if len(v1s) != 1 {
		t.Fatalf("expected exactly 1 v1 block receipt, got %d", len(v1s))
	}
	if err := receipt.VerifyWithKey(v1s[0], hex.EncodeToString(h.pub)); err != nil {
		t.Fatalf("v1 verify: %v", err)
	}
	ar := v1s[0].ActionRecord
	if ar.PolicyHash != a2aEmitterConfigHash {
		t.Errorf("v1 PolicyHash = %q, want %q", ar.PolicyHash, a2aEmitterConfigHash)
	}
	if ar.Layer != mcpReceiptLayerA2A {
		t.Errorf("v1 Layer = %q, want %q", ar.Layer, mcpReceiptLayerA2A)
	}
	if ar.Target != "SendMessage" {
		t.Errorf("v1 Target = %q, want SendMessage", ar.Target)
	}

	// v2 decision: signed, policy-hash bound (closes the recorder — call last).
	v2s := mcpV2Receipts(t, h)
	if len(v2s) != 1 {
		t.Fatalf("expected exactly 1 v2 decision, got %d", len(v2s))
	}
	if err := contractreceipt.VerifyWithKey(v2s[0], h.pub, h.kid); err != nil {
		t.Fatalf("v2 verify: %v", err)
	}
	if v2s[0].PolicyHash != mcpTestPolicyHash {
		t.Errorf("v2 PolicyHash = %q, want %q", v2s[0].PolicyHash, mcpTestPolicyHash)
	}
	var payload struct {
		Target  string `json:"target"`
		Verdict string `json:"verdict"`
	}
	if err := json.Unmarshal(v2s[0].Payload, &payload); err != nil {
		t.Fatalf("unmarshal v2 payload: %v", err)
	}
	if payload.Target != "SendMessage" {
		t.Errorf("v2 target = %q, want SendMessage", payload.Target)
	}
}

// 5b (general content path): a non-tools/call A2A method with a DLP hit caught
// by the general content scan (A2A body scan disabled) is blocked at the
// effective-action switch, not the A2A gate. That block must ALSO emit a
// receipt — pre-fix actionID was empty so it was suppressed. This is the path
// the brief's "DLP hit on SendMessage" test exercises.
func TestA2ABodyBlock_ContentScan_EmitsReceiptWithPolicyHash(t *testing.T) {
	sc := testScannerForHTTP(t)
	h := newMCPDecisionReceiptHarness(t)

	opts := MCPProxyOpts{
		Scanner:  sc,
		InputCfg: &InputScanConfig{Enabled: true, Action: config.ActionBlock, OnParseError: config.ActionBlock},
		// A2A scanning OFF: the block must come from the general content scan.
		ReceiptEmitter: h.v1,
		PolicyHash:     mcpTestPolicyHash,
		Transport:      a2aReceiptListenerTrans,
	}
	var logBuf bytes.Buffer
	decision := scanHTTPInputDecision([]byte(a2aSendMessageWithToken(8)), &logBuf, "s", "s", opts)
	if decision.Blocked == nil {
		t.Fatalf("expected content-scan block on A2A method, got forward; log=%s", logBuf.String())
	}

	blocks := a2aBlockReceipts(t, h.dir)
	if len(blocks) != 1 {
		t.Fatalf("expected exactly 1 block receipt for A2A content-scan block, got %d", len(blocks))
	}
	ar := blocks[0].ActionRecord
	if ar.PolicyHash != a2aEmitterConfigHash {
		t.Errorf("PolicyHash = %q, want %q", ar.PolicyHash, a2aEmitterConfigHash)
	}
	if ar.Verdict != config.ActionBlock {
		t.Errorf("Verdict = %q, want %q", ar.Verdict, config.ActionBlock)
	}
	if ar.Target != "SendMessage" {
		t.Errorf("Target = %q, want SendMessage", ar.Target)
	}
}

// 5b (pre-redaction path): with a redaction matcher configured, an A2A method
// carrying a DLP secret is blocked by the pre-redaction content scan, which
// returns BEFORE the gate-evaluation step that normally sets mcpMethod. This
// proves the early A2A-method capture is load-bearing: without it the deferred
// emitter could not see this is an A2A frame and would suppress the receipt.
func TestA2ABodyBlock_PreRedaction_EmitsReceipt(t *testing.T) {
	sc := testScannerForHTTP(t)
	h := newMCPDecisionReceiptHarness(t)

	opts := MCPProxyOpts{
		Scanner:        sc,
		InputCfg:       &InputScanConfig{Enabled: true, Action: config.ActionBlock, OnParseError: config.ActionBlock},
		RedactMatcher:  testHTTPRedactionMatcher(),
		ReceiptEmitter: h.v1,
		PolicyHash:     mcpTestPolicyHash,
		Transport:      a2aReceiptListenerTrans,
	}
	var logBuf bytes.Buffer
	decision := scanHTTPInputDecision([]byte(a2aSendMessageWithToken(11)), &logBuf, "s", "s", opts)
	if decision.Blocked == nil {
		t.Fatalf("expected pre-redaction block on A2A method, got forward; log=%s", logBuf.String())
	}

	blocks := a2aBlockReceipts(t, h.dir)
	if len(blocks) != 1 {
		t.Fatalf("expected exactly 1 block receipt for pre-redaction A2A block, got %d", len(blocks))
	}
	if blocks[0].ActionRecord.PolicyHash != a2aEmitterConfigHash {
		t.Errorf("PolicyHash = %q, want %q", blocks[0].ActionRecord.PolicyHash, a2aEmitterConfigHash)
	}
}

// Regression: a clean/allowed A2A request must NOT emit a receipt (block-parity
// only — we do not add allow receipts for A2A in this change).
func TestA2ACleanRequest_EmitsNoReceipt(t *testing.T) {
	sc := testScannerForHTTP(t)
	h := newMCPDecisionReceiptHarness(t)

	body := makeRequest(9, "SendMessage", map[string]any{
		"message": map[string]any{"parts": []map[string]any{{"text": "hello peer"}}},
	})
	opts := MCPProxyOpts{
		Scanner:          sc,
		InputCfg:         &InputScanConfig{Enabled: true, Action: config.ActionBlock, OnParseError: config.ActionBlock},
		A2ACfg:           &config.A2AScanning{Enabled: true, Action: config.ActionBlock},
		ReceiptEmitter:   h.v1,
		V2ReceiptEmitter: h.v2,
		PolicyHash:       mcpTestPolicyHash,
		Transport:        a2aReceiptListenerTrans,
	}
	var logBuf bytes.Buffer
	decision := scanHTTPInputDecision([]byte(body), &logBuf, "s", "s", opts)
	if decision.Blocked != nil {
		t.Fatalf("expected clean A2A request to pass, got blocked: %+v", decision.Blocked)
	}

	// A clean request emits nothing, so the recorder never creates an evidence
	// file. readReceiptEntriesHTTP scans the dir and tolerates its absence.
	for _, e := range readReceiptEntriesHTTP(t, h.dir) {
		if e.Type == actionReceiptEntryType {
			t.Fatal("expected no action receipt for clean A2A request, found one")
		}
	}
}

// Under require_receipts, a clean A2A allow must still produce exactly one
// provable allow receipt. Without the fix, A2A clean allows leave both actionID
// and verdict empty, so emission is dropped and the request forwards with no
// receipt -- a hole in the every-allow-is-provable guarantee. tools/call clean
// allows are unaffected because they always mint an actionID.
func TestA2ACleanRequest_RequireReceipts_EmitsAllowReceipt(t *testing.T) {
	sc := testScannerForHTTP(t)
	h := newMCPDecisionReceiptHarness(t)

	body := makeRequest(11, "SendMessage", map[string]any{
		"message": map[string]any{"parts": []map[string]any{{"text": "hello peer"}}},
	})
	opts := MCPProxyOpts{
		Scanner:          sc,
		InputCfg:         &InputScanConfig{Enabled: true, Action: config.ActionBlock, OnParseError: config.ActionBlock},
		A2ACfg:           &config.A2AScanning{Enabled: true, Action: config.ActionBlock},
		ReceiptEmitter:   h.v1,
		V2ReceiptEmitter: h.v2,
		PolicyHash:       mcpTestPolicyHash,
		Transport:        a2aReceiptListenerTrans,
		RequireReceipts:  true,
	}
	var logBuf bytes.Buffer
	decision := scanHTTPInputDecision([]byte(body), &logBuf, "s", "s", opts)
	if decision.Blocked != nil {
		t.Fatalf("expected clean A2A allow to pass under require_receipts, got blocked: %+v", decision.Blocked)
	}

	var allow []receipt.Receipt
	for _, r := range decisionReceiptLogFor(t, h.dir) {
		if r.ActionRecord.Verdict == config.ActionAllow {
			allow = append(allow, r)
		}
	}
	if len(allow) != 1 {
		t.Fatalf("expected exactly 1 allow receipt for clean A2A allow under require_receipts, got %d", len(allow))
	}
	ar := allow[0].ActionRecord
	if ar.ActionID == "" {
		t.Error("A2A allow receipt has empty ActionID")
	}
	if ar.Target != "SendMessage" {
		t.Errorf("A2A allow receipt Target = %q, want SendMessage", ar.Target)
	}
}

// Regression: a blocked tools/call still emits exactly one block receipt with a
// real actionID. The A2A fix must not change tools/call.
func TestToolsCallBlock_ReceiptUnchanged(t *testing.T) {
	sc := testScannerForHTTP(t)
	h := newMCPDecisionReceiptHarness(t)

	body := makeRequest(10, "tools/call", map[string]any{
		"name":      "run",
		"arguments": map[string]any{"code": "echo " + fakeGHTokenA2A},
	})
	opts := MCPProxyOpts{
		Scanner:        sc,
		InputCfg:       &InputScanConfig{Enabled: true, Action: config.ActionBlock, OnParseError: config.ActionBlock},
		ReceiptEmitter: h.v1,
		PolicyHash:     mcpTestPolicyHash,
		Transport:      a2aReceiptListenerTrans,
	}
	var logBuf bytes.Buffer
	decision := scanHTTPInputDecision([]byte(body), &logBuf, "s", "s", opts)
	if decision.Blocked == nil {
		t.Fatalf("expected tools/call block, got forward; log=%s", logBuf.String())
	}

	blocks := a2aBlockReceipts(t, h.dir)
	if len(blocks) != 1 {
		t.Fatalf("expected exactly 1 block receipt for tools/call, got %d", len(blocks))
	}
	if blocks[0].ActionRecord.ActionID == "" {
		t.Error("tools/call block receipt has empty ActionID")
	}
}
