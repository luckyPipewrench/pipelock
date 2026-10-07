// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gobwas/ws"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/httpstream"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func TestDeferredResolutionKeepsAdmissionShard(t *testing.T) {
	opts, rec, dir, shards := newMCPTransportReceiptGroup(t)
	set := opts.ReceiptGroup.Shards
	_ = set.Admit(receipt.EmitOpts{})
	intent := set.Admit(receipt.EmitOpts{
		ActionID: "deferred-shard-action", Verdict: config.ActionDefer,
		Transport: opts.Transport, Target: "tools/call", PolicyHash: mcpTestPolicyHash,
	})
	if intent.ShardIndex != 1 {
		t.Fatalf("admission shard = %d, want 1", intent.ShardIndex)
	}
	if _, err := opts.emitReceiptDecision(MCPDecision{Receipt: intent, RequireReceipt: true}); err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	if err := EmitDeferredResolutionReceipt(opts, &log, deferred.Resolution{
		DeferID: intent.ActionID, ParentActionID: intent.ActionID,
		ShardIndex: intent.ShardIndex, ShardSelected: intent.ShardSelected,
		FinalDecision: config.ActionBlock, ResolutionSource: deferred.SourceOperator,
		Target: "tools/call", Method: "tools/call",
	}); err != nil {
		t.Fatal(err)
	}
	for _, emitter := range set.Emitters() {
		if err := emitter.EmitSessionClose("graceful_shutdown"); err != nil {
			t.Fatal(err)
		}
		if err := emitter.EmitTranscriptRoot(emitter.Session()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := set.PublishClose(); err != nil {
		t.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	assertMCPTransportReceiptShard(t, dir, shards, intent.ActionID)
	open, _ := set.Opening()
	if got := receipt.VerifyReceiptGroup(dir, open.GroupID, []string{open.SignerKey}); got.Verdict != receipt.GroupValid {
		t.Fatalf("group verdict = %+v", got)
	}
}

func newMCPTransportReceiptGroup(t *testing.T) (MCPProxyOpts, *recorder.Recorder, string, []receipt.ReceiptGroupShard) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	shards, err := receipt.OpenInitialReceiptShardSet(receipt.EmitterConfig{
		Recorder: rec, PrivKey: key, ConfigHash: mcpTestPolicyHash,
		Principal: "local", Actor: "pipelock",
	}, "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	opening, _ := shards.Opening()
	group := &MCPReceiptGroup{Shards: shards, V2: make([]*proxydecision.Emitter, 2)}
	for i, shard := range opening.Shards {
		group.V2[i] = proxydecision.NewEmitter(proxydecision.EmitterConfig{
			Recorder: rec, Signer: proxydecision.NewKeyedSigner(key),
			Principal: "local", Actor: "pipelock", Session: shard.SessionID,
		})
	}
	return MCPProxyOpts{
		ReceiptGroup: group, ReceiptEmitter: shards.ProcessEmitter(), V2ReceiptEmitter: group.V2[0],
		RequireReceipts: true, PolicyHash: mcpTestPolicyHash, Transport: "mcp_http_listener",
		AuthorityDestination: "https://mcp.vendor.example",
	}, rec, dir, opening.Shards
}

func assertMCPTransportReceiptShard(t *testing.T, dir string, shards []receipt.ReceiptGroupShard, actionID string) {
	t.Helper()
	for i, shard := range shards {
		paths, err := filepath.Glob(filepath.Join(dir, "evidence-"+shard.SessionID+"-*.jsonl"))
		if err != nil || len(paths) != 1 {
			t.Fatalf("shard %d evidence files=%v err=%v", i, paths, err)
		}
		entries, err := recorder.ReadEntries(paths[0])
		if err != nil {
			t.Fatal(err)
		}
		var v1, v2 int
		for _, entry := range entries {
			if entry.Type == "action_receipt" && bytes.Contains(entry.RawDetail, []byte(actionID)) {
				v1++
			}
			if entry.Type == "evidence_receipt" {
				v2++
			}
		}
		if i == 1 {
			if v1 != 2 || v2 != 2 {
				t.Fatalf("shard %d action %s: v1=%d v2=%d, want paired decision and outcome", i, actionID, v1, v2)
			}
		} else if v1 != 0 || v2 != 0 {
			t.Fatalf("other shard %d: v1=%d v2=%d, want no action receipts", i, v1, v2)
		}
	}
}

func TestMCPStreamOutcomesKeepAdmissionShard(t *testing.T) {
	for _, path := range []string{"listener", "tracked_upstream"} {
		t.Run(path, func(t *testing.T) {
			opts, rec, dir, shards := newMCPTransportReceiptGroup(t)
			// Admission must choose the non-process shard; a process-emitter
			// fallback would then be visible in the evidence files.
			_ = opts.ReceiptGroup.Shards.Admit(receipt.EmitOpts{})
			intent := opts.ReceiptGroup.Shards.Admit(receipt.EmitOpts{
				ActionID: "stream-shard-action", Verdict: config.ActionAllow,
				Transport: opts.Transport, Target: "initialize", PolicyHash: mcpTestPolicyHash,
			})
			if intent.ShardIndex != 1 {
				t.Fatalf("admission shard = %d, want 1", intent.ShardIndex)
			}
			if _, err := opts.emitReceiptDecision(MCPDecision{Receipt: intent, RequireReceipt: true}); err != nil {
				t.Fatal(err)
			}
			var log bytes.Buffer
			switch path {
			case "listener":
				recordListenerStreamError(context.Background(), &log, opts, intent, false, transport.ErrIncompleteResponse)
			case "tracked_upstream":
				tracker := NewRequestTracker()
				tracker.TrackOutcome(json.RawMessage(`1`), TrackedRequestOutcome{Receipt: intent})
				emitTrackedStreamError(context.Background(), &log, tracker, json.RawMessage(`1`), opts, transport.ErrIncompleteResponse)
			}
			if err := rec.Close(); err != nil {
				t.Fatal(err)
			}
			assertMCPTransportReceiptShard(t, dir, shards, intent.ActionID)
		})
	}
}

func TestMCPContractRefusalKeepsAdmissionShard(t *testing.T) {
	opts, rec, dir, shards := newMCPTransportReceiptGroup(t)
	_ = opts.ReceiptGroup.Shards.Admit(receipt.EmitOpts{})
	intent := opts.ReceiptGroup.Shards.Admit(receipt.EmitOpts{
		ActionID: "refused-shard-action", Verdict: config.ActionAllow,
		Transport: opts.Transport, Target: "fetch", MCPMethod: methodToolsCall,
		ToolName: "fetch", PolicyHash: mcpTestPolicyHash,
	})
	if intent.ShardIndex != 1 {
		t.Fatalf("admission shard = %d, want 1", intent.ShardIndex)
	}
	if _, err := opts.emitReceiptDecision(MCPDecision{Receipt: intent}); err != nil {
		t.Fatal(err)
	}
	emitContractRefusedOutcome(io.Discard, TrackedRequestOutcome{Receipt: intent}, mcpContractGateOutput{}, "contract_refused", 0, opts)
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	assertMCPTransportReceiptShard(t, dir, shards, intent.ActionID)
}

func TestMCPStreamRequiredOutcomeFailureClasses(t *testing.T) {
	for _, tc := range []struct {
		name       string
		breakShard func(*MCPReceiptGroup, *recorder.Recorder)
		wantStop   bool
	}{
		{"missing_v2_pair", func(g *MCPReceiptGroup, _ *recorder.Recorder) { g.V2[1] = nil }, false},
		{"unhealthy_v1", func(g *MCPReceiptGroup, _ *recorder.Recorder) {
			g.Shards.Emitters()[1].MarkUnhealthy(errors.New("writer failed"))
		}, true},
		{"post_advance_sync_failure", func(_ *MCPReceiptGroup, rec *recorder.Recorder) {
			rec.SetSyncForTest(func(*os.File) error { return errors.New("sync failed") })
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts, rec, _, _ := newMCPTransportReceiptGroup(t)
			_ = opts.ReceiptGroup.Shards.Admit(receipt.EmitOpts{})
			intent := opts.ReceiptGroup.Shards.Admit(receipt.EmitOpts{
				ActionID: "stream-failure", Verdict: config.ActionAllow,
				Transport: opts.Transport, Target: "initialize", PolicyHash: mcpTestPolicyHash,
			})
			var stops int
			opts.ReceiptGroup.OnRequiredFailure = func(error) { stops++ }
			tc.breakShard(opts.ReceiptGroup, rec)
			var log bytes.Buffer
			recordListenerStreamError(context.Background(), &log, opts, intent, false, io.ErrUnexpectedEOF)
			if !bytes.Contains(log.Bytes(), []byte("receipt")) {
				t.Fatalf("required outcome failure was not logged: %q", log.String())
			}
			if (stops != 0) != tc.wantStop {
				t.Fatalf("required failure callback count=%d, want stop=%t", stops, tc.wantStop)
			}
			if unhealthy := opts.ReceiptGroup.Shards.Emitters()[0].HealthError() != nil; unhealthy != tc.wantStop {
				t.Fatalf("other shard unhealthy=%t, want %t", unhealthy, tc.wantStop)
			}
		})
	}
}

func TestMCPBestEffortStreamOutcomeFailureKeepsGroupRunning(t *testing.T) {
	for _, path := range []string{"stream", "websocket", "sse", "outcome"} {
		t.Run(path, func(t *testing.T) {
			opts, rec, _, _ := newMCPTransportReceiptGroup(t)
			opts.RequireReceipts = false
			_ = opts.ReceiptGroup.Shards.Admit(receipt.EmitOpts{})
			var stops int
			opts.ReceiptGroup.OnRequiredFailure = func(error) { stops++ }
			// A failed v2 pair is pre-advance: no shard may be quarantined.
			opts.ReceiptGroup.V2[1] = nil
			var log bytes.Buffer
			switch path {
			case "stream":
				intent := opts.ReceiptGroup.Shards.Admit(receipt.EmitOpts{
					ActionID: "stream-best-effort", Verdict: config.ActionAllow,
					Transport: opts.Transport, Target: "initialize", PolicyHash: mcpTestPolicyHash,
				})
				recordListenerStreamError(context.Background(), &log, opts, intent, false, io.ErrUnexpectedEOF)
			case "outcome":
				intent := opts.ReceiptGroup.Shards.Admit(receipt.EmitOpts{
					ActionID: "outcome-best-effort", Verdict: config.ActionAllow,
					Transport: opts.Transport, Target: "initialize", PolicyHash: mcpTestPolicyHash,
				})
				emitMCPOutcomeReceipt(nil, nil, opts.ReceiptGroup, &log, intent, "incomplete", -1, "stream_closed", opts.requireReceipts())
			case "websocket":
				emitMCPStandaloneStreamReceipt(opts, &log, mcpStreamReceipt(opts, "WS"), "incomplete", httpstream.Incomplete)
			case "sse":
				emitMCPStandaloneStreamReceipt(opts, &log, mcpStreamReceipt(opts, http.MethodGet), "incomplete", httpstream.Incomplete)
			}
			if stops != 0 || !bytes.Contains(log.Bytes(), []byte("receipt")) {
				t.Fatalf("best-effort outcome stops=%d log=%q", stops, log.String())
			}
			for i, shard := range opts.ReceiptGroup.Shards.Emitters() {
				if err := shard.HealthError(); err != nil {
					t.Fatalf("shard %d quarantined after pre-advance failure: %v", i, err)
				}
			}
			if err := rec.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMCPGroupedDeferAndRefusalFailureModes(t *testing.T) {
	for _, tc := range []struct {
		name     string
		required bool
		deferRun bool
	}{
		{"best_effort_defer", false, true},
		{"required_defer", true, true},
		{"best_effort_refusal", false, false},
		{"required_refusal", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts, rec, _, _ := newMCPTransportReceiptGroup(t)
			opts.RequireReceipts = tc.required
			_ = opts.ReceiptGroup.Shards.Admit(receipt.EmitOpts{})
			shard := opts.ReceiptGroup.Shards.Admit(receipt.EmitOpts{
				ActionID: "failure-mode", Transport: opts.Transport,
				Target: "fetch", MCPMethod: methodToolsCall, ToolName: "fetch",
				PolicyHash: mcpTestPolicyHash,
			})
			if shard.ShardIndex != 1 {
				t.Fatalf("admission shard = %d, want 1", shard.ShardIndex)
			}
			var stops int
			opts.ReceiptGroup.OnRequiredFailure = func(error) { stops++ }
			var log bytes.Buffer
			if tc.deferRun {
				rec.SetSyncForTest(func(*os.File) error { return errors.New("sync failed") })
				err := emitMCPToolReceipt(mcpToolReceiptOpts{
					Group: opts.ReceiptGroup, Shard: shard, Log: &log,
					ActionID: shard.ActionID, Transport: opts.Transport,
					ToolName: "fetch", Verdict: config.ActionAllow,
					PolicyHash: mcpTestPolicyHash, DecisionPhase: receipt.DecisionPhaseResolution,
					RequireReceipt: true, RequireReceipts: tc.required, Durable: true,
				})
				if !errors.Is(err, ErrReceiptRequired) {
					t.Fatalf("defer emit error = %v, want required call failure", err)
				}
			} else {
				opts.ReceiptGroup.Shards.Emitters()[1].MarkUnhealthy(errors.New("writer failed"))
				emitMCPBlockedOutcomeReceipt(nil, nil, opts.ReceiptGroup, &log, shard, 0, "contract_refused", tc.required)
				if !strings.Contains(log.String(), "receipt") {
					t.Fatalf("refused outcome failure not logged: %q", log.String())
				}
			}
			if tc.required {
				if stops != 1 || opts.ReceiptGroup.Shards.Emitters()[0].HealthError() == nil {
					t.Fatalf("required failure stops=%d other shard health=%v", stops, opts.ReceiptGroup.Shards.Emitters()[0].HealthError())
				}
			} else if stops != 0 || opts.ReceiptGroup.Shards.Emitters()[0].HealthError() != nil {
				t.Fatalf("best-effort failure stops=%d other shard health=%v", stops, opts.ReceiptGroup.Shards.Emitters()[0].HealthError())
			}
		})
	}
}

func TestMCPStreamReceiptSingleChainFieldsUnchanged(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost, "WS"} {
		t.Run(method, func(t *testing.T) {
			opts := MCPProxyOpts{Transport: "mcp_http_upstream", AuthorityDestination: "https://mcp.vendor.example", PolicyHash: mcpTestPolicyHash}
			got := mcpStreamReceipt(opts, method)
			if got.ActionID == "" || got.Transport != opts.Transport || got.Method != method || got.Target != opts.AuthorityDestination || got.PolicyHash != opts.PolicyHash || got.ShardSelected {
				t.Fatalf("single-chain stream receipt changed: %+v", got)
			}
		})
	}
}

func TestMCPStandaloneStreamSingleChainOutcomeUnchanged(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost, "WS"} {
		t.Run(method, func(t *testing.T) {
			h := newMCPDecisionReceiptHarness(t)
			opts := MCPProxyOpts{
				ReceiptEmitter: h.v1, V2ReceiptEmitter: h.v2,
				Transport: "mcp_http_upstream", AuthorityDestination: "https://mcp.vendor.example",
				PolicyHash: mcpTestPolicyHash,
			}
			intent := mcpStreamReceipt(opts, method)
			emitMCPStandaloneStreamReceipt(opts, io.Discard, intent, "incomplete", httpstream.Incomplete)
			if err := h.rec.Close(); err != nil {
				t.Fatal(err)
			}
			var found bool
			for _, entry := range readReceiptEntriesHTTP(t, h.dir) {
				if entry.Type != "action_receipt" || !bytes.Contains(entry.RawDetail, []byte(intent.ActionID)) {
					continue
				}
				found = true
				if !bytes.Contains(entry.RawDetail, []byte(`"decision_phase":"outcome"`)) || !bytes.Contains(entry.RawDetail, []byte(`"verdict":"allow"`)) || bytes.Contains(entry.RawDetail, []byte(`"shard_index"`)) {
					t.Fatalf("single-chain %s receipt fields changed: %s", method, entry.RawDetail)
				}
			}
			if !found {
				t.Fatal("missing single-chain outcome receipt")
			}
		})
	}
}

func TestMCPStandaloneStreamRequiredFailureClasses(t *testing.T) {
	for _, method := range []string{http.MethodGet, "WS"} {
		t.Run(method, func(t *testing.T) {
			for _, tc := range []struct {
				name       string
				breakShard func(*MCPReceiptGroup, *recorder.Recorder)
				wantStop   bool
			}{
				{"missing_v2_pair", func(g *MCPReceiptGroup, _ *recorder.Recorder) { g.V2[1] = nil }, false},
				{"unhealthy_v1", func(g *MCPReceiptGroup, _ *recorder.Recorder) {
					g.Shards.Emitters()[1].MarkUnhealthy(errors.New("writer failed"))
				}, true},
				{"post_advance_sync_failure", func(_ *MCPReceiptGroup, rec *recorder.Recorder) {
					rec.SetSyncForTest(func(*os.File) error { return errors.New("sync failed") })
				}, true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					opts, rec, _, _ := newMCPTransportReceiptGroup(t)
					_ = opts.ReceiptGroup.Shards.Admit(receipt.EmitOpts{})
					var stops int
					opts.ReceiptGroup.OnRequiredFailure = func(error) { stops++ }
					tc.breakShard(opts.ReceiptGroup, rec)
					var log bytes.Buffer
					emitMCPStandaloneStreamReceipt(opts, &log, mcpStreamReceipt(opts, method), "incomplete", httpstream.Incomplete)
					if !bytes.Contains(log.Bytes(), []byte("receipt")) {
						t.Fatalf("required diagnostic failure was not logged: %q", log.String())
					}
					if (stops != 0) != tc.wantStop {
						t.Fatalf("required failure callback count=%d, want stop=%t", stops, tc.wantStop)
					}
					if unhealthy := opts.ReceiptGroup.Shards.Emitters()[0].HealthError() != nil; unhealthy != tc.wantStop {
						t.Fatalf("other shard unhealthy=%t, want %t", unhealthy, tc.wantStop)
					}
				})
			}
		})
	}
}

func TestMCPWebSocketOutcomeKeepsAdmissionShard(t *testing.T) {
	responseSent := make(chan struct{})
	srv := wsRespondServer(t, []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`), responseSent)
	defer srv.Close()
	opts, rec, dir, shards := newMCPTransportReceiptGroup(t)
	opts.Scanner = testScannerForWS(t)
	_ = opts.ReceiptGroup.Shards.Admit(receipt.EmitOpts{})
	stdin, input := io.Pipe()
	var stdout, stderr lockedHTTPBuffer
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- RunWSProxy(ctx, stdin, &stdout, &stderr, wsURL(srv), opts) }()
	_, _ = io.WriteString(input, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`+"\n")
	waitForResponse(t, responseSent)
	testwait.For(t, time.Second, func() bool { return stdout.contains(`"id":1`) }, "WebSocket response forwarded")
	_ = input.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	// This is the first real admission after the dummy selection above.
	var actionID string
	for _, entry := range readReceiptEntriesHTTP(t, dir) {
		if entry.Type != "action_receipt" || !bytes.Contains(entry.RawDetail, []byte(`"decision_phase":"intent"`)) {
			continue
		}
		var detail struct {
			ActionRecord struct {
				ActionID string `json:"action_id"`
			} `json:"action_record"`
		}
		if err := json.Unmarshal(entry.RawDetail, &detail); err != nil {
			t.Fatal(err)
		}
		actionID = detail.ActionRecord.ActionID
	}
	if actionID == "" {
		t.Fatal("missing WebSocket intent")
	}
	assertMCPTransportReceiptShard(t, dir, shards, actionID)
}

func TestMCPGETSSEIncompleteOutcomeUsesSelectedShard(t *testing.T) {
	const notification = "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/resources/updated\"}\n\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Length", "4096")
		_, _ = io.WriteString(w, notification)
	}))
	defer srv.Close()
	opts, rec, dir, shards := newMCPTransportReceiptGroup(t)
	opts.Scanner = testScannerForHTTP(t)
	opts.Transport = "mcp_http_upstream"
	opts.AuthorityDestination = srv.URL
	_ = opts.ReceiptGroup.Shards.Admit(receipt.EmitOpts{})
	var stderr lockedHTTPBuffer
	ctx, cancel := context.WithCancel(t.Context())
	var wg sync.WaitGroup
	startGETStream(ctx, transport.NewHTTPClient(srv.URL, nil), &syncWriter{w: io.Discard}, &syncWriter{w: &stderr}, opts, NewRequestTracker(), &wg)
	testwait.For(t, 3*time.Second, func() bool { return stderr.contains("GET stream scan error") }, "incomplete GET SSE outcome")
	cancel()
	wg.Wait()
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	assertMCPStandaloneDiagnosticShard(t, dir, shards, 1)
}

func TestMCPWebSocketStandaloneFailureUsesSelectedShard(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			t.Errorf("WebSocket upgrade: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()
		// A declared five-byte text frame with one byte of payload is a
		// transport failure with no admitted JSON-RPC request.
		_, _ = conn.Write([]byte{0x81, 0x05, 'x'})
	}))
	defer srv.Close()
	opts, rec, dir, shards := newMCPTransportReceiptGroup(t)
	opts.Scanner = testScannerForWS(t)
	_ = opts.ReceiptGroup.Shards.Admit(receipt.EmitOpts{})
	stdin, input := io.Pipe()
	defer func() { _ = input.Close() }()
	var stdout, stderr lockedHTTPBuffer
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := RunWSProxy(ctx, stdin, &stdout, &stderr, wsURL(srv), opts); err != nil && !strings.Contains(err.Error(), "incomplete") {
		t.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	assertMCPStandaloneDiagnosticShard(t, dir, shards, 1)
}

func assertMCPStandaloneDiagnosticShard(t *testing.T, dir string, shards []receipt.ReceiptGroupShard, selected int) {
	t.Helper()
	for i, shard := range shards {
		paths, err := filepath.Glob(filepath.Join(dir, "evidence-"+shard.SessionID+"-*.jsonl"))
		if err != nil || len(paths) != 1 {
			t.Fatalf("shard %d evidence files=%v err=%v", i, paths, err)
		}
		entries, err := recorder.ReadEntries(paths[0])
		if err != nil {
			t.Fatal(err)
		}
		var diagnostic, v2 int
		for _, entry := range entries {
			if entry.Type == "action_receipt" && bytes.Contains(entry.RawDetail, []byte("reason=incomplete")) {
				if bytes.Contains(entry.RawDetail, []byte(`"decision_phase":`)) || !bytes.Contains(entry.RawDetail, []byte(`"verdict":"warn"`)) {
					t.Fatal("standalone stream diagnostic claimed a decision phase or success verdict")
				}
				diagnostic++
			}
			if entry.Type == "evidence_receipt" {
				v2++
			}
		}
		if i == selected && (diagnostic != 1 || v2 != 1) {
			t.Fatalf("selected shard %d: diagnostic=%d v2=%d, want paired 1/1", i, diagnostic, v2)
		}
		if i != selected && (diagnostic != 0 || v2 != 0) {
			t.Fatalf("other shard %d: diagnostic=%d v2=%d, want 0/0", i, diagnostic, v2)
		}
	}
}
