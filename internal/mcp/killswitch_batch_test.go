// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

const killSwitchBatchMessage = "test kill"

// killSwitchBatchCases are the refused batches every transport must handle the
// way it handles the same messages sent one at a time: every tool call and A2A
// member is receipted, every member with an id gets a -32004 error in a batch
// response, and a batch of notifications gets no response at all.
var killSwitchBatchCases = []struct {
	name        string
	body        string
	wantTargets []string // receipt targets, in member order
	wantIDs     []int    // ids of the -32004 errors in the batch response; nil means no response
	// listenerStatus overrides the HTTP listener's status when a stage ahead of
	// the kill switch (JSON validation) answers first.
	listenerStatus int
}{
	{
		name: "mixed members",
		body: `[` +
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"x"}}},` +
			`{"jsonrpc":"2.0","id":2,"method":"message/send","params":{}},` +
			`{"jsonrpc":"2.0","id":3,"method":"tools/list"},` +
			`{"jsonrpc":"2.0","method":"notifications/initialized"},` +
			`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"write_file","arguments":{"path":"y"}}}` +
			`]`,
		wantTargets: []string{"read_file", "message/send", "write_file"},
		wantIDs:     []int{1, 2, 3},
	},
	{
		name: "only notifications",
		body: `[` +
			`{"jsonrpc":"2.0","method":"notifications/initialized"},` +
			`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"write_file","arguments":{"path":"y"}}}` +
			`]`,
		wantTargets: []string{"write_file"},
	},
	{name: "empty batch", body: `[]`},
	{name: "malformed batch", body: `[{"jsonrpc":"2.0","id":1,"method":"tools/call"`, listenerStatus: http.StatusBadRequest},
	{name: "nested batch", body: `[[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}]]`},
}

func requireKillSwitchBatchReceipts(t *testing.T, got *allReceipts, wantTargets []string) {
	t.Helper()
	recs := got.snapshot()
	if len(recs) != len(wantTargets) {
		t.Fatalf("receipts = %d (%+v), want %d kill-switch blocks for %v", len(recs), recs, len(wantTargets), wantTargets)
	}
	for i, rec := range recs {
		if rec.Verdict != config.ActionBlock || rec.Layer != mcpReceiptLayerKillSwitch || rec.Target != wantTargets[i] {
			t.Fatalf("receipt %d = verdict %q layer %q target %q, want block %q %q",
				i, rec.Verdict, rec.Layer, rec.Target, mcpReceiptLayerKillSwitch, wantTargets[i])
		}
	}
}

// requireKillSwitchBatchResponse checks body is a batch response holding one
// -32004 error per wantIDs entry, in order, or empty when wantIDs is nil.
func requireKillSwitchBatchResponse(t *testing.T, body string, wantIDs []int) {
	t.Helper()
	body = strings.TrimSpace(body)
	if wantIDs == nil {
		if body != "" {
			t.Fatalf("response = %s, want no response", body)
		}
		return
	}
	var resps []struct {
		ID    int `json:"id"`
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &resps); err != nil {
		t.Fatalf("response is not a batch response array: %q: %v", body, err)
	}
	if len(resps) != len(wantIDs) {
		t.Fatalf("batch response has %d entries, want %d: %s", len(resps), len(wantIDs), body)
	}
	for i, r := range resps {
		if r.ID != wantIDs[i] || r.Error.Code != -32004 || r.Error.Message != killSwitchBatchMessage {
			t.Fatalf("response %d = %+v, want id %d code -32004 message %q", i, r, wantIDs[i], killSwitchBatchMessage)
		}
	}
}

func killSwitchBatchController() *killswitch.Controller {
	return killSwitchDenialController()
}

func TestKillSwitchBatchResponse(t *testing.T) {
	for _, tc := range killSwitchBatchCases {
		t.Run(tc.name, func(t *testing.T) {
			got := killSwitchBatchResponse(ParseMCPFrame([]byte(tc.body)), killSwitchBatchMessage)
			if tc.wantIDs == nil {
				if got != nil {
					t.Fatalf("response = %s, want nil", got)
				}
				return
			}
			requireKillSwitchBatchResponse(t, string(got), tc.wantIDs)
		})
	}
	t.Run("single object is not answered as a batch", func(t *testing.T) {
		if got := killSwitchBatchResponse(ParseMCPFrame([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`)), "m"); got != nil {
			t.Fatalf("response = %s, want nil", got)
		}
	})
}

func TestHTTPListenerKillSwitchBatchIsReceipted(t *testing.T) {
	for _, tc := range killSwitchBatchCases {
		t.Run(tc.name, func(t *testing.T) {
			var upstreamCalls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { upstreamCalls.Add(1) }))
			defer upstream.Close()

			got := &allReceipts{}
			emitter, _, _, _ := newReceiptTestHarnessWithObserver(t, got.observe)
			baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{
				Scanner: testScannerForHTTP(t), ReceiptEmitter: emitter, KillSwitch: killSwitchBatchController(),
			})
			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/", strings.NewReader(tc.body))
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("POST: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("ReadAll: %v", err)
			}
			if upstreamCalls.Load() != 0 {
				t.Fatalf("refused batch reached upstream")
			}
			wantStatus := http.StatusOK
			if tc.wantIDs == nil {
				wantStatus = http.StatusAccepted
			}
			if tc.listenerStatus != 0 {
				wantStatus = tc.listenerStatus
			}
			if resp.StatusCode != wantStatus {
				t.Fatalf("status = %d, want %d: %s", resp.StatusCode, wantStatus, body)
			}
			if tc.listenerStatus == 0 {
				requireKillSwitchBatchResponse(t, string(body), tc.wantIDs)
			}
			requireKillSwitchBatchReceipts(t, got, tc.wantTargets)
		})
	}
}

func TestWSProxyKillSwitchBatchIsReceipted(t *testing.T) {
	for _, tc := range killSwitchBatchCases {
		t.Run(tc.name, func(t *testing.T) {
			srv, upstreamFrames := wsDrainServer(t)
			defer srv.Close()

			got := &allReceipts{}
			emitter, _, _, _ := newReceiptTestHarnessWithObserver(t, got.observe)
			var stdout, stderr bytes.Buffer
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := RunWSProxy(ctx, strings.NewReader(tc.body+"\n"), &stdout, &stderr, wsURL(srv), MCPProxyOpts{
				Scanner: testInputScanner(t), ReceiptEmitter: emitter, KillSwitch: killSwitchBatchController(),
			})
			if err != nil {
				t.Fatalf("RunWSProxy: %v", err)
			}
			if n := upstreamFrames.Load(); n != 0 {
				t.Fatalf("refused batch reached upstream (%d frames)", n)
			}
			requireKillSwitchBatchResponse(t, stdout.String(), tc.wantIDs)
			requireKillSwitchBatchReceipts(t, got, tc.wantTargets)
		})
	}
}

func TestHTTPBridgeKillSwitchBatchIsReceipted(t *testing.T) {
	for _, tc := range killSwitchBatchCases {
		t.Run(tc.name, func(t *testing.T) {
			var upstreamCalls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { upstreamCalls.Add(1) }))
			defer upstream.Close()

			got := &allReceipts{}
			emitter, _, _, _ := newReceiptTestHarnessWithObserver(t, got.observe)
			var stdout, stderr bytes.Buffer
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := RunHTTPProxy(ctx, strings.NewReader(tc.body+"\n"), &stdout, &stderr, upstream.URL, nil, MCPProxyOpts{
				Scanner: testInputScanner(t), ReceiptEmitter: emitter, KillSwitch: killSwitchBatchController(),
			})
			if err != nil {
				t.Fatalf("RunHTTPProxy: %v", err)
			}
			if upstreamCalls.Load() != 0 {
				t.Fatalf("refused batch reached upstream")
			}
			requireKillSwitchBatchResponse(t, stdout.String(), tc.wantIDs)
			requireKillSwitchBatchReceipts(t, got, tc.wantTargets)
		})
	}
}

func TestStdioKillSwitchBatchIsReceipted(t *testing.T) {
	for _, tc := range killSwitchBatchCases {
		t.Run(tc.name, func(t *testing.T) {
			ks := killSwitchBatchController()
			got := &allReceipts{}
			emitter, _, _, _ := newReceiptTestHarnessWithObserver(t, got.observe)
			inputR, inputW := io.Pipe()
			var upstream, logBuf syncBuffer
			blocked := make(chan BlockedRequest, 8)
			done := make(chan struct{})
			go func() {
				defer close(done)
				ForwardScannedInput(transport.NewStdioReader(inputR), transport.NewStdioWriter(&upstream), &logBuf,
					config.ActionWarn, config.ActionBlock, blocked, nil, nil, MCPProxyOpts{
						Scanner: testInputScanner(t), ReceiptEmitter: emitter,
						Transport: deferred.SurfaceMCPStdio, KillSwitch: ks,
					})
			}()
			if _, err := inputW.Write([]byte(tc.body + "\n")); err != nil {
				t.Fatalf("write input: %v", err)
			}
			if err := inputW.Close(); err != nil {
				t.Fatalf("close input: %v", err)
			}
			<-done
			if upstream.String() != "" {
				t.Fatalf("refused batch reached upstream: %s", upstream.String())
			}
			var response string
			for b := range blocked {
				if b.IsNotification {
					continue
				}
				if b.SyntheticResponse == nil {
					t.Fatalf("batch refusal queued a single-object error: %+v", b)
				}
				response += string(b.SyntheticResponse)
			}
			requireKillSwitchBatchResponse(t, response, tc.wantIDs)
			requireKillSwitchBatchReceipts(t, got, tc.wantTargets)
		})
	}
}
