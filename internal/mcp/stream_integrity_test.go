// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/httpstream"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// The MCP listener serves plain HTTP/1; it does not negotiate HTTP/2. Exercise
// its actual server, rather than a recorder that cannot observe chunk framing.
func TestMCPListenerStreamIntegrity(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		for _, ending := range []string{"chunked_break", "short_length", "completed_rpc_then_break", "cancel", "complete"} {
			t.Run(method+"/"+ending, func(t *testing.T) {
				if method == http.MethodGet && ending == "completed_rpc_then_break" {
					t.Skip("GET subscriptions carry notifications rather than client request results")
				}
				payload := "data: " + jsonProgressNotification50 + "\n\n"
				if ending == "completed_rpc_then_break" {
					payload += "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"hello\"}]}}\n\n"
				}
				release := make(chan struct{})
				var releaseOnce sync.Once
				releaseUpstream := func() { releaseOnce.Do(func() { close(release) }) }
				upstreamDone := make(chan struct{})
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer close(upstreamDone)
					w.Header().Set("Content-Type", "text/event-stream")
					if ending == "short_length" {
						w.Header().Set("Content-Length", strconv.Itoa(len(payload)+1024))
					}
					_, _ = io.WriteString(w, payload)
					w.(http.Flusher).Flush()
					select {
					case <-release:
					case <-r.Context().Done():
						return
					}
					if ending == "chunked_break" || ending == "completed_rpc_then_break" {
						panic(http.ErrAbortHandler)
					}
				}))
				h := newMCPDecisionReceiptHarness(t)
				auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
				logger, err := audit.New("json", "file", auditPath, false, false)
				if err != nil {
					t.Fatal(err)
				}
				ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancelListener := context.WithCancel(t.Context())
				listenerDone := make(chan error, 1)
				sc := testScannerForHTTP(t)
				go func() {
					listenerDone <- RunHTTPListenerProxy(ctx, ln, upstream.URL, io.Discard, MCPProxyOpts{
						Scanner: sc, ReceiptEmitter: h.v1, AuditLogger: logger, RequireReceipts: true,
					})
				}()
				t.Cleanup(func() {
					releaseUpstream()
					cancelListener()
					_ = ln.Close()
					upstream.Close()
					logger.Close()
				})
				baseURL := "http://" + ln.Addr().String()
				waitForHTTPHealth(t, baseURL)
				requestCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				var requestBody io.Reader
				if method == http.MethodPost {
					requestBody = strings.NewReader(jsonToolsCallEcho)
				}
				req, err := http.NewRequestWithContext(requestCtx, method, baseURL+"/", requestBody)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Accept", "text/event-stream")
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatalf("before upstream break: %v", err)
				}
				defer func() { _ = resp.Body.Close() }()
				if resp.StatusCode != http.StatusOK {
					body, _ := io.ReadAll(resp.Body)
					t.Fatalf("status=%d body=%s", resp.StatusCode, body)
				}
				first := make([]byte, len(payload))
				if _, err := io.ReadFull(resp.Body, first); err != nil {
					t.Fatal(err)
				}
				if string(first) != payload {
					t.Fatalf("event = %s", first)
				}
				if ending == "cancel" {
					cancel()
				} else {
					releaseUpstream()
				}
				_, readErr := io.ReadAll(resp.Body)
				if (readErr == nil) != (ending == "complete") {
					t.Fatalf("read error = %v, ending = %s", readErr, ending)
				}
				select {
				case <-upstreamDone:
				case <-time.After(5 * time.Second):
					t.Fatal("upstream did not end after downstream cancellation")
				}
				cancelListener()
				select {
				case err := <-listenerDone:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(6 * time.Second):
					t.Fatal("listener handler did not end")
				}
				if err := h.rec.Close(); err != nil {
					t.Fatal(err)
				}
				var receipts []receipt.Receipt
				if method == http.MethodGet && ending == "complete" {
					_, err := os.Stat(filepath.Join(h.dir, "evidence-proxy-0.jsonl"))
					if !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("completed GET subscription created receipt evidence: %v", err)
					}
				} else {
					receipts = readActionReceipts(t, h.dir)
				}
				wantReason := httpstream.Incomplete
				if ending == "cancel" {
					wantReason = httpstream.Cancelled
				}
				found := false
				outcomeIDs := make(map[string]bool)
				for _, rec := range receipts {
					if method == http.MethodGet {
						if rec.ActionRecord.Layer != "outcome" {
							t.Fatalf("GET subscription emitted a new decision receipt: %+v", rec.ActionRecord)
						}
						if ending == "complete" {
							t.Fatalf("completed GET subscription emitted a new outcome receipt: %+v", rec.ActionRecord)
						}
					}
					if rec.ActionRecord.Layer == "outcome" {
						if outcomeIDs[rec.ActionRecord.ActionID] {
							t.Fatalf("duplicate outcome for action %s", rec.ActionRecord.ActionID)
						}
						outcomeIDs[rec.ActionRecord.ActionID] = true
					}
					if rec.ActionRecord.Layer == "outcome" && strings.Contains(rec.ActionRecord.Pattern, "reason="+wantReason) {
						found = true
					}
				}
				if ending != "complete" && !found {
					t.Fatalf("missing %s outcome: %+v", wantReason, receipts)
				}
				logger.Close()
				logBytes, err := os.ReadFile(filepath.Clean(auditPath))
				if err != nil {
					t.Fatal(err)
				}
				wantAudit := ending != "cancel" && ending != "complete"
				if got := strings.Contains(string(logBytes), "response stream incomplete"); got != wantAudit {
					t.Fatalf("incomplete audit=%v want=%v: %s", got, wantAudit, logBytes)
				}
			})
		}
	}
}
