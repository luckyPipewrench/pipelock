// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

type bridgeIntegrityWriter struct {
	bytes.Buffer
	match  string
	signal chan struct{}
	once   sync.Once
}

func (w *bridgeIntegrityWriter) Write(p []byte) (int, error) {
	n, err := w.Buffer.Write(p)
	if strings.Contains(string(p), w.match) {
		w.once.Do(func() { close(w.signal) })
	}
	return n, err
}

// Stdio bridges forward complete JSON-RPC messages, rather than HTTP bytes.
// A partial HTTP body or WebSocket frame must still fail the owning bridge
// and leave incomplete evidence for the outstanding request.
func TestMCPBridgeStreamIntegrity(t *testing.T) {
	for _, wire := range []string{"http", "http_get", "ws"} {
		for _, ending := range []string{"chunked_break", "short_length", "completed_rpc_then_break", "fragment_break", "fragment_close", "cancel", "complete"} {
			t.Run(wire+"/"+ending, func(t *testing.T) {
				if wire != "ws" && strings.HasPrefix(ending, "fragment_") {
					t.Skip("fragmented messages apply only to WebSocket transports")
				}
				release := make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				t.Cleanup(unblock)
				upstreamDone := make(chan struct{})
				progress := "data: " + jsonProgressNotification50 + "\n\n"
				result := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hello"}]}}`
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if wire == "http_get" {
						switch r.Method {
						case http.MethodPost:
							w.Header().Set("Mcp-Session-Id", "integrity-session")
							w.Header().Set("Content-Type", "application/json")
							_, _ = io.WriteString(w, result)
							return
						case http.MethodDelete:
							w.WriteHeader(http.StatusNoContent)
							return
						}
					}
					defer close(upstreamDone)
					if wire == "ws" {
						conn, _, _, err := ws.UpgradeHTTP(r, w)
						if err != nil {
							return
						}
						defer func() { _ = conn.Close() }()
						_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
						if _, _, err := wsutil.ReadClientData(conn); err != nil {
							return
						}
						_ = wsutil.WriteServerMessage(conn, ws.OpText, []byte(jsonProgressNotification50))
						if ending == "completed_rpc_then_break" {
							_ = wsutil.WriteServerMessage(conn, ws.OpText, []byte(result))
						}
						if ending == "cancel" {
							_, _, _ = wsutil.ReadClientData(conn)
							return
						}
						<-release
						switch ending {
						case "chunked_break", "completed_rpc_then_break":
							// Break inside a frame header.
							_, _ = conn.Write([]byte{0x81})
						case "short_length":
							// Break inside the declared frame payload.
							_ = ws.WriteHeader(conn, ws.Header{Fin: true, OpCode: ws.OpText, Length: int64(len(result) + 10)})
							_, _ = io.WriteString(conn, result[:len(result)/2])
						case "fragment_break", "fragment_close":
							partial := result[:len(result)/2]
							_ = ws.WriteHeader(conn, ws.Header{Fin: false, OpCode: ws.OpText, Length: int64(len(partial))})
							_, _ = io.WriteString(conn, partial)
							if ending == "fragment_close" {
								_ = wsutil.WriteServerMessage(conn, ws.OpClose, ws.NewCloseFrameBody(ws.StatusNormalClosure, ""))
							}
						case "complete":
							_ = wsutil.WriteServerMessage(conn, ws.OpText, []byte(result))
							_ = wsutil.WriteServerMessage(conn, ws.OpClose, ws.NewCloseFrameBody(ws.StatusNormalClosure, ""))
						}
						return
					}
					w.Header().Set("Content-Type", "text/event-stream")
					if ending == "short_length" {
						w.Header().Set("Content-Length", strconv.Itoa(len(progress)+1024))
					}
					_, _ = io.WriteString(w, progress)
					if ending == "completed_rpc_then_break" && wire != "http_get" {
						_, _ = io.WriteString(w, "data: "+result+"\n\n")
					}
					w.(http.Flusher).Flush()
					select {
					case <-release:
					case <-r.Context().Done():
						return
					}
					if ending == "chunked_break" || ending == "completed_rpc_then_break" {
						panic(http.ErrAbortHandler)
					}
					if ending == "complete" && wire != "http_get" {
						_, _ = io.WriteString(w, "data: "+result+"\n\n")
					}
				}))
				t.Cleanup(upstream.Close)
				h := newMCPDecisionReceiptHarness(t)
				auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
				logger, err := audit.New("json", "file", auditPath, false, false)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(logger.Close)
				clientIn, clientWriter := io.Pipe()
				t.Cleanup(func() { _ = clientIn.Close(); _ = clientWriter.Close() })
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				first := &bridgeIntegrityWriter{match: jsonProgressNotification50, signal: make(chan struct{})}
				logs := &bridgeIntegrityWriter{match: "response stream incomplete", signal: make(chan struct{})}
				bridgeDone := make(chan error, 1)
				opts := MCPProxyOpts{Scanner: testScannerForHTTP(t), ReceiptEmitter: h.v1, AuditLogger: logger, RequireReceipts: true}
				go func() {
					if wire == "ws" {
						bridgeDone <- RunWSProxy(ctx, clientIn, first, logs, "ws"+strings.TrimPrefix(upstream.URL, "http"), opts)
					} else {
						bridgeDone <- RunHTTPProxy(ctx, clientIn, first, logs, upstream.URL, nil, opts)
					}
				}()
				if _, err := io.WriteString(clientWriter, jsonToolsCallEcho+"\n"); err != nil {
					t.Fatal(err)
				}
				waitBridgeSignal(t, first.signal)
				if ending == "cancel" {
					cancel()
				} else {
					unblock()
				}
				if ending != "complete" && ending != "cancel" {
					waitBridgeSignal(t, logs.signal)
				}
				waitBridgeSignal(t, upstreamDone)
				if wire != "ws" || ending == "cancel" {
					_ = clientWriter.Close()
				}
				select {
				case err := <-bridgeDone:
					if ending != "complete" && ending != "cancel" {
						if wire != "http_get" && !errors.Is(err, transport.ErrIncompleteResponse) {
							t.Fatalf("bridge error=%v, want incomplete response", err)
						}
					} else if ending == "complete" && err != nil {
						t.Fatalf("complete bridge=%v", err)
					}
				case <-ctx.Done():
					if ending != "cancel" {
						t.Fatalf("bridge did not finish: %s", logs.String())
					}
					select {
					case <-bridgeDone:
					case <-time.After(time.Second):
						t.Fatal("cancelled bridge did not finish")
					}
				}
				if err := h.rec.Close(); err != nil {
					t.Fatal(err)
				}
				wantIncomplete := ending != "cancel" && ending != "complete"
				found := false
				foundIncomplete := false
				outcomeIDs := make(map[string]bool)
				for _, rec := range readActionReceipts(t, h.dir) {
					if rec.ActionRecord.Layer != "outcome" {
						continue
					}
					found = true
					if outcomeIDs[rec.ActionRecord.ActionID] {
						t.Fatalf("duplicate outcome for completed action %s", rec.ActionRecord.ActionID)
					}
					outcomeIDs[rec.ActionRecord.ActionID] = true
					got := strings.Contains(rec.ActionRecord.Pattern, "reason=incomplete")
					foundIncomplete = foundIncomplete || got
					if got && !wantIncomplete {
						t.Fatalf("outcome=%s", rec.ActionRecord.Pattern)
					}
					if ending == "cancel" && strings.Contains(rec.ActionRecord.Pattern, "status=incomplete") {
						t.Fatalf("cancelled outcome=%s", rec.ActionRecord.Pattern)
					}
				}
				if !found {
					t.Fatal("no bridge outcome")
				}
				if foundIncomplete != wantIncomplete {
					t.Fatalf("incomplete receipt=%v want=%v", foundIncomplete, wantIncomplete)
				}
				logger.Close()
				logBytes, err := os.ReadFile(filepath.Clean(auditPath))
				if err != nil {
					t.Fatal(err)
				}
				if got := strings.Contains(string(logBytes), "response stream incomplete"); got != wantIncomplete {
					t.Fatalf("incomplete audit=%v want=%v: %s", got, wantIncomplete, logBytes)
				}
			})
		}
	}
}

func waitBridgeSignal(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stream bridge goroutine did not finish")
	}
}
