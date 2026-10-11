// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gobwas/ws"
	gobwasutil "github.com/gobwas/ws/wsutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

func responseStateReader(t *testing.T, kind, raw string) transport.MessageReader {
	t.Helper()
	switch kind {
	case "http":
		return &transport.SingleMessageReader{Body: io.NopCloser(strings.NewReader(raw))}
	case "sse":
		return transport.NewSSEReader(strings.NewReader("data: " + raw + "\n\n"))
	case "websocket":
		client, server := net.Pipe()
		t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
		go func() {
			defer func() { _ = server.Close() }()
			_ = gobwasutil.WriteServerMessage(server, ws.OpText, []byte(raw))
		}()
		return transport.NewWSClientFromConn(client, false)
	default:
		return transport.NewStdioReader(strings.NewReader(raw + "\n"))
	}
}

func TestResponseKeyRejectionPreservesOutcomeReceipts(t *testing.T) {
	for _, kind := range []string{"stdio", "http", "sse", "websocket"} {
		for _, tc := range []struct {
			name, raw   string
			wantOutcome bool
		}{
			{"duplicate", `{"jsonrpc":"2.0","id":1,"result":{},"result":{}}`, true},
			{"alias", `{"jsonrpc":"2.0","id":1,"Result":{}}`, true},
			{"nested-alias", `{"jsonrpc":"2.0","id":1,"result":{"Content":[]}}`, true},
			{"duplicate-id", `{"jsonrpc":"2.0","id":1,"id":2,"result":{}}`, false},
			{"aliased-id", `{"jsonrpc":"2.0","id":1,"ID":2,"result":{}}`, false},
			{"unsolicited", `{"jsonrpc":"2.0","id":2,"Result":{}}`, false},
			{"server-request", `{"jsonrpc":"2.0","id":1,"Method":"ping"}`, false},
			{"malformed", `{"jsonrpc":"2.0","id":1,"result":`, false},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				emitter, rec, dir, _ := newReceiptTestHarness(t)
				intent := receipt.EmitOpts{
					ActionID: receipt.NewActionID(), Verdict: config.ActionAllow,
					Transport: kind, Target: "read_file", MCPMethod: methodToolsCall, ToolName: "read_file",
				}
				if _, err := EmitMCPDecision(emitter, nil, nil, MCPDecision{Receipt: intent, RequireReceipt: true}); err != nil {
					t.Fatal(err)
				}
				tracker := NewRequestTracker()
				tracked := TrackedRequestOutcome{Receipt: intent, Method: methodToolsCall}
				tracker.TrackOutcome(json.RawMessage("1"), tracked)
				baseline := tools.NewToolBaseline()
				opts := buildTestOpts(testInputScanner(t), withToolCfg(&tools.ToolScanConfig{Action: config.ActionWarn, DetectDrift: true, Baseline: baseline}))
				opts.ReceiptEmitter = emitter
				opts.Transport = kind
				admissions := 0
				opts.OnResponseKeysValidated = func() { admissions++ }
				var out, logs bytes.Buffer
				if _, err := ForwardScanned(responseStateReader(t, kind, tc.raw), transport.NewStdioWriter(&out), &logs, tracker, opts); err != nil {
					t.Fatal(err)
				}
				if !bytes.Contains(out.Bytes(), []byte(`"error"`)) {
					t.Fatalf("rejected response forwarded: %s", out.String())
				}
				if admissions != 0 || baseline.HasBaseline() || baseline.HasDriftBaseline() {
					t.Fatal("rejection admitted response state")
				}
				if got, ok := tracker.Consume(json.RawMessage("1")); !ok || !reflect.DeepEqual(got, tracked) {
					t.Fatal("rejection consumed or changed request metadata")
				}
				if err := rec.Close(); err != nil {
					t.Fatal(err)
				}
				receipts := readActionReceipts(t, dir)
				want := 1
				if tc.wantOutcome {
					want++
				}
				if len(receipts) != want {
					t.Fatalf("receipts=%d, want %d (intent plus expected rejection outcome)", len(receipts), want)
				}
				if tc.wantOutcome {
					got := receipts[1].ActionRecord
					if got.ActionID != intent.ActionID || got.DecisionPhase != receipt.DecisionPhaseOutcome || !strings.Contains(got.Pattern, "status=error") || !strings.Contains(got.Pattern, "reason=response_key_validation") {
						t.Fatalf("unexpected rejection outcome: %+v", got)
					}
				}
			})
		}
	}
}

func TestResponseKeyRejectionBoundsOutcomeReceipts(t *testing.T) {
	for _, kind := range []string{"stdio", "http", "sse", "websocket"} {
		for _, concurrent := range []bool{false, true} {
			t.Run(kind+"/concurrent="+strconv.FormatBool(concurrent), func(t *testing.T) {
				emitter, rec, dir, _ := newReceiptTestHarness(t)
				intent := receipt.EmitOpts{ActionID: receipt.NewActionID(), Verdict: config.ActionAllow, Transport: kind, Target: "read_file", MCPMethod: methodToolsCall, ToolName: "read_file"}
				if _, err := EmitMCPDecision(emitter, nil, nil, MCPDecision{Receipt: intent, RequireReceipt: true}); err != nil {
					t.Fatal(err)
				}
				tracker := NewRequestTracker()
				tracker.TrackOutcome(json.RawMessage("1"), TrackedRequestOutcome{Receipt: intent, Method: methodToolsCall})
				baseline := tools.NewToolBaseline()
				opts := buildTestOpts(testInputScanner(t), withToolCfg(&tools.ToolScanConfig{Action: config.ActionWarn, DetectDrift: true, Baseline: baseline}))
				opts.ReceiptEmitter, opts.Transport = emitter, kind
				var admissions atomic.Int32
				opts.OnResponseKeysValidated = func() { admissions.Add(1) }
				reject := func() {
					var out, logs bytes.Buffer
					if _, err := ForwardScanned(responseStateReader(t, kind, `{"jsonrpc":"2.0","id":1,"Result":{}}`), transport.NewStdioWriter(&out), &logs, tracker, opts); err != nil {
						t.Error(err)
					} else if !bytes.Contains(out.Bytes(), []byte(`"error"`)) {
						t.Errorf("rejected response forwarded: %s", out.String())
					}
				}
				const attempts = 8
				if concurrent {
					start, done := make(chan struct{}), make(chan struct{}, attempts)
					for range attempts {
						go func() {
							<-start
							reject()
							done <- struct{}{}
						}()
					}
					close(start)
					for range attempts {
						<-done
					}
				} else {
					for range attempts {
						reject()
					}
				}
				if admissions.Load() != 0 || baseline.HasBaseline() || baseline.HasDriftBaseline() {
					t.Fatal("rejection admitted response state")
				}
				var out, logs bytes.Buffer
				if _, err := ForwardScanned(responseStateReader(t, kind, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`), transport.NewStdioWriter(&out), &logs, tracker, opts); err != nil {
					t.Fatal(err)
				}
				if admissions.Load() != 1 || !bytes.Contains(out.Bytes(), []byte(`"result"`)) || tracker.Validate(json.RawMessage("1")) {
					t.Fatal("valid response did not consume preserved correlation exactly once")
				}
				if err := rec.Close(); err != nil {
					t.Fatal(err)
				}
				receipts := readActionReceipts(t, dir)
				if len(receipts) != 3 {
					t.Fatalf("receipts=%d, want intent, one rejection outcome and valid outcome", len(receipts))
				}
				for i, status := range []string{"error", "result"} {
					got := receipts[i+1].ActionRecord
					if got.ActionID != intent.ActionID || got.DecisionPhase != receipt.DecisionPhaseOutcome || !strings.Contains(got.Pattern, "status="+status) {
						t.Fatalf("unexpected outcome: %+v", got)
					}
				}
			})
		}
	}
}

func TestMalformedResponseKeyRejectionPreservesCorrelation(t *testing.T) {
	for _, kind := range []string{"stdio", "http", "sse", "websocket"} {
		for _, tc := range []struct {
			name string
			raw  string
			id   string
		}{
			{"numeric", `{"id":7,"result":`, "7"},
			{"string", `{"id":"request-a","result":`, `"request-a"`},
			{"escaped", `{"i\u0064":7,"result":`, "7"},
			{"unrecoverable", `{"result":`, jsonrpc.Null},
			{"field-type-error", `{"jsonrpc":1,"id":7,"result":{}}`, jsonrpc.Null},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				baseline := tools.NewToolBaseline()
				opts := buildTestOpts(testScannerWithAction(t, config.ActionWarn), withToolCfg(&tools.ToolScanConfig{Action: config.ActionWarn, DetectDrift: true, Baseline: baseline}))
				admitted := 0
				opts.OnResponseKeysValidated = func() { admitted++ }
				tracker := NewStrictRequestTrackerFor(json.RawMessage("7"), "tools/list")
				var out, logs bytes.Buffer
				if _, err := ForwardScanned(responseStateReader(t, kind, tc.raw), transport.NewStdioWriter(&out), &logs, tracker, opts); err != nil {
					t.Fatal(err)
				}
				var response struct {
					ID    json.RawMessage `json:"id"`
					Error json.RawMessage `json:"error"`
				}
				if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &response); err != nil {
					t.Fatal(err)
				}
				if string(response.ID) != tc.id || len(response.Error) == 0 {
					t.Fatalf("block response = %s, want id %s", out.String(), tc.id)
				}
				if tc.name != "field-type-error" {
					if admitted != 0 || baseline.HasDriftBaseline() || baseline.HasBaseline() {
						t.Fatal("malformed response admitted session state")
					}
					if _, ok := tracker.Consume(json.RawMessage("7")); !ok {
						t.Fatal("malformed response consumed outstanding request")
					}
				}
			})
		}
	}
}

func TestResponseKeyRejectionLeavesStateUntouched(t *testing.T) {
	const valid = `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"safe","description":"A normal tool"}]}}`
	for _, kind := range []string{"stdio", "http", "sse", "websocket"} {
		for _, seeded := range []bool{false, true} {
			for _, variant := range []string{"alias", "duplicate", "batch", "valid"} {
				t.Run(kind+"/"+variant+"/seeded="+strconv.FormatBool(seeded), func(t *testing.T) {
					baseline := tools.NewToolBaseline()
					cfg := &tools.ToolScanConfig{Action: config.ActionWarn, DetectDrift: true, Baseline: baseline}
					sc := testScannerWithAction(t, config.ActionWarn)
					opts := buildTestOpts(sc, withToolCfg(cfg))
					if seeded {
						var out, log bytes.Buffer
						if _, err := ForwardScanned(responseStateReader(t, "stdio", valid), transport.NewStdioWriter(&out), &log, nil, opts); err != nil {
							t.Fatal(err)
						}
					}
					_, beforeHash, _ := baseline.CheckAndUpdatePromote("safe", "probe", false, false)
					beforeDrift, beforeInventory := baseline.HasDriftBaseline(), baseline.HasBaseline()
					raw := strings.Replace(valid, "A normal tool", "A changed normal tool", 1)
					switch variant {
					case "alias":
						raw = strings.Replace(raw, `"result"`, `"Result"`, 1)
					case "duplicate":
						raw = strings.Replace(raw, `"id":1`, `"id":1,"id":1`, 1)
					case "batch":
						raw = "[" + valid + "," + strings.Replace(raw, `"result"`, `"Result"`, 1) + "]"
					}
					tracker := NewStrictRequestTrackerFor(json.RawMessage("1"), "tools/list")
					rec := &taintRecorder{}
					opts.Rec = rec
					taintCfg := config.Defaults().Taint
					opts.TaintCfg = &taintCfg
					opts.TaintExternalSource = true
					beforeRisk := rec.RiskSnapshot()
					admitted := 0
					opts.OnResponseKeysValidated = func() { admitted++ }
					var out, log bytes.Buffer
					blocked, err := ForwardScanned(responseStateReader(t, kind, raw), transport.NewStdioWriter(&out), &log, tracker, opts)
					if err != nil {
						t.Fatal(err)
					}
					_, afterHash, _ := baseline.CheckAndUpdatePromote("safe", "probe", false, false)
					if variant != "valid" {
						if !blocked || !strings.Contains(out.String(), `"error"`) {
							t.Fatalf("rejection missing: %s", out.String())
						}
						if !reflect.DeepEqual(beforeRisk, rec.RiskSnapshot()) || admitted != 0 || baseline.HasDriftBaseline() != beforeDrift || baseline.HasBaseline() != beforeInventory || beforeHash != afterHash || baseline.IsKnownTool("safe") != seeded {
							t.Fatal("rejected response changed admission, drift, or inventory")
						}
						if _, ok := tracker.Consume(json.RawMessage("1")); !ok {
							t.Fatal("rejected response consumed request correlation")
						}
					} else {
						if admitted != 1 || !baseline.HasDriftBaseline() || !baseline.IsKnownTool("safe") || afterHash == beforeHash {
							t.Fatal("valid response did not update state")
						}
					}
				})
			}
		}
	}
}

func TestHTTPResponseKeyRejectionDefersSessionHeaders(t *testing.T) {
	for _, contentType := range []string{"application/json", "text/event-stream"} {
		for _, alias := range []bool{false, true} {
			t.Run(contentType+"/alias="+strconv.FormatBool(alias), func(t *testing.T) {
				raw := `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`
				if alias {
					raw = strings.Replace(raw, `"result"`, `"Result"`, 1)
				}
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", contentType)
					w.Header().Set("Mcp-Session-Id", "session-test")
					if contentType == "text/event-stream" {
						_, _ = io.WriteString(w, "data: "+raw+"\n\n")
					} else {
						_, _ = io.WriteString(w, raw)
					}
				}))
				defer srv.Close()
				client := transport.NewHTTPClient(srv.URL, nil)
				client.ResponseKeyValidator = jsonrpc.ValidateMessageKeys
				reader, err := client.SendMessage(t.Context(), []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if closer, ok := reader.(io.Closer); ok {
						_ = closer.Close()
					}
				}()
				if client.SessionID() != "" {
					t.Fatal("headers committed before message validation")
				}
				if _, err := reader.ReadMessage(); err != nil {
					t.Fatal(err)
				}
				if alias && client.SessionID() != "" {
					t.Fatal("rejected alias established HTTP session")
				}
				if !alias && client.SessionID() != "session-test" {
					t.Fatal("valid message did not establish HTTP session")
				}
			})
		}
	}
}

func TestScanStreamKeyRejectionLeavesStateUntouched(t *testing.T) {
	const valid = `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"safe","description":"A normal tool"}]}}`
	baseline := tools.NewToolBaseline()
	cfg := &tools.ToolScanConfig{Action: config.ActionWarn, DetectDrift: true, Baseline: baseline}
	sc := testScannerWithAction(t, config.ActionWarn)
	raw := "[" + valid + "," + strings.Replace(valid, `"result"`, `"Result"`, 1) + "]"
	verdict, _ := scanStreamResponse([]byte(raw), sc, cfg)
	if verdict.Clean || verdict.Error == "" || baseline.HasDriftBaseline() || baseline.HasBaseline() {
		t.Fatal("rejected batch changed baseline")
	}
	if verdict, _ := scanStreamResponse([]byte(valid), sc, cfg); !verdict.Clean || !baseline.HasDriftBaseline() {
		t.Fatal("valid control failed")
	}
}

func TestListenerResponseKeyRejectionDefersSessionRegistration(t *testing.T) {
	for _, contentType := range []string{"application/json", "text/event-stream"} {
		for _, alias := range []bool{false, true} {
			t.Run(contentType+"/alias="+strconv.FormatBool(alias), func(t *testing.T) {
				raw := `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`
				if alias {
					raw = strings.Replace(raw, `"result"`, `"Result"`, 1)
				}
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", contentType)
					w.Header().Set("Mcp-Session-Id", "registered-session")
					if contentType == "text/event-stream" {
						_, _ = io.WriteString(w, "data: "+raw+"\n\n")
					} else {
						_, _ = io.WriteString(w, raw)
					}
				}))
				defer upstream.Close()
				var registrations atomic.Int32
				baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{
					Scanner:            testScannerForHTTP(t),
					DoWRegisterSession: func(string) { registrations.Add(1) },
				})
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, baseURL+"/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Content-Type", "application/json")
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = resp.Body.Close() }()
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				want := int32(1)
				if alias {
					want = 0
				}
				if registrations.Load() != want || (alias && !bytes.Contains(body, []byte(`"error"`))) {
					t.Fatalf("registrations=%d want=%d body=%s", registrations.Load(), want, body)
				}
				if alias && resp.Header.Get(listenerSessionTokenHeader) != "" {
					t.Fatal("rejected response admitted listener session")
				}
			})
		}
	}
}

func TestHTTPResponseKeyRejectionDefersProtocolNegotiation(t *testing.T) {
	for _, alias := range []bool{false, true} {
		t.Run("alias="+strconv.FormatBool(alias), func(t *testing.T) {
			seen := make(chan string, 2)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen <- r.Header.Get(listenerProtocolVersion)
				w.Header().Set("Content-Type", "application/json")
				raw := `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}`
				if alias {
					raw = strings.Replace(raw, `"result"`, `"Result"`, 1)
				}
				_, _ = io.WriteString(w, raw)
			}))
			defer upstream.Close()
			client := transport.NewHTTPClient(upstream.URL, http.Header{listenerProtocolVersion: {"2025-03-26"}})
			client.ResponseKeyValidator = jsonrpc.ValidateMessageKeys
			reader, err := client.SendMessage(t.Context(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := reader.ReadMessage(); err != nil {
				t.Fatal(err)
			}
			if closer, ok := reader.(io.Closer); ok {
				_ = closer.Close()
			}
			if got := <-seen; got != "2025-03-26" {
				t.Fatalf("initial protocol=%q", got)
			}
			reader, err = client.SendMessage(t.Context(), []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
			if err != nil {
				t.Fatal(err)
			}
			if closer, ok := reader.(io.Closer); ok {
				_ = closer.Close()
			}
			want := "2025-06-18"
			if alias {
				want = "2025-03-26"
			}
			if got := <-seen; got != want {
				t.Fatalf("next request protocol=%q want=%q", got, want)
			}
		})
	}
}
