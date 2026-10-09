// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

const (
	identityRefusalText = "verified local service vendor-indexer registration changed; restart pipelock run"
	identityUpstreamOK  = `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hi"}]}}`
)

func TestHTTPListener_ServerIdentityFn(t *testing.T) {
	tests := []struct {
		name         string
		fn           func(calls *atomic.Int32) func() ServerIdentity
		wantStatus   int
		wantUpstream int32
		wantCalls    int32
		wantBody     string
		wantLog      string
	}{
		{
			name:         "no identity hook leaves the listener unchanged",
			fn:           func(*atomic.Int32) func() ServerIdentity { return nil },
			wantStatus:   http.StatusOK,
			wantUpstream: 1,
		},
		{
			name: "a stamped identity is consulted per request and the request proceeds",
			fn: func(calls *atomic.Int32) func() ServerIdentity {
				return func() ServerIdentity {
					calls.Add(1)
					return ServerIdentity{Name: "vendor-indexer", PolicyName: "vendor-indexer", Binding: "binding", BindingMode: "verified-local-session", Revision: "rev"}
				}
			},
			wantStatus:   http.StatusOK,
			wantUpstream: 1,
			wantCalls:    4,
		},
		{
			name: "a refusal answers 503 with a JSON-RPC error and never reaches the upstream",
			fn: func(calls *atomic.Int32) func() ServerIdentity {
				return func() ServerIdentity {
					calls.Add(1)
					return ServerIdentity{Refusal: identityRefusalText}
				}
			},
			wantStatus: http.StatusServiceUnavailable,
			wantCalls:  1,
			wantBody:   `"code":-32003`,
			wantLog:    "pipelock: " + identityRefusalText,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var upstreamHits, identityCalls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				upstreamHits.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, identityUpstreamOK)
			}))
			defer upstream.Close()

			baseURL, logBuf := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{
				Scanner:          testScannerForHTTP(t),
				ServerIdentityFn: tt.fn(&identityCalls),
			})

			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, baseURL+"/", strings.NewReader(jsonToolsCallEcho))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", resp.StatusCode, tt.wantStatus, body)
			}
			if got := upstreamHits.Load(); got != tt.wantUpstream {
				t.Errorf("upstream hits = %d, want %d", got, tt.wantUpstream)
			}
			if got := identityCalls.Load(); got != tt.wantCalls {
				t.Errorf("identity fn calls = %d, want %d", got, tt.wantCalls)
			}
			if tt.wantBody != "" && !strings.Contains(string(body), tt.wantBody) {
				t.Errorf("body = %s, want containing %q", body, tt.wantBody)
			}
			if tt.wantLog != "" && !strings.Contains(logBuf.String(), tt.wantLog) {
				t.Errorf("log = %q, want containing %q", logBuf.String(), tt.wantLog)
			}
		})
	}
}

func TestHTTPListenerIdentityChangeDuringResponse(t *testing.T) {
	for _, sse := range []bool{false, true} {
		name := "json"
		if sse {
			name = "sse"
		}
		t.Run(name, func(t *testing.T) {
			var changed atomic.Bool
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				// Model a reload after admission, before the first upstream byte.
				changed.Store(true)
				body := identityUpstreamOK
				w.Header().Set("Content-Type", "application/json")
				if sse {
					w.Header().Set("Content-Type", "text/event-stream")
					body = "data: " + body + "\n\n"
				}
				_, _ = io.WriteString(w, body)
			}))
			defer upstream.Close()
			baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{
				Scanner: testScannerForHTTP(t),
				ServerIdentityFn: func() ServerIdentity {
					if changed.Load() {
						return ServerIdentity{Refusal: identityRefusalText}
					}
					return ServerIdentity{Name: "vendor-indexer", PolicyName: "vendor-indexer", Binding: "binding", BindingMode: config.MCPAckBindingModeVerifiedLocalSession, Revision: "rev"}
				},
			})
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, baseURL+"/", strings.NewReader(jsonToolsCallEcho))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			body, _ := io.ReadAll(resp.Body)
			if strings.Contains(string(body), `"text":"hi"`) || resp.StatusCode < http.StatusBadRequest {
				t.Fatalf("changed registration forwarded response: status %d body %s", resp.StatusCode, body)
			}
		})
	}
}

func TestStatelessListenerRestoresAcknowledgmentIdentity(t *testing.T) {
	entry := proxyAckEntry(t)
	set := tools.NewCredentialAckSet([]config.MCPAcknowledgedFinding{entry}, proxyAckKey)
	for _, revoked := range []bool{false, true} {
		if revoked {
			set.Revoke()
		}
		opts := listenerStatelessRequestOpts(MCPProxyOpts{
			Scanner:       testScannerWithAction(t, config.ActionWarn),
			ToolCfg:       &tools.ToolScanConfig{Action: config.ActionBlock, CredentialAcks: set},
			ServerName:    proxyAckServer,
			ServerBinding: proxyAckBinding,
		})
		var output, log strings.Builder
		line := `{"jsonrpc":"2.0","id":1,"result":{"tools":[` + proxyAckTool + `]}}`
		_, err := ForwardScanned(&transport.SingleMessageReader{Body: io.NopCloser(strings.NewReader(line))}, transport.NewStdioWriter(&output), &log, nil, opts)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(output.String(), `"store_secret"`); got == revoked {
			t.Fatalf("forwarded=%v revoked=%v, output=%s", got, revoked, output.String())
		}
	}
}
