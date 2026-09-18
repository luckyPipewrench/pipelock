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
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

type capacityTestStore struct {
	rec session.Recorder
}

func (s *capacityTestStore) GetOrCreate(string) session.Recorder { return s.rec }
func (*capacityTestStore) Delete(string)                         {}

func TestSessionCapacityRefusesMCPInvocations(t *testing.T) {
	for _, transport := range []string{"stdio", "sandbox", "http", "websocket"} {
		for _, admit := range []bool{false, true} {
			name := transport + "/refused"
			if admit {
				name = transport + "/admitted-control"
			}
			t.Run(name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
				defer cancel()
				store := &capacityTestStore{}
				if admit {
					store.rec = &mockRecorder{}
				}
				var dials atomic.Int32
				opts := MCPProxyOpts{
					Store: store, Scanner: testScannerForHTTP(t),
					DialContext: func(context.Context, string, string) (net.Conn, error) {
						dials.Add(1)
						return nil, errors.New("capacity test dial witness")
					},
				}
				missing := filepath.Join(t.TempDir(), "missing-mcp-server")
				input := strings.NewReader(jsonToolsCallEcho + "\n")
				var err error
				switch transport {
				case "stdio":
					err = RunProxy(ctx, input, io.Discard, io.Discard, []string{missing}, opts)
				case "sandbox":
					err = RunProxyWithSandbox(ctx, exec.CommandContext(ctx, missing), input, io.Discard, io.Discard, opts)
				case "http":
					err = RunHTTPProxy(ctx, input, io.Discard, io.Discard, "http://api.vendor.example/mcp", nil, opts)
				case "websocket":
					err = RunWSProxy(ctx, input, io.Discard, io.Discard, "ws://api.vendor.example/mcp", opts)
				}
				if !admit {
					if !errors.Is(err, session.ErrCapacity) || dials.Load() != 0 {
						t.Fatalf("refused invocation: err=%v dials=%d", err, dials.Load())
					}
					return
				}
				if errors.Is(err, session.ErrCapacity) {
					t.Fatal("admitted invocation was refused")
				}
				if transport == "http" || transport == "websocket" {
					if dials.Load() == 0 {
						t.Fatalf("admitted control did not attempt upstream: %v", err)
					}
				} else if err == nil || !strings.Contains(err.Error(), "missing-mcp-server") {
					t.Fatalf("admitted control did not reach child launch: %v", err)
				}
			})
		}
	}
}

func TestSessionCapacityListenerStateAdmission(t *testing.T) {
	for _, kind := range []string{"principal", "legacy", "unbound", "setup"} {
		t.Run(kind, func(t *testing.T) {
			store := &capacityTestStore{}
			states := newMCPListenerClientStates(store)
			for _, admit := range []bool{false, true} {
				if admit {
					store.rec = &mockRecorder{}
				}
				var state *mcpListenerClientState
				var ok bool
				switch kind {
				case "principal":
					state, ok = states.stateForPrincipal(mcpListenerPrincipal{key: "verified-principal"})
				case "legacy":
					state = states.stateForLegacySession("legacy-client")
					ok = state != nil
				case "unbound":
					state = states.newUnboundState()
					ok = state != nil
				case "setup":
					var err error
					state, err = states.newSetupState()
					if err != nil {
						t.Fatal(err)
					}
					ok = states.admitSetup(state)
				}
				if state != nil {
					defer state.revoke()
				}
				if ok != admit {
					t.Fatalf("admission=%t, want %t", ok, admit)
				}
				if !admit && len(states.clients) != 0 {
					t.Fatal("refused recorder left a durable listener state")
				}
				if admit && (state == nil || state.recorder == nil) {
					t.Fatal("admitted state has no recorder")
				}
			}
		})
	}
}

func TestSessionCapacityListenerRefusesBeforeUpstream(t *testing.T) {
	for _, kind := range []string{"principal", "legacy", "unbound", "setup"} {
		for _, admit := range []bool{false, true} {
			name := kind + "/refused"
			if admit {
				name = kind + "/admitted-control"
			}
			t.Run(name, func(t *testing.T) {
				var calls atomic.Int32
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					calls.Add(1)
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
				}))
				defer upstream.Close()
				store := &capacityTestStore{}
				if admit {
					store.rec = &mockRecorder{}
				}
				opts := MCPProxyOpts{
					Scanner: testScannerForHTTP(t), Store: store,
					AdaptiveCfg: &config.AdaptiveEnforcement{Enabled: true, EscalationThreshold: 100},
				}
				if kind == "principal" {
					opts.ListenerBearerToken = "capacity-test-bearer"
				}
				if kind == "unbound" || kind == "setup" {
					opts.listenerStateTokenRequired = boolPtr(true)
				}
				baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, opts)
				body := `{"jsonrpc":"2.0","id":1,"method":"ping"}`
				if kind == "setup" {
					body = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"capacity-test","version":"1"}}}`
				}
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, baseURL, strings.NewReader(body))
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Content-Type", "application/json")
				if kind == "principal" {
					req.Header.Set("Authorization", "Bearer "+opts.ListenerBearerToken)
				}
				if kind == "legacy" {
					req.Header.Set("Mcp-Session-Id", "capacity-legacy-client")
				}
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = resp.Body.Close() }()
				output, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				if !admit {
					if resp.StatusCode != http.StatusServiceUnavailable || calls.Load() != 0 || resp.Header.Get(blockreason.HeaderReason) != string(blockreason.DataBudget) {
						t.Fatalf("capacity refusal: status=%d upstream=%d reason=%q body=%s", resp.StatusCode, calls.Load(), resp.Header.Get(blockreason.HeaderReason), output)
					}
				} else if resp.StatusCode != http.StatusOK || calls.Load() != 1 {
					t.Fatalf("admitted control: status=%d upstream=%d body=%s", resp.StatusCode, calls.Load(), output)
				}
			})
		}
	}
}
