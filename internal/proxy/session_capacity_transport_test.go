// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

const capacityDeliveryWitness = "capacity delivery witness"

func TestSessionCapacityRetainedManagerWithoutProfiling(t *testing.T) {
	for _, transport := range []string{TransportForward, TransportFetch, TransportReverse} {
		t.Run(transport, func(t *testing.T) {
			cfg := airlockAdmissionConfig(t, config.AirlockTierNone)
			cfg.SessionProfiling.Enabled = false
			cfg.SessionProfiling.MaxSessions = 1
			var calls atomic.Int32
			rp, p, upstream := newReverseParityHarness(t, cfg, func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				_, _ = fmt.Fprint(w, capacityDeliveryWitness)
			})
			// Retained security state must still govern recorder acquisition
			// when the request-profiling writer is inactive.
			sm := NewSessionManager(&cfg.SessionProfiling, &cfg.AdaptiveEnforcement, p.metrics)
			p.sessionMgrPtr.Store(sm)
			quarantine := sm.GetOrCreate("other-quarantined-client")
			_, _, _ = quarantine.AirlockForScope("").SetTier(config.AirlockTierDrain)
			for _, released := range []bool{false, true} {
				if released {
					_, _, _ = quarantine.ForceSetAirlockTierAllScopes(config.AirlockTierNone, airlockTriggerManual, airlockSourceAdminAPI)
				}
				target := upstream.String() + "/control"
				if transport == TransportFetch {
					target = "http://proxy.example/fetch?url=" + url.QueryEscape(target)
				}
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
				req.RemoteAddr = airlockAdmissionClient + ":12345"
				w := httptest.NewRecorder()
				switch transport {
				case TransportForward:
					p.handleForwardHTTP(w, req)
				case TransportFetch:
					p.handleFetch(w, req)
				case TransportReverse:
					rp.ServeHTTP(w, req)
				}
				if !released {
					if w.Code != http.StatusServiceUnavailable || w.Header().Get(blockreason.HeaderLayer) != sessionCapacityLayer || calls.Load() != 0 || sm.Len() != 1 {
						t.Fatalf("retained capacity: status=%d upstream=%d sessions=%d body=%s", w.Code, calls.Load(), sm.Len(), w.Body.String())
					}
				} else if w.Code != http.StatusOK || calls.Load() != 1 || !strings.Contains(w.Body.String(), capacityDeliveryWitness) {
					t.Fatalf("released capacity: status=%d upstream=%d body=%s", w.Code, calls.Load(), w.Body.String())
				}
			}
		})
	}
}

func TestSessionCapacityConnectAdmissionAndRelease(t *testing.T) {
	cfg := airlockAdmissionConfig(t, config.AirlockTierNone)
	cfg.SessionProfiling.MaxSessions = 1
	// The local witness uses plaintext HTTP inside its opaque CONNECT tunnel.
	sniVerification := false
	cfg.ForwardProxy.SNIVerification = &sniVerification
	var calls atomic.Int32
	_, p, upstream := newReverseParityHarness(t, cfg, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = fmt.Fprint(w, capacityDeliveryWitness)
	})
	sm := p.sessionMgrPtr.Load()
	quarantine := sm.GetOrCreate("other-quarantined-client")
	_, _, _ = quarantine.AirlockForScope("").SetTier(config.AirlockTierDrain)
	listener := httptest.NewServer(http.HandlerFunc(p.handleConnect))
	defer listener.Close()
	for _, released := range []bool{false, true} {
		if released {
			_, _, _ = quarantine.ForceSetAirlockTierAllScopes(config.AirlockTierNone, airlockTriggerManual, airlockSourceAdminAPI)
		}
		conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", strings.TrimPrefix(listener.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", upstream.Host, upstream.Host)
		if err != nil {
			t.Fatal(err)
		}
		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
		if err != nil {
			t.Fatal(err)
		}
		if !released {
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get(blockreason.HeaderLayer) != sessionCapacityLayer || calls.Load() != 0 {
				t.Fatalf("CONNECT capacity: status=%d upstream=%d", resp.StatusCode, calls.Load())
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("released CONNECT status=%d", resp.StatusCode)
		}
		_, err = fmt.Fprintf(conn, "GET /control HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", upstream.Host)
		if err != nil {
			t.Fatal(err)
		}
		inner, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(inner.Body)
		_ = inner.Body.Close()
		if err != nil || inner.StatusCode != http.StatusOK || string(body) != capacityDeliveryWitness || calls.Load() != 1 {
			t.Fatalf("CONNECT delivery: status=%d upstream=%d body=%s err=%v", inner.StatusCode, calls.Load(), body, err)
		}
	}
}

func TestSessionCapacityWebSocketAdmissionBeforeAndAfterUpgrade(t *testing.T) {
	for _, requiredReceipts := range []bool{false, true} {
		t.Run(fmt.Sprintf("required_receipts=%t", requiredReceipts), func(t *testing.T) {
			cfg := airlockAdmissionConfig(t, config.AirlockTierNone)
			cfg.SessionProfiling.Enabled = false
			cfg.SessionProfiling.MaxSessions = 1
			cfg.WebSocketProxy.Enabled = true
			cfg.FlightRecorder.RequireReceipts = requiredReceipts
			var calls atomic.Int32
			_, p, upstream := newReverseParityHarness(t, cfg, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				conn, _, _, err := ws.UpgradeHTTP(r, w)
				if err != nil {
					return
				}
				defer func() { _ = conn.Close() }()
				_ = wsutil.WriteServerMessage(conn, ws.OpText, []byte(capacityDeliveryWitness))
			})
			emitter, recorder, _ := newCoverageEmitter(t, t.TempDir())
			p.receiptEmitterPtr.Store(emitter)
			t.Cleanup(func() { _ = recorder.Close() })
			sm := NewSessionManager(&cfg.SessionProfiling, &cfg.AdaptiveEnforcement, p.metrics)
			p.sessionMgrPtr.Store(sm)
			quarantine := sm.GetOrCreate("other-quarantined-client")
			_, _, _ = quarantine.AirlockForScope("").SetTier(config.AirlockTierDrain)
			listener := httptest.NewServer(http.HandlerFunc(p.handleWebSocket))
			defer listener.Close()
			client := &http.Client{Timeout: 3 * time.Second}
			for _, released := range []bool{false, true} {
				if released {
					_, _, _ = quarantine.ForceSetAirlockTierAllScopes(config.AirlockTierNone, airlockTriggerManual, airlockSourceAdminAPI)
				}
				target := "ws" + strings.TrimPrefix(upstream.String(), "http")
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, listener.URL+"/ws?url="+url.QueryEscape(target), nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Connection", "Upgrade")
				req.Header.Set("Upgrade", "websocket")
				req.Header.Set("Sec-WebSocket-Version", "13")
				req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBs"+"ZSBub25jZQ==")
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				if requiredReceipts && !released {
					_ = resp.Body.Close()
					if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get(blockreason.HeaderLayer) != sessionCapacityLayer || calls.Load() != 0 {
						t.Fatalf("pre-upgrade refusal: status=%d upstream=%d", resp.StatusCode, calls.Load())
					}
					continue
				}
				header, err := ws.ReadHeader(resp.Body)
				var body []byte
				if err == nil && header.Length <= 125 {
					body = make([]byte, header.Length)
					_, err = io.ReadFull(resp.Body, body)
				}
				_ = resp.Body.Close()
				if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
					t.Fatalf("upgrade result: status=%d err=%v", resp.StatusCode, err)
				}
				if !released {
					if header.OpCode != ws.OpClose || !strings.Contains(string(body), sessionCapacityLayer) || calls.Load() != 0 {
						t.Fatalf("post-upgrade refusal: opcode=%d body=%s upstream=%d", header.OpCode, body, calls.Load())
					}
				} else if header.OpCode != ws.OpText || string(body) != capacityDeliveryWitness || calls.Load() != 1 {
					t.Fatalf("released WS delivery: opcode=%d body=%s upstream=%d", header.OpCode, body, calls.Load())
				}
			}
		})
	}
}
