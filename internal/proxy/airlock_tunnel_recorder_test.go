// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"bytes"
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

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// Exercise the actual handshake and, for admitted CONNECT, traffic through
// the tunnel. A status without origin delivery would be a vacuous control.
func airlockTunnelExchange(t *testing.T, proxyURL, target, transport, marker string) (int, string) {
	t.Helper()
	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", strings.TrimPrefix(proxyURL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var request string
	if transport == TransportConnect {
		request = fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	} else {
		request = fmt.Sprintf("GET /ws?url=%s HTTP/1.1\r\nHost: proxy.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n", url.QueryEscape("ws://"+target+"/control"))
	}
	if marker != "" {
		request += "Authorization: Bearer " + marker + "\r\n"
	}
	if _, err := io.WriteString(conn, request+"\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if transport == TransportWS && resp.StatusCode == http.StatusSwitchingProtocols {
		header, err := ws.ReadHeader(reader)
		if err != nil || header.Length > 125 {
			t.Fatalf("WS response frame: header=%+v err=%v", header, err)
		}
		body := make([]byte, header.Length)
		if _, err := io.ReadFull(reader, body); err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, string(body)
	}
	if transport == TransportConnect && resp.StatusCode == http.StatusOK {
		if _, err := fmt.Fprintf(conn, "GET /control HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target); err != nil {
			t.Fatal(err)
		}
		resp, err = http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatal(err)
		}
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(body)
}

func TestAirlockTunnelRetainsFindingRecorder(t *testing.T) {
	for _, transport := range []string{TransportConnect, TransportWS} {
		for _, stage := range []string{"header", "url"} {
			for _, tier := range []string{config.AirlockTierNone, config.AirlockTierDrain} {
				t.Run(transport+"/"+stage+"/"+tier, func(t *testing.T) {
					cfg := airlockAdmissionConfig(t, tier)
					cfg.ForwardProxy.SNIVerification = ptrBool(false)
					cfg.WebSocketProxy.Enabled = true
					if stage == "url" {
						cfg.Enforce = ptrBool(false)
						cfg.FetchProxy.Monitoring.Blocklist = []string{"127.0.0.1"}
					}
					var calls atomic.Int32
					_, p, upstream := newReverseParityHarness(t, cfg, func(w http.ResponseWriter, r *http.Request) {
						calls.Add(1)
						if transport == TransportWS {
							conn, _, _, err := ws.UpgradeHTTP(r, w)
							if err == nil {
								defer func() { _ = conn.Close() }()
								_ = wsutil.WriteServerMessage(conn, ws.OpText, []byte(capacityDeliveryWitness))
							}
							return
						}
						_, _ = fmt.Fprint(w, capacityDeliveryWitness)
					})
					originalManager := p.sessionMgrPtr.Load()
					t.Cleanup(originalManager.Close)
					original := originalManager.GetOrCreate(airlockAdmissionClient)
					var replaced atomic.Bool
					var scopedAudit atomic.Bool
					logger, err := audit.NewWithStream("json", "stdout", "", true, true, airlockLogCallback(func(record []byte) {
						if bytes.Contains(record, []byte(`"event":"airlock_enter"`)) && bytes.Contains(record, []byte(fmt.Sprintf(`"scope":%q`, adaptiveScopeForHost(upstream.Hostname())))) {
							scopedAudit.Store(true)
						}
						if !bytes.Contains(record, []byte(`"event":"`+string(audit.EventAdaptiveEscalation)+`"`)) || !replaced.CompareAndSwap(false, true) {
							return
						}
						current := NewSessionManager(&cfg.SessionProfiling, &cfg.AdaptiveEnforcement, p.metrics)
						current.UpdateConfig(&cfg.SessionProfiling, &cfg.AdaptiveEnforcement, &cfg.Airlock)
						p.sessionMgrPtr.Store(current)
					}))
					if err != nil {
						t.Fatal(err)
					}
					p.logger = logger
					t.Cleanup(logger.Close)
					listener := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						r.RemoteAddr = airlockAdmissionClient + ":12345"
						if transport == TransportConnect {
							p.handleConnect(w, r)
						} else {
							p.handleWebSocket(w, r)
						}
					}))
					defer listener.Close()
					marker := ""
					if stage == "header" {
						marker = airlockHeaderMarker
					}
					status, body := airlockTunnelExchange(t, listener.URL, upstream.Host, transport, marker)
					if !replaced.Load() || airlockTierForScope(original, adaptiveScopeForHost(upstream.Hostname())) != tier {
						t.Fatal("the original finding recorder did not reach the requested transition")
					}
					if tier == config.AirlockTierDrain {
						if !scopedAudit.Load() {
							t.Error("airlock entry did not identify the affected destination in its audit record")
						}
						if calls.Load() != 0 || !strings.Contains(body, "airlock") || (status != http.StatusForbidden && status != http.StatusSwitchingProtocols) {
							t.Fatalf("quarantined recorder lost: status=%d upstream=%d body=%q", status, calls.Load(), body)
						}
					} else if calls.Load() != 1 || body != capacityDeliveryWitness {
						t.Fatalf("control did not deliver: status=%d upstream=%d body=%q", status, calls.Load(), body)
					}
				})
			}
		}
	}
}

func TestAirlockForwardStripRetainsAdmittedRecorder(t *testing.T) {
	cfg := airlockAdmissionConfig(t, config.AirlockTierDrain)
	cfg.ResponseScanning.Enabled = true
	cfg.ResponseScanning.Action = config.ActionStrip
	cfg.ResponseScanning.Patterns = []config.ResponseScanPattern{{Name: "strip witness", Regex: airlockResponseMarker}}
	var owner atomic.Pointer[Proxy]
	_, p, upstream := newReverseParityHarness(t, cfg, func(w http.ResponseWriter, _ *http.Request) {
		current := NewSessionManager(&cfg.SessionProfiling, &cfg.AdaptiveEnforcement, nil)
		current.UpdateConfig(&cfg.SessionProfiling, &cfg.AdaptiveEnforcement, &cfg.Airlock)
		owner.Load().sessionMgrPtr.Store(current)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprint(w, "ordinary text "+airlockResponseMarker+" ordinary text")
	})
	owner.Store(p)
	originalManager := p.sessionMgrPtr.Load()
	t.Cleanup(originalManager.Close)
	original := originalManager.GetOrCreate(airlockAdmissionClient)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, upstream.String()+"/control", nil)
	req.RemoteAddr = airlockAdmissionClient + ":12345"
	w := httptest.NewRecorder()
	p.handleForwardHTTP(w, req)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), airlockResponseMarker) || !strings.Contains(w.Body.String(), "ordinary text") {
		t.Fatalf("strip control: status=%d body=%s", w.Code, w.Body.String())
	}
	if got := airlockTierForScope(original, adaptiveScopeForHost(upstream.Hostname())); got != config.AirlockTierDrain {
		t.Fatalf("admitted recorder lost response strip: tier=%q", got)
	}
}

func TestSessionCapacityInterceptAudit(t *testing.T) {
	for _, afterCEE := range []bool{false, true} {
		t.Run(fmt.Sprintf("after_cee=%t", afterCEE), func(t *testing.T) {
			cfg := airlockAdmissionConfig(t, config.AirlockTierDrain)
			cfg.SessionProfiling.MaxSessions = 1
			cfg.CrossRequestDetection.Enabled = afterCEE
			_, p, upstream := newReverseParityHarness(t, cfg, func(http.ResponseWriter, *http.Request) {})
			var stream bytes.Buffer
			logger, err := audit.NewWithStream("json", "stdout", "", true, true, &stream)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(logger.Close)
			full := func() {
				sm := p.sessionMgrPtr.Load()
				quarantine := sm.GetOrCreate("other-quarantined-client")
				_, _, _ = quarantine.AirlockForScope("").SetTier(config.AirlockTierDrain)
			}
			if afterCEE {
				p.ceeAdmissionLocked = full
			} else {
				full()
			}
			ic := &InterceptContext{
				TargetHost: upstream.Hostname(), TargetPort: upstream.Port(), Config: cfg,
				Scanner: p.scannerPtr.Load(), Logger: logger, Metrics: p.metrics,
				ClientIP: airlockAdmissionClient, RequestID: "capacity-audit-request", SessionMgr: p.sessionMgrPtr.Load(), Proxy: p,
			}
			var calls atomic.Int32
			handler := newInterceptHandler(ic, capacityRoundTripper(func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return nil, fmt.Errorf("unexpected upstream call")
			}))
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, upstream.String()+"/control", nil))
			if w.Code != http.StatusServiceUnavailable || w.Header().Get(blockreason.HeaderLayer) != sessionCapacityLayer || calls.Load() != 0 {
				t.Fatalf("capacity refusal: status=%d calls=%d body=%s", w.Code, calls.Load(), w.Body.String())
			}
			if !strings.Contains(stream.String(), `"event":"blocked"`) || !strings.Contains(stream.String(), `"scanner":"session_capacity"`) {
				t.Fatalf("capacity denial absent from audit: %s", stream.String())
			}
		})
	}
}

func TestSessionCapacityConnectAfterEntropySnapshot(t *testing.T) {
	for _, refused := range []bool{false, true} {
		t.Run(fmt.Sprintf("refused=%t", refused), func(t *testing.T) {
			cfg := airlockAdmissionConfig(t, config.AirlockTierNone)
			cfg.SessionProfiling.MaxSessions = 1
			cfg.ForwardProxy.SNIVerification = ptrBool(false)
			cfg.CrossRequestDetection.Enabled = true
			cfg.CrossRequestDetection.EntropyBudget.Enabled = true
			cfg.CrossRequestDetection.EntropyBudget.BitsPerWindow = 1
			cfg.CrossRequestDetection.EntropyBudget.Action = config.ActionWarn
			var calls atomic.Int32
			_, p, upstream := newReverseParityHarness(t, cfg, func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				_, _ = fmt.Fprint(w, capacityDeliveryWitness)
			})
			key := CeeSessionKey(agentAnonymous, airlockAdmissionClient)
			tracker := p.entropyTrackerPtr.Load()
			tracker.Record(testCEEIdentity(key), []byte("abc123"))
			if !tracker.BudgetExceeded(testCEEIdentity(key)) {
				t.Fatal("fixture did not exhaust entropy")
			}
			var reached atomic.Bool
			p.connectCEEReady = func() {
				reached.Store(true)
				if refused {
					other := p.sessionMgrPtr.Load().GetOrCreate("other-quarantined-client")
					_, _, _ = other.AirlockForScope("").SetTier(config.AirlockTierDrain)
				}
			}
			listener := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.RemoteAddr = airlockAdmissionClient + ":12345"
				p.handleConnect(w, r)
			}))
			defer listener.Close()
			status, body := airlockTunnelExchange(t, listener.URL, upstream.Host, TransportConnect, "")
			if !reached.Load() {
				t.Fatal("CONNECT did not consume its entropy snapshot")
			}
			if refused {
				if status != http.StatusServiceUnavailable || calls.Load() != 0 || !strings.Contains(body, session.ErrCapacity.Error()) {
					t.Fatalf("late capacity refusal: status=%d upstream=%d body=%q", status, calls.Load(), body)
				}
			} else if status != http.StatusOK || calls.Load() != 1 || body != capacityDeliveryWitness {
				t.Fatalf("warning control: status=%d upstream=%d body=%q", status, calls.Load(), body)
			}
		})
	}
}

func TestSessionCapacityWebSocketHeaderResponse(t *testing.T) {
	for _, refused := range []bool{false, true} {
		t.Run(fmt.Sprintf("refused=%t", refused), func(t *testing.T) {
			cfg := airlockAdmissionConfig(t, config.AirlockTierNone)
			cfg.SessionProfiling.MaxSessions = 1
			cfg.WebSocketProxy.Enabled = true
			cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "capacity disabled marker", Regex: "CAPACITYDROP"})
			cfg.RequestBodyScanning.DisablePatterns = []string{"capacity disabled marker"}
			var calls atomic.Int32
			_, p, upstream := newReverseParityHarness(t, cfg, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				conn, _, _, err := ws.UpgradeHTTP(r, w)
				if err == nil {
					defer func() { _ = conn.Close() }()
					_ = wsutil.WriteServerMessage(conn, ws.OpText, []byte(capacityDeliveryWitness))
				}
			})
			var reached atomic.Bool
			logger, err := audit.NewWithStream("json", "stdout", "", true, true, airlockLogCallback(func(record []byte) {
				if !bytes.Contains(record, []byte(`"pattern":"capacity disabled marker"`)) || !reached.CompareAndSwap(false, true) {
					return
				}
				if refused {
					other := p.sessionMgrPtr.Load().GetOrCreate("other-quarantined-client")
					_, _, _ = other.AirlockForScope("").SetTier(config.AirlockTierDrain)
				}
			}))
			if err != nil {
				t.Fatal(err)
			}
			p.logger = logger
			t.Cleanup(logger.Close)
			listener := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.RemoteAddr = airlockAdmissionClient + ":12345"
				p.handleWebSocket(w, r)
			}))
			defer listener.Close()
			status, body := airlockTunnelExchange(t, listener.URL, upstream.Host, TransportWS, airlockHeaderMarker+" CAPACITYDROP")
			if !reached.Load() {
				t.Fatal("header scan did not reach the recorder boundary")
			}
			if refused {
				if status != http.StatusServiceUnavailable || calls.Load() != 0 || !strings.Contains(body, session.ErrCapacity.Error()) {
					t.Fatalf("header capacity response: status=%d upstream=%d body=%q", status, calls.Load(), body)
				}
			} else if calls.Load() != 1 || body != capacityDeliveryWitness {
				t.Fatalf("header control: status=%d upstream=%d body=%q", status, calls.Load(), body)
			}
		})
	}
}
