// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"fmt"
	"io"
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
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestSessionCapacityCEERechecksBeforeForwarding(t *testing.T) {
	for _, transport := range []string{TransportForward, TransportFetch, TransportReverse, "intercept", TransportWS} {
		for _, refused := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/refused=%t", transport, refused), func(t *testing.T) {
				cfg := airlockAdmissionConfig(t, config.AirlockTierNone)
				cfg.SessionProfiling.MaxSessions = 1
				cfg.CrossRequestDetection.Enabled = true
				cfg.WebSocketProxy.Enabled = true
				var calls atomic.Int32
				rp, p, upstream := newReverseParityHarness(t, cfg, func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					if transport == TransportWS {
						conn, _, _, err := ws.UpgradeHTTP(r, w)
						if err != nil {
							return
						}
						defer func() { _ = conn.Close() }()
						_ = wsutil.WriteServerMessage(conn, ws.OpText, []byte(capacityDeliveryWitness))
						return
					}
					_, _ = fmt.Fprint(w, capacityDeliveryWitness)
				})
				original := p.sessionMgrPtr.Load()
				var auditStream bytes.Buffer
				auditLogger, err := audit.NewWithStream("json", "stdout", "", true, true, &auditStream)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(auditLogger.Close)
				p.logger, rp.logger = auditLogger, auditLogger
				t.Cleanup(original.Close)
				var reached atomic.Bool
				p.ceeAdmissionLocked = func() {
					if !reached.CompareAndSwap(false, true) || !refused {
						return
					}
					// Replace state at the existing reload seam, after initial
					// admission but before CEE acquires its recorder.
					full := NewSessionManager(&cfg.SessionProfiling, &cfg.AdaptiveEnforcement, p.metrics)
					quarantine := full.GetOrCreate("other-quarantined-client")
					_, _, _ = quarantine.AirlockForScope("").SetTier(config.AirlockTierDrain)
					p.sessionMgrPtr.Store(full)
				}
				if transport == TransportWS {
					listener := httptest.NewServer(http.HandlerFunc(p.handleWebSocket))
					defer listener.Close()
					target := "ws" + strings.TrimPrefix(upstream.String(), "http") + "/control"
					req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, listener.URL+"/ws?url="+url.QueryEscape(target), nil)
					if err != nil {
						t.Fatal(err)
					}
					req.Header.Set("Connection", "Upgrade")
					req.Header.Set("Upgrade", "websocket")
					req.Header.Set("Sec-WebSocket-Version", "13")
					req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBs"+"ZSBub25jZQ==")
					client := &http.Client{Timeout: 3 * time.Second}
					resp, err := client.Do(req)
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = resp.Body.Close() }()
					if refused {
						body, err := io.ReadAll(resp.Body)
						if err != nil {
							t.Fatal(err)
						}
						if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get(blockreason.HeaderLayer) != sessionCapacityLayer || !strings.Contains(string(body), session.ErrCapacity.Error()) || calls.Load() != 0 {
							t.Fatalf("WS capacity refusal: status=%d upstream=%d body=%s", resp.StatusCode, calls.Load(), body)
						}
					} else {
						header, err := ws.ReadHeader(resp.Body)
						var body []byte
						if err == nil && header.Length <= 125 {
							body = make([]byte, header.Length)
							_, err = io.ReadFull(resp.Body, body)
						}
						if err != nil || resp.StatusCode != http.StatusSwitchingProtocols || header.OpCode != ws.OpText || string(body) != capacityDeliveryWitness || calls.Load() != 1 {
							t.Fatalf("WS admitted control: status=%d upstream=%d body=%s err=%v", resp.StatusCode, calls.Load(), body, err)
						}
					}
				} else {
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
					case "intercept":
						ic := &InterceptContext{
							TargetHost: upstream.Hostname(), TargetPort: upstream.Port(), Config: cfg,
							Scanner: p.scannerPtr.Load(), Logger: p.logger, Metrics: p.metrics,
							ClientIP: airlockAdmissionClient, SessionMgr: original, Proxy: p,
						}
						fixtureTransport := capacityRoundTripper(func(r *http.Request) (*http.Response, error) {
							clone := r.Clone(r.Context())
							target := *r.URL
							// The inner HTTP handler normally dials TLS. This local
							// fixture uses a plaintext origin as its delivery witness.
							target.Scheme = "http"
							clone.URL = &target
							return http.DefaultTransport.RoundTrip(clone)
						})
						newInterceptHandler(ic, fixtureTransport).ServeHTTP(w, req)
					}
					if refused {
						if w.Code != http.StatusServiceUnavailable || w.Header().Get(blockreason.HeaderLayer) != sessionCapacityLayer || !strings.Contains(w.Body.String(), session.ErrCapacity.Error()) || calls.Load() != 0 {
							t.Fatalf("capacity refusal: status=%d upstream=%d body=%s", w.Code, calls.Load(), w.Body.String())
						}
					} else if w.Code != http.StatusOK || calls.Load() != 1 || !strings.Contains(w.Body.String(), capacityDeliveryWitness) {
						t.Fatalf("admitted control: status=%d upstream=%d body=%s", w.Code, calls.Load(), w.Body.String())
					}
				}
				if !reached.Load() {
					t.Fatal("request never reached the CEE admission boundary")
				}
				if refused && p.sessionMgrPtr.Load().Len() != 1 {
					t.Fatal("refused request grew the quarantined session table")
				}
				if refused && !strings.Contains(auditStream.String(), `"scanner":"session_capacity"`) {
					t.Fatalf("capacity refusal missing from audit stream: %s", auditStream.String())
				}
			})
		}
	}
}

func TestReverseAirlockRechecksAfterPolicy(t *testing.T) {
	for _, tier := range []string{config.AirlockTierNone, config.AirlockTierDrain} {
		t.Run(tier, func(t *testing.T) {
			cfg := airlockAdmissionConfig(t, config.AirlockTierNone)
			var calls atomic.Int32
			rp, p, upstream := newReverseParityHarness(t, cfg, func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				_, _ = fmt.Fprint(w, capacityDeliveryWitness)
			})
			sess := p.sessionMgrPtr.Load().GetOrCreate(airlockAdmissionClient)
			rp.reqPolicyFn = func(requestPolicyInput) requestPolicyResult {
				_, _, _ = sess.AirlockForScope(adaptiveScopeForHost(upstream.Hostname())).SetTier(tier)
				return requestPolicyResult{}
			}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, upstream.String()+"/control", nil)
			req.RemoteAddr = airlockAdmissionClient + ":12345"
			w := httptest.NewRecorder()
			rp.ServeHTTP(w, req)
			if tier == config.AirlockTierDrain {
				if w.Code != http.StatusForbidden || calls.Load() != 0 {
					t.Fatalf("late quarantine not enforced: status=%d upstream=%d", w.Code, calls.Load())
				}
			} else if w.Code != http.StatusOK || calls.Load() != 1 || w.Body.String() != capacityDeliveryWitness {
				t.Fatalf("allowed control not delivered: status=%d upstream=%d", w.Code, calls.Load())
			}
		})
	}
}

func TestShieldSignalEvidenceRequiresRecorder(t *testing.T) {
	for _, full := range []bool{false, true} {
		t.Run(fmt.Sprintf("full=%t", full), func(t *testing.T) {
			cfg := airlockAdmissionConfig(t, config.AirlockTierNone)
			cfg.SessionProfiling.MaxSessions = 1
			_, p, upstream := newReverseParityHarness(t, cfg, func(http.ResponseWriter, *http.Request) {})
			if full {
				other := p.sessionMgrPtr.Load().GetOrCreate("other-quarantined-client")
				_, _, _ = other.AirlockForScope("").SetTier(config.AirlockTierDrain)
			}
			summary := &receipt.ShieldSummary{TotalRewrites: 1}
			actx := newHTTPAuditContext(t.Context(), p.logger, httpAuditEvent{
				Method: http.MethodGet, TargetURL: upstream.String(), ClientIP: airlockAdmissionClient, RequestID: "req-shield-capacity",
			})
			p.recordShieldIntervention(summary, cfg, upstream.Hostname(), actx, airlockAdmissionClient, "req-shield-capacity", TransportForward, "")
			want := 1
			if full {
				want = 0
			}
			if summary.AdaptiveSignalsRecorded != want {
				t.Fatalf("reported signals=%d, want %d", summary.AdaptiveSignalsRecorded, want)
			}
		})
	}
}

func TestSessionCapacityReductionPreservesQuarantine(t *testing.T) {
	cfg := airlockAdmissionConfig(t, config.AirlockTierNone)
	cfg.SessionProfiling.MaxSessions = 2
	sm := NewSessionManager(&cfg.SessionProfiling, &cfg.AdaptiveEnforcement, nil)
	t.Cleanup(sm.Close)
	quarantine := sm.GetOrCreate("retained-quarantine")
	_, _, _ = quarantine.AirlockForScope("").SetTier(config.AirlockTierDrain)
	_ = sm.GetOrCreate("eligible-for-eviction")
	reduced := cfg.SessionProfiling
	reduced.MaxSessions = 1
	sm.UpdateConfig(&reduced, &cfg.AdaptiveEnforcement, &cfg.Airlock)
	if rec := sm.GetOrCreate("new-client"); rec != nil {
		t.Fatal("shrinking the limit admitted an extra session")
	}
	if sm.Len() != 1 || sm.SessionByKey("retained-quarantine") != quarantine || sm.SessionByKey("eligible-for-eviction") != nil {
		t.Fatal("capacity reduction did not evict only the eligible session")
	}
	_, _, _ = quarantine.ForceSetAirlockTierAllScopes(config.AirlockTierNone, airlockTriggerManual, airlockSourceAdminAPI)
	if sm.GetOrCreate("new-client") == nil || sm.Len() != 1 {
		t.Fatal("release did not restore admission under the reduced limit")
	}
}

func TestSessionCapacityReverseResponseRequiresTaintRecorder(t *testing.T) {
	for _, refused := range []bool{false, true} {
		t.Run(fmt.Sprintf("refused=%t", refused), func(t *testing.T) {
			cfg := airlockAdmissionConfig(t, config.AirlockTierNone)
			cfg.SessionProfiling.MaxSessions = 1
			cfg.Taint.Enabled = true
			var owner atomic.Pointer[Proxy]
			var calls atomic.Int32
			rp, p, upstream := newReverseParityHarness(t, cfg, func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				if refused {
					full := NewSessionManager(&cfg.SessionProfiling, &cfg.AdaptiveEnforcement, nil)
					quarantine := full.GetOrCreate("other-quarantined-client")
					_, _, _ = quarantine.AirlockForScope("").SetTier(config.AirlockTierDrain)
					owner.Load().sessionMgrPtr.Store(full)
				}
				_, _ = fmt.Fprint(w, capacityDeliveryWitness)
			})
			owner.Store(p)
			t.Cleanup(p.sessionMgrPtr.Load().Close)
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, upstream.String()+"/control", nil)
			req.RemoteAddr = airlockAdmissionClient + ":12345"
			w := httptest.NewRecorder()
			rp.ServeHTTP(w, req)
			if calls.Load() != 1 {
				t.Fatal("request did not reach the response boundary")
			}
			if refused {
				if w.Code != http.StatusBadGateway || strings.Contains(w.Body.String(), capacityDeliveryWitness) {
					t.Fatalf("unrecorded response delivered: status=%d body=%s", w.Code, w.Body.String())
				}
			} else if w.Code != http.StatusOK || w.Body.String() != capacityDeliveryWitness {
				t.Fatalf("response control: status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}
