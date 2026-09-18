// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
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

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestSessionCapacityHTTPAdmission(t *testing.T) {
	for _, transport := range []string{TransportForward, TransportFetch, TransportReverse} {
		t.Run(transport, func(t *testing.T) {
			cfg := airlockAdmissionConfig(t, config.AirlockTierDrain)
			cfg.SessionProfiling.MaxSessions = 1
			var calls atomic.Int32
			rp, p, upstream := newReverseParityHarness(t, cfg, func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				_, _ = fmt.Fprint(w, "capacity control")
			})
			send := func() *httptest.ResponseRecorder {
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
				return w
			}
			if w := send(); w.Code != http.StatusOK || calls.Load() != 1 {
				t.Fatalf("initial admission: status=%d upstream=%d body=%s", w.Code, calls.Load(), w.Body.String())
			}
			sm := p.sessionMgrPtr.Load()
			quarantine := sm.GetOrCreate("capacity-quarantined-client")
			_, _, _ = quarantine.AirlockForScope(adaptiveScopeForHost(upstream.Hostname())).SetTier(config.AirlockTierDrain)
			w := send()
			if w.Code != http.StatusServiceUnavailable || calls.Load() != 1 || w.Header().Get(blockreason.HeaderReason) != string(blockreason.DataBudget) || !strings.Contains(w.Body.String(), session.ErrCapacity.Error()) {
				t.Fatalf("full store: status=%d upstream=%d reason=%s body=%s", w.Code, calls.Load(), w.Header().Get(blockreason.HeaderReason), w.Body.String())
			}
			if sm.Len() != 1 || sm.SessionByKey("capacity-quarantined-client") != quarantine {
				t.Fatal("denial lost the session bound or quarantine")
			}
			_, _, _ = quarantine.ForceSetAirlockTierAllScopes(config.AirlockTierNone, airlockTriggerManual, airlockSourceAdminAPI)
			if w := send(); w.Code != http.StatusOK || calls.Load() != 2 {
				t.Fatalf("admission after release: status=%d upstream=%d body=%s", w.Code, calls.Load(), w.Body.String())
			}
		})
	}
}

func TestSessionCapacityCEEDeniesWithoutDiscardingQuarantine(t *testing.T) {
	cfg := airlockAdmissionConfig(t, config.AirlockTierDrain)
	cfg.SessionProfiling.MaxSessions = 1
	sm := NewSessionManager(&cfg.SessionProfiling, &cfg.AdaptiveEnforcement, nil)
	defer sm.Close()
	quarantine := sm.GetOrCreate("capacity-quarantined-client")
	_, _, _ = quarantine.AirlockForScope(adaptiveScopeForHost(adaptiveScopePollHost)).SetTier(config.AirlockTierDrain)
	params := ceeSignalParams{Sessions: sm, SessionKey: "new-cee-client", AdaptiveCfg: &cfg.AdaptiveEnforcement}
	if rec, denied := ceeRecordSignalsAndBlockAll(params); rec != nil || !denied {
		t.Fatalf("full store: recorder=%v denied=%t", rec, denied)
	}
	if sm.Len() != 1 || sm.SessionByKey("capacity-quarantined-client") != quarantine {
		t.Fatal("CEE refusal lost quarantine")
	}
	_, _, _ = quarantine.ForceSetAirlockTierAllScopes(config.AirlockTierNone, airlockTriggerManual, airlockSourceAdminAPI)
	if rec, denied := ceeRecordSignalsAndBlockAll(params); rec == nil || denied {
		t.Fatalf("released store: recorder=%v denied=%t", rec, denied)
	}
}

type capacityRoundTripper func(*http.Request) (*http.Response, error)

func (f capacityRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestSessionCapacityInterceptAdmission(t *testing.T) {
	cfg := airlockAdmissionConfig(t, config.AirlockTierDrain)
	cfg.SessionProfiling.MaxSessions = 1
	_, p, upstream := newReverseParityHarness(t, cfg, func(http.ResponseWriter, *http.Request) {})
	sm := p.sessionMgrPtr.Load()
	quarantine := sm.GetOrCreate("capacity-quarantined-client")
	_, _, _ = quarantine.AirlockForScope(adaptiveScopeForHost(upstream.Hostname())).SetTier(config.AirlockTierDrain)
	var calls atomic.Int32
	ic := &InterceptContext{
		TargetHost: upstream.Hostname(), TargetPort: upstream.Port(), Config: cfg,
		Scanner: p.scannerPtr.Load(), Logger: p.logger, Metrics: p.metrics,
		ClientIP: airlockAdmissionClient, SessionMgr: sm, Proxy: p,
	}
	handler := newInterceptHandler(ic, capacityRoundTripper(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{
			StatusCode: http.StatusOK, Header: make(http.Header), Request: r,
			Body: io.NopCloser(strings.NewReader("intercept capacity control")),
		}, nil
	}))
	for _, released := range []bool{false, true} {
		if released {
			_, _, _ = quarantine.ForceSetAirlockTierAllScopes(config.AirlockTierNone, airlockTriggerManual, airlockSourceAdminAPI)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, upstream.String()+"/control", nil))
		if !released {
			if w.Code != http.StatusServiceUnavailable || calls.Load() != 0 || w.Header().Get(blockreason.HeaderReason) != string(blockreason.DataBudget) {
				t.Fatalf("full store: status=%d upstream=%d body=%s", w.Code, calls.Load(), w.Body.String())
			}
		} else if w.Code != http.StatusOK || calls.Load() != 1 {
			t.Fatalf("released store: status=%d upstream=%d body=%s", w.Code, calls.Load(), w.Body.String())
		}
	}
	if ic.Recorder != nil {
		t.Fatal("request-local admission mutated the shared tunnel context")
	}
}

func TestSessionCapacityWebSocketResponseRefusesUnrecordedTaint(t *testing.T) {
	for _, scanText := range []bool{false, true} {
		t.Run(fmt.Sprintf("scan=%t", scanText), func(t *testing.T) {
			cfg := airlockAdmissionConfig(t, config.AirlockTierDrain)
			cfg.SessionProfiling.MaxSessions = 1
			cfg.Taint.Enabled = true
			cfg.ResponseScanning.Enabled = true
			_, p, upstream := newReverseParityHarness(t, cfg, func(http.ResponseWriter, *http.Request) {})
			sm := p.sessionMgrPtr.Load()
			quarantine := sm.GetOrCreate("capacity-quarantined-client")
			_, _, _ = quarantine.AirlockForScope(adaptiveScopeForHost(upstream.Hostname())).SetTier(config.AirlockTierDrain)
			client, peer := net.Pipe()
			defer func() { _ = client.Close() }()
			defer func() { _ = peer.Close() }()
			if err := peer.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			type closeResult struct {
				header ws.Header
				body   []byte
				err    error
			}
			closed := make(chan closeResult, 1)
			go func() {
				hdr, err := ws.ReadHeader(peer)
				var body []byte
				if err == nil && hdr.Length <= 125 {
					body = make([]byte, hdr.Length)
					_, err = io.ReadFull(peer, body)
				}
				closed <- closeResult{hdr, body, err}
			}()
			relay := &wsRelay{
				proxy: p, cfg: cfg, scanner: p.scannerPtr.Load(), scanText: scanText,
				clientConn: client, hostname: upstream.Hostname(), targetURL: upstream.String(),
				taintSessionKey: "capacity-new-ws-client", clientIP: airlockAdmissionClient,
			}
			if _, blocked := relay.enforceUpstreamTextPayload(t.Context(), p.logger, []byte("ordinary response"), true); !blocked {
				t.Fatal("unrecorded response was admitted")
			}
			frame := <-closed
			if frame.err != nil || frame.header.OpCode != ws.OpClose || !strings.Contains(string(frame.body), sessionCapacityLayer) {
				t.Fatalf("capacity close frame: header=%+v body=%q err=%v", frame.header, frame.body, frame.err)
			}
			_, _, _ = quarantine.ForceSetAirlockTierAllScopes(config.AirlockTierNone, airlockTriggerManual, airlockSourceAdminAPI)
			if _, blocked := relay.enforceUpstreamTextPayload(t.Context(), p.logger, []byte("ordinary response"), true); blocked {
				t.Fatal("control with available state was refused")
			}
			if sm.SessionByKey("capacity-new-ws-client") == nil {
				t.Fatal("admitted control did not retain taint state")
			}
		})
	}
}
