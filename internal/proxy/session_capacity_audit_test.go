// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestSessionCapacityAuditAndReceipt(t *testing.T) {
	for _, transport := range []string{TransportForward, TransportFetch, TransportReverse, TransportConnect, TransportWS} {
		for _, profiling := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/profiling=%t", transport, profiling), func(t *testing.T) {
				cfg := airlockAdmissionConfig(t, config.AirlockTierNone)
				cfg.SessionProfiling.Enabled = profiling
				cfg.SessionProfiling.MaxSessions = 1
				cfg.WebSocketProxy.Enabled = true
				cfg.FlightRecorder.RequireReceipts = true
				var calls atomic.Int32
				rp, p, upstream := newReverseParityHarness(t, cfg, func(http.ResponseWriter, *http.Request) { calls.Add(1) })
				var stream bytes.Buffer
				logger, err := audit.NewWithStream("json", "stdout", "", true, true, &stream)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(logger.Close)
				p.logger, rp.logger = logger, logger
				dir := t.TempDir()
				emitter, recorder, _ := newCoverageEmitter(t, dir)
				p.receiptEmitterPtr.Store(emitter)
				rp.SetReceiptEmitter(&p.receiptEmitterPtr)
				t.Cleanup(func() { _ = recorder.Close() })
				sm := p.sessionMgrPtr.Load()
				if sm == nil {
					sm = NewSessionManager(&cfg.SessionProfiling, &cfg.AdaptiveEnforcement, p.metrics)
					p.sessionMgrPtr.Store(sm)
				}
				other := sm.GetOrCreate("other-quarantined-client")
				_, _, _ = other.AirlockForScope("").SetTier(config.AirlockTierDrain)
				target := upstream.String() + "/control"
				method := http.MethodGet
				switch transport {
				case TransportFetch:
					target = "http://proxy.example/fetch?url=" + url.QueryEscape(target)
				case TransportWS:
					target = "http://proxy.example/ws?url=" + url.QueryEscape("ws://"+upstream.Host+"/control")
				case TransportConnect:
					method = http.MethodConnect
				}
				req := httptest.NewRequestWithContext(t.Context(), method, target, nil)
				if transport == TransportConnect {
					req.Host = upstream.Host
				}
				req.RemoteAddr = airlockAdmissionClient + ":12345"
				w := httptest.NewRecorder()
				switch transport {
				case TransportForward:
					p.handleForwardHTTP(w, req)
				case TransportFetch:
					p.handleFetch(w, req)
				case TransportReverse:
					rp.ServeHTTP(w, req)
				case TransportConnect:
					p.handleConnect(w, req)
				case TransportWS:
					p.handleWebSocket(w, req)
				}
				if w.Code != http.StatusServiceUnavailable || w.Header().Get(blockreason.HeaderLayer) != sessionCapacityLayer || calls.Load() != 0 {
					t.Fatalf("capacity refusal: status=%d calls=%d body=%s", w.Code, calls.Load(), w.Body.String())
				}
				if !strings.Contains(stream.String(), `"event":"blocked"`) || !strings.Contains(stream.String(), `"scanner":"session_capacity"`) {
					t.Fatalf("capacity audit missing: %s", stream.String())
				}
				if err := recorder.Close(); err != nil {
					t.Fatal(err)
				}
				receipts := extractReceiptsFromDir(t, dir)
				if len(receipts) != 1 || receipts[0].ActionRecord.Layer != sessionCapacityLayer || receipts[0].ActionRecord.Verdict != config.ActionBlock {
					t.Fatalf("capacity receipt missing or misclassified: %+v", receipts)
				}
			})
		}
	}
}
