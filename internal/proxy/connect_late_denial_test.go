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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

type lateConnectHijacker struct {
	http.ResponseWriter
	afterHijack func()
}

func (w lateConnectHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, buffered, err := w.ResponseWriter.(http.Hijacker).Hijack()
	if err == nil {
		w.afterHijack()
	}
	return conn, buffered, err
}

func TestConnectLateDenialEvidence(t *testing.T) {
	for _, outcome := range []string{"allowed", "quarantine", "capacity"} {
		t.Run(outcome, func(t *testing.T) {
			cfg := airlockAdmissionConfig(t, config.AirlockTierNone)
			cfg.SessionProfiling.MaxSessions = 1
			cfg.ForwardProxy.SNIVerification = ptrBool(false)
			cfg.TLSInterception.Enabled = outcome == "capacity"
			var calls atomic.Int32
			_, p, upstream := newReverseParityHarness(t, cfg, func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				_, _ = fmt.Fprint(w, capacityDeliveryWitness)
			})
			if cfg.TLSInterception.Enabled {
				cache, _, _, _, _, _ := testInterceptSetup(t)
				p.certCachePtr.Store(cache)
			}
			original := p.sessionMgrPtr.Load()
			t.Cleanup(original.Close)
			admitted := original.GetOrCreate(airlockAdmissionClient)
			var auditStream bytes.Buffer
			logger, err := audit.NewWithStream("json", "stdout", "", true, true, &auditStream)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(logger.Close)
			p.logger = logger
			dir := t.TempDir()
			emitter, recorder, _ := newCoverageEmitter(t, dir)
			p.receiptEmitterPtr.Store(emitter)
			t.Cleanup(func() { _ = recorder.Close() })
			done := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(done)
				r.RemoteAddr = airlockAdmissionClient + ":12345"
				p.handleConnect(lateConnectHijacker{ResponseWriter: w, afterHijack: func() {
					switch outcome {
					case "quarantine":
						_, _, _ = admitted.AirlockForScope(adaptiveScopeForHost(upstream.Hostname())).SetTier(config.AirlockTierDrain)
					case "capacity":
						full := NewSessionManager(&cfg.SessionProfiling, &cfg.AdaptiveEnforcement, p.metrics)
						other := full.GetOrCreate("other-quarantined-client")
						_, _, _ = other.AirlockForScope("").SetTier(config.AirlockTierDrain)
						p.sessionMgrPtr.Store(full)
					}
				}}, r)
			}))
			defer server.Close()
			conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", strings.TrimPrefix(server.URL, "http://"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			// Pipeline real inner-request bytes so the denied case reaches the
			// buffered forwarding branch; the allowed control proves delivery.
			if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\nGET /control HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", upstream.Host, upstream.Host, upstream.Host); err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(conn)
			connectResponse, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = connectResponse.Body.Close() }()
			var body []byte
			if outcome == "allowed" {
				response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
				if err != nil {
					t.Fatal(err)
				}
				body, err = io.ReadAll(response.Body)
				_ = response.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			_ = conn.Close()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("CONNECT handler did not finish")
			}
			if err := recorder.Close(); err != nil {
				t.Fatal(err)
			}
			receipts := extractReceiptsFromDir(t, dir)
			if outcome == "allowed" {
				if calls.Load() != 1 || !strings.Contains(string(body), capacityDeliveryWitness) || !strings.Contains(auditStream.String(), `"event":"tunnel_open"`) {
					t.Fatalf("allowed tunnel was not delivered: calls=%d body=%s audit=%s", calls.Load(), body, auditStream.String())
				}
				return
			}
			if calls.Load() != 0 || strings.Contains(auditStream.String(), `"event":"tunnel_open"`) {
				t.Fatalf("denied tunnel delivered or recorded as open: calls=%d audit=%s", calls.Load(), auditStream.String())
			}
			if outcome == "capacity" {
				found := false
				for _, got := range receipts {
					if got.ActionRecord.Verdict == config.ActionBlock && got.ActionRecord.Layer == sessionCapacityLayer {
						found = true
					}
				}
				if !found {
					t.Fatalf("late capacity refusal omitted block receipt: %+v", receipts)
				}
			}
		})
	}
}
