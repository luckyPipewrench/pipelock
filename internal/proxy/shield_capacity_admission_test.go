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

func TestShieldResponseRequiresSignalCapacity(t *testing.T) {
	for _, maxBytes := range []int{0, 64} {
		t.Run(fmt.Sprintf("max_bytes=%d", maxBytes), func(t *testing.T) {
			testShieldResponseRequiresSignalCapacity(t, maxBytes)
		})
	}
}

func testShieldResponseRequiresSignalCapacity(t *testing.T, maxBytes int) {
	t.Helper()
	for _, transport := range []string{TransportForward, TransportFetch, "intercept"} {
		for _, full := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/full=%t", transport, full), func(t *testing.T) {
				cfg := airlockAdmissionConfig(t, config.AirlockTierNone)
				cfg.FlightRecorder.RequireReceipts = true
				cfg.SessionProfiling.MaxSessions = 1
				cfg.Taint.Enabled = false
				cfg.ResponseScanning.Enabled = false
				cfg.BrowserShield.Enabled = true
				cfg.BrowserShield.Strictness = config.ShieldStrictnessAggressive
				cfg.BrowserShield.InjectFingerprintShims = true
				if maxBytes > 0 {
					cfg.BrowserShield.MaxShieldBytes = maxBytes
					cfg.BrowserShield.OversizeAction = config.ShieldOversizeScanHead
				}
				var owner atomic.Pointer[Proxy]
				var calls atomic.Int32
				const upstreamBody = `<html><head></head><body>capacity shield control<script>navigator.sendBeacon("/collect", "x")</script></body></html>`
				_, p, upstream := newReverseParityHarness(t, cfg, func(w http.ResponseWriter, _ *http.Request) {
					calls.Add(1)
					if full {
						manager := NewSessionManager(&cfg.SessionProfiling, &cfg.AdaptiveEnforcement, nil)
						other := manager.GetOrCreate("other-quarantined-client")
						_, _, _ = other.AirlockForScope("").SetTier(config.AirlockTierDrain)
						owner.Load().sessionMgrPtr.Store(manager)
					}
					w.Header().Set("Content-Type", "text/html")
					_, _ = fmt.Fprint(w, upstreamBody)
				})
				owner.Store(p)
				var logBuffer bytes.Buffer
				logger, err := audit.NewWithStream("json", "stdout", "", true, true, &logBuffer)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(logger.Close)
				p.logger = logger
				receiptDir := t.TempDir()
				emitter, recorder, _ := newCoverageEmitter(t, receiptDir)
				p.receiptEmitterPtr.Store(emitter)
				t.Cleanup(func() { _ = recorder.Close() })
				original := p.sessionMgrPtr.Load()
				t.Cleanup(original.Close)
				target := upstream.String() + "/page"
				if transport == TransportFetch {
					target = "http://proxy.example/fetch?url=" + url.QueryEscape(target)
				}
				r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
				r.RemoteAddr = airlockAdmissionClient + ":12345"
				w := httptest.NewRecorder()
				switch transport {
				case TransportForward:
					p.handleForwardHTTP(w, r)
				case TransportFetch:
					p.handleFetch(w, r)
				case "intercept":
					ic := &InterceptContext{
						TargetHost: upstream.Hostname(), TargetPort: upstream.Port(), Config: cfg,
						Scanner: p.scannerPtr.Load(), Logger: logger, Metrics: p.metrics,
						ClientIP: airlockAdmissionClient, RequestID: "req-shield-capacity", SessionMgr: original, Proxy: p,
					}
					localTransport := capacityRoundTripper(func(r *http.Request) (*http.Response, error) {
						clone := r.Clone(r.Context())
						u := *r.URL
						u.Scheme = "http" // Local origin witnesses the decrypted inner HTTP delivery.
						clone.URL = &u
						return http.DefaultTransport.RoundTrip(clone)
					})
					newInterceptHandler(ic, localTransport).ServeHTTP(w, r)
				}
				if err := recorder.Close(); err != nil {
					t.Fatal(err)
				}
				if calls.Load() != 1 {
					t.Fatal("request did not reach the response boundary")
				}
				if full {
					if w.Code != http.StatusServiceUnavailable || w.Header().Get(blockreason.HeaderLayer) != sessionCapacityLayer || strings.Contains(w.Body.String(), "capacity shield control") {
						t.Fatalf("unrecorded shield response delivered: status=%d layer=%q body=%s", w.Code, w.Header().Get(blockreason.HeaderLayer), w.Body.String())
					}
					if !strings.Contains(logBuffer.String(), `"scanner":"session_capacity"`) {
						t.Fatalf("shield capacity missing from audit: %s", logBuffer.String())
					}
					denied, outcomeRecorded := false, false
					wantBytes := int64(len(upstreamBody))
					if transport == "intercept" {
						// Intercepted blocked outcomes retain their unknown-byte contract.
						wantBytes = -1
					}
					wantOutcome := receiptOutcomePattern("503", wantBytes, sessionCapacityLayer)
					for _, got := range extractReceiptsFromDir(t, receiptDir) {
						if got.ActionRecord.Layer == receiptOutcomeLayer {
							outcomeRecorded = true
							if got.ActionRecord.Pattern != wantOutcome {
								t.Errorf("capacity outcome = %q, want %q", got.ActionRecord.Pattern, wantOutcome)
							}
						}
						if got.ActionRecord.Verdict == config.ActionBlock && got.ActionRecord.Layer == sessionCapacityLayer {
							denied = true
						}
						if got.ActionRecord.Layer == browserShieldLayer && got.ActionRecord.Verdict == config.ActionAllow {
							t.Fatal("failed intervention emitted a Shield allow receipt")
						}
					}
					if !denied {
						t.Fatal("shield capacity missing from receipts")
					}
					if !outcomeRecorded {
						t.Fatal("shield capacity missing its terminal outcome")
					}
				} else {
					recorded := original.SessionByKey(airlockAdmissionClient)
					if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "capacity shield control") || recorded == nil || recorded.ThreatScore() == 0 {
						t.Fatalf("shield control did not deliver and record its intervention: status=%d body=%s", w.Code, w.Body.String())
					}
				}
			})
		}
	}
}
