// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/hitl"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestRequiredResponseReceiptAfterAdmission(t *testing.T) {
	for _, surface := range []string{"fetch", "forward", "intercept", "reverse"} {
		for _, outage := range []bool{false, true} {
			for _, shape := range []string{"warn", "strip", "sse warn", "approve", "approve strip"} {
				if strings.HasPrefix(shape, "approve") && surface != "fetch" {
					continue
				}
				if shape == "sse warn" && surface == "fetch" {
					continue
				}
				t.Run(surface+"/"+shape+"/"+map[bool]string{false: "healthy", true: "v2 outage"}[outage], func(t *testing.T) {
					f := newDualEmitFixture(t, false)
					cfg := config.Defaults()
					cfg.Internal = nil
					cfg.Taint.Enabled = false
					cfg.FlightRecorder.RequireReceipts = true
					cfg.ForwardProxy.Enabled = true
					cfg.ResponseScanning.Enabled = true
					cfg.ResponseScanning.Action = config.ActionWarn
					if shape == "strip" {
						cfg.ResponseScanning.Action = config.ActionStrip
					}
					if strings.HasPrefix(shape, "approve") {
						cfg.ResponseScanning.Action = config.ActionAsk
					}
					cfg.ResponseScanning.Patterns = []config.ResponseScanPattern{{Name: "response marker", Regex: "POLICY_MARKER"}}
					cfg.ResponseScanning.SSEStreaming.Enabled = true
					cfg.ResponseScanning.SSEStreaming.Action = config.ActionWarn
					sc := scanner.MustNew(cfg)
					p, err := New(cfg, f.p.logger, sc, f.p.metrics, WithRecorder(f.rec), WithReceiptEmitter(f.p.receiptEmitterPtr.Load()), WithV2ReceiptEmitter(f.p.v2EmitterPtr.Load()))
					if err != nil {
						t.Fatal(err)
					}
					defer p.Close()
					if strings.HasPrefix(shape, "approve") {
						answer := "y\n"
						if shape == "approve strip" {
							answer = "s\n"
						}
						p.approver = hitl.New(5, hitl.WithInput(strings.NewReader(answer)), hitl.WithOutput(&bytes.Buffer{}), hitl.WithTerminal(true))
						defer p.approver.Close()
					}
					target := "https://api.vendor.example/content"
					var admitted bool
					retire := func() {
						if !outage {
							admitted = true
							return
						}
						if _, _, err := p.v2EmitterPtr.Load().Retire(); err != nil {
							t.Fatal(err)
						}
						admitted = true
					}
					rt := forwardBoundaryRoundTripper(func(r *http.Request) (*http.Response, error) {
						retire()
						ctype, body := "text/plain", "ordinary text POLICY_MARKER rest"
						if shape == "sse warn" {
							ctype, body = "text/event-stream", `data: {"choices":[{"delta":{"content":"ordinary text POLICY_MARKER rest"}}]}`+"\n\n"
						}
						return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {ctype}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
					})
					p.client = &http.Client{Transport: rt}
					requestURL := target
					if surface == "fetch" {
						requestURL = "/fetch?url=" + target
					}
					r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, requestURL, nil)
					w := httptest.NewRecorder()
					var reverseOutcome *reverseOutcomeTracker
					switch surface {
					case "fetch":
						p.handleFetch(w, r)
					case "forward":
						p.handleForwardHTTP(w, r)
					case "intercept":
						h := newInterceptHandler(&InterceptContext{TargetHost: "api.vendor.example", TargetPort: "443", Config: cfg, Scanner: sc, Logger: p.logger, Metrics: p.metrics, Proxy: p}, rt)
						h.ServeHTTP(w, r)
					case "reverse":
						reverseOutcome = newReverseOutcomeTracker(cfg, receipt.EmitOpts{})
						r = r.WithContext(context.WithValue(r.Context(), ctxKeyReverseOutcome, reverseOutcome))
						if err := p.emitRequiredReceipt(receipt.EmitOpts{ActionID: receipt.NewActionID(), Verdict: config.ActionAllow, Transport: TransportReverse, Target: target, Method: http.MethodGet}); err != nil {
							t.Fatal(err)
						}
						resp, err := rt.RoundTrip(r)
						if err != nil {
							t.Fatal(err)
						}
						rp := &ReverseProxyHandler{cfgPtr: &p.cfgPtr, scPtr: &p.scannerPtr, logger: p.logger, metrics: p.metrics, owner: p, captureObs: p.captureObs, receiptEmitterPtr: &p.receiptEmitterPtr, v2EmitterPtr: &p.v2EmitterPtr, envelopeEmitterPtr: &p.envelopeEmitterPtr, envelopeVerifierPtr: &p.envelopeVerifierPtr}
						if err := rp.modifyResponse(resp); err != nil {
							t.Fatal(err)
						}
						body, err := io.ReadAll(resp.Body)
						_ = resp.Body.Close()
						if err != nil && !outage {
							t.Fatalf("healthy response read: %v", err)
						}
						w.WriteHeader(resp.StatusCode)
						_, _ = w.Write(body)
					}
					if !admitted {
						t.Fatal("positive control failed: request never reached admitted upstream")
					}
					delivered := strings.Contains(w.Body.String(), "ordinary text")
					if delivered == outage {
						t.Fatalf("response delivered after required v2 retired: status=%d body=%s", w.Code, w.Body.String())
					}
					if reverseOutcome != nil && shape == "sse warn" && outage {
						reverseOutcome.mu.Lock()
						reason := reverseOutcome.reason
						reverseOutcome.mu.Unlock()
						if reason != receiptEmissionFailedLayer {
							t.Fatalf("failed stream outcome reason=%q", reason)
						}
					}
					if !outage && strings.Contains(shape, "strip") && strings.Contains(w.Body.String(), "POLICY_MARKER") {
						t.Fatal("strip delivered the finding unchanged")
					}
				})
			}
		}
	}
}
