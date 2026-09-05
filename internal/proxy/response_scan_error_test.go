// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestResponseScanCancellationIsAnErrorAcrossHTTPHandlers(t *testing.T) {
	for _, transport := range []string{"fetch", "forward", "intercept"} {
		t.Run(transport, func(t *testing.T) {
			cfg := testScannerConfig()
			cfg.DNS.HostOverrides = map[string][]string{"api.vendor.example": {"93.184.216.34"}}
			cfg.ResponseScanning.Enabled = true
			cfg.ResponseScanning.Action = config.ActionWarn
			cfg.DLP.ScanEnv = false
			var logs bytes.Buffer
			logger, err := audit.NewWithStream("json", "stdout", "", true, true, &logs)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(logger.Close)
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			m := metrics.New()
			p, err := New(cfg, logger, sc, m)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(p.Close)
			obs := newReverseDLPRecordObserver()
			p.captureObs = obs
			rph := newReceiptProxyHelperWithMetrics(t, m)
			p.receiptEmitterPtr.Store(rph.emitter)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			rt := forwardBoundaryRoundTripper(func(r *http.Request) (*http.Response, error) {
				cancel()
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("ordinary content")), Request: r}, nil
			})
			p.client = &http.Client{Transport: rt}
			target := "http://api.vendor.example/content"
			requestURL := target
			if transport == "fetch" {
				requestURL = "/fetch?url=" + target
			}
			r := httptest.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
			w := httptest.NewRecorder()
			switch transport {
			case "fetch":
				p.handleFetch(w, r)
			case "forward":
				p.handleForwardHTTP(w, r)
			case "intercept":
				h := newInterceptHandler(&InterceptContext{TargetHost: "api.vendor.example", TargetPort: "443", Config: cfg, Scanner: sc, Logger: logger, Metrics: m, ClientIP: "192.0.2.1", RequestID: "scan-error", Proxy: p}, rt)
				h.ServeHTTP(w, r)
			}
			assertScanErrorEvidence(t, obs, rph)
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("status=%d body=%s logs=%s", w.Code, w.Body.String(), logs.String())
			}
			if !strings.Contains(logs.String(), "response scan failed") {
				t.Fatalf("scan error missing: %s", logs.String())
			}
			for _, forbidden := range []string{"response scan detected prompt injection", "context_canceled", "T1059", "suppress:"} {
				if strings.Contains(logs.String(), forbidden) {
					t.Fatalf("error misclassified as %q: %s", forbidden, logs.String())
				}
			}
		})
	}
}

func TestResponseScanCancellationIsAnErrorForReverseAndWebSocket(t *testing.T) {
	for _, transport := range []string{"reverse", "websocket"} {
		t.Run(transport, func(t *testing.T) {
			cfg := testScannerConfig()
			cfg.ResponseScanning.Enabled = true
			cfg.ResponseScanning.Action = config.ActionWarn
			var logs bytes.Buffer
			logger, err := audit.NewWithStream("json", "stdout", "", true, true, &logs)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(logger.Close)
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			m := metrics.New()
			obs := newReverseDLPRecordObserver()
			rph := newReceiptProxyHelperWithMetrics(t, m)
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if transport == "reverse" {
				var cfgPtr atomic.Pointer[config.Config]
				var scPtr atomic.Pointer[scanner.Scanner]
				cfgPtr.Store(cfg)
				scPtr.Store(sc)
				target, parseErr := url.Parse("http://api.vendor.example/content")
				if parseErr != nil {
					t.Fatal(parseErr)
				}
				rp := NewReverseProxy(target, &cfgPtr, &scPtr, logger, m, killswitch.New(cfg), nil, nil)
				rp.captureObs = obs
				var emitter atomic.Pointer[receipt.Emitter]
				emitter.Store(rph.emitter)
				rp.SetReceiptEmitter(&emitter)
				resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("ordinary content")), Request: httptest.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)}
				if modifyErr := rp.modifyResponse(resp); modifyErr != nil {
					t.Fatal(modifyErr)
				}
				defer func() { _ = resp.Body.Close() }()
				if resp.StatusCode != http.StatusForbidden {
					t.Fatalf("reverse status=%d, want blocked", resp.StatusCode)
				}
			} else {
				p := &Proxy{logger: logger, metrics: m, captureObs: obs}
				p.receiptEmitterPtr.Store(rph.emitter)
				relay := &wsRelay{proxy: p, cfg: cfg, scanner: sc, scanText: true, clientConn: discardConn{}, upstreamConn: discardConn{}, targetURL: "ws://api.vendor.example/events", hostname: "api.vendor.example"}
				payload, blocked := relay.enforceUpstreamTextPayload(ctx, logger, []byte("ordinary content"), true)
				if !blocked || payload != nil {
					t.Fatalf("websocket payload=%q blocked=%v", payload, blocked)
				}
			}
			if transport == "websocket" {
				// WebSocket frames do not have a response-capture observer;
				// their durable outcome is recorded by the receipt emitter.
				r := rph.requireReceipt(t, "response_scan_error")
				if r.ActionRecord.Verdict != config.ActionBlock {
					t.Fatalf("scan error receipt verdict = %q", r.ActionRecord.Verdict)
				}
			} else {
				assertScanErrorEvidence(t, obs, rph)
			}
			if !strings.Contains(logs.String(), "response scan failed") || strings.Contains(logs.String(), "context_canceled") || strings.Contains(logs.String(), "prompt injection") {
				t.Fatalf("scan failure not classified as error: %s", logs.String())
			}
		})
	}
}

func assertScanErrorEvidence(t *testing.T, obs *reverseDLPRecordObserver, rph *receiptProxyHelper) {
	t.Helper()
	select {
	case record := <-obs.responseCh:
		if record.EffectiveAction != config.ActionBlock || record.Outcome != capture.OutcomeBlocked || len(record.RawFindings) != 0 || len(record.EffectiveFindings) != 0 {
			t.Fatalf("incomplete scan capture = %+v", record)
		}
	default:
		t.Fatal("missing response capture")
	}
	r := rph.requireReceipt(t, "response_scan_error")
	if r.ActionRecord.Verdict != config.ActionBlock {
		t.Fatalf("scan error receipt verdict = %q", r.ActionRecord.Verdict)
	}
}

func TestFetchResponseScanErrorRecordsErrorOutcomeForHTMLAndPlain(t *testing.T) {
	for _, tt := range []struct {
		name        string
		contentType string
		body        string
	}{
		{
			name:        "html_hidden_content",
			contentType: "text/html",
			body:        "<!doctype html><html><body><!-- ordinary hidden content --><p>visible response</p></body></html>",
		},
		{
			name:        "plain_content",
			contentType: "text/plain",
			body:        "ordinary response",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p, rph := fetchRequireReceiptsLiveProxy(t, func(cfg *config.Config) {
				cfg.DNS.HostOverrides = map[string][]string{"api.vendor.example": {"93.184.216.34"}}
				cfg.DLP.ScanEnv = false
				cfg.ResponseScanning.Enabled = true
				cfg.ResponseScanning.Action = config.ActionWarn
			})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			p.client = &http.Client{Transport: forwardBoundaryRoundTripper(func(r *http.Request) (*http.Response, error) {
				cancel()
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": {tt.contentType}},
					Body:       io.NopCloser(strings.NewReader(tt.body)),
					Request:    r,
				}, nil
			})}
			w := httptest.NewRecorder()
			p.handleFetch(w, httptest.NewRequestWithContext(ctx, http.MethodGet, "/fetch?url=http://api.vendor.example/content", nil))

			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusServiceUnavailable, w.Body.String())
			}
			assertMetricsContain(t, p.metrics, `pipelock_scanner_hits_total{agent="_default",scanner="response_scan_error"} 1`)
			assertResponseScanErrorOutcome(t, rph)
		})
	}
}

func TestForwardA2AResponseScanErrorRecordsErrorOutcome(t *testing.T) {
	cfg := testScannerConfig()
	cfg.Internal = nil
	cfg.DNS.HostOverrides = map[string][]string{"api.vendor.example": {"93.184.216.34"}}
	cfg.DLP.ScanEnv = false
	cfg.FlightRecorder.RequireReceipts = true
	cfg.A2AScanning.Enabled = true
	cfg.A2AScanning.Action = config.ActionWarn
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	m := metrics.New()
	p, err := New(cfg, audit.NewNop(), sc, m)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	rph := newReceiptProxyHelperWithMetrics(t, m)
	p.receiptEmitterPtr.Store(rph.emitter)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	p.client = &http.Client{Transport: forwardBoundaryRoundTripper(func(r *http.Request) (*http.Response, error) {
		cancel()
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": {"application/a2a+json"}},
			Body:       io.NopCloser(strings.NewReader(`{"message":{"parts":[{"text":"ordinary response"}]}}`)),
			Request:    r,
		}, nil
	})}
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "http://api.vendor.example/message", strings.NewReader(`{"method":"tasks/send"}`))
	req.Header.Set("Content-Type", "application/a2a+json")
	w := httptest.NewRecorder()
	p.handleForwardHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusServiceUnavailable, w.Body.String())
	}
	assertMetricsContain(t, m, `pipelock_scanner_hits_total{agent="_default",scanner="response_scan_error"} 1`)
	assertResponseScanErrorOutcome(t, rph)
}

func assertResponseScanErrorOutcome(t *testing.T, rph *receiptProxyHelper) {
	t.Helper()
	var errorReceipt, outcome receipt.Receipt
	for _, r := range rph.findReceipts(t) {
		switch r.ActionRecord.Layer {
		case "response_scan", "a2a_response":
			t.Fatalf("scanner failure emitted a content-finding receipt: %+v", r.ActionRecord)
		case "response_scan_error":
			errorReceipt = r
		case receiptOutcomeLayer:
			if r.ActionRecord.DecisionPhase == receipt.DecisionPhaseOutcome {
				outcome = r
			}
		}
	}
	if errorReceipt.ActionRecord.Layer == "" || errorReceipt.ActionRecord.Verdict != config.ActionBlock {
		t.Fatalf("missing response-scan error block receipt: %+v", errorReceipt.ActionRecord)
	}
	if outcome.ActionRecord.DecisionPhase != receipt.DecisionPhaseOutcome || !strings.Contains(outcome.ActionRecord.Pattern, "status=503") || !strings.Contains(outcome.ActionRecord.Pattern, "reason=response_scan_error") {
		t.Fatalf("outcome receipt = %+v, want status=503 reason=response_scan_error", outcome.ActionRecord)
	}
}

type bodyScanCheckpointContext struct {
	context.Context
	cancel context.CancelFunc
	checks atomic.Int32
	after  int32
}

func (c *bodyScanCheckpointContext) Err() error {
	if c.checks.Add(1) == c.after {
		c.cancel()
	}
	return c.Context.Err()
}

func TestRequestBodyCancellationAtSuccessiveScanCheckpoints(t *testing.T) {
	sc := scanner.MustNew(testScannerConfig())
	defer sc.Close()
	const maxCheckpoint = 64
	cancelledCheckpoints := 0
	ended := false
	for checkpoint := int32(1); checkpoint <= maxCheckpoint; checkpoint++ {
		reached := false
		t.Run(fmt.Sprint(checkpoint), func(t *testing.T) {
			base, cancel := context.WithCancel(t.Context())
			defer cancel()
			ctx := &bodyScanCheckpointContext{Context: base, cancel: cancel, after: checkpoint}
			body, result := scanRequestBody(ctx, BodyScanRequest{
				Body:        strings.NewReader(`{"a":"ordinary","b":"content"}`),
				ContentType: "application/json", MaxBytes: 1024, Scanner: sc, Action: config.ActionWarn,
			})
			if base.Err() == nil {
				t.Skipf("checkpoint %d not reached; finite request-body scan completed", checkpoint)
			}
			reached = true
			cancelledCheckpoints++
			if result.Clean || result.Action != config.ActionBlock || !isFailClosedBodyResult(result, body) || len(result.InjectionMatches) != 0 {
				t.Fatalf("cancelled body returned %+v", result)
			}
		})
		if !reached {
			ended = true
			break
		}
	}
	if cancelledCheckpoints == 0 {
		t.Fatal("request-body scan exposed no reachable cancellation checkpoint")
	}
	if !ended && cancelledCheckpoints == maxCheckpoint {
		t.Fatalf("request-body scan exceeded bounded checkpoint guard of %d", maxCheckpoint)
	}
}
