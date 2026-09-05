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
	for checkpoint := int32(1); checkpoint <= 64; checkpoint++ {
		t.Run(fmt.Sprint(checkpoint), func(t *testing.T) {
			base, cancel := context.WithCancel(t.Context())
			defer cancel()
			ctx := &bodyScanCheckpointContext{Context: base, cancel: cancel, after: checkpoint}
			body, result := scanRequestBody(ctx, BodyScanRequest{
				Body:        strings.NewReader(`{"a":"ordinary","b":"content"}`),
				ContentType: "application/json", MaxBytes: 1024, Scanner: sc, Action: config.ActionWarn,
			})
			if base.Err() != nil && (result.Clean || result.Action != config.ActionBlock || !isFailClosedBodyResult(result, body) || len(result.InjectionMatches) != 0) {
				t.Fatalf("cancelled body returned %+v", result)
			}
		})
	}
}
