// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/cardtest"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func cardTransportCases() []cardtest.JSONCase {
	card := "41111111" + "11111111"
	return append(cardtest.TransportCases(), []cardtest.JSONCase{
		{Name: "integer part", Body: `{"n":-` + card + `.1}`, Clean: false},
		{Name: "dotted string", Body: `{"n":"0.` + card + `"}`, Clean: false},
		{Name: "encoded", Body: `{"n":"` + base64.StdEncoding.EncodeToString([]byte(card)) + `"}`, Clean: false},
		{Name: "decoy", Body: `{"n":0.` + card + `,"s":"` + card + `"}`, Clean: false},
	}...)
}

func TestCardJSONHTTPRequests(t *testing.T) {
	for _, surface := range []string{"forward", "intercept"} {
		for _, tt := range cardTransportCases() {
			t.Run(surface+"/"+tt.Name, func(t *testing.T) {
				cfg := testScannerConfig()
				cfg.DNS.HostOverrides = map[string][]string{"api.vendor.example": {"93.184.216.34"}}
				cfg.DLP.ScanEnv = false
				cfg.RequestBodyScanning.Enabled = true
				cfg.RequestBodyScanning.Action = config.ActionBlock
				s := scanner.MustNew(cfg)
				t.Cleanup(s.Close)
				m := metrics.New()
				var records bytes.Buffer
				log, err := audit.NewWithStream("json", "stdout", "", true, true, &records)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(log.Close)
				p, err := New(cfg, log, s, m)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(p.Close)
				forwarded := false
				rt := forwardBoundaryRoundTripper(func(r *http.Request) (*http.Response, error) {
					body, readErr := io.ReadAll(r.Body)
					if readErr != nil {
						return nil, readErr
					}
					if string(body) != tt.Body {
						t.Fatalf("forwarded body changed: %q", body)
					}
					forwarded = true
					return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("accepted")), Request: r}, nil
				})
				p.client = &http.Client{Transport: rt}
				r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://api.vendor.example/metrics", strings.NewReader(tt.Body))
				r.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				if surface == "forward" {
					p.handleForwardHTTP(w, r)
				} else {
					newInterceptHandler(&InterceptContext{TargetHost: "api.vendor.example", TargetPort: "443", Config: cfg, Scanner: s, Logger: log, Metrics: m, ClientIP: "192.0.2.1", RequestID: "card-number", Proxy: p}, rt).ServeHTTP(w, r)
				}
				want := http.StatusForbidden
				if tt.Clean || tt.Warn {
					want = http.StatusOK
				}
				if forwarded != (tt.Clean || tt.Warn) || w.Code != want {
					t.Fatalf("forwarded=%v status=%d want=%d body=%s", forwarded, w.Code, want, w.Body.String())
				}
				recorded := strings.Contains(records.String(), `"action":"warn"`)
				if surface == "intercept" {
					recorded = strings.Contains(records.String(), `"event":"anomaly"`) && strings.Contains(records.String(), `"scanner":"body_dlp"`)
				}
				if tt.Warn && (!recorded || !strings.Contains(records.String(), "Credit Card Number")) {
					t.Fatal("forwarded number-only body lacks its audit warning")
				}
			})
		}
	}
}

func TestCardJSONWebSocketRequests(t *testing.T) {
	cases := cardTransportCases()
	cases = append(cases, cardtest.JSONCase{Name: "scalar decimal", Body: "0." + "41111111" + "11111111", Clean: false})
	for _, tt := range cases {
		t.Run(tt.Name, func(t *testing.T) {
			cfg := testScannerConfig()
			cfg.DLP.ScanEnv = false
			s := scanner.MustNew(cfg)
			t.Cleanup(s.Close)
			p, err := New(cfg, audit.NewNop(), s, metrics.New())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(p.Close)
			var wire bytes.Buffer
			if err := wsutil.WriteClientMessage(&wire, ws.OpText, []byte(tt.Body)); err != nil {
				t.Fatal(err)
			}
			// A complete numeric message keeps its type in the retained tail.
			if err := wsutil.WriteClientMessage(&wire, ws.OpText, []byte(tt.Body)); err != nil {
				t.Fatal(err)
			}
			source := &receiptFrameConn{input: bytes.NewReader(wire.Bytes())}
			sink := &receiptFrameConn{input: bytes.NewReader(nil)}
			r := &wsRelay{proxy: p, cfg: cfg, scanner: s, hostname: "api.vendor.example", targetURL: "wss://api.vendor.example/metrics", maxMsg: cfg.WebSocketProxy.MaxMessageBytes, scanText: true, clientConn: source, upstreamConn: sink}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			_, _, _, blocked := r.clientToUpstream(ctx, cancel, time.Minute)
			if blocked == (tt.Clean || tt.Warn) {
				t.Fatalf("blocked=%v want=%v", blocked, !tt.Clean && !tt.Warn)
			}
			frames := bytes.NewReader(sink.output.Bytes())
			delivered := false
			for frames.Len() > 0 {
				frame, readErr := ws.ReadFrame(frames)
				if readErr != nil {
					t.Fatal(readErr)
				}
				if frame.Header.OpCode == ws.OpText {
					ws.Cipher(frame.Payload, frame.Header.Mask, 0)
					delivered = true
					if string(frame.Payload) != tt.Body {
						t.Fatal("numeric data changed")
					}
				}
			}
			if delivered != (tt.Clean || tt.Warn) {
				t.Fatalf("delivered=%v want=%v", delivered, tt.Clean || tt.Warn)
			}
		})
	}
}

func TestCardJSONWebSocketNumberSeam(t *testing.T) {
	card := "4111" + "1111" + "1111" + "1111"
	for _, tt := range []struct {
		name, first, last string
		blocked           bool
	}{
		{"card pieces", card[:8], card[8:], false},
		{"ordinary telemetry", "12003400", "56007800", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testScannerConfig()
			cfg.DLP.ScanEnv = false
			s := scanner.MustNew(cfg)
			t.Cleanup(s.Close)
			p, err := New(cfg, audit.NewNop(), s, metrics.New())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(p.Close)
			var wire bytes.Buffer
			for _, piece := range []string{tt.first, tt.last} {
				message := `{"data":{"value":` + piece + `}}`
				if err := wsutil.WriteClientMessage(&wire, ws.OpText, []byte(message)); err != nil {
					t.Fatal(err)
				}
			}
			source := &receiptFrameConn{input: bytes.NewReader(wire.Bytes())}
			sink := &receiptFrameConn{input: bytes.NewReader(nil)}
			r := &wsRelay{proxy: p, cfg: cfg, scanner: s, hostname: "api.vendor.example", targetURL: "wss://api.vendor.example/metrics", maxMsg: cfg.WebSocketProxy.MaxMessageBytes, scanText: true, clientConn: source, upstreamConn: sink}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			_, _, _, blocked := r.clientToUpstream(ctx, cancel, time.Minute)
			if blocked != tt.blocked {
				t.Fatalf("blocked=%v want=%v", blocked, tt.blocked)
			}
		})
	}
}
