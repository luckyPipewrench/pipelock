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
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func cardTransportCases() []struct {
	name, body string
	clean      bool
} {
	card := "41111111" + "11111111"
	return []struct {
		name, body string
		clean      bool
	}{
		{"metric", `{"n":0.` + card + `}`, true},
		{"integer", `{"n":` + card + `}`, false},
		{"integer part", `{"n":-` + card + `.1}`, false},
		{"string", `{"n":"0.` + card + `"}`, false},
		{"encoded", `{"n":"` + base64.StdEncoding.EncodeToString([]byte(card)) + `"}`, false},
		{"decoy", `{"n":0.` + card + `,"s":"` + card + `"}`, false},
	}
}

func TestCardJSONHTTPRequests(t *testing.T) {
	for _, surface := range []string{"forward", "intercept"} {
		for _, tt := range cardTransportCases() {
			t.Run(surface+"/"+tt.name, func(t *testing.T) {
				cfg := testScannerConfig()
				cfg.DNS.HostOverrides = map[string][]string{"api.vendor.example": {"93.184.216.34"}}
				cfg.DLP.ScanEnv = false
				cfg.RequestBodyScanning.Enabled = true
				cfg.RequestBodyScanning.Action = config.ActionBlock
				s := scanner.MustNew(cfg)
				t.Cleanup(s.Close)
				m := metrics.New()
				p, err := New(cfg, audit.NewNop(), s, m)
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
					if string(body) != tt.body {
						t.Fatalf("forwarded body changed: %q", body)
					}
					forwarded = true
					return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("accepted")), Request: r}, nil
				})
				p.client = &http.Client{Transport: rt}
				r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://api.vendor.example/metrics", strings.NewReader(tt.body))
				r.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				if surface == "forward" {
					p.handleForwardHTTP(w, r)
				} else {
					newInterceptHandler(&InterceptContext{TargetHost: "api.vendor.example", TargetPort: "443", Config: cfg, Scanner: s, Logger: audit.NewNop(), Metrics: m, ClientIP: "192.0.2.1", RequestID: "card-number", Proxy: p}, rt).ServeHTTP(w, r)
				}
				want := http.StatusForbidden
				if tt.clean {
					want = http.StatusOK
				}
				if forwarded != tt.clean || w.Code != want {
					t.Fatalf("forwarded=%v status=%d want=%d body=%s", forwarded, w.Code, want, w.Body.String())
				}
			})
		}
	}
}

func TestCardJSONWebSocketRequests(t *testing.T) {
	for _, tt := range cardTransportCases() {
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
			if err := wsutil.WriteClientMessage(&wire, ws.OpText, []byte(tt.body)); err != nil {
				t.Fatal(err)
			}
			// A complete numeric message keeps its type in the retained tail.
			if err := wsutil.WriteClientMessage(&wire, ws.OpText, []byte(tt.body)); err != nil {
				t.Fatal(err)
			}
			source := &receiptFrameConn{input: bytes.NewReader(wire.Bytes())}
			sink := &receiptFrameConn{input: bytes.NewReader(nil)}
			r := &wsRelay{proxy: p, cfg: cfg, scanner: s, hostname: "api.vendor.example", targetURL: "wss://api.vendor.example/metrics", maxMsg: cfg.WebSocketProxy.MaxMessageBytes, scanText: true, clientConn: source, upstreamConn: sink}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			_, _, _, blocked := r.clientToUpstream(ctx, cancel, time.Minute)
			if blocked == tt.clean {
				t.Fatalf("blocked=%v want=%v", blocked, !tt.clean)
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
					if string(frame.Payload) != tt.body {
						t.Fatal("numeric data changed")
					}
				}
			}
			if delivered != tt.clean {
				t.Fatalf("delivered=%v want=%v", delivered, tt.clean)
			}
		})
	}
}
