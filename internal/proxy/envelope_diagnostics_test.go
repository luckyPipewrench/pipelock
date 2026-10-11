// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestInboundEnvelopeDiagnosticsStayServerSide(t *testing.T) {
	t.Parallel()
	for _, transport := range []string{"CONNECT", "forward", "WebSocket", "reverse"} {
		t.Run(transport, func(t *testing.T) {
			logger, path := newAuditModeLogger(t)
			t.Cleanup(logger.Close)
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.ForwardProxy.Enabled = true
			cfg.WebSocketProxy.Enabled = true
			enableInboundEnvelopeVerificationForTest(t, cfg)
			p, err := New(cfg, logger, scanner.MustNew(cfg), metrics.New())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(p.Close)
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.vendor.example/", nil)
			w := httptest.NewRecorder()
			switch transport {
			case "CONNECT":
				req.Method = http.MethodConnect
				p.handleConnect(w, req)
			case "forward":
				p.handleForwardHTTP(w, req)
			case "WebSocket":
				p.handleWebSocket(w, req)
			case "reverse":
				upstream, parseErr := url.Parse("http://api.vendor.example/")
				if parseErr != nil {
					t.Fatal(parseErr)
				}
				rp := NewReverseProxy(upstream, &p.cfgPtr, &p.scannerPtr, logger, p.metrics, nil, nil, nil)
				rp.SetEnvelopeVerifier(&p.envelopeVerifierPtr)
				rp.ServeHTTP(w, req)
			}
			if w.Code != http.StatusForbidden {
				t.Fatalf("status %d", w.Code)
			}
			data, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), "inbound envelope verify rejected "+transport) || !strings.Contains(string(data), "missing") {
				t.Fatalf("missing verifier diagnostics: %s", data)
			}
			if strings.Contains(w.Body.String(), "missing") || strings.Contains(w.Body.String(), "trusted key") {
				t.Fatalf("verifier detail leaked: %s", w.Body.String())
			}
		})
	}
}
