// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestLegacyIPv4LiteralBlockedAtTransportEntryPoints(t *testing.T) {
	t.Run("fetch", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.APIAllowlist = nil
		cfg.SSRF.IPAllowlist = nil
		sc := scanner.MustNew(cfg)
		t.Cleanup(sc.Close)
		p, err := New(cfg, audit.NewNop(), sc, metrics.New())
		if err != nil {
			t.Fatalf("proxy.New: %v", err)
		}
		t.Cleanup(p.Close)

		req := httptest.NewRequestWithContext(
			t.Context(),
			http.MethodGet,
			"/fetch?url="+url.QueryEscape("http://127.1/private"),
			nil,
		)
		rec := httptest.NewRecorder()
		p.handleFetch(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("fetch status = %d, want %d; body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
		}
	})

	t.Run("forward proxy", func(t *testing.T) {
		proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
			cfg.SSRF.IPAllowlist = nil
		})
		defer cleanup()

		client := proxyClient(proxyAddr)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://127.1/private", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("forward request: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusForbidden {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("forward status = %d, want %d; body=%s", resp.StatusCode, http.StatusForbidden, body)
		}
	})

	t.Run("CONNECT", func(t *testing.T) {
		proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
			cfg.SSRF.IPAllowlist = nil
		})
		defer cleanup()

		conn := dialProxy(t, proxyAddr)
		defer func() { _ = conn.Close() }()
		if _, err := io.WriteString(conn, "CONNECT 127.1:443 HTTP/1.1\r\nHost: 127.1:443\r\n\r\n"); err != nil {
			t.Fatalf("write CONNECT: %v", err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("read CONNECT response: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("CONNECT status = %d, want %d", resp.StatusCode, http.StatusForbidden)
		}
	})

	t.Run("WebSocket", func(t *testing.T) {
		proxyAddr, cleanup := setupWSProxy(t, func(cfg *config.Config) {
			cfg.SSRF.IPAllowlist = nil
		})
		defer cleanup()

		client := &http.Client{Timeout: 2 * time.Second}
		req, err := http.NewRequestWithContext(
			t.Context(),
			http.MethodGet,
			"http://"+proxyAddr+"/ws?url="+url.QueryEscape("ws://127.1/private"),
			nil,
		)
		if err != nil {
			t.Fatalf("new WebSocket request: %v", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("WebSocket request: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusForbidden {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("WebSocket status = %d, want %d; body=%s", resp.StatusCode, http.StatusForbidden, body)
		}
	})
}
