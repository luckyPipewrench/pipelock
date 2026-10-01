// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobwas/ws"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const browserCanaryFixture = "browser-fixture-canary-marker"

func configureBrowserCanary(cfg *config.Config) {
	cfg.DLP.ScanEnv = false
	cfg.DLP.SecretsFile = ""
	cfg.CanaryTokens.Enabled = true
	cfg.CanaryTokens.Tokens = []config.CanaryToken{{Name: "browser-fixture", Value: browserCanaryFixture}}
}

func TestCanaryURLWithoutKnownSecretsAcrossHTTPPaths(t *testing.T) {
	for _, surface := range []string{"fetch", "forward", "websocket"} {
		t.Run(surface, func(t *testing.T) {
			var arrivals atomic.Int32
			arrived := make(chan struct{}, 1)
			backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				arrivals.Add(1)
				if surface == "websocket" {
					conn, _, _, upgradeErr := ws.UpgradeHTTP(r, w)
					if upgradeErr == nil {
						_ = conn.Close()
						arrived <- struct{}{}
					}
					return
				}
				_, _ = fmt.Fprint(w, "ordinary fixture response")
				arrived <- struct{}{}
			}))
			defer backend.Close()
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8"}
			cfg.APIAllowlist = nil
			cfg.ForwardProxy.Enabled = true
			cfg.WebSocketProxy.Enabled = true
			configureBrowserCanary(cfg)
			sc := scanner.MustNew(cfg)
			p, err := New(cfg, audit.NewNop(), sc, metrics.New())
			if err != nil {
				sc.Close()
				t.Fatal(err)
			}
			defer p.Close()
			handler := p.handleForwardHTTP
			switch surface {
			case "fetch":
				handler = p.handleFetch
			case "websocket":
				handler = p.handleWebSocket
			}
			proxyServer := newIPv4Server(t, http.HandlerFunc(handler))
			defer proxyServer.Close()
			client := &http.Client{Timeout: 5 * time.Second}
			transport := &http.Transport{}
			if surface == "forward" {
				proxyURL, parseErr := url.Parse(proxyServer.URL)
				if parseErr != nil {
					t.Fatal(parseErr)
				}
				transport.Proxy = http.ProxyURL(proxyURL)
			}
			client.Transport = transport
			defer transport.CloseIdleConnections()
			request := func(value string) *http.Response {
				target := backend.URL + "/fixture?value=" + url.QueryEscape(value)
				path := target
				switch surface {
				case "fetch":
					path = proxyServer.URL + "/fetch?url=" + url.QueryEscape(target)
				case "websocket":
					path = proxyServer.URL + "/ws?url=" + url.QueryEscape("ws"+strings.TrimPrefix(target, "http"))
				}
				req, requestErr := http.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
				if requestErr != nil {
					t.Fatal(requestErr)
				}
				if surface == "websocket" {
					req.Header.Set("Connection", "Upgrade")
					req.Header.Set("Upgrade", "websocket")
					req.Header.Set("Sec-WebSocket-Version", "13")
					req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
				}
				response, requestErr := client.Do(req)
				if requestErr != nil {
					t.Fatal(requestErr)
				}
				return response
			}
			blocked := request(browserCanaryFixture)
			defer func() { _ = blocked.Body.Close() }()
			if blocked.StatusCode != http.StatusForbidden || blocked.Header.Get(blockreason.HeaderReason) != string(blockreason.DLPMatch) {
				t.Fatalf("canary was not DLP-blocked: status=%d headers=%v", blocked.StatusCode, blocked.Header)
			}
			if got := arrivals.Load(); got != 0 {
				t.Fatalf("blocked marker reached fixture %d times", got)
			}
			// The owned endpoint is reachable for the same path without a canary.
			// The WebSocket positive completes a handshake only; it does not claim
			// browser rendering, authentication or frame-scanning acceptance.
			allowed := request("ordinary-value")
			defer func() { _ = allowed.Body.Close() }()
			select {
			case <-arrived:
			case <-time.After(5 * time.Second):
				t.Fatal("owned endpoint did not witness the positive route")
			}
			wantStatus := http.StatusOK
			if surface == "websocket" {
				wantStatus = http.StatusSwitchingProtocols
			}
			if got := arrivals.Load(); got != 1 || allowed.StatusCode != wantStatus {
				t.Fatalf("positive route control failed: arrivals=%d status=%d headers=%v", got, allowed.StatusCode, allowed.Header)
			}
		})
	}
}

func TestCanaryURLWithoutKnownSecretsCONNECT(t *testing.T) {
	const host = browserCanaryFixture + ".fixture.example"
	addr, calls, _, cleanup := setupConnectIdentityProxy(t, func(cfg *config.Config) {
		configureBrowserCanary(cfg)
		cfg.DNS.HostOverrides = map[string][]string{
			host:                       {"127.0.0.1"},
			"ordinary.fixture.example": {"127.0.0.1"},
		}
	})
	defer cleanup()
	blocked := doConnectLiveLock(t, addr, host+":6443")
	defer func() { _ = blocked.Body.Close() }()
	if blocked.StatusCode != http.StatusForbidden || blocked.Header.Get(blockreason.HeaderReason) != string(blockreason.DLPMatch) || calls.Load() != 0 {
		t.Fatalf("canary CONNECT admission changed: status=%d headers=%v calls=%d", blocked.StatusCode, blocked.Header, calls.Load())
	}
	allowed := doConnectLiveLock(t, addr, "ordinary.fixture.example:6443")
	defer func() { _ = allowed.Body.Close() }()
	if calls.Load() != 1 || allowed.StatusCode != http.StatusBadGateway {
		t.Fatalf("positive CONNECT did not reach the test-only stopped dial: status=%d calls=%d", allowed.StatusCode, calls.Load())
	}
}
