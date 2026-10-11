// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func queryViewsCredential() string { return "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" }

func queryViewsForms() []string {
	token := queryViewsCredential()
	return []string{"%67" + token[1:] + "%ZZ", "%2567" + token[1:] + "%", base64.StdEncoding.EncodeToString([]byte(token))}
}

func queryViewsProxyConfig(cfg *config.Config) {
	cfg.DLP.ScanEnv = false
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.Action = config.ActionBlock
}

func TestQueryDecodeViewsURLTransports(t *testing.T) {
	addr, cleanup := setupForwardProxy(t, queryViewsProxyConfig)
	defer cleanup()
	for i, value := range queryViewsForms() {
		for _, query := range []string{"q=" + url.QueryEscape(value), "q=" + value + ";x=1"} {
			target := "https://api.vendor.example/?" + query
			for _, route := range []string{"fetch", "forward"} {
				t.Run(fmt.Sprintf("%s/%d/%d", route, i, len(query)), func(t *testing.T) {
					client := proxyClient(addr)
					requestURL := target
					if route == "fetch" {
						client = &http.Client{}
						requestURL = "http://" + addr + "/fetch?url=" + url.QueryEscape(target)
					}
					req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, requestURL, nil)
					if err != nil {
						t.Fatal(err)
					}
					// Absolute HTTP URI selects forward rather than CONNECT.
					if route == "forward" {
						req.URL.Scheme = "http"
					}
					resp, err := client.Do(req)
					if err != nil {
						t.Fatal(err)
					}
					body, err := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					if err != nil {
						t.Fatal(err)
					}
					if resp.StatusCode != http.StatusForbidden || !strings.Contains(strings.ToLower(string(body)), "dlp") {
						t.Fatalf("status=%d, expected DLP rejection", resp.StatusCode)
					}
				})
			}
		}
	}
}

func TestQueryDecodeViewsConnectHostname(t *testing.T) {
	addr, cleanup := setupForwardProxy(t, queryViewsProxyConfig)
	defer cleanup()
	h := queryViewsCredential()
	host := h[:20] + "." + h[20:] + ".vendor.example:443"
	conn := dialProxy(t, addr)
	defer func() { _ = conn.Close() }()
	_, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", host, host)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(strings.ToLower(string(body)), "dlp") {
		t.Fatalf("CONNECT status=%d, expected DLP rejection", resp.StatusCode)
	}
}

func TestQueryDecodeViewsForwardBody(t *testing.T) {
	var hits atomic.Int32
	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); _, _ = io.WriteString(w, "ok") }))
	defer upstream.Close()
	addr, cleanup := setupForwardProxy(t, queryViewsProxyConfig)
	defer cleanup()
	for _, value := range append([]string{"ordinary status update"}, queryViewsForms()...) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, upstream.URL, strings.NewReader(value))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "text/plain")
		resp, err := proxyClient(addr).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		want := http.StatusForbidden
		if value == "ordinary status update" {
			want = http.StatusOK
		}
		if resp.StatusCode != want {
			t.Errorf("body status=%d, want %d", resp.StatusCode, want)
		}
	}
	if hits.Load() != 1 {
		t.Errorf("upstream received %d requests; want only the benign control", hits.Load())
	}
}

func TestQueryDecodeViewsInterceptBody(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); _, _ = io.WriteString(w, "ok") }))
	defer upstream.Close()
	cache, pool, cfg, _, _, m := testInterceptSetup(t)
	queryViewsProxyConfig(cfg)
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	for _, value := range queryViewsForms() {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, upstream.URL+"/upload", strings.NewReader(value))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "text/plain")
		resp := interceptAndRequest(t, upstream, cache, pool, cfg, sc, audit.NewNop(), m, req)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("intercept status=%d", resp.StatusCode)
		}
	}
	if hits.Load() != 0 {
		t.Fatal("intercept forwarded a credential body")
	}
}

func TestQueryDecodeViewsWebSocketBody(t *testing.T) {
	backend, backendCleanup := wsEchoServer(t)
	defer backendCleanup()
	addr, cleanup := setupWSProxy(t, queryViewsProxyConfig)
	defer cleanup()
	for _, value := range queryViewsForms() {
		conn := dialWS(t, addr, backend)
		if err := wsutil.WriteClientMessage(conn, ws.OpText, []byte(value)); err != nil {
			_ = conn.Close()
			t.Fatal(err)
		}
		_, _, err := wsutil.ReadServerData(conn)
		_ = conn.Close()
		var closed wsutil.ClosedError
		if !errors.As(err, &closed) || closed.Code != ws.StatusPolicyViolation {
			t.Fatalf("expected policy close, got %v", err)
		}
	}
}

func TestQueryDecodeViewsDoH(t *testing.T) {
	var hits atomic.Int32
	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); _, _ = io.WriteString(w, "ok") }))
	defer upstream.Close()
	addr, cleanup := setupForwardProxy(t, queryViewsProxyConfig)
	defer cleanup()
	h := queryViewsCredential()
	wire := []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range []string{h[:20], h[20:], "vendor", "example"} {
		if len(label) > 63 {
			t.Fatal("DNS fixture label exceeds wire limit")
		}
		wire = append(wire, byte(len(label)&0x3f))
		wire = append(wire, label...)
	}
	wire = append(wire, 0, 0, 1, 0, 1)
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		target := upstream.URL + "/dns-query"
		var body io.Reader
		if method == http.MethodGet {
			target += "?x=%ZZ;dns=" + base64.RawURLEncoding.EncodeToString(wire)
		} else {
			body = strings.NewReader(string(wire))
		}
		req, err := http.NewRequestWithContext(t.Context(), method, target, body)
		if err != nil {
			t.Fatal(err)
		}
		if method == http.MethodPost {
			req.Header.Set("Content-Type", "application/dns-message")
		}
		resp, err := proxyClient(addr).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("DoH %s status=%d", method, resp.StatusCode)
		}
	}
	if hits.Load() != 0 {
		t.Fatal("DoH forwarded credential-bearing query")
	}
}

func TestQueryDecodeViewsAuditMalformedURL(t *testing.T) {
	var hits atomic.Int32
	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); _, _ = io.WriteString(w, "ok") }))
	defer upstream.Close()
	addr, cleanup := setupForwardProxy(t, func(cfg *config.Config) { queryViewsProxyConfig(cfg); cfg.Enforce = ptrBool(false) })
	defer cleanup()
	target := upstream.URL + "/?q=" + hex.EncodeToString([]byte(queryViewsCredential())) + "#%zz"
	conn := dialProxy(t, addr)
	defer func() { _ = conn.Close() }()
	_, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: api.vendor.example\r\nConnection: close\r\n\r\n", target)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("audit malformed URL status=%d", resp.StatusCode)
	}
	if hits.Load() != 0 {
		t.Fatal("audit mode forwarded uninspected credential")
	}
}
