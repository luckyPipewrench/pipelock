// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// TestProxy_EmptyLabelHostBlocksOnEveryTransport proves the empty-label
// verdict on all three mediated request surfaces rather than in the scanner
// alone, because each builds its destination at a different place.
//
// The backend is reachable only through a dns.host_overrides pin, and the
// pinned name is on the blocklist. Before the fix the two-dot spelling
// produced "blocked": false on every surface and reached the network layer,
// where it survived only because the dialer's fresh lookup of the two-dot
// name failed. That is a policy verdict decided by a resolver.
func TestProxy_EmptyLabelHostBlocksOnEveryTransport(t *testing.T) {
	var backendHits atomic.Int32
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		backendHits.Add(1)
		_, _ = fmt.Fprint(w, "backend reached")
	}))
	backendHost, backendPort, splitErr := net.SplitHostPort(backend.Listener.Addr().String())
	if splitErr != nil {
		t.Fatalf("split backend addr: %v", splitErr)
	}

	const pinnedHost = "pinned.vendor.example"

	cfg := config.Defaults()
	cfg.FetchProxy.TimeoutSeconds = 5
	cfg.ForwardProxy.Enabled = true
	cfg.SSRF.IPAllowlist = nil
	cfg.APIAllowlist = nil
	cfg.TrustedDomains = []string{pinnedHost}
	cfg.DNS.HostOverrides = map[string][]string{pinnedHost: {backendHost}}
	cfg.FetchProxy.Monitoring.Blocklist = []string{pinnedHost}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config.Validate: %v", err)
	}

	p, err := New(cfg, audit.NewNop(), scanner.MustNew(cfg), metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()
	proxyURL, parseErr := url.Parse(srv.URL)
	if parseErr != nil {
		t.Fatalf("parse proxy URL: %v", parseErr)
	}

	// Control first: the exact pinned host is blocked by the blocklist on all
	// three surfaces, which is what makes a refusal below meaningful.
	// Then the empty-label spellings, which must also be refused.
	cases := []struct {
		host    string
		control bool
	}{
		{host: pinnedHost, control: true},
		{host: pinnedHost + "."},
		{host: pinnedHost + ".."},
		{host: pinnedHost + "..."},
	}

	for _, tc := range cases {
		target := "http://" + net.JoinHostPort(tc.host, backendPort) + "/leak"

		t.Run("fetch/"+tc.host, func(t *testing.T) {
			before := backendHits.Load()
			fetchReq, fetchReqErr := http.NewRequestWithContext(
				t.Context(), http.MethodGet, srv.URL+"/fetch?url="+url.QueryEscape(target), nil)
			if fetchReqErr != nil {
				t.Fatalf("new fetch request: %v", fetchReqErr)
			}
			resp, getErr := http.DefaultClient.Do(fetchReq)
			if getErr != nil {
				t.Fatalf("fetch: %v", getErr)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status %d body %q, want 403", resp.StatusCode, body)
			}
			if !strings.Contains(string(body), `"blocked":true`) {
				t.Fatalf("body %q does not report a block", body)
			}
			if backendHits.Load() != before {
				t.Fatal("backend was reached")
			}
		})

		t.Run("forward/"+tc.host, func(t *testing.T) {
			before := backendHits.Load()
			transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
			req, reqErr := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
			if reqErr != nil {
				t.Fatalf("new request: %v", reqErr)
			}
			resp, doErr := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Do(req)
			if doErr != nil {
				t.Fatalf("forward: %v", doErr)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status %d body %q, want 403", resp.StatusCode, body)
			}
			if backendHits.Load() != before {
				t.Fatal("backend was reached")
			}
		})

		t.Run("connect/"+tc.host, func(t *testing.T) {
			before := backendHits.Load()
			dialer := &net.Dialer{Timeout: 5 * time.Second}
			conn, dialErr := dialer.DialContext(t.Context(), "tcp", srv.Listener.Addr().String())
			if dialErr != nil {
				t.Fatalf("dial proxy: %v", dialErr)
			}
			defer func() { _ = conn.Close() }()
			authority := net.JoinHostPort(tc.host, backendPort)
			if _, writeErr := fmt.Fprintf(conn,
				"CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority); writeErr != nil {
				t.Fatalf("write CONNECT: %v", writeErr)
			}
			if deadlineErr := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); deadlineErr != nil {
				t.Fatalf("set deadline: %v", deadlineErr)
			}
			buf := make([]byte, 256)
			n, _ := conn.Read(buf)
			reply := string(buf[:n])
			if !strings.HasPrefix(reply, "HTTP/1.1 403") {
				t.Fatalf("CONNECT reply %q, want 403", reply)
			}
			if backendHits.Load() != before {
				t.Fatal("backend was reached")
			}
		})
	}
}

// TestWebSocketProxy_EmptyLabelHostRefused covers the /ws surface, which
// builds its destination from the url query parameter rather than from a
// request line. The review that read this change confirmed statically that
// the native WebSocket path scans before it dials, and this exercises it, so
// the transport-parity claim is proven rather than argued.
func TestWebSocketProxy_EmptyLabelHostRefused(t *testing.T) {
	backendAddr, backendCleanup := wsEchoServer(t)
	defer backendCleanup()
	backendHost, backendPort, splitErr := net.SplitHostPort(backendAddr)
	if splitErr != nil {
		t.Fatalf("split backend addr: %v", splitErr)
	}

	const pinnedHost = "ws-pinned.vendor.example"
	proxyAddr, proxyCleanup := setupWSProxy(t, func(cfg *config.Config) {
		cfg.SSRF.IPAllowlist = nil
		cfg.TrustedDomains = []string{pinnedHost}
		cfg.DNS.HostOverrides = map[string][]string{pinnedHost: {backendHost}}
	})
	defer proxyCleanup()

	// Control first: the exact pinned host upgrades, so a refusal below is
	// the empty label rather than an unreachable backend.
	if status := wsUpgradeStatus(t, proxyAddr, net.JoinHostPort(pinnedHost, backendPort)); status != http.StatusSwitchingProtocols {
		t.Fatalf("control upgrade status %d, want 101", status)
	}

	for _, host := range []string{pinnedHost + "..", pinnedHost + "..."} {
		status := wsUpgradeStatus(t, proxyAddr, net.JoinHostPort(host, backendPort))
		if status == http.StatusSwitchingProtocols {
			t.Fatalf("host %q upgraded; an empty-label host must be refused before the dial", host)
		}
		if status != http.StatusForbidden {
			t.Fatalf("host %q status %d, want 403", host, status)
		}
	}
}

// wsUpgradeStatus performs one manual WebSocket upgrade through the proxy and
// returns the status code. It is manual for the same reason the DNS override
// end-to-end test is: a client-side dialer would resolve the hostname itself,
// and the point is what pipelock does with the name.
func wsUpgradeStatus(t *testing.T, proxyAddr, targetHostPort string) int {
	t.Helper()
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, dialErr := dialer.DialContext(t.Context(), "tcp", proxyAddr)
	if dialErr != nil {
		t.Fatalf("dial proxy: %v", dialErr)
	}
	defer func() { _ = conn.Close() }()
	if deadlineErr := conn.SetDeadline(time.Now().Add(5 * time.Second)); deadlineErr != nil {
		t.Fatalf("set deadline: %v", deadlineErr)
	}
	upgrade := fmt.Sprintf(
		"%s /ws?url=%s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		http.MethodGet, url.QueryEscape("ws://"+targetHostPort+"/echo"), proxyAddr, generateWSKey(t),
	)
	if _, writeErr := conn.Write([]byte(upgrade)); writeErr != nil {
		t.Fatalf("write upgrade: %v", writeErr)
	}
	resp, respErr := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if respErr != nil {
		t.Fatalf("read upgrade response: %v", respErr)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}
