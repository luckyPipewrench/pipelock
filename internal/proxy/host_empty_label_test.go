// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
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
			resp, getErr := http.Get(srv.URL + "/fetch?url=" + url.QueryEscape(target))
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
			req, reqErr := http.NewRequest(http.MethodGet, target, nil)
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
			conn, dialErr := net.DialTimeout("tcp", srv.Listener.Addr().String(), 5*time.Second)
			if dialErr != nil {
				t.Fatalf("dial proxy: %v", dialErr)
			}
			defer conn.Close()
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
