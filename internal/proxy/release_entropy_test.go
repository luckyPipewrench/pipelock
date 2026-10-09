// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestReleaseFilenameEntropyTransports(t *testing.T) {
	const host = "assets.vendor.example"
	const version = "0.0.46-nightly.20261009.2873"
	const filename = "Example-Code-" + version + "-x86_64.AppImage"
	for _, transport := range []string{"fetch", "forward", "intercept"} {
		for _, tc := range []struct {
			name, path string
			allowed    bool
		}{
			{"release", "/download/v" + version + "/" + filename, true},
			{"build metadata", "/download/v" + version + "+b/Example-Code-" + version + "+b-x86_64.AppImage", true},
			{"unversioned", "/download/" + filename, false},
			{"credential", "/download/v" + version + "/" + filename + "?key=" + fakeAPIKey(), false},
			{"opaque query", "/download/v" + version + "/" + filename + "?ref=" + opaqueHighEntropyBodyValue(), false},
		} {
			t.Run(transport+"/"+tc.name, func(t *testing.T) {
				cfg := testScannerConfig()
				cfg.DNS.HostOverrides = map[string][]string{host: {"93.184.216.34"}}
				sc := scanner.MustNew(cfg)
				t.Cleanup(sc.Close)
				var hits atomic.Int32
				rt := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
					hits.Add(1)
					return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("download ready")), Request: r}, nil
				})
				target := "https://" + host + tc.path
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
				w := httptest.NewRecorder()
				if transport == "intercept" {
					h := newInterceptHandler(&InterceptContext{TargetHost: host, TargetPort: "443", Config: cfg, Scanner: sc, Logger: audit.NewNop(), Metrics: metrics.New(), ClientIP: testLoopbackIP, Agent: agentAnonymous}, rt)
					h.ServeHTTP(w, req)
				} else {
					p, err := New(cfg, audit.NewNop(), sc, metrics.New())
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(p.Close)
					p.client.Transport = rt
					if transport == "fetch" {
						req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(target), nil)
						p.handleFetch(w, req)
					} else {
						p.handleForwardHTTP(w, req)
					}
				}
				wantStatus, wantHits := http.StatusForbidden, int32(0)
				if tc.allowed {
					wantStatus, wantHits = http.StatusOK, 1
				}
				if w.Code != wantStatus || hits.Load() != wantHits {
					t.Fatalf("status/hits = %d/%d, want %d/%d: %s", w.Code, hits.Load(), wantStatus, wantHits, w.Body.String())
				}
			})
		}
	}
}

func TestReleaseFilenameEntropyWebSocket(t *testing.T) {
	backendAddr, cleanup := wsEchoServer(t)
	t.Cleanup(cleanup)
	proxyAddr, cleanup := setupWSProxy(t, nil)
	t.Cleanup(cleanup)
	const version = "0.0.46-nightly.20261009.2873"
	const filename = "Example-Code-" + version + "-x86_64.AppImage"
	for _, tc := range []struct {
		name, path string
		allowed    bool
	}{
		{"release", "/download/v" + version + "/" + filename, true},
		{"unversioned", "/download/" + filename, false},
		{"credential", "/download/v" + version + "/" + filename + "?key=" + fakeAPIKey(), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			target := "ws://" + backendAddr + tc.path
			conn, err := wsTestDial(ctx, ws.Dialer{}, "ws://"+proxyAddr+"/ws?url="+url.QueryEscape(target))
			if !tc.allowed {
				if conn != nil {
					_ = conn.Close()
				}
				if err == nil || !strings.Contains(err.Error(), "403") {
					t.Fatalf("wanted denied handshake, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := wsutil.WriteClientMessage(conn, ws.OpText, []byte(testWSHello)); err != nil {
				t.Fatal(err)
			}
			reply, op, err := wsutil.ReadServerData(conn)
			if err != nil || op != ws.OpText || string(reply) != testWSHello {
				t.Fatalf("echo = %q, op = %v, err = %v", reply, op, err)
			}
		})
	}
}
