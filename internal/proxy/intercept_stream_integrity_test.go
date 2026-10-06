// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/httpstream"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// Exercise the actual TLS server inside a hijacked CONNECT connection. Its
// net/http handler must turn the abort panic into a TLS close or an h2 reset.
func TestInterceptTunnelStreamIntegrity(t *testing.T) {
	for _, proto := range []int{1, 2} {
		for _, ending := range []string{"chunked_break", "short_length", "cancel", "complete"} {
			t.Run(fmt.Sprintf("h%d/%s", proto, ending), func(t *testing.T) {
				payload := strings.Repeat("intercepted integrity bytes\n", 512)
				release := make(chan struct{})
				var releaseOnce sync.Once
				releaseUpstream := func() { releaseOnce.Do(func() { close(release) }) }
				upstreamDone := make(chan struct{})
				upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer close(upstreamDone)
					w.Header().Set("Content-Type", "text/plain")
					if ending == "short_length" {
						w.Header().Set("Content-Length", strconv.Itoa(len(payload)+256))
					}
					_, _ = io.WriteString(w, payload)
					w.(http.Flusher).Flush()
					select {
					case <-release:
					case <-r.Context().Done():
						return
					}
					if ending == "chunked_break" {
						panic(http.ErrAbortHandler)
					}
				}))
				t.Cleanup(func() { releaseUpstream(); upstream.Close() })
				cache, pool, cfg, _, logger, m := testInterceptSetup(t)
				cfg.FlightRecorder.RequireReceipts = true
				integrityExempt(cfg)
				sc := scanner.MustNew(cfg)
				t.Cleanup(sc.Close)
				rph := newReceiptProxyHelper(t)
				p, err := New(cfg, logger, sc, m, WithReceiptEmitter(rph.emitter))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(p.Close)
				u, err := url.Parse(upstream.URL)
				if err != nil {
					t.Fatal(err)
				}
				clientConn, proxyConn := net.Pipe()
				t.Cleanup(func() { _ = clientConn.Close(); _ = proxyConn.Close() })
				tunnelDone := make(chan error, 1)
				go func() {
					tunnelDone <- interceptTunnel(t.Context(), proxyConn, &InterceptContext{
						TargetHost: u.Hostname(), TargetPort: u.Port(), Config: cfg, Scanner: sc,
						CertCache: cache, Logger: logger, Metrics: m, Proxy: p,
						UpstreamRT: upstream.Client().Transport, RequestID: "integrity-tunnel",
					})
				}()
				tr := &http.Transport{
					TLSClientConfig:   &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
					ForceAttemptHTTP2: proto == 2,
					DialContext: func(context.Context, string, string) (net.Conn, error) {
						return clientConn, nil
					},
				}
				t.Cleanup(tr.CloseIdleConnections)
				client := &http.Client{Transport: tr}
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, upstream.URL+"/payload", nil)
				if err != nil {
					t.Fatal(err)
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = resp.Body.Close() }()
				if resp.ProtoMajor != proto || resp.StatusCode != http.StatusOK {
					t.Fatalf("response=%s/%d", resp.Proto, resp.StatusCode)
				}
				first := make([]byte, 1)
				if _, err := io.ReadFull(resp.Body, first); err != nil {
					t.Fatal(err)
				}
				if ending == "cancel" {
					cancel()
				} else {
					releaseUpstream()
				}
				body, readErr := io.ReadAll(resp.Body)
				if ending == "complete" {
					if readErr != nil || string(first)+string(body) != payload {
						t.Fatalf("complete response bytes=%d err=%v", len(body)+1, readErr)
					}
				} else if readErr == nil {
					t.Fatal("intercepted truncated response ended cleanly")
				}
				tr.CloseIdleConnections()
				_ = clientConn.Close()
				select {
				case err := <-tunnelDone:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("intercept tunnel did not end")
				}
				integrityWait(t, upstreamDone)
				wantReason := httpstream.Incomplete
				if ending == "cancel" {
					wantReason = httpstream.Cancelled
				}
				found := ending == "complete"
				for _, rec := range rph.findReceipts(t) {
					if rec.ActionRecord.Layer == "outcome" && strings.Contains(rec.ActionRecord.Pattern, "reason="+wantReason) {
						found = true
					}
				}
				if !found {
					t.Fatalf("no %s receipt from intercepted stream", wantReason)
				}
			})
		}
	}
}
