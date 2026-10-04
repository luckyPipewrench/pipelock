// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// A raw CONNECT tunnel forwards framing unchanged. It never synthesizes an
// HTTP chunk terminator, and an upstream read error must close both sockets
// and survive into the tunnel outcome rather than becoming "complete".
func TestRawConnectStreamIntegrity(t *testing.T) {
	for _, ending := range []string{"chunked_break", "short_length", "cancel", "complete"} {
		t.Run(ending, func(t *testing.T) {
			ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = ln.Close() })
			release := make(chan struct{})
			var releaseOnce sync.Once
			releaseUpstream := func() { releaseOnce.Do(func() { close(release) }) }
			t.Cleanup(releaseUpstream)
			upstreamDone := make(chan struct{})
			go func() {
				defer close(upstreamDone)
				conn, acceptErr := ln.Accept()
				if acceptErr != nil {
					return
				}
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				req, readErr := http.ReadRequest(bufio.NewReader(conn))
				if readErr != nil {
					return
				}
				_ = req.Body.Close()
				if ending == "short_length" {
					_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 26\r\n\r\npartial bytes")
				} else {
					_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nd\r\npartial bytes\r\n")
				}
				if ending == "cancel" {
					_, _ = io.Copy(io.Discard, conn)
					return
				}
				<-release
				if ending == "complete" {
					_, _ = io.WriteString(conn, "0\r\n\r\n")
				} else if tcp, ok := conn.(*net.TCPConn); ok {
					_ = tcp.SetLinger(0)
				}
			}()
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.APIAllowlist = nil
			cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8"}
			cfg.ForwardProxy.Enabled = true
			cfg.FlightRecorder.RequireReceipts = true
			disableSNIVerify(cfg)
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			rph := newReceiptProxyHelper(t)
			auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
			logger, err := audit.New("json", "file", auditPath, false, false)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(logger.Close)
			p, err := New(cfg, logger, sc, metrics.New(), WithReceiptEmitter(rph.emitter))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(p.Close)
			handlerDone := make(chan struct{})
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(handlerDone)
				p.handleConnect(w, r)
			}))
			t.Cleanup(srv.Close)
			conn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", strings.TrimPrefix(srv.URL, "http://"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", ln.Addr(), ln.Addr())
			reader := bufio.NewReader(conn)
			connectResp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = connectResp.Body.Close() }()
			if connectResp.StatusCode != http.StatusOK {
				t.Fatalf("CONNECT status=%d", connectResp.StatusCode)
			}
			_, _ = fmt.Fprintf(conn, "GET /payload HTTP/1.1\r\nHost: %s\r\n\r\n", ln.Addr())
			resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			first := make([]byte, 13)
			if _, err := io.ReadFull(resp.Body, first); err != nil {
				t.Fatal(err)
			}
			if ending == "cancel" {
				_ = conn.Close()
			} else {
				releaseUpstream()
				_, readErr := io.ReadAll(resp.Body)
				if (readErr == nil) != (ending == "complete") {
					t.Fatalf("read error=%v, ending=%s", readErr, ending)
				}
				_ = conn.Close()
			}
			integrityWait(t, handlerDone)
			integrityWait(t, upstreamDone)
			wantIncomplete := ending == "chunked_break" || ending == "short_length"
			found := false
			for _, rec := range rph.findReceipts(t) {
				if rec.ActionRecord.Layer == "outcome" {
					found = true
					if got := strings.Contains(rec.ActionRecord.Pattern, "reason=incomplete"); got != wantIncomplete {
						t.Fatalf("outcome=%s", rec.ActionRecord.Pattern)
					}
				}
			}
			if !found {
				t.Fatal("no raw CONNECT outcome")
			}
			logger.Close()
			logBytes, err := os.ReadFile(filepath.Clean(auditPath))
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Contains(string(logBytes), "response stream incomplete"); got != wantIncomplete {
				t.Fatalf("incomplete audit=%v want=%v: %s", got, wantIncomplete, logBytes)
			}
		})
	}
}
