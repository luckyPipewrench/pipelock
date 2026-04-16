// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// TestWSProxy_HandshakeSigned exercises the happy-path WebSocket
// envelope signing branch: a handshake through a proxy with
// mediation_envelope.sign=true must carry valid Signature and
// Signature-Input headers by the time the dialer hits the upstream
// server. Covers the PR #403 websocket.go envelope + RFC 9421 path
// that codecov/patch flagged at 0%.
func TestWSProxy_HandshakeSigned(t *testing.T) {
	t.Parallel()

	var gotSig, gotSigInput, gotMediation string
	var handshakes int32
	lc := net.ListenConfig{}
	upLn, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = upLn.Close() })
	go func() {
		srv := &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotSig = r.Header.Get("Signature")
				gotSigInput = r.Header.Get("Signature-Input")
				gotMediation = r.Header.Get("Pipelock-Mediation")
				atomic.AddInt32(&handshakes, 1)
				conn, _, _, upgradeErr := ws.UpgradeHTTP(r, w)
				if upgradeErr != nil {
					return
				}
				defer func() { _ = conn.Close() }()
				msg, op, readErr := wsutil.ReadClientData(conn)
				if readErr != nil {
					return
				}
				_ = wsutil.WriteServerMessage(conn, op, msg)
			}),
			ReadHeaderTimeout: 5 * time.Second,
		}
		_ = srv.Serve(upLn)
	}()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.APIAllowlist = nil
	cfg.WebSocketProxy.Enabled = true
	cfg.WebSocketProxy.MaxMessageBytes = 1048576
	cfg.WebSocketProxy.MaxConcurrentConnections = 128
	cfg.WebSocketProxy.MaxConnectionSeconds = 10
	cfg.WebSocketProxy.IdleTimeoutSeconds = 5
	enableEnvelopeSigning(t, cfg, writeEnvelopeKey(t))

	sc := scanner.New(cfg)
	m := metrics.New()
	p, err := New(cfg, audit.NewNop(), sc, m)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	proxyLn, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	t.Cleanup(func() { _ = proxyLn.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/ws", p.handleWebSocket)
		srv := &http.Server{
			Handler:           p.buildHandler(mux),
			ReadHeaderTimeout: 5 * time.Second,
			BaseContext:       func(_ net.Listener) context.Context { return ctx },
		}
		_ = srv.Serve(proxyLn)
	}()

	wsURL := fmt.Sprintf("ws://%s/ws?url=ws://%s", proxyLn.Addr().String(), upLn.Addr().String())
	dialer := ws.Dialer{Extensions: nil}
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()
	conn, _, _, err := dialer.Dial(dialCtx, wsURL)
	if err != nil {
		t.Fatalf("ws dial through signing proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	if err := wsutil.WriteClientMessage(conn, ws.OpText, []byte("ping")); err != nil {
		t.Fatalf("write client frame: %v", err)
	}
	if _, _, err := wsutil.ReadServerData(conn); err != nil {
		t.Fatalf("read server echo: %v", err)
	}

	if atomic.LoadInt32(&handshakes) == 0 {
		t.Fatal("upstream never saw a handshake")
	}
	if gotSig == "" {
		t.Error("upstream handshake missing Signature header")
	}
	if gotSigInput == "" {
		t.Error("upstream handshake missing Signature-Input header")
	}
	if !strings.Contains(gotSigInput, "pipelock1") {
		t.Errorf("Signature-Input lacks pipelock1 label: %q", gotSigInput)
	}
	if gotMediation == "" {
		t.Error("upstream handshake missing Pipelock-Mediation header")
	}
}
