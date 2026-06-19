// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// wsPushServer upgrades the connection and then pushes nChunks server frames
// (one every gap) WITHOUT waiting for any client frame. It models a
// server-push stream (the WebSocket analogue of an SSE/token stream) where the
// client->upstream direction is silent for the whole response.
func wsPushServer(t *testing.T, gap time.Duration, nChunks int) (string, func()) {
	t.Helper()
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, _, _, upErr := ws.UpgradeHTTP(r, w)
			if upErr != nil {
				return
			}
			defer func() { _ = conn.Close() }()
			ticker := time.NewTicker(gap)
			defer ticker.Stop()
			for i := 0; i < nChunks; i++ {
				<-ticker.C
				if wErr := wsutil.WriteServerMessage(conn, ws.OpText, []byte("token")); wErr != nil {
					return
				}
			}
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	return ln.Addr().String(), func() { _ = srv.Close() }
}

// TestWSServerPushSurvivesSilentClient is the WebSocket parity proof for the
// shared idle clock. The upstream pushes frames well inside idle_timeout while
// the client stays silent. Pre-fix, the silent client->upstream direction
// reaped itself at idle_timeout and canceled the relay, killing an actively
// streaming socket. With the shared clock, server frames keep the whole
// connection alive.
func TestWSServerPushSurvivesSilentClient(t *testing.T) {
	const (
		idleSeconds = 1
		gap         = 300 * time.Millisecond
		nChunks     = 8
	)

	backendAddr, stopBackend := wsPushServer(t, gap, nChunks)
	defer stopBackend()

	proxyAddr, stopProxy := setupWSProxy(t, func(cfg *config.Config) {
		cfg.WebSocketProxy.IdleTimeoutSeconds = idleSeconds
		cfg.WebSocketProxy.MaxConnectionSeconds = 30
	})
	defer stopProxy()

	conn := dialWS(t, proxyAddr, backendAddr)
	defer func() { _ = conn.Close() }()

	// Client never sends a frame; it only reads the server push, which runs
	// well past idle_timeout.
	got := 0
	for got < nChunks {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, op, rErr := wsutil.ReadServerData(conn)
		if rErr != nil {
			break
		}
		if op == ws.OpText {
			got++
		}
	}

	if got < nChunks {
		t.Fatalf("ws stream killed early: received %d/%d frames; the silent client->upstream direction reaped the connection at idle_timeout", got, nChunks)
	}
}

// wsHoldServer upgrades the connection then blocks without ever sending a
// frame, modeling a fully idle WebSocket (no traffic in either direction).
func wsHoldServer(t *testing.T) (string, func()) {
	t.Helper()
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, _, _, upErr := ws.UpgradeHTTP(r, w)
			if upErr != nil {
				return
			}
			defer func() { _ = conn.Close() }()
			_, _, _ = wsutil.ReadClientData(conn) // block; never send
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	return ln.Addr().String(), func() { _ = srv.Close() }
}

// TestWSIdleReapBothSilent confirms the shared idle clock still reaps a fully
// idle WebSocket: neither side sends a frame, so the connection must be torn
// down near idle_timeout rather than held open.
func TestWSIdleReapBothSilent(t *testing.T) {
	backendAddr, stopBackend := wsHoldServer(t)
	defer stopBackend()

	proxyAddr, stopProxy := setupWSProxy(t, func(cfg *config.Config) {
		cfg.WebSocketProxy.IdleTimeoutSeconds = 1
		cfg.WebSocketProxy.MaxConnectionSeconds = 30
	})
	defer stopProxy()

	conn := dialWS(t, proxyAddr, backendAddr)
	defer func() { _ = conn.Close() }()

	// Both directions silent: the connection must be reaped near idle_timeout.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	_, _, rErr := wsutil.ReadServerData(conn)
	elapsed := time.Since(start)

	if rErr == nil {
		t.Fatal("expected idle WS connection to be reaped, got no error")
	}
	if elapsed < 500*time.Millisecond {
		t.Fatalf("WS connection closed too early after %v; expected the shared idle timeout to drive teardown", elapsed)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("WS idle reap took %v; expected near idle_timeout (1s)", elapsed)
	}
}
