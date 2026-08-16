// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobwas/ws"
	gobwasutil "github.com/gobwas/ws/wsutil"
)

func wsSessionExitServer(t *testing.T) (*httptest.Server, <-chan struct{}) {
	t.Helper()
	connected := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		close(connected)
		for {
			if _, err := gobwasutil.ReadClientMessage(conn, nil); err != nil {
				return
			}
		}
	}))
	return srv, connected
}

func TestSessionExit_WSStopsBridge(t *testing.T) {
	upstream, connected := wsSessionExitServer(t)
	defer upstream.Close()

	clientIn := newBlockingReader()
	defer func() { _ = clientIn.Close() }()
	sc := testScannerForWS(t)
	var parentDied atomic.Bool
	var clientOut, logBuf lockedHTTPBuffer
	done := make(chan error, 1)
	go func() {
		done <- RunWSProxy(context.Background(), clientIn, &clientOut, &logBuf, wsURL(upstream), MCPProxyOpts{
			Scanner: sc,
			sessionExitForTest: &sessionExitTestHooks{watch: parentWatchOpts{
				interval:  time.Millisecond,
				startPPID: 4242,
				getppid: func() int {
					if parentDied.Load() {
						return orphanedPPID
					}
					return 4242
				},
			}},
		})
	}()

	select {
	case <-connected:
	case <-time.After(5 * time.Second):
		t.Fatal("WebSocket bridge never connected to its upstream")
	}
	parentDied.Store(true)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunWSProxy after session exit = %v, want clean teardown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("WebSocket bridge stayed alive after the spawning session exited")
	}

	if !logBuf.contains("spawning session exited") {
		t.Errorf("missing session-exit explanation in operator log, got %q", logBuf.String())
	}
}

func TestSessionExit_WSLiveSessionIsNotTornDown(t *testing.T) {
	upstream, connected := wsSessionExitServer(t)
	defer upstream.Close()

	clientIn := newBlockingReader()
	sc := testScannerForWS(t)
	var clientOut, logBuf lockedHTTPBuffer
	done := make(chan error, 1)
	go func() {
		done <- RunWSProxy(context.Background(), clientIn, &clientOut, &logBuf, wsURL(upstream), MCPProxyOpts{
			Scanner:            sc,
			sessionExitForTest: liveSessionExitHooks(),
		})
	}()

	select {
	case <-connected:
	case <-time.After(5 * time.Second):
		t.Fatal("WebSocket bridge never connected to its upstream")
	}
	select {
	case err := <-done:
		t.Fatalf("RunWSProxy exited while its session was alive: %v; log: %q", err, logBuf.String())
	case <-time.After(250 * time.Millisecond):
	}

	if logBuf.contains("spawning session exited") {
		t.Errorf("session-exit path ran against a live parent, got %q", logBuf.String())
	}

	_ = clientIn.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunWSProxy after input close = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("WebSocket bridge did not stop after its input closed")
	}
}
