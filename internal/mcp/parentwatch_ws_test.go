// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobwas/ws"
	gobwasutil "github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// wsSessionExitServer serves the WebSocket upstream these tests dial, and
// returns its ws:// URL plus a channel closed on the first successful upgrade.
//
// It uses a raw listener and http.Server rather than httptest.Server on
// purpose. ws.UpgradeHTTP hijacks the connection, and httptest.Server.Close
// blocks waiting for outstanding requests, so a test that leaves the
// connection open would hang on cleanup rather than fail. Closing the listener
// does not have that dependency.
func wsSessionExitServer(t *testing.T) (string, <-chan struct{}) {
	t.Helper()
	connected := make(chan struct{})
	// The handler can be entered more than once. Closing an already-closed
	// channel panics in the server goroutine, which takes down the whole test
	// binary rather than failing one test.
	var once sync.Once
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening for WebSocket upstream: %v", err)
	}
	srv := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, _, _, err := ws.UpgradeHTTP(r, w)
			if err != nil {
				return
			}
			defer func() { _ = conn.Close() }()
			once.Do(func() { close(connected) })
			for {
				if _, err := gobwasutil.ReadClientMessage(conn, nil); err != nil {
					return
				}
			}
		}),
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = ln.Close() })
	return "ws://" + ln.Addr().String(), connected
}

func TestSessionExit_WSStopsBridge(t *testing.T) {
	upstreamURL, connected := wsSessionExitServer(t)

	clientIn := newBlockingReader()
	defer func() { _ = clientIn.Close() }()
	sc := testScannerForWS(t)
	var parentDied atomic.Bool
	var clientOut, logBuf lockedHTTPBuffer
	done := make(chan error, 1)
	go func() {
		done <- RunWSProxy(context.Background(), clientIn, &clientOut, &logBuf, upstreamURL, MCPProxyOpts{
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

	// RunWSProxy returning and the operator log being written are not ordered
	// with respect to each other, so reading the buffer the instant done fires
	// races the write and fails under load. Poll for the explanation instead of
	// assuming it has already landed.
	testwait.For(t, 5*time.Second, func() bool {
		return logBuf.contains("spawning session exited")
	}, "missing session-exit explanation in operator log, got %q", logBuf.String())
}

func TestSessionExit_WSCancellationDuringDialIsClean(t *testing.T) {
	clientIn := newBlockingReader()
	defer func() { _ = clientIn.Close() }()
	sc := testScannerForWS(t)
	var parentDied atomic.Bool
	dialStarted := make(chan struct{})
	var dialOnce sync.Once
	var clientOut, logBuf lockedHTTPBuffer
	done := make(chan error, 1)
	go func() {
		done <- RunWSProxy(context.Background(), clientIn, &clientOut, &logBuf, "ws://api.vendor.example/mcp", MCPProxyOpts{
			Scanner: sc,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				dialOnce.Do(func() { close(dialStarted) })
				<-ctx.Done()
				return nil, ctx.Err()
			},
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
	case <-dialStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("WebSocket dial never started")
	}
	parentDied.Store(true)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunWSProxy after session exit during dial = %v, want clean teardown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("WebSocket dial stayed alive after the spawning session exited")
	}
	testwait.For(t, 5*time.Second, func() bool {
		return logBuf.contains("spawning session exited")
	}, "missing session-exit explanation in operator log, got %q", logBuf.String())
}

func TestSessionExit_WSAuthorityDialCancellationIsClean(t *testing.T) {
	msg := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"com.pipelock/authority":"grant"}}}` + "\n"
	var parentDied atomic.Bool
	dialStarted := make(chan struct{})
	var dialOnce sync.Once
	var clientOut, logBuf lockedHTTPBuffer
	done := make(chan error, 1)
	go func() {
		done <- RunWSProxy(context.Background(), strings.NewReader(msg), &clientOut, &logBuf, "ws://api.vendor.example/mcp", MCPProxyOpts{
			Scanner:              testScannerForWS(t),
			AuthorityVerifier:    allowAuthorityVerifier(nil),
			AuthorityActor:       "agent-a",
			AuthorityDestination: "ws://api.vendor.example/mcp",
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				dialOnce.Do(func() { close(dialStarted) })
				<-ctx.Done()
				return nil, ctx.Err()
			},
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
	case <-dialStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("authority-delayed WebSocket dial never started")
	}
	parentDied.Store(true)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunWSProxy after session exit during authority-delayed dial = %v, want clean teardown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("authority-delayed WebSocket dial stayed alive after the spawning session exited")
	}
	testwait.For(t, 5*time.Second, func() bool {
		return logBuf.contains("spawning session exited")
	}, "missing session-exit explanation in operator log, got %q", logBuf.String())
}

func TestSessionExit_WSLiveSessionIsNotTornDown(t *testing.T) {
	upstreamURL, connected := wsSessionExitServer(t)

	clientIn := newBlockingReader()
	sc := testScannerForWS(t)
	var clientOut, logBuf lockedHTTPBuffer
	done := make(chan error, 1)
	go func() {
		done <- RunWSProxy(context.Background(), clientIn, &clientOut, &logBuf, upstreamURL, MCPProxyOpts{
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
