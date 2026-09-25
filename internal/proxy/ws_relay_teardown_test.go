// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// When one side of a WebSocket relay leaves, the relay must end at once rather
// than wait out the idle timeout on the other side's blocked read, which held
// the upstream socket and the scanner for the whole idle window.
func TestWSRelayEndsPromptlyWhenEitherSideLeaves(t *testing.T) {
	for _, tc := range []struct {
		name        string
		closeClient bool
	}{
		{"client leaves", true},
		{"upstream leaves", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The upstream-leaves backend echoes once and then closes its own
			// hijacked connection; http.Server.Close does not close hijacked
			// connections, so closing the server would not end the relay.
			newBackend := wsEchoServer
			if !tc.closeClient {
				newBackend = wsEchoOnceServer
			}
			backendAddr, backendCleanup := newBackend(t)
			defer backendCleanup()

			done := make(chan struct{})
			var once sync.Once
			proxyAddr, _, cleanup := setupWSProxyWithHandlerDone(t, func(cfg *config.Config) {
				// Long enough that an idle-timeout exit could never land
				// inside the wait below.
				cfg.WebSocketProxy.IdleTimeoutSeconds = 60
				cfg.WebSocketProxy.MaxConnectionSeconds = 120
			}, nil, func() { once.Do(func() { close(done) }) })
			defer cleanup()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, _, _, err := ws.Dial(ctx, fmt.Sprintf("ws://%s/ws?url=ws://%s", proxyAddr, backendAddr))
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer func() { _ = conn.Close() }()
			if err := wsutil.WriteClientMessage(conn, ws.OpText, []byte(testWSHello)); err != nil {
				t.Fatalf("write: %v", err)
			}
			if reply, _, err := wsutil.ReadServerData(conn); err != nil || string(reply) != testWSHello {
				t.Fatalf("echo = %q, %v", reply, err)
			}

			if tc.closeClient {
				_ = conn.Close()
			}

			select {
			case <-done:
			case <-time.After(testwait.Deadline(5 * time.Second)):
				t.Fatal("relay did not end after one side left; it is waiting out the idle timeout")
			}
		})
	}
}

// wsEchoOnceServer echoes one message and then closes the connection, so the
// upstream is the side that leaves.
func wsEchoOnceServer(t *testing.T) (string, func()) {
	t.Helper()
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	go func() { _ = srv.Serve(ln) }()
	return ln.Addr().String(), func() { _ = srv.Close() }
}

// armReadDeadline must wake a read at once when the relay is already
// cancelled, and otherwise leave the read waiting for data.
func TestWSRelayArmReadDeadline(t *testing.T) {
	r := &wsRelay{clockStart: time.Now()}
	for _, tc := range []struct {
		name      string
		cancelled bool
	}{
		{"cancelled relay wakes the read", true},
		{"live relay waits for data", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := net.Pipe()
			defer func() { _ = a.Close() }()
			defer func() { _ = b.Close() }()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancelled {
				cancel()
			}
			r.armReadDeadline(ctx, a, time.Minute)
			if !tc.cancelled {
				go func() { _, _ = b.Write([]byte("x")) }()
			}
			type readResult struct {
				n   int
				buf []byte
				err error
			}
			done := make(chan readResult, 1)
			go func() {
				buf := make([]byte, 1)
				n, err := a.Read(buf)
				done <- readResult{n, buf, err}
			}()
			select {
			case got := <-done:
				if tc.cancelled {
					var nerr net.Error
					if !errors.As(got.err, &nerr) || !nerr.Timeout() {
						t.Fatalf("read err = %v, want a timeout", got.err)
					}
					return
				}
				if got.err != nil || got.n != 1 || string(got.buf) != "x" {
					t.Fatalf("read = %d %q %v, want 1 %q <nil>", got.n, got.buf, got.err, "x")
				}
			case <-time.After(testwait.Deadline(5 * time.Second)):
				t.Fatal("read did not return")
			}
		})
	}
}

// wakeRelayConn must interrupt a write blocked on a peer that stopped reading,
// not only a blocked read.
func TestWakeRelayConnInterruptsBlockedWrite(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	done := make(chan error, 1)
	go func() {
		// net.Pipe has no buffer, so this write blocks until b reads.
		_, err := a.Write([]byte("frame"))
		done <- err
	}()
	// Reading one byte proves the write is under way; b then stops reading,
	// so the rest of the write stays blocked until the wake.
	if _, err := b.Read(make([]byte, 1)); err != nil {
		t.Fatalf("read first byte: %v", err)
	}
	wakeRelayConn(a)
	select {
	case err := <-done:
		var nerr net.Error
		if !errors.As(err, &nerr) || !nerr.Timeout() {
			t.Fatalf("blocked write returned %v, want a timeout", err)
		}
	case <-time.After(testwait.Deadline(5 * time.Second)):
		t.Fatal("blocked write was not interrupted")
	}
}

// A client that starts a normal close must get a close reply through the
// relay, not an abrupt disconnect: ending one direction leaves the other
// relayCloseGrace to carry the upstream's reply back.
func TestWSRelayCompletesNormalCloseHandshake(t *testing.T) {
	backendAddr, backendCleanup := wsEchoServer(t)
	defer backendCleanup()
	proxyAddr, _, cleanup := setupWSProxyWithHandlerDone(t, func(cfg *config.Config) {
		cfg.WebSocketProxy.IdleTimeoutSeconds = 60
		cfg.WebSocketProxy.MaxConnectionSeconds = 120
	}, nil, nil)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, _, err := ws.Dial(ctx, fmt.Sprintf("ws://%s/ws?url=ws://%s", proxyAddr, backendAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	body := ws.NewCloseFrameBody(ws.StatusNormalClosure, "")
	if err := ws.WriteFrame(conn, ws.MaskFrame(ws.NewCloseFrame(body))); err != nil {
		t.Fatalf("write close: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(testwait.Deadline(5 * time.Second))); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	for {
		hdr, err := ws.ReadHeader(conn)
		if err != nil {
			t.Fatalf("no close reply before the connection ended: %v", err)
		}
		payload := make([]byte, hdr.Length)
		if _, err := io.ReadFull(conn, payload); err != nil {
			t.Fatalf("read frame payload: %v", err)
		}
		if hdr.OpCode != ws.OpClose {
			continue
		}
		code, _ := ws.ParseCloseFrameData(payload)
		if code != ws.StatusNormalClosure {
			t.Fatalf("close code = %d, want %d", code, ws.StatusNormalClosure)
		}
		return
	}
}
