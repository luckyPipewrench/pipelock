// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

func websocketBoundaryBackend(t *testing.T) (string, *atomic.Int32, *atomic.Int32, <-chan struct{}) {
	t.Helper()

	var handshakes atomic.Int32
	var delivered atomic.Int32
	done := make(chan struct{})
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handshakes.Add(1)
			conn, _, _, upgradeErr := ws.UpgradeHTTP(r, w)
			if upgradeErr != nil {
				return
			}
			defer func() {
				_ = conn.Close()
				close(done)
			}()

			if _, op, readErr := wsutil.ReadClientData(conn); readErr == nil &&
				(op == ws.OpText || op == ws.OpBinary) {
				delivered.Add(1)
			}
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	return ln.Addr().String(), &handshakes, &delivered, done
}

func assertWebSocketBoundaryClose(t *testing.T, conn net.Conn, wantCode ws.StatusCode) {
	t.Helper()

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	frame, err := ws.ReadFrame(conn)
	if err != nil {
		t.Fatalf("read close frame: %v", err)
	}
	if frame.Header.OpCode != ws.OpClose {
		t.Fatalf("opcode = %v, want close", frame.Header.OpCode)
	}
	if len(frame.Payload) < 2 {
		t.Fatalf("close payload length = %d, want at least 2", len(frame.Payload))
	}
	if got := ws.StatusCode(binary.BigEndian.Uint16(frame.Payload[:2])); got != wantCode {
		t.Fatalf("close code = %d, want %d", got, wantCode)
	}
}

func assertWebSocketBoundaryBackendReceivedNothing(
	t *testing.T,
	delivered *atomic.Int32,
	done <-chan struct{},
) {
	t.Helper()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("backend did not observe relay termination")
	}
	if got := delivered.Load(); got != 0 {
		t.Fatalf("backend received %d application messages, want 0", got)
	}
}

func TestWebSocketSecurityBoundary_MalformedUpgradeNeverDialsUpstream(t *testing.T) {
	backendAddr, handshakes, delivered, _ := websocketBoundaryBackend(t)
	proxyAddr, stopProxy := setupWSProxy(t, nil)
	defer stopProxy()

	req, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"http://"+proxyAddr+"/ws?url=ws://"+backendAddr,
		nil,
	)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	// Deliberately omit Upgrade, Connection, Sec-WebSocket-Key, and
	// Sec-WebSocket-Version. The client handshake must fail before any dial.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("send malformed upgrade: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	if got := handshakes.Load(); got != 0 {
		t.Fatalf("backend received %d handshake requests, want 0", got)
	}
	if got := delivered.Load(); got != 0 {
		t.Fatalf("backend received %d application messages, want 0", got)
	}
}

func TestWebSocketSecurityBoundary_SubprotocolDLPBlocksBeforeUpstreamHandshake(t *testing.T) {
	backendAddr, handshakes, delivered, _ := websocketBoundaryBackend(t)
	proxyAddr, stopProxy := setupWSProxy(t, nil)
	defer stopProxy()

	secret := "AKIA" + "IOSFODNN7" + testWSExample
	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp4", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := fmt.Fprintf(
		conn,
		"GET /ws?url=ws://%s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: %s\r\n\r\n",
		backendAddr,
		proxyAddr,
		secret,
	); err != nil {
		t.Fatalf("write handshake: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read DLP rejection: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if got := handshakes.Load(); got != 0 {
		t.Fatalf("backend received %d handshake requests, want 0", got)
	}
	if got := delivered.Load(); got != 0 {
		t.Fatalf("backend received %d application messages, want 0", got)
	}
}

func TestWebSocketSecurityBoundary_ClientFragmentProtocolViolationsFailClosed(t *testing.T) {
	tests := []struct {
		name string
		send func(*testing.T, net.Conn)
	}{
		{
			name: "orphan continuation",
			send: func(t *testing.T, conn net.Conn) {
				writeMaskedClientFrame(t, conn, true, ws.OpContinuation, []byte("unscanned"))
			},
		},
		{
			name: "new data frame during fragmented message",
			send: func(t *testing.T, conn net.Conn) {
				writeMaskedClientFrame(t, conn, false, ws.OpText, []byte("unfinished "))
				writeMaskedClientFrame(t, conn, true, ws.OpText, []byte("replacement"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backendAddr, handshakes, delivered, backendDone := websocketBoundaryBackend(t)
			proxyAddr, stopProxy := setupWSProxy(t, nil)
			defer stopProxy()

			conn := dialWS(t, proxyAddr, backendAddr)
			defer func() { _ = conn.Close() }()

			tt.send(t, conn)
			assertWebSocketBoundaryClose(t, conn, ws.StatusProtocolError)
			assertWebSocketBoundaryBackendReceivedNothing(t, delivered, backendDone)
			if got := handshakes.Load(); got != 1 {
				t.Fatalf("backend handshake count = %d, want 1", got)
			}
		})
	}
}
