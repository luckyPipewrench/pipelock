// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gobwas/ws"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// A missing runtime is an unexpected internal failure. Both relay directions
// must contain it, report a block, cancel their sibling and close both sockets.
func TestWSRelayContainsUnexpectedPanic(t *testing.T) {
	t.Parallel()
	for _, clientDirection := range []bool{false, true} {
		t.Run(map[bool]string{true: "client", false: "upstream"}[clientDirection], func(t *testing.T) {
			client, clientPeer := net.Pipe()
			upstream, upstreamPeer := net.Pipe()
			defer func() { _ = clientPeer.Close() }()
			defer func() { _ = upstreamPeer.Close() }()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			relay := &wsRelay{clientConn: client, upstreamConn: upstream}
			pump := relay.upstreamToClient
			if clientDirection {
				pump = relay.clientToUpstream
			}
			done := make(chan bool, 1)
			go func() {
				_, _, _, blocked := pump(ctx, cancel, time.Second)
				done <- blocked
			}()
			if err := clientPeer.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			frame, err := ws.ReadFrame(clientPeer)
			if err != nil {
				t.Fatalf("panic close frame: %v", err)
			}
			code, _ := ws.ParseCloseFrameData(frame.Payload)
			if frame.Header.OpCode != ws.OpClose || code != ws.StatusInternalServerError {
				t.Fatalf("panic wire close: opcode=%v code=%d", frame.Header.OpCode, code)
			}
			blocked := <-done
			if !blocked || ctx.Err() == nil || !relay.panicked.Load() {
				t.Fatal("panic did not fail closed")
			}
			for _, peer := range []net.Conn{clientPeer, upstreamPeer} {
				if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil && !errors.Is(err, io.ErrClosedPipe) {
					t.Fatal(err)
				}
				var b [1]byte
				if _, err := peer.Read(b[:]); !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
					t.Fatalf("want closed connection, got %v", err)
				}
			}
		})
	}
}

func TestWSRelayCloseOutcome(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		stats  wsRelayStats
		code   ws.StatusCode
		reason string
	}{
		{"complete", wsRelayStats{}, ws.StatusNormalClosure, "complete"},
		{"incomplete", wsRelayStats{incomplete: true}, ws.StatusAbnormalClosure, "incomplete"},
		{"cancelled", wsRelayStats{cancelled: true}, ws.StatusGoingAway, "stream_cancelled"},
		{"policy", wsRelayStats{blocked: true, cancelled: true}, ws.StatusPolicyViolation, "policy_blocked"},
		{"panic", wsRelayStats{panicked: true, blocked: true, incomplete: true}, ws.StatusInternalServerError, "relay_panic"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, reason := tc.stats.closeOutcome()
			if code != tc.code || reason != tc.reason {
				t.Fatalf("close outcome: %d %s", code, reason)
			}
		})
	}
}

func TestWSRelayPanicOutcomeReceipt(t *testing.T) {
	t.Parallel()
	backend, stop := wsEchoServer(t)
	defer stop()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8"}
	cfg.WebSocketProxy.Enabled = true
	cfg.FlightRecorder.RequireReceipts = true
	rph := newReceiptProxyHelper(t)
	p := newTestProxyWithConfig(t, cfg)
	p.receiptEmitterPtr.Store(rph.emitter)
	done := make(chan struct{})
	server := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		defer close(done)
		p.handleWebSocket(panicRelayHijacker{ResponseWriter: w}, req)
	}))
	defer server.Close()
	conn := dialWS(t, strings.TrimPrefix(server.URL, "http://"), backend)
	defer func() { _ = conn.Close() }()
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	frame, err := ws.ReadFrame(conn)
	if err != nil {
		t.Fatalf("panic close frame: %v", err)
	}
	code, _ := ws.ParseCloseFrameData(frame.Payload)
	if frame.Header.OpCode != ws.OpClose || code != ws.StatusInternalServerError {
		t.Fatalf("panic wire close: opcode=%v code=%d", frame.Header.OpCode, code)
	}
	integrityWait(t, done)
	r := rph.requireReceipt(t, receiptOutcomeLayer)
	if err := receipt.VerifyWithKey(r, rph.pubHex); err != nil {
		t.Fatalf("panic receipt signature: %v", err)
	}
	if !strings.Contains(r.ActionRecord.Pattern, "status=1011") || !strings.Contains(r.ActionRecord.Pattern, "reason=relay_panic") {
		t.Fatalf("panic receipt reason: %s", r.ActionRecord.Pattern)
	}
	closeReceipt := rph.requireReceipt(t, "session_close")
	if closeReceipt.ActionRecord.Pattern != "relay_panic" || closeReceipt.ActionRecord.Verdict != config.ActionBlock {
		t.Fatalf("panic close receipt: %+v", closeReceipt.ActionRecord)
	}
	if err := receipt.VerifyWithKey(closeReceipt, rph.pubHex); err != nil {
		t.Fatalf("panic close signature: %v", err)
	}
}

// The HTTP upgrade succeeds; the first relay read fails unexpectedly.
type panicRelayHijacker struct{ http.ResponseWriter }

func (w panicRelayHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, buffered, err := w.ResponseWriter.(http.Hijacker).Hijack()
	if err != nil {
		return nil, nil, err
	}
	return panicRelayConn{Conn: conn}, buffered, nil
}

type panicRelayConn struct{ net.Conn }

func (panicRelayConn) Read([]byte) (int, error) { panic("unexpected relay read failure") }

func TestWSRelayPanicCloseContainment(t *testing.T) {
	for _, panicWrite := range []bool{false, true} {
		conn := &panicCloseConn{panicWrite: panicWrite}
		closePanickedRelayConn(conn, true)
		if !conn.closed {
			t.Fatal("recovery did not close the panicking connection")
		}
	}
	closePanickedRelayConn(nil, true)
}

type panicCloseConn struct {
	discardConn
	panicWrite bool
	closed     bool
}

func (c *panicCloseConn) Write(p []byte) (int, error) {
	if c.panicWrite {
		panic("unexpected write failure")
	}
	return len(p), nil
}

func (c *panicCloseConn) Close() error {
	c.closed = true
	panic("unexpected close failure")
}

func TestWSRelayCompletionMetrics(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name               string
		stats              wsRelayStats
		revoked            bool
		blocked, completed int
	}{
		{"policy", wsRelayStats{blocked: true}, false, 1, 0},
		{"panic", wsRelayStats{blocked: true, panicked: true}, false, 0, 0},
		{"revoked", wsRelayStats{blocked: true}, true, 0, 0},
		{"normal", wsRelayStats{}, false, 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &Proxy{metrics: metrics.New()}
			p.recordWSRelayCompletion(tc.stats, tc.revoked)
			rec := httptest.NewRecorder()
			p.metrics.PrometheusHandler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
			for suffix, want := range map[string]int{"blocked": tc.blocked, "completed": tc.completed} {
				line := "pipelock_ws_connections_total{result=\"" + suffix + "\"} " + strconv.Itoa(want)
				if want == 0 {
					if strings.Contains(rec.Body.String(), strings.TrimSuffix(line, "0")+"1") {
						t.Fatalf("unexpected metric: %s", rec.Body.String())
					}
					continue
				}
				if !strings.Contains(rec.Body.String(), line) {
					t.Fatalf("metric missing %s: %s", line, rec.Body.String())
				}
			}
		})
	}
}
