// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/httpstream"
)

func TestWebSocketStreamIntegrity(t *testing.T) {
	for _, ending := range []string{"header_break", "payload_break", "fragment_break", "cancel", "complete"} {
		t.Run(ending, func(t *testing.T) {
			release := make(chan struct{})
			var releaseOnce sync.Once
			releaseUpstream := func() { releaseOnce.Do(func() { close(release) }) }
			upstreamDone := make(chan struct{})
			upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(upstreamDone)
				conn, _, _, err := ws.UpgradeHTTP(r, w)
				if err != nil {
					return
				}
				defer func() { _ = conn.Close() }()
				_ = wsutil.WriteServerMessage(conn, ws.OpText, []byte("integrity-token"))
				if ending == "cancel" {
					_, _, _ = wsutil.ReadClientData(conn)
					return
				}
				<-release
				switch ending {
				case "header_break":
					_, _ = conn.Write([]byte{0x81})
				case "payload_break":
					_ = ws.WriteHeader(conn, ws.Header{Fin: true, OpCode: ws.OpText, Length: 32})
					_, _ = io.WriteString(conn, "partial")
				case "fragment_break":
					_ = ws.WriteHeader(conn, ws.Header{Fin: false, OpCode: ws.OpText, Length: 7})
					_, _ = io.WriteString(conn, "partial")
				case "complete":
					_ = wsutil.WriteServerMessage(conn, ws.OpClose, ws.NewCloseFrameBody(ws.StatusNormalClosure, "complete"))
				}
			}))
			t.Cleanup(func() { releaseUpstream(); upstream.Close() })
			auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
			logger, err := audit.New("json", "file", auditPath, false, false)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(logger.Close)
			handlerDone := make(chan struct{})
			proxyAddr, p, stop := setupWSProxyWithLogger(t, logger, func(cfg *config.Config) {
				cfg.FlightRecorder.RequireReceipts = true
			}, nil, func() { close(handlerDone) })
			t.Cleanup(stop)
			rph := newReceiptProxyHelper(t)
			p.receiptEmitterPtr.Store(rph.emitter)
			backendAddr := strings.TrimPrefix(upstream.URL, "http://")
			conn := dialWS(t, proxyAddr, backendAddr)
			t.Cleanup(func() { _ = conn.Close() })
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			msg, _, err := wsutil.ReadServerData(conn)
			if err != nil || string(msg) != "integrity-token" {
				t.Fatalf("first message=%s err=%v", msg, err)
			}
			if ending == "cancel" {
				_ = conn.Close()
			} else {
				releaseUpstream()
				_, _, err = wsutil.ReadServerData(conn)
				var closeErr wsutil.ClosedError
				gotClose := errors.As(err, &closeErr)
				if ending == "complete" {
					if !gotClose || closeErr.Code != ws.StatusNormalClosure {
						t.Fatalf("stream ending=%s read error=%v", ending, err)
					}
				} else if err == nil || gotClose {
					// A truncated stream must be aborted, never closed with a
					// WebSocket close handshake of any code.
					t.Fatalf("stream ending=%s read error=%v", ending, err)
				}
				_ = conn.Close()
			}
			integrityWait(t, handlerDone)
			integrityWait(t, upstreamDone)
			wantIncomplete := ending != "cancel" && ending != "complete"
			wantReason := "reason=" + receiptReasonIncomplete
			switch ending {
			case "complete":
				wantReason = "reason=complete"
			case "cancel":
				wantReason = "reason=" + httpstream.Cancelled
			}
			foundOutcome := false
			for _, rec := range rph.findReceipts(t) {
				if rec.ActionRecord.Layer == "outcome" {
					foundOutcome = true
					if !strings.Contains(rec.ActionRecord.Pattern, wantReason) {
						t.Fatalf("ending=%s outcome=%s, want %s", ending, rec.ActionRecord.Pattern, wantReason)
					}
				}
			}
			if !foundOutcome {
				t.Fatal("no WebSocket outcome receipt")
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

// An idle connection reaching its read deadline is closed by the proxy. That
// is not an upstream stream that broke off, so it keeps its Going Away frame.
func TestWebSocketIdleUpstreamIsNotIncomplete(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	p := newTestProxyWithConfig(t, cfg)
	upstreamConn, upstreamPeer := net.Pipe()
	clientConn, clientPeer := net.Pipe()
	t.Cleanup(func() {
		for _, c := range []net.Conn{upstreamConn, upstreamPeer, clientConn, clientPeer} {
			_ = c.Close()
		}
	})
	relay := &wsRelay{
		proxy: p, cfg: cfg, upstreamConn: upstreamConn, clientConn: clientConn,
		maxMsg: 1024, targetURL: "ws://api.vendor.example/socket", agent: agentAnonymous,
	}
	// The shared activity clock has been idle far longer than the timeout, so
	// the first upstream read wakes on an already expired deadline.
	relay.clockStart = time.Now().Add(-time.Hour)

	frameRead := make(chan ws.Frame, 1)
	go func() {
		_ = clientPeer.SetReadDeadline(time.Now().Add(5 * time.Second))
		frame, err := ws.ReadFrame(clientPeer)
		if err != nil {
			close(frameRead)
			return
		}
		frameRead <- frame
	}()

	relay.upstreamToClient(t.Context(), func() {}, 50*time.Millisecond)
	if relay.upstreamIncomplete {
		t.Fatal("idle timeout recorded as an incomplete upstream stream")
	}
	frame, ok := <-frameRead
	if !ok || frame.Header.OpCode != ws.OpClose {
		t.Fatalf("client did not receive a close frame: ok=%v frame=%+v", ok, frame.Header)
	}
	if code, _ := ws.ParseCloseFrameData(frame.Payload); code != ws.StatusGoingAway {
		t.Fatalf("close code = %d, want %d", code, ws.StatusGoingAway)
	}
}
