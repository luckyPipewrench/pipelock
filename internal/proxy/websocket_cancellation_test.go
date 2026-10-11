// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/gobwas/ws"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// Cancel at payload completion, after the loop's initial context check.
func TestWSRelayCancellationAfterPayloadRead(t *testing.T) {
	for _, clientDirection := range []bool{false, true} {
		t.Run(map[bool]string{true: "client", false: "upstream"}[clientDirection], func(t *testing.T) {
			cfg := testScannerConfig()
			cfg.Internal = nil
			sc := scanner.MustNew(cfg)
			p, err := New(cfg, audit.NewNop(), sc, metrics.New())
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			frame := ws.NewTextFrame([]byte("plain message"))
			if clientDirection {
				frame = ws.MaskFrameInPlace(frame)
			}
			var wire bytes.Buffer
			if err := ws.WriteFrame(&wire, frame); err != nil {
				t.Fatal(err)
			}
			source := &cancelPayloadConn{reader: bytes.NewReader(wire.Bytes()), cancel: cancel}
			sink := &cancelPayloadConn{}
			relay := &wsRelay{proxy: p, scanner: sc, cfg: cfg, clientConn: sink, upstreamConn: source, maxMsg: 1024, scanText: true}
			pump := relay.upstreamToClient
			if clientDirection {
				relay.clientConn, relay.upstreamConn = source, sink
				pump = relay.clientToUpstream
			}
			n, _, _, blocked := pump(ctx, cancel, time.Second)
			if ctx.Err() == nil || blocked || relay.panicked.Load() || n != 0 || source.writes != 0 || sink.writes != 0 {
				t.Fatalf("cancelled payload was forwarded or classified as policy: bytes=%d blocked=%v panic=%v writes=%d/%d", n, blocked, relay.panicked.Load(), source.writes, sink.writes)
			}
		})
	}
}

// Response scan cancellation is teardown, not an incomplete-response finding.
func TestWSRelayCancelledResponseScan(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	relay := &wsRelay{scanner: sc, cfg: cfg, scanText: true}
	payload, blocked := relay.enforceUpstreamTextPayload(ctx, audit.NewNop(), []byte("plain response"), true)
	if blocked || payload != nil {
		t.Fatal("cancelled scan produced a policy result")
	}
}

func TestWSRelayClientCloseDoesNotForwardData(t *testing.T) {
	for _, op := range []ws.OpCode{ws.OpText, ws.OpPing} {
		t.Run(opCodeLabel(op), func(t *testing.T) {
			cfg := testScannerConfig()
			p := newTestProxyWithConfig(t, cfg)
			var wire bytes.Buffer
			if err := ws.WriteFrame(&wire, ws.NewFrame(op, true, []byte("after close"))); err != nil {
				t.Fatal(err)
			}
			source := &cancelPayloadConn{reader: bytes.NewReader(wire.Bytes()), cancel: func() {}}
			sink := &cancelPayloadConn{}
			relay := &wsRelay{proxy: p, cfg: cfg, upstreamConn: source, clientConn: sink, maxMsg: 1024}
			relay.clientClosing.Store(true)
			n, _, _, blocked := relay.upstreamToClient(t.Context(), func() {}, time.Second)
			if n != 0 || blocked || relay.panicked.Load() || !relay.upstreamCancelled || sink.writes != 0 {
				t.Fatalf("data after client close: bytes=%d blocked=%v panic=%v cancelled=%v writes=%d", n, blocked, relay.panicked.Load(), relay.upstreamCancelled, sink.writes)
			}
		})
	}
}

type cancelPayloadConn struct {
	net.Conn
	reader *bytes.Reader
	cancel context.CancelFunc
	writes int
}

func (c *cancelPayloadConn) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	if c.reader.Len() == 0 {
		c.cancel()
	}
	return n, err
}
func (c *cancelPayloadConn) Write(p []byte) (int, error)    { c.writes++; return len(p), nil }
func (*cancelPayloadConn) SetReadDeadline(time.Time) error  { return nil }
func (*cancelPayloadConn) SetWriteDeadline(time.Time) error { return nil }
func (*cancelPayloadConn) Close() error                     { return nil }
