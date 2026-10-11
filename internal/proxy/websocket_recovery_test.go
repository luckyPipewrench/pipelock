// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gobwas/ws"

	"github.com/luckyPipewrench/pipelock/internal/config"
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
			_, _, _, blocked := pump(ctx, cancel, time.Second)
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
		{"panic", wsRelayStats{panicked: true, blocked: true, incomplete: true}, ws.StatusPolicyViolation, "relay_panic"},
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
	client, clientPeer := net.Pipe()
	upstream, upstreamPeer := net.Pipe()
	defer func() { _ = clientPeer.Close() }()
	defer func() { _ = upstreamPeer.Close() }()
	cfg := config.Defaults()
	cfg.FlightRecorder.RequireReceipts = true
	// Both pumps panic before reading because their runtime is absent.
	relay := &wsRelay{clientConn: client, upstreamConn: upstream, cfg: cfg}
	stats := relay.run(t.Context())
	if !stats.blocked || !stats.panicked {
		t.Fatal("panic state not retained")
	}
	code, reason := stats.closeOutcome()
	rph := newReceiptProxyHelper(t)
	p := &Proxy{}
	p.receiptEmitterPtr.Store(rph.emitter)
	p.emitOutcomeReceipt(cfg, receipt.EmitOpts{ActionID: receipt.NewActionID(), Transport: TransportWS, Method: "WS", Target: "ws://api.vendor.example/"}, strconv.Itoa(int(code)), 0, reason)
	r := rph.requireReceipt(t, receiptOutcomeLayer)
	if err := receipt.VerifyWithKey(r, rph.pubHex); err != nil {
		t.Fatalf("panic receipt signature: %v", err)
	}
	if !strings.Contains(r.ActionRecord.Pattern, "reason=relay_panic") {
		t.Fatalf("panic receipt reason: %s", r.ActionRecord.Pattern)
	}
}
