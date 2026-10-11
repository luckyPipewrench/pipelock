// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
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
			if !blocked || ctx.Err() == nil {
				t.Fatal("panic did not fail closed")
			}
			for _, peer := range []net.Conn{clientPeer, upstreamPeer} {
				if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil && !errors.Is(err, io.ErrClosedPipe) {
					t.Fatal(err)
				}
				var b [1]byte
				if _, err := peer.Read(b[:]); err == nil {
					t.Fatal("peer remained open")
				}
			}
		})
	}
}
