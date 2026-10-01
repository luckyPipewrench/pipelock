// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package dialfallback connects to the first reachable address of a host whose
// addresses were already validated, within a fixed number of attempts.
package dialfallback

import (
	"context"
	"errors"
	"net"
)

// MaxAttempts is how many addresses are tried before the dial gives up. A host
// commonly resolves to an IPv6 and an IPv4 address; three covers that pair plus
// one spare. Without a bound, a name with N unreachable records holds the
// caller for N dial timeouts, and the name's owner chooses N. Addresses past
// the bound are not tried at all, so a host whose only reachable record is
// beyond it fails: that is the cost of a bound, and the resolver order is the
// order of preference.
const MaxAttempts = 3

// Dial tries addrs in order and returns the first connection that dial
// establishes. It stops after MaxAttempts attempts and as soon as ctx is done,
// whether or not dial itself honours ctx, so a dial function that ignores its
// context cannot be called again after the deadline. The error is that of the
// last attempt, or the context's error when no attempt was made. Every path
// out of the loop has set it, because addrs is not empty and MaxAttempts is
// positive.
func Dial(ctx context.Context, addrs []string, dial func(ctx context.Context, addr string) (net.Conn, error)) (net.Conn, error) {
	if len(addrs) == 0 {
		return nil, errors.New("no addresses to dial")
	}
	var lastErr error
	for i, addr := range addrs {
		if i >= MaxAttempts {
			break
		}
		if err := ctx.Err(); err != nil {
			if lastErr == nil {
				lastErr = err
			}
			break
		}
		conn, err := dial(ctx, addr)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}
