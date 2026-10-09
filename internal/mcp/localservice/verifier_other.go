// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package localservice

import (
	"context"
	"fmt"
	"net"
	"runtime"
)

// Verifier checks the owner of the server end of a loopback connection. On
// this platform it only refuses.
type Verifier struct{}

// NewVerifier returns a Verifier.
func NewVerifier() *Verifier { return &Verifier{} }

// VerifyConn always fails: owner verification needs Linux /proc.
func (v *Verifier) VerifyConn(conn net.Conn, pin Pin) (Evidence, error) {
	return v.VerifyConnContext(context.Background(), conn, pin)
}

// Observe always fails: owner discovery needs Linux /proc.
func (*Verifier) Observe(context.Context, net.Conn) (Observation, error) {
	return Observation{}, fmt.Errorf("verified local service needs Linux /proc, not %s: %w", runtime.GOOS, ErrUnsupportedPlatform)
}

// VerifyConnContext always fails: owner verification needs Linux /proc.
func (*Verifier) VerifyConnContext(context.Context, net.Conn, Pin) (Evidence, error) {
	return Evidence{}, fmt.Errorf("verified local service needs Linux /proc, not %s: %w", runtime.GOOS, ErrUnsupportedPlatform)
}
