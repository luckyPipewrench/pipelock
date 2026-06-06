// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package testport provides TOCTOU-tolerant TCP port selection for tests that
// must hand a concrete listen address to a server they then start.
//
// Servers like `pipelock run` bind from an address string rather than an
// inherited listener fd, so a test cannot pass an already-open listener; it
// must pick a free port, close it, and let the server re-bind it. That
// close-then-rebind window is an unavoidable TOCTOU: another process — or a
// sibling test under `go test -count=N` or parallel packages — can grab the
// port in between. WithRetry tolerates that by re-running the attempt with a
// fresh port whenever the server reports the address is already in use.
//
// For listeners the test never dials, prefer "127.0.0.1:0" directly: the
// server binds an ephemeral port itself and there is no window to lose.
package testport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"testing"
)

// maxAttempts bounds the retry loop. A genuine collision is rare and clears
// within one retry; a persistent bind failure (e.g. the ephemeral range
// exhausted) should surface quickly rather than spin, so the ceiling stays low.
const maxAttempts = 5

// ListenAddrs returns count distinct free loopback TCP addresses. All listeners
// are opened simultaneously so the returned addresses are guaranteed distinct
// from each other, then closed before returning so the caller can rebind them.
func ListenAddrs(t testing.TB, count int) []string {
	t.Helper()
	if count < 0 {
		t.Fatalf("listen address count must be non-negative, got %d", count)
	}

	lc := net.ListenConfig{}
	listeners := make([]net.Listener, 0, count)
	defer func() {
		for _, ln := range listeners {
			_ = ln.Close()
		}
	}()

	addrs := make([]string, 0, count)
	for range count {
		ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		listeners = append(listeners, ln)
		addrs = append(addrs, ln.Addr().String())
	}
	return addrs
}

// IsBindCollision reports whether err is an "address already in use" bind
// failure — the only error WithRetry retries. It checks both the typed syscall
// errno and the string form, since the error is usually wrapped through several
// layers (cmd.Execute, the wait helper) before reaching the test.
func IsBindCollision(err error) bool {
	return err != nil && (errors.Is(err, syscall.EADDRINUSE) ||
		strings.Contains(err.Error(), "address already in use"))
}

// WithRetry runs fn with portCount fresh addresses, retrying up to maxAttempts
// times when fn returns a bind-collision error. Any other error fails the test
// immediately so real bugs (config errors, genuine startup timeouts) surface
// fast instead of being masked as a retryable collision. Exhausting the retries
// also fails the test.
func WithRetry(t testing.TB, portCount int, fn func(addrs []string) error) {
	t.Helper()
	if err := retry(func() []string { return ListenAddrs(t, portCount) }, fn); err != nil {
		t.Fatalf("%v", err)
	}
}

// retry holds the pure retry policy so it is unit-testable without a real
// *testing.T: testing.TB cannot be faked (it has an unexported method), so the
// loop is separated from the t.Fatalf wrapper above. addrs supplies a fresh
// address set per attempt.
func retry(addrs func() []string, fn func(addrs []string) error) error {
	var lastErr error
	for range maxAttempts {
		err := fn(addrs())
		if err == nil {
			return nil
		}
		if !IsBindCollision(err) {
			return fmt.Errorf("test run failed: %w", err)
		}
		lastErr = err
	}
	return fmt.Errorf("hit port bind collisions after %d attempts: %w", maxAttempts, lastErr)
}
