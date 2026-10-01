// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/dialfallback"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

const dialFallbackHost = "multi.vendor.example"

// dialFallbackProxy builds a proxy whose resolver returns the given addresses
// for dialFallbackHost.
func dialFallbackProxy(t *testing.T, addrs ...string) *Proxy {
	t.Helper()
	cfg := config.Defaults()
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8"}
	cfg.DNS.HostOverrides = map[string][]string{dialFallbackHost: addrs}
	p, err := New(cfg, audit.NewNop(), scanner.MustNew(cfg), metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(p.Close)
	return p
}

// dialFallbackListener accepts connections and counts them.
func dialFallbackListener(t *testing.T) (port string, accepted *atomic.Int32) {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepted = &atomic.Int32{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = c.Close()
		}
	}()
	_, port, _ = net.SplitHostPort(ln.Addr().String())
	return port, accepted
}

// Only 127.0.0.1 has a listener; 127.0.0.2 refuses. The dial must fall through
// to the second validated address.
func TestSSRFSafeDialContext_FallsBackToNextValidatedAddress(t *testing.T) {
	port, accepted := dialFallbackListener(t)
	p := dialFallbackProxy(t, "127.0.0.2", "127.0.0.1")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := p.ssrfSafeDialContext(ctx, "tcp", net.JoinHostPort(dialFallbackHost, port))
	if err != nil {
		t.Fatalf("expected fallback to succeed, got: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if got := conn.RemoteAddr().String(); got != net.JoinHostPort("127.0.0.1", port) {
		t.Fatalf("connected to %s, want 127.0.0.1", got)
	}
	testwait.For(t, 2*time.Second, func() bool { return accepted.Load() > 0 }, "listener to accept the fallback connection")
	if accepted.Load() != 1 {
		t.Fatalf("listener accepted %d, want 1", accepted.Load())
	}
}

func TestSSRFSafeDialContext_AllAddressesUnreachableNamesHost(t *testing.T) {
	// Reserve a port, then close it so nothing listens.
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	_ = ln.Close()

	p := dialFallbackProxy(t, "127.0.0.2", "127.0.0.1")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = p.ssrfSafeDialContext(ctx, "tcp", net.JoinHostPort(dialFallbackHost, port))
	if err == nil {
		t.Fatal("expected error when every address is unreachable")
	}
	if !strings.Contains(err.Error(), dialFallbackHost) {
		t.Errorf("error should name host %q: %v", dialFallbackHost, err)
	}
}

// One blocked address poisons the whole host: nothing may be dialed, not even
// the allowed address that has a listener.
func TestSSRFSafeDialContext_MetadataAddressRefusesBeforeAnyConnect(t *testing.T) {
	port, accepted := dialFallbackListener(t)
	for _, order := range [][]string{
		{"127.0.0.1", "169.254.169.254"},
		{"169.254.169.254", "127.0.0.1"},
	} {
		p := dialFallbackProxy(t, order...)
		var attempts atomic.Int32
		p.dialer = &net.Dialer{Control: func(string, string, syscall.RawConn) error {
			attempts.Add(1)
			return nil
		}}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := p.ssrfSafeDialContext(ctx, "tcp", net.JoinHostPort(dialFallbackHost, port))
		cancel()
		if err == nil || !strings.Contains(err.Error(), "SSRF blocked") {
			t.Fatalf("order %v: expected SSRF block, got %v", order, err)
		}
		if attempts.Load() != 0 {
			t.Errorf("order %v: %d connect attempts, want 0", order, attempts.Load())
		}
	}
	// Barrier instead of a wall-clock wait: the kernel queues connections in
	// order and the accept loop is sequential, so once this probe connection is
	// counted any earlier connection to the listener has been counted too.
	probe, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		t.Fatalf("probe dial: %v", err)
	}
	_ = probe.Close()
	testwait.For(t, 2*time.Second, func() bool { return accepted.Load() > 0 }, "listener to accept the probe connection")
	if got := accepted.Load(); got != 1 {
		t.Errorf("listener saw %d connections, want 1 (the probe only)", got)
	}
}

// A name with many unreachable validated records costs a bounded number of
// attempts, tried in resolver order.
func TestSSRFSafeDialContext_AttemptsAreBounded(t *testing.T) {
	p := dialFallbackProxy(t, "127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5", "127.0.0.6", "127.0.0.1")
	port, accepted := dialFallbackListener(t)
	var tried []string
	p.dialer = &net.Dialer{Control: func(_, address string, _ syscall.RawConn) error {
		tried = append(tried, address)
		return net.ErrClosed
	}}
	_, err := p.ssrfSafeDialContext(context.Background(), "tcp", net.JoinHostPort(dialFallbackHost, port))
	if err == nil {
		t.Fatal("expected an error when every attempted address is unreachable")
	}
	if len(tried) != dialfallback.MaxAttempts {
		t.Fatalf("attempts = %d (%v), want %d", len(tried), tried, dialfallback.MaxAttempts)
	}
	if tried[0] != net.JoinHostPort("127.0.0.2", port) || tried[2] != net.JoinHostPort("127.0.0.4", port) {
		t.Errorf("addresses not tried in resolver order: %v", tried)
	}
	if accepted.Load() != 0 {
		t.Errorf("listener saw %d connections, want 0 (the reachable record is past the bound)", accepted.Load())
	}
}

// Cancelling the context during the first attempt stops further attempts. The
// explicit stop between attempts is pinned where a dial function that ignores
// its context can be supplied: internal/dialfallback.
func TestSSRFSafeDialContext_CancelStopsFurtherAttempts(t *testing.T) {
	port, accepted := dialFallbackListener(t)
	p := dialFallbackProxy(t, "127.0.0.2", "127.0.0.1")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var attempts atomic.Int32
	p.dialer = &net.Dialer{Control: func(string, string, syscall.RawConn) error {
		attempts.Add(1)
		cancel()
		return net.ErrClosed
	}}
	_, err := p.ssrfSafeDialContext(ctx, "tcp", net.JoinHostPort(dialFallbackHost, port))
	if err == nil {
		t.Fatal("expected error after cancel")
	}
	if attempts.Load() != 1 {
		t.Errorf("attempts = %d, want 1", attempts.Load())
	}
	if accepted.Load() != 0 {
		t.Errorf("listener saw %d connections, want 0", accepted.Load())
	}
	if !strings.Contains(err.Error(), dialFallbackHost) {
		t.Errorf("error should name host: %v", err)
	}
}
