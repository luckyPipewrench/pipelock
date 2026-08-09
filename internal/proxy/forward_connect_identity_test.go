// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	contractruntime "github.com/luckyPipewrench/pipelock/internal/contract/runtime"
	"github.com/luckyPipewrench/pipelock/internal/contract/runtime/contractruntimetest"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

var errConnectIdentityDialStopped = errors.New("connect identity test stopped dial")

// installConnectDialRecorder records the exact address handed to the kernel's
// TCP dial path, then stops before a network connection can be made. That
// keeps these handler tests deterministic while proving that the dial call was
// reached with the target we assert.
func installConnectDialRecorder(t *testing.T, p *Proxy) (*atomic.Int32, <-chan string) {
	t.Helper()
	if p.dialer == nil {
		t.Fatal("proxy dialer is nil")
	}

	var calls atomic.Int32
	targets := make(chan string, 1)
	p.dialer.ControlContext = func(_ context.Context, _ string, address string, _ syscall.RawConn) error {
		calls.Add(1)
		select {
		case targets <- address:
		default:
			t.Errorf("unexpected additional CONNECT dial to %q", address)
		}
		return errConnectIdentityDialStopped
	}
	return &calls, targets
}

// setupConnectIdentityProxy builds every request-observed dependency before
// the HTTP server starts. In particular, the capture observer, receipt
// emitter, contract loader, and net.Dialer hook must not be swapped while a
// handler can read them; the race detector would rightfully flag that as test
// harness data-race rather than exercising CONNECT behavior.
func setupConnectIdentityProxy(t *testing.T, cfgMod func(*config.Config), opts ...Option) (string, *atomic.Int32, <-chan string, func()) {
	t.Helper()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.APIAllowlist = nil
	cfg.ForwardProxy.Enabled = true
	cfg.ForwardProxy.MaxTunnelSeconds = 10
	cfg.ForwardProxy.IdleTimeoutSeconds = 2
	cfg.FetchProxy.TimeoutSeconds = 5
	if cfgMod != nil {
		cfgMod(cfg)
	}

	// Preserve the test's disabled DNS-based SSRF configuration while applying
	// defaults needed by conditionally enabled features.
	savedInternal := cfg.Internal
	cfg.ApplyDefaults()
	cfg.Internal = savedInternal

	sc := scanner.MustNew(cfg)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New(), opts...)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	dialCalls, dialTargets := installConnectDialRecorder(t, p)

	lc := net.ListenConfig{}
	ln, err := lc.Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		p.Close()
		t.Fatalf("listen proxy: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)
	mux.HandleFunc("/health", p.handleHealth)
	srv := &http.Server{
		Handler:           p.buildHandler(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()

	return ln.Addr().String(), dialCalls, dialTargets, func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		p.Close()
	}
}

func requireIPv6Loopback(t *testing.T) {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback is unavailable: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("close IPv6 probe listener: %v", err)
	}
}

func readConnectDialTarget(t *testing.T, targets <-chan string) string {
	t.Helper()
	select {
	case target := <-targets:
		return target
	case <-time.After(2 * time.Second):
		t.Fatal("CONNECT never reached the TCP dial path")
		return "" // unreachable
	}
}

func findConnectIntentReceipt(t *testing.T, receipts []receipt.Receipt) receipt.Receipt {
	t.Helper()
	for _, got := range receipts {
		if got.ActionRecord.Transport == TransportConnect &&
			got.ActionRecord.DecisionPhase == receipt.DecisionPhaseIntent &&
			got.ActionRecord.Verdict == config.ActionAllow {
			return got
		}
	}
	t.Fatalf("no allowed CONNECT intent receipt in %d receipts", len(receipts))
	return receipt.Receipt{} // unreachable
}

// TestConnectHandler_TargetIdentityBindsScannerReceiptAndDial drives complete
// CONNECT requests. The scanner input and intent receipt retain the same
// normalized CONNECT authority. For IP literals, the outbound dial has that
// same address; for hostnames, it has the resolver-approved IP address.
// The dial hook rejects after observation, so a 502 proves the handler reached
// the TCP dial stage without creating an outbound connection.
func TestConnectHandler_TargetIdentityBindsScannerReceiptAndDial(t *testing.T) {
	tests := []struct {
		name           string
		authority      string
		wantTarget     string
		wantScannerURL string
		cfgMod         func(*config.Config)
		requireIPv6    bool
	}{
		{
			name:           "bare IPv4 defaults to 443",
			authority:      "127.0.0.1",
			wantTarget:     "127.0.0.1:443",
			wantScannerURL: "https://127.0.0.1:443/",
		},
		{
			name:           "explicit port stays exact",
			authority:      "127.0.0.1:6443",
			wantTarget:     "127.0.0.1:6443",
			wantScannerURL: "https://127.0.0.1:6443/",
		},
		{
			name:           "bare IPv6 defaults to 443",
			authority:      "[::1]",
			wantTarget:     "[::1]:443",
			wantScannerURL: "https://[::1]:443/",
			requireIPv6:    true,
		},
		{
			name:           "hostname authority survives resolver-approved dial",
			authority:      "connect-target.test:6443",
			wantTarget:     "127.0.0.1:6443",
			wantScannerURL: "https://connect-target.test:6443/",
			cfgMod: func(cfg *config.Config) {
				cfg.DNS.HostOverrides = map[string][]string{
					"connect-target.test": {"127.0.0.1"},
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.requireIPv6 {
				requireIPv6Loopback(t)
			}
			rph := newReceiptProxyHelper(t)
			obs := newCaptureMetadataObserver()
			proxyAddr, dialCalls, dialTargets, cleanup := setupConnectIdentityProxy(t, func(cfg *config.Config) {
				cfg.FlightRecorder.RequireReceipts = true
				if tc.cfgMod != nil {
					tc.cfgMod(cfg)
				}
			}, WithCaptureObserver(obs), WithReceiptEmitter(rph.emitter))
			defer cleanup()

			resp := doConnectLiveLock(t, proxyAddr, tc.authority)
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusBadGateway {
				t.Fatalf("CONNECT status = %d, want %d", resp.StatusCode, http.StatusBadGateway)
			}

			captureRecord := waitCaptureRecord(t, obs, capture.SurfaceURL, "connect_url")
			if captureRecord.Request.URL != tc.wantScannerURL {
				t.Fatalf("scanner URL = %q, want %q", captureRecord.Request.URL, tc.wantScannerURL)
			}
			if got := readConnectDialTarget(t, dialTargets); got != tc.wantTarget {
				t.Fatalf("dial target = %q, want %q", got, tc.wantTarget)
			}
			if got := dialCalls.Load(); got != 1 {
				t.Fatalf("dial calls = %d, want 1", got)
			}

			r := findConnectIntentReceipt(t, rph.findReceipts(t))
			if r.ActionRecord.Target != tc.wantScannerURL {
				t.Fatalf("receipt target = %q, want %q", r.ActionRecord.Target, tc.wantScannerURL)
			}
		})
	}
}

// TestConnectHandler_DenialsDoNotReachDial proves the two admission layers
// closest to the dial boundary remain fail-closed. The recorder would fail the
// test if either denial path reached the kernel dial call.
func TestConnectHandler_DenialsDoNotReachDial(t *testing.T) {
	t.Run("scanner block", func(t *testing.T) {
		proxyAddr, dialCalls, _, cleanup := setupConnectIdentityProxy(t, func(cfg *config.Config) {
			cfg.FetchProxy.Monitoring.Blocklist = []string{"blocked.example"}
			// The override makes the target resolvable and allowlisted. If the
			// scanner block were removed, the request would reach the dial hook;
			// this keeps the zero-dial assertion load-bearing rather than relying
			// on an unrelated DNS failure.
			cfg.DNS.HostOverrides = map[string][]string{
				"blocked.example": {"127.0.0.1"},
			}
		})
		defer cleanup()

		resp := doConnectLiveLock(t, proxyAddr, "blocked.example:6443")
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("CONNECT status = %d, want %d", resp.StatusCode, http.StatusForbidden)
		}
		if got := dialCalls.Load(); got != 0 {
			t.Fatalf("scanner-blocked CONNECT dial calls = %d, want 0", got)
		}
	})

	t.Run("contract block", func(t *testing.T) {
		allowOtherHost := contractruntimetest.HTTPEnforceRule("r-connect", "allowed.example", "/", http.MethodConnect)
		proxyAddr, dialCalls, _, cleanup := setupConnectIdentityProxy(t, nil, WithContractLoader(testContractLoader(t, contractruntime.ModeLive, allowOtherHost)))
		defer cleanup()

		resp := doConnectLiveLock(t, proxyAddr, "127.0.0.1:6443")
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("CONNECT status = %d, want %d", resp.StatusCode, http.StatusForbidden)
		}
		if got := resp.Header.Get(blockreason.HeaderReason); got != contractDefaultDenyReason {
			t.Fatalf("block reason = %q, want %q", got, contractDefaultDenyReason)
		}
		if got := dialCalls.Load(); got != 0 {
			t.Fatalf("contract-blocked CONNECT dial calls = %d, want 0", got)
		}
	})
}
