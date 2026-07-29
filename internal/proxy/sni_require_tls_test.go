// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestSNIRequireTLS_ProductionConnectPath(t *testing.T) {
	tests := []struct {
		name       string
		requireTLS *bool
		payload    []byte
		wantEcho   bool
	}{
		{name: "enabled blocks non TLS", requireTLS: ptrBool(true), payload: []byte("opaque secret bytes")},
		{name: "enabled blocks ClientHello without SNI", requireTLS: ptrBool(true), payload: buildClientHelloNoExtensions()},
		{name: "explicit opt out permits non TLS", requireTLS: ptrBool(false), payload: []byte("legacy protocol"), wantEcho: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			echoLn := listenEcho(t)
			defer func() { _ = echoLn.Close() }()
			proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
				cfg.ForwardProxy.SNIRequireTLS = tc.requireTLS
			})
			defer cleanup()

			conn := dialProxy(t, proxyAddr)
			defer func() { _ = conn.Close() }()
			target := echoLn.Addr().String()
			_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
			reader := bufio.NewReader(conn)
			resp, err := http.ReadResponse(reader, nil)
			if err != nil {
				t.Fatalf("read CONNECT response: %v", err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
			}
			if _, err := conn.Write(tc.payload); err != nil {
				t.Fatalf("write tunnel payload: %v", err)
			}
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			got := make([]byte, len(tc.payload))
			n, err := io.ReadFull(reader, got)
			if tc.wantEcho {
				if err != nil || string(got) != string(tc.payload) {
					t.Fatalf("opt-out tunnel echo = %q, err=%v", got, err)
				}
				return
			}
			if err == nil || n > 0 {
				t.Fatalf("opaque tunnel leaked %d byte(s) upstream; want zero-byte fail-closed connection", n)
			}
		})
	}
}

// TestSNIRequireTLS_DoesNotClaimPayloadVisibility pins the honest boundary:
// matching SNI authenticates the tunnel destination name, but the tunnel is
// still opaque unless TLS interception is active. The bytes after ClientHello
// are relayed without DLP inspection. This hardening must never be advertised
// as closing CONNECT body blindness.
func TestSNIRequireTLS_DoesNotClaimPayloadVisibility(t *testing.T) {
	echoLn := listenEcho(t)
	defer func() { _ = echoLn.Close() }()
	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.ForwardProxy.SNIRequireTLS = ptrBool(true)
	})
	defer cleanup()

	conn := dialProxy(t, proxyAddr)
	defer func() { _ = conn.Close() }()
	target := echoLn.Addr().String()
	_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	_ = resp.Body.Close()
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("split target: %v", err)
	}
	payload := append(buildClientHello(host), []byte("synthetic-secret-after-matching-sni")...)
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write opaque tunnel: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatalf("read opaque tunnel echo: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatal("opaque tunnel bytes did not round-trip")
	}
}

// TestForwardProxy_SNIRequireTLSEnabled covers the config accessor defaults:
// nil (unset) must default to false for backward compatibility; explicit
// true/false must round-trip.
func TestForwardProxy_SNIRequireTLSEnabled(t *testing.T) {
	if (config.ForwardProxy{}).SNIRequireTLSEnabled() {
		t.Error("unset SNIRequireTLS must default to false")
	}
	if !(config.ForwardProxy{SNIRequireTLS: ptrBool(true)}).SNIRequireTLSEnabled() {
		t.Error("SNIRequireTLS=true must return true")
	}
	if (config.ForwardProxy{SNIRequireTLS: ptrBool(false)}).SNIRequireTLSEnabled() {
		t.Error("SNIRequireTLS=false must return false")
	}
}

func TestSNIRequireTLS_HotReloadLifecycle(t *testing.T) {
	echoLn := listenEcho(t)
	defer func() { _ = echoLn.Close() }()
	proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
		cfg.ForwardProxy.SNIRequireTLS = ptrBool(false)
	})
	defer cleanup()

	assertOpaque := func(wantEcho bool) {
		t.Helper()
		conn := dialProxy(t, proxyAddr)
		defer func() { _ = conn.Close() }()
		target := echoLn.Addr().String()
		_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatalf("read CONNECT response: %v", err)
		}
		_ = resp.Body.Close()
		payload := []byte("opaque reload probe")
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("write tunnel payload: %v", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		got := make([]byte, len(payload))
		n, err := io.ReadFull(reader, got)
		if wantEcho {
			if err != nil || string(got) != string(payload) {
				t.Fatalf("legacy tunnel echo = %q, err=%v", got, err)
			}
			return
		}
		if err == nil || n > 0 {
			t.Fatalf("opaque tunnel leaked %d byte(s) after fail-closed reload", n)
		}
	}

	reload := func(requireTLS bool, unrelatedMode string) {
		t.Helper()
		cfg := config.Defaults()
		cfg.Internal = nil
		cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
		cfg.APIAllowlist = nil
		cfg.ForwardProxy.Enabled = true
		cfg.ForwardProxy.MaxTunnelSeconds = 10
		cfg.ForwardProxy.IdleTimeoutSeconds = 2
		cfg.FetchProxy.TimeoutSeconds = 5
		cfg.ForwardProxy.SNIRequireTLS = ptrBool(requireTLS)
		if unrelatedMode != "" {
			cfg.Mode = unrelatedMode
		}
		cfg.ApplyDefaults()
		cfg.Internal = nil
		if !p.Reload(cfg, scanner.MustNew(cfg)) {
			t.Fatal("Reload returned false")
		}
	}

	assertOpaque(true)
	reload(true, "")
	assertOpaque(false)
	reload(true, "")
	assertOpaque(false)
	reload(true, config.ModeStrict)
	assertOpaque(false)
	reload(false, "")
	assertOpaque(true)
	reload(false, config.ModeStrict)
	assertOpaque(true)
	reload(true, "")
	assertOpaque(false)
}
