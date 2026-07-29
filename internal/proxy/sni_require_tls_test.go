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
)

func TestSNIRequireTLS_ProductionConnectPath(t *testing.T) {
	tests := []struct {
		name       string
		requireTLS *bool
		payload    []byte
		wantEcho   bool
	}{
		{name: "enabled blocks non TLS", requireTLS: boolPointer(true), payload: []byte("opaque secret bytes")},
		{name: "enabled blocks ClientHello without SNI", requireTLS: boolPointer(true), payload: buildClientHelloNoExtensions()},
		{name: "explicit opt out permits non TLS", requireTLS: boolPointer(false), payload: []byte("legacy protocol"), wantEcho: true},
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
			_, err = io.ReadFull(reader, got)
			if tc.wantEcho {
				if err != nil || string(got) != string(tc.payload) {
					t.Fatalf("opt-out tunnel echo = %q, err=%v", got, err)
				}
				return
			}
			if err == nil {
				t.Fatal("opaque tunnel payload reached upstream; want fail-closed connection")
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
		cfg.ForwardProxy.SNIRequireTLS = boolPointer(true)
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
	boolPtr := func(b bool) *bool { return &b }

	if (config.ForwardProxy{}).SNIRequireTLSEnabled() {
		t.Error("unset SNIRequireTLS must default to false")
	}
	if !(config.ForwardProxy{SNIRequireTLS: boolPtr(true)}).SNIRequireTLSEnabled() {
		t.Error("SNIRequireTLS=true must return true")
	}
	if (config.ForwardProxy{SNIRequireTLS: boolPtr(false)}).SNIRequireTLSEnabled() {
		t.Error("SNIRequireTLS=false must return false")
	}
}

func boolPointer(v bool) *bool { return &v }
