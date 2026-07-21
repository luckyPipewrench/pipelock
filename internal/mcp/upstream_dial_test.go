// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestMetadataSafeDialContext_BlocksMetadataAtDialTime(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DNS.HostOverrides = map[string][]string{
		"metadata.vendor.example": {"169.254.169.254"},
		"mapped.vendor.example":   {"::ffff:169.254.169.254"},
	}
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	dial := NewMetadataSafeDialContext(func() *scanner.Scanner { return sc })

	tests := []struct {
		name string
		addr string
	}{
		{name: "literal IPv4 metadata", addr: "169.254.169.254:80"},
		{name: "DNS metadata", addr: "metadata.vendor.example:80"},
		{name: "IPv4-mapped DNS metadata", addr: "mapped.vendor.example:80"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := dial(context.Background(), "tcp", tt.addr)
			if err == nil {
				t.Fatal("expected metadata dial to fail closed")
			}
			if !strings.Contains(err.Error(), "ssrf_metadata") {
				t.Fatalf("dial error = %v, want ssrf_metadata classification", err)
			}
		})
	}
}

func TestMetadataSafeDialContext_BlocksMetadataHostnameWithoutScanner(t *testing.T) {
	origLookup := defaultMCPDialLookupHost
	defaultMCPDialLookupHost = func(context.Context, string) ([]string, error) {
		return []string{"169.254.169.254"}, nil
	}
	t.Cleanup(func() { defaultMCPDialLookupHost = origLookup })

	dial := NewMetadataSafeDialContext(nil)
	_, err := dial(context.Background(), "tcp", "metadata.vendor.example:80")
	if err == nil {
		t.Fatal("expected metadata hostname dial to fail closed without scanner")
	}
	if !strings.Contains(err.Error(), "ssrf_metadata") {
		t.Fatalf("dial error = %v, want ssrf_metadata classification", err)
	}
}

func TestMetadataSafeDialContext_AllowsNonMetadataLoopbackUpstream(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DNS.HostOverrides = map[string][]string{
		"local.vendor.example": {"127.0.0.1"},
	}
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split listener addr: %v", err)
	}
	dial := NewMetadataSafeDialContext(func() *scanner.Scanner { return sc })

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := dial(ctx, "tcp", net.JoinHostPort("local.vendor.example", port))
	if err != nil {
		t.Fatalf("loopback MCP upstream should remain allowed: %v", err)
	}
	_ = conn.Close()
	select {
	case acceptedConn := <-accepted:
		_ = acceptedConn.Close()
	case <-ctx.Done():
		t.Fatal("listener did not receive loopback dial")
	}
}

func TestMetadataSafeDialContext_AllowsNonMetadataPrivateUpstream(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DNS.HostOverrides = map[string][]string{
		"private.vendor.example": {"10.0.0.8"},
	}
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)

	var dialedAddr string
	dial := newMetadataSafeDialContext(func() *scanner.Scanner { return sc }, func(_ context.Context, _ string, addr string) (net.Conn, error) {
		dialedAddr = addr
		client, server := net.Pipe()
		_ = server.Close()
		return client, nil
	})

	conn, err := dial(context.Background(), "tcp", "private.vendor.example:443")
	if err != nil {
		t.Fatalf("private non-metadata MCP upstream should remain allowed: %v", err)
	}
	_ = conn.Close()
	if dialedAddr != "10.0.0.8:443" {
		t.Fatalf("dialed addr = %q, want %q", dialedAddr, "10.0.0.8:443")
	}
}
