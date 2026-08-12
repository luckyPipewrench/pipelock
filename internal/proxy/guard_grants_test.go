// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/destination"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestGuardDestinationGrantRequiresExactPortAndScanSnapshot(t *testing.T) {
	t.Parallel()

	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()
	port := listener.Addr().(*net.TCPAddr).Port
	portText := strconv.Itoa(port)

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DNS.HostOverrides = map[string][]string{"guard.internal.example": {"127.0.0.1"}}
	grantPort, err := destination.ParsePort(portText)
	if err != nil {
		t.Fatalf("ParsePort: %v", err)
	}
	grant, err := destination.NewGrant(destination.NetworkTCP, "guard.internal.example", grantPort)
	if err != nil {
		t.Fatalf("NewGrant: %v", err)
	}
	grants, err := destination.NewGrantSet(grant)
	if err != nil {
		t.Fatalf("NewGrantSet: %v", err)
	}
	sc, err := scanner.NewWithOptions(cfg, scanner.Options{DestinationGrants: grants})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	defer sc.Close()
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	scanResult := sc.Scan(context.Background(), "http://guard.internal.example:"+portText+"/")
	if !scanResult.Allowed {
		t.Fatalf("guard-granted scan blocked: %+v", scanResult)
	}
	ctx := withAllowedSSRFDialScanSnapshot(context.Background(), sc, "guard.internal.example", portText, scanResult)
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	conn, err := p.ssrfSafeDialContext(ctx, "tcp", net.JoinHostPort("guard.internal.example", portText))
	if err != nil {
		t.Fatalf("exact grant dial: %v", err)
	}
	_ = conn.Close()

	wrongPort := port + 1
	if wrongPort > 65535 {
		wrongPort = port - 1
	}
	_, err = p.ssrfSafeDialContext(ctx, "tcp", net.JoinHostPort("guard.internal.example", strconv.Itoa(wrongPort)))
	if err == nil {
		t.Fatal("guard grant authorized a sibling port")
	}
	var blocked *ssrfDialBlockError
	if !errors.As(err, &blocked) || blocked.reason != blockreason.SSRFPrivateIP {
		t.Fatalf("wrong-port error = %T %v, want private-IP refusal", err, err)
	}

	rebindCtx := withSSRFDialScanSnapshot(context.Background(), "guard.internal.example", portText, []string{"203.0.113.10"})
	rebindCtx, rebindCancel := context.WithTimeout(rebindCtx, 2*time.Second)
	defer rebindCancel()
	_, err = p.ssrfSafeDialContext(rebindCtx, "tcp", net.JoinHostPort("guard.internal.example", portText))
	if !errors.As(err, &blocked) || blocked.reason != blockreason.SSRFDNSRebind {
		t.Fatalf("rebind error = %T %v, want DNS-rebind refusal", err, err)
	}
}

func TestGuardSSRFDialSnapshotContainsExactPort(t *testing.T) {
	ip := net.ParseIP("203.0.113.10")
	var absentContext context.Context
	if ssrfDialSnapshotContains(absentContext, "api.vendor.example", ip) {
		t.Fatal("nil context matched a dial snapshot")
	}
	ctx := withSSRFDialScanSnapshot(context.Background(), "api.vendor.example", "443", []string{ip.String()})
	if ssrfDialSnapshotContains(ctx, "other.vendor.example", ip) {
		t.Fatal("different host matched a dial snapshot")
	}
	if ssrfDialSnapshotContains(ctx, "api.vendor.example", ip) {
		t.Fatal("snapshot without a dial port matched")
	}
	ctx = withSSRFDialPort(ctx, "443")
	if !ssrfDialSnapshotContains(ctx, "API.VENDOR.EXAMPLE.", ip) {
		t.Fatal("exact host, port, and IP did not match")
	}
	if ssrfDialSnapshotContains(ctx, "api.vendor.example", net.IP{}) {
		t.Fatal("malformed IP matched a dial snapshot")
	}
}
