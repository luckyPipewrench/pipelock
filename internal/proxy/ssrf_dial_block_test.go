// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"net"
	"testing"
)

func TestSSRFDialSnapshotMultiAddressIPv6Binding(t *testing.T) {
	ctx := withSSRFDialScanSnapshot(context.Background(), "REbind.test.", "443", []string{
		"203.0.113.10",
		"2001:db8::10",
	})
	ctx = withSSRFDialPort(ctx, "443")

	if isSSRFDNSRebind(ctx, "rebind.test", net.ParseIP("2001:db8::10")) {
		t.Fatal("IPv6 address returned at scan time was treated as a DNS rebind")
	}
	if !isSSRFDNSRebind(ctx, "rebind.test", net.ParseIP("fd00::1")) {
		t.Fatal("new IPv6 address after a multi-address scan did not fail as a DNS rebind")
	}
}
