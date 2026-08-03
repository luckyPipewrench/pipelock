// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package destination_test

import (
	"context"
	"net"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/destination"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// TestRawTransportGetsAVerdictWithoutAURL is the point of the whole extraction.
//
// Before it, every destination decision was reachable only through a hostname
// recovered from an http/https URL, so a raw TCP target had to invent one. The
// URL scanner rejects any other scheme outright, which is asserted below, so
// the invented URL could never produce a verdict anyway. A destination that
// cannot be evaluated is a destination that cannot be mediated.
func TestRawTransportGetsAVerdictWithoutAURL(t *testing.T) {
	// The old workaround: fabricate a URL for a non-HTTP target. It is refused
	// at the scheme check, which is why the workaround was never viable.
	cfg := config.Defaults()
	cfg.Internal = nil // avoid DNS SSRF in a unit test; the literal floor remains
	sc, err := scanner.New(cfg)
	if err != nil {
		t.Fatalf("scanner.New: %v", err)
	}
	res := sc.Scan(context.Background(), "ssh://build.internal.example:22")
	if res.Allowed {
		t.Fatal("expected the invented ssh:// URL to be refused at the scheme check")
	}

	// The new path: name the destination directly, no URL anywhere.
	dest, err := destination.New(destination.NetworkTCP, "build.internal.example", 22)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if dest.Port != 22 {
		t.Fatalf("port = %d, want 22; the port is what makes a grant exact", dest.Port)
	}

	// And it can be evaluated: a resolved address for that destination is
	// classified by the same floor and containment passes the HTTP path uses.
	_, cidr, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}
	addrs := destination.ParseResolved([]string{"10.4.5.6"})
	if _, found := destination.FirstInternalHit(addrs, []*net.IPNet{cidr}, nil); !found {
		t.Fatal("a raw tcp destination's resolved address must be evaluable against internal CIDRs")
	}

	// The floor applies to a raw transport exactly as it does to HTTP: no
	// transport may reach a cloud-metadata endpoint.
	meta := destination.ParseResolved([]string{"169.254.169.254"})
	if _, found := destination.FirstFloorHit(meta); !found {
		t.Fatal("the non-overridable floor must apply to a raw tcp destination too")
	}
}

// TestUnknownTransportFailsClosed pins the direction for a transport this
// package does not recognize. An unnamed transport must be refused rather than
// defaulted to TCP, because a destination whose transport we cannot name is one
// we cannot claim to have mediated.
func TestUnknownTransportFailsClosed(t *testing.T) {
	if _, err := destination.New(destination.Network("sctp"), "host.example", 443); err == nil {
		t.Fatal("an unrecognized transport must be refused, not defaulted")
	}
	if _, err := destination.New(destination.NetworkTCP, "host.example", 0); err == nil {
		t.Fatal("port 0 must be refused: it is the any-port wildcard, not a destination")
	}
}
