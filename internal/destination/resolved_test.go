// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package destination

import (
	"net"
	"testing"
)

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", s, err)
	}
	return n
}

func TestParseResolved(t *testing.T) {
	tests := []struct {
		name        string
		in          []string
		wantIPs     []string
		wantDisplay []string
	}{
		{
			name:        "plain ipv4",
			in:          []string{"10.0.0.1"},
			wantIPs:     []string{"10.0.0.1"},
			wantDisplay: []string{"10.0.0.1"},
		},
		{
			// The zone index names a local interface, not a different
			// destination, and it makes net.ParseIP return nil. Dropping the
			// entry would silently skip every CIDR check for that address.
			name:        "ipv6 zone index is stripped but still displayed",
			in:          []string{"fe80::1%eth0"},
			wantIPs:     []string{"fe80::1"},
			wantDisplay: []string{"fe80::1%eth0"},
		},
		{
			// A mapped address reaches the IPv4 address it encodes, so it must
			// be checked against IPv4 CIDRs rather than sliding past them.
			name:        "ipv4-mapped ipv6 reduces to v4",
			in:          []string{"::ffff:127.0.0.1"},
			wantIPs:     []string{"127.0.0.1"},
			wantDisplay: []string{"::ffff:127.0.0.1"},
		},
		{
			name:        "undialable entries are dropped",
			in:          []string{"not-an-ip", "10.0.0.2", ""},
			wantIPs:     []string{"10.0.0.2"},
			wantDisplay: []string{"10.0.0.2"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseResolved(tc.in)
			if len(got) != len(tc.wantIPs) {
				t.Fatalf("got %d addrs, want %d (%+v)", len(got), len(tc.wantIPs), got)
			}
			for i, a := range got {
				if a.IP.String() != tc.wantIPs[i] {
					t.Errorf("addr[%d].IP = %q, want %q", i, a.IP, tc.wantIPs[i])
				}
				if a.Display != tc.wantDisplay[i] {
					t.Errorf("addr[%d].Display = %q, want %q; the operator must see "+
						"what the resolver returned, not a normalized rewrite",
						i, a.Display, tc.wantDisplay[i])
				}
			}
		})
	}
}

func TestFirstFloorHit(t *testing.T) {
	tests := []struct {
		name    string
		in      []string
		wantHit string
	}{
		{name: "public address is not a floor hit", in: []string{"93.184.216.34"}},
		{name: "loopback is not a floor hit", in: []string{"127.0.0.1"}},
		{name: "rfc1918 is not a floor hit", in: []string{"10.0.0.1"}},
		{name: "cloud metadata", in: []string{"169.254.169.254"}, wantHit: "169.254.169.254"},
		{name: "link local", in: []string{"169.254.1.1"}, wantHit: "169.254.1.1"},
		{name: "multicast", in: []string{"224.0.0.1"}, wantHit: "224.0.0.1"},
		{name: "unspecified", in: []string{"0.0.0.0"}, wantHit: "0.0.0.0"},
		{
			// A hostname resolving to several addresses is only as safe as its
			// worst one; a floor address anywhere in the set must be found.
			name:    "floor address hidden behind a public one",
			in:      []string{"93.184.216.34", "169.254.169.254"},
			wantHit: "169.254.169.254",
		},
		{
			name:    "mapped ipv6 metadata still hits the floor",
			in:      []string{"::ffff:169.254.169.254"},
			wantHit: "::ffff:169.254.169.254",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hit, found := FirstFloorHit(ParseResolved(tc.in))
			if tc.wantHit == "" {
				if found {
					t.Fatalf("unexpected floor hit %q", hit.Display)
				}
				return
			}
			if !found {
				t.Fatalf("no floor hit, want %q", tc.wantHit)
			}
			if hit.Display != tc.wantHit {
				t.Fatalf("floor hit = %q, want %q", hit.Display, tc.wantHit)
			}
		})
	}
}

func TestFirstInternalHit(t *testing.T) {
	cidrs := []*net.IPNet{mustCIDR(t, "10.0.0.0/8"), mustCIDR(t, "127.0.0.0/8")}

	t.Run("inside a cidr is a hit", func(t *testing.T) {
		if _, found := FirstInternalHit(ParseResolved([]string{"10.1.2.3"}), cidrs, nil); !found {
			t.Fatal("expected an internal hit for 10.1.2.3")
		}
	})

	t.Run("outside every cidr is not a hit", func(t *testing.T) {
		if _, found := FirstInternalHit(ParseResolved([]string{"93.184.216.34"}), cidrs, nil); found {
			t.Fatal("unexpected internal hit for a public address")
		}
	})

	t.Run("allowlisted address is exempt", func(t *testing.T) {
		allow := func(ip net.IP) bool { return ip.String() == "10.1.2.3" }
		if _, found := FirstInternalHit(ParseResolved([]string{"10.1.2.3"}), cidrs, allow); found {
			t.Fatal("allowlisted address should be exempt")
		}
	})

	t.Run("nil allowlist exempts nothing", func(t *testing.T) {
		// A nil callback must read as "nothing is exempt", never as "everything
		// is", because the latter turns a missing policy into an open door.
		if _, found := FirstInternalHit(ParseResolved([]string{"10.1.2.3"}), cidrs, nil); !found {
			t.Fatal("a nil allowlist must exempt nothing")
		}
	})

	t.Run("a non-allowlisted address behind an allowlisted one is still found", func(t *testing.T) {
		allow := func(ip net.IP) bool { return ip.String() == "10.1.2.3" }
		hit, found := FirstInternalHit(ParseResolved([]string{"10.1.2.3", "127.0.0.5"}), cidrs, allow)
		if !found {
			t.Fatal("expected the non-exempt address to be found")
		}
		if hit.Display != "127.0.0.5" {
			t.Fatalf("hit = %q, want 127.0.0.5", hit.Display)
		}
	})

	t.Run("nil cidr entries are skipped safely", func(t *testing.T) {
		if _, found := FirstInternalHit(ParseResolved([]string{"10.1.2.3"}), []*net.IPNet{nil}, nil); found {
			t.Fatal("a nil CIDR must not match anything")
		}
	})
}
