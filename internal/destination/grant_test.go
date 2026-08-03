// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package destination

import (
	"errors"
	"testing"
)

func mustGrantSet(t *testing.T, grants ...Grant) GrantSet {
	t.Helper()
	gs, err := NewGrantSet(grants...)
	if err != nil {
		t.Fatalf("NewGrantSet() unexpected error: %v", err)
	}
	return gs
}

func TestNewGrant_Valid(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		network Network
		host    string
		port    uint16
	}{
		{"tcp dns host", NetworkTCP, "api.dev.example", 6443},
		{"tcp ipv4", NetworkTCP, "10.0.0.1", 8080},
		{"tcp ipv6", NetworkTCP, "2001:db8::1", 443},
		{"udp host", NetworkUDP, "syslog.internal.example", 514},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			g, err := NewGrant(tc.network, tc.host, tc.port)
			if err != nil {
				t.Fatalf("NewGrant(%q, %q, %d) unexpected error: %v", tc.network, tc.host, tc.port, err)
			}
			if g.Destination().Port != tc.port {
				t.Errorf("port = %d, want %d", g.Destination().Port, tc.port)
			}
		})
	}
}

func TestNewGrant_FloorViolation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		host string
	}{
		{"aws metadata ipv4", "169.254.169.254"},
		{"azure wireserver", "168.63.129.16"},
		{"alibaba metadata", "100.100.100.200"},
		{"aws metadata ipv6", "fd00:ec2::254"},
		{"link-local ipv4", "169.254.1.1"},
		{"multicast ipv4", "224.0.0.1"},
		{"unspecified ipv4", "0.0.0.0"},
		{"unspecified ipv6", "::"},
		{"link-local ipv6", "fe80::1"},
		{"metadata hex spelling", "0xa9fea9fe"},
		{"metadata integer spelling", "2852039166"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewGrant(NetworkTCP, tc.host, 80)
			if err == nil {
				t.Fatalf("NewGrant for floor address %q should fail", tc.host)
			}
			if !errors.Is(err, ErrGrantFloorViolation) {
				t.Errorf("error = %v, want ErrGrantFloorViolation", err)
			}
		})
	}
}

func TestNewGrant_InvalidInputs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		network Network
		host    string
		port    uint16
		wantErr error
	}{
		{"empty host", NetworkTCP, "", 443, ErrEmptyHost},
		{"zero port", NetworkTCP, "example.com", 0, ErrInvalidPort},
		{"bad network", Network("quic"), "example.com", 443, ErrInvalidNetwork},
		{"control char host", NetworkTCP, "evil\x00.example", 443, ErrInvalidHost},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewGrant(tc.network, tc.host, tc.port)
			if err == nil {
				t.Fatalf("NewGrant should have failed for %s", tc.name)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestGrantSet_EmptyAuthorizesNothing(t *testing.T) {
	t.Parallel()
	gs := mustGrantSet(t)
	d, _ := New(NetworkTCP, "api.dev.example", 6443)
	dec := gs.Evaluate(d)
	if dec.Matched() {
		t.Fatalf("empty grant set should not match anything, got %+v", dec)
	}
	if dec.Effect != EffectNoMatch {
		t.Errorf("effect = %v, want EffectNoMatch", dec.Effect)
	}
}

func TestGrantSet_ExactMatch(t *testing.T) {
	t.Parallel()
	g, err := NewGrant(NetworkTCP, "api.dev.example", 6443)
	if err != nil {
		t.Fatal(err)
	}
	gs := mustGrantSet(t, g)

	d, _ := New(NetworkTCP, "api.dev.example", 6443)
	dec := gs.Evaluate(d)
	if dec.Effect != EffectAllow {
		t.Fatalf("exact match should allow, got %+v", dec)
	}
	if dec.Scope != ScopeExact {
		t.Errorf("scope = %v, want ScopeExact", dec.Scope)
	}
	if dec.Source != SourceGuardGrant {
		t.Errorf("source = %v, want SourceGuardGrant", dec.Source)
	}
}

func TestGrantSet_Exactness(t *testing.T) {
	t.Parallel()
	g, err := NewGrant(NetworkTCP, "api.dev.example", 6443)
	if err != nil {
		t.Fatal(err)
	}
	gs := mustGrantSet(t, g)

	cases := []struct {
		name    string
		network Network
		host    string
		port    uint16
	}{
		{"wrong port", NetworkTCP, "api.dev.example", 443},
		{"wrong network", NetworkUDP, "api.dev.example", 6443},
		{"different host", NetworkTCP, "other.dev.example", 6443},
		{"subdomain", NetworkTCP, "sub.api.dev.example", 6443},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d, _ := New(tc.network, tc.host, tc.port)
			dec := gs.Evaluate(d)
			if dec.Matched() {
				t.Errorf("should not match %s, got %+v", tc.name, dec)
			}
		})
	}
}

func TestGrantSet_IPExactness(t *testing.T) {
	t.Parallel()
	// Grant for a specific IP:port.
	g, err := NewGrant(NetworkTCP, "10.0.0.1", 8080)
	if err != nil {
		t.Fatal(err)
	}
	gs := mustGrantSet(t, g)

	cases := []struct {
		name    string
		host    string
		port    uint16
		matched bool
	}{
		{"exact match", "10.0.0.1", 8080, true},
		{"wrong port", "10.0.0.1", 9090, false},
		{"different ip", "10.0.0.2", 8080, false},
		{"ipv4-mapped ipv6 spelling", "::ffff:10.0.0.1", 8080, true}, // normalized to 10.0.0.1
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d, _ := New(NetworkTCP, tc.host, tc.port)
			dec := gs.Evaluate(d)
			if dec.Matched() != tc.matched {
				t.Errorf("matched = %v, want %v; decision = %+v", dec.Matched(), tc.matched, dec)
			}
		})
	}
}

func TestGrantSet_FloorOverridesGrant(t *testing.T) {
	t.Parallel()
	// Simulate a grant set that somehow contains a floor address
	// (construction prevents this, but defense-in-depth evaluate must deny).
	metaDest := Destination{Network: NetworkTCP, Host: "169.254.169.254", Port: 80}
	gs := GrantSet{
		byKey: map[string]Grant{
			metaDest.String(): {dest: metaDest},
		},
	}
	dec := gs.Evaluate(metaDest)
	if dec.Effect != EffectDeny {
		t.Fatalf("floor should deny metadata even if grant exists, got %+v", dec)
	}
	if dec.Source != SourceImmutableFloor {
		t.Errorf("source = %v, want SourceImmutableFloor", dec.Source)
	}
}

func TestGrantSet_ResolvedIPNotGranted(t *testing.T) {
	t.Parallel()
	// A grant for a DNS name does NOT authorize the resolved IP.
	g, err := NewGrant(NetworkTCP, "api.dev.example", 443)
	if err != nil {
		t.Fatal(err)
	}
	gs := mustGrantSet(t, g)

	// Query by the IP that api.dev.example might resolve to.
	d, _ := New(NetworkTCP, "93.184.216.34", 443)
	dec := gs.Evaluate(d)
	if dec.Matched() {
		t.Errorf("grant for DNS name should not match resolved IP, got %+v", dec)
	}
}

func TestGrantSet_HostNormalization(t *testing.T) {
	t.Parallel()
	g, err := NewGrant(NetworkTCP, "API.Dev.Example", 443)
	if err != nil {
		t.Fatal(err)
	}
	gs := mustGrantSet(t, g)

	d, _ := New(NetworkTCP, "api.dev.example", 443)
	dec := gs.Evaluate(d)
	if dec.Effect != EffectAllow {
		t.Errorf("case-normalized host should match, got %+v", dec)
	}
}

func TestGrant_String(t *testing.T) {
	t.Parallel()
	g, err := NewGrant(NetworkTCP, "api.dev.example", 6443)
	if err != nil {
		t.Fatal(err)
	}
	want := "tcp://api.dev.example:6443"
	if got := g.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestNewGrant_UnknownNetworkFailsClosed(t *testing.T) {
	t.Parallel()
	_, err := NewGrant(Network("sctp"), "example.com", 443)
	if err == nil {
		t.Fatal("unknown network should be rejected")
	}
	if !errors.Is(err, ErrInvalidNetwork) {
		t.Errorf("error = %v, want ErrInvalidNetwork", err)
	}
}

func TestGrantSet_AlternativeIPSpellingNormalized(t *testing.T) {
	t.Parallel()
	// Grant for an IP in hex form — should normalize to dotted decimal.
	g, err := NewGrant(NetworkTCP, "0x0a000001", 8080)
	if err != nil {
		t.Fatal(err)
	}
	gs := mustGrantSet(t, g)

	// Query with standard dotted decimal for the same address.
	d, _ := New(NetworkTCP, "10.0.0.1", 8080)
	dec := gs.Evaluate(d)
	if dec.Effect != EffectAllow {
		t.Errorf("hex IP grant should match dotted-decimal query, got %+v", dec)
	}
}

// TestGrantSet_LenAndContains covers the set accessors, including the nil-set
// case. Contains must answer for the EXACT destination only, matching Evaluate,
// so a caller cannot use it as a cheaper but looser membership test.
func TestGrantSet_LenAndContains(t *testing.T) {
	var empty GrantSet
	if empty.Len() != 0 {
		t.Errorf("zero GrantSet Len = %d, want 0", empty.Len())
	}
	d, err := New(NetworkTCP, "api.dev.example", 6443)
	if err != nil {
		t.Fatal(err)
	}
	if empty.Contains(d) {
		t.Error("a zero GrantSet must contain nothing")
	}

	g, err := NewGrant(NetworkTCP, "api.dev.example", 6443)
	if err != nil {
		t.Fatal(err)
	}
	gs := mustGrantSet(t, g)
	if gs.Len() != 1 {
		t.Errorf("Len = %d, want 1", gs.Len())
	}
	if !gs.Contains(d) {
		t.Error("Contains must find the exact granted destination")
	}

	// Contains must be exactly as narrow as Evaluate. A looser membership test
	// would become the bypass, since callers reach for the cheap check.
	for _, other := range []struct {
		network Network
		host    string
		port    uint16
	}{
		{NetworkTCP, "api.dev.example", 443},
		{NetworkUDP, "api.dev.example", 6443},
		{NetworkTCP, "other.dev.example", 6443},
	} {
		od, err := New(other.network, other.host, other.port)
		if err != nil {
			t.Fatal(err)
		}
		if gs.Contains(od) {
			t.Errorf("Contains(%s) = true; a grant authorizes one destination, not its neighbours", od)
		}
	}
}

func TestNewGrantSet_RejectsInvalidEntriesAllOrNothing(t *testing.T) {
	t.Parallel()
	valid, err := NewGrant(NetworkTCP, "api.dev.example", 6443)
	if err != nil {
		t.Fatal(err)
	}
	floor := Grant{dest: Destination{Network: NetworkTCP, Host: "169.254.169.254", Port: 80}}

	for _, tc := range []struct {
		name  string
		grant Grant
	}{
		{name: "zero value", grant: Grant{}},
		{name: "floor address", grant: floor},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gs, err := NewGrantSet(valid, tc.grant)
			if err == nil {
				t.Fatal("NewGrantSet should reject an invalid entry")
			}
			if gs.Len() != 0 {
				t.Fatalf("failed construction returned %d live grants, want 0", gs.Len())
			}
		})
	}
}

func TestGrantSet_DuplicateKeyLastWins(t *testing.T) {
	t.Parallel()
	g1, err := NewGrant(NetworkTCP, "api.dev.example", 6443)
	if err != nil {
		t.Fatal(err)
	}
	g2, err := NewGrant(NetworkTCP, "API.DEV.EXAMPLE", 6443)
	if err != nil {
		t.Fatal(err)
	}
	gs := mustGrantSet(t, g1, g2)
	if gs.Len() != 1 {
		t.Errorf("Len = %d, want 1 for duplicate destination", gs.Len())
	}
}

func TestGrantSet_ContainsHonorsImmutableFloor(t *testing.T) {
	t.Parallel()
	metaDest := Destination{Network: NetworkTCP, Host: "169.254.169.254", Port: 80}
	gs := GrantSet{byKey: map[string]Grant{metaDest.String(): {dest: metaDest}}}
	if gs.Contains(metaDest) {
		t.Fatal("Contains must not authorize a destination denied by Evaluate")
	}
}
