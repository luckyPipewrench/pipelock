// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"reflect"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/destination"
)

const destinationGrantTestHost = "preview.vendor.example"

func TestDestinationGrantValidation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		entry DestinationGrant
		valid bool
	}{
		{"exact hostname", DestinationGrant{"tcp", destinationGrantTestHost, 8443}, true},
		{"canonical hostname", DestinationGrant{"tcp", "PREVIEW.VENDOR.EXAMPLE.", 8443}, true},
		{"loopback", DestinationGrant{"tcp", "127.0.0.1", 8443}, true},
		{"private IPv6", DestinationGrant{"tcp", "fd00::1", 8443}, true},
		{"missing protocol", DestinationGrant{"", destinationGrantTestHost, 8443}, false},
		{"unsupported protocol", DestinationGrant{"udp", destinationGrantTestHost, 8443}, false},
		{"scheme as protocol", DestinationGrant{"https", destinationGrantTestHost, 8443}, false},
		{"wildcard", DestinationGrant{"tcp", "*.vendor.example", 8443}, false},
		{"CIDR", DestinationGrant{"tcp", "10.0.0.0/8", 8443}, false},
		{"URL", DestinationGrant{"tcp", "https://preview.vendor.example", 8443}, false},
		{"authority", DestinationGrant{"tcp", "preview.vendor.example:8443", 8443}, false},
		{"empty host", DestinationGrant{"tcp", "", 8443}, false},
		{"empty label", DestinationGrant{"tcp", "preview..vendor.example", 8443}, false},
		{"invalid label", DestinationGrant{"tcp", "preview!.vendor.example", 8443}, false},
		{"control character", DestinationGrant{"tcp", "preview\n.vendor.example", 8443}, false},
		{"zero port", DestinationGrant{"tcp", destinationGrantTestHost, 0}, false},
		{"metadata", DestinationGrant{"tcp", "169.254.169.254", 80}, false},
		{"mapped metadata", DestinationGrant{"tcp", "::ffff:169.254.169.254", 80}, false},
		{"alternative metadata", DestinationGrant{"tcp", "0xa9fea9fe", 80}, false},
		{"link local", DestinationGrant{"tcp", "fe80::1", 80}, false},
		{"multicast", DestinationGrant{"tcp", "224.0.0.1", 80}, false},
		{"unspecified", DestinationGrant{"tcp", "::", 80}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.DestinationGrants = []DestinationGrant{tc.entry}
			if err := cfg.Validate(); (err == nil) != tc.valid {
				t.Fatalf("Validate() = %v, valid=%t", err, tc.valid)
			}
		})
	}
	for _, raw := range []string{
		"destination_grants: [{protocol: tcp, host: preview.vendor.example, port: 65536}]",
		"destination_grants: [{protocol: tcp, host: preview.vendor.example, port: -1}]",
		"destination_grants: [{protocol: tcp, host: preview.vendor.example, port: many}]",
	} {
		if _, err := LoadBytes([]byte(raw)); err == nil {
			t.Fatalf("invalid YAML accepted: %s", raw)
		}
	}
}

func TestDestinationGrantsConfigAndCanonicalPolicy(t *testing.T) {
	t.Parallel()
	baseline, err := LoadBytes([]byte("version: 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"", "destination_grants: null", "destination_grants: []"} {
		cfg, err := LoadBytes([]byte("version: 1\n" + raw))
		if err != nil {
			t.Fatal(err)
		}
		gs, err := cfg.DestinationGrantSet()
		if err != nil || gs.Len() != 0 {
			t.Fatalf("empty declaration = %v, %v", gs, err)
		}
		if cfg.CanonicalPolicyHash() != baseline.CanonicalPolicyHash() {
			t.Fatal("empty grants changed default policy hash")
		}
	}
	a := Defaults()
	a.DestinationGrants = []DestinationGrant{{"tcp", "PREVIEW.VENDOR.EXAMPLE.", 8443}, {"tcp", "127.0.0.1", 8080}}
	b := Defaults()
	b.DestinationGrants = []DestinationGrant{{"tcp", "127.0.0.1", 8080}, {"tcp", destinationGrantTestHost, 8443}, {"tcp", destinationGrantTestHost, 8443}}
	if a.CanonicalPolicyHash() != b.CanonicalPolicyHash() {
		t.Fatal("equivalent grant sets hash differently")
	}
	c := b.Clone()
	c.DestinationGrants[1].Port++
	if b.CanonicalPolicyHash() == c.CanonicalPolicyHash() {
		t.Fatal("port change absent from policy hash")
	}
	if a.DestinationGrants[0].Host != "PREVIEW.VENDOR.EXAMPLE." {
		t.Fatal("canonicalization mutated config")
	}
	gs, err := b.DestinationGrantSet()
	if err != nil || gs.Len() != 2 {
		t.Fatalf("deduplicated grants = %v, %v", gs, err)
	}
	dest, err := destination.New(destination.NetworkTCP, destinationGrantTestHost, 8443)
	if err != nil || !gs.Contains(dest) {
		t.Fatalf("exact grant missing: %v", err)
	}
}

func TestDestinationGrantsReloadWarnings(t *testing.T) {
	t.Parallel()
	grant := DestinationGrant{"tcp", destinationGrantTestHost, 8443}
	for _, tc := range []struct {
		name      string
		old, next []DestinationGrant
		warn      bool
	}{
		{"add", nil, []DestinationGrant{grant}, true},
		{"remove", []DestinationGrant{grant}, nil, false},
		{"preserve", []DestinationGrant{grant}, []DestinationGrant{grant}, false},
		{"normalize", []DestinationGrant{{"tcp", "PREVIEW.VENDOR.EXAMPLE.", 8443}}, []DestinationGrant{grant}, false},
		{"change port", []DestinationGrant{grant}, []DestinationGrant{{"tcp", destinationGrantTestHost, 8444}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old, next := Defaults(), Defaults()
			old.DestinationGrants, next.DestinationGrants = tc.old, tc.next
			found := false
			for _, warning := range ValidateReload(old, next) {
				if warning.Field == "destination_grants" {
					found = true
					if warning.Disposition != "" {
						t.Fatal("trust expansion treated as advisory")
					}
				}
			}
			if found != tc.warn {
				t.Fatalf("warning=%t, want %t", found, tc.warn)
			}
		})
	}
}

func TestDestinationGrantsPreserveConductorLocalPolicy(t *testing.T) {
	t.Parallel()
	for _, local := range [][]DestinationGrant{nil, {{"tcp", destinationGrantTestHost, 8443}}} {
		old, next := Defaults(), Defaults()
		old.DestinationGrants = local
		next.DestinationGrants = []DestinationGrant{{"tcp", "other.vendor.example", 8080}}
		if err := PreserveConductorBundleLocalRuntimeState(next, old, "version: 1\n"); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(next.DestinationGrants, local) {
			t.Fatal("bundle changed follower-local authorization")
		}
		if len(local) > 0 {
			next.DestinationGrants[0].Port++
			if old.DestinationGrants[0].Port != 8443 {
				t.Fatal("bundle preservation aliased grants")
			}
		}
	}
}
