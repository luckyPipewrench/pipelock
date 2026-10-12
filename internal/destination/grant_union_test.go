// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package destination

import "testing"

func TestGrantSetUnion(t *testing.T) {
	t.Parallel()
	first, err := NewGrant(NetworkTCP, "preview.vendor.example", 8443)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewGrant(NetworkTCP, "preview.vendor.example", 8444)
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewGrantSet(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewGrantSet(first, second)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name        string
		left, right GrantSet
		size        int
	}{
		{"empty", GrantSet{}, GrantSet{}, 0},
		{"left empty", GrantSet{}, a, 1},
		{"right empty", a, GrantSet{}, 1},
		{"overlap", a, b, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.left.Union(tc.right)
			if err != nil || got.Len() != tc.size {
				t.Fatalf("Union=%v, %v", got, err)
			}
			for _, grant := range []Grant{first, second} {
				dest := grant.Destination()
				want := tc.left.Contains(dest) || tc.right.Contains(dest)
				if got.Contains(dest) != want {
					t.Errorf("Union membership for %v = %t, want %t", dest, got.Contains(dest), want)
				}
			}
			ungranted := first.Destination()
			ungranted.Port = 8445
			if got.Contains(ungranted) {
				t.Fatal("union granted an absent destination")
			}
		})
	}
	if a.Len() != 1 || b.Len() != 2 || !a.Contains(first.Destination()) || a.Contains(second.Destination()) || !b.Contains(first.Destination()) || !b.Contains(second.Destination()) {
		t.Fatal("union mutated input")
	}
	malformed := GrantSet{byKey: map[string]Grant{"invalid": {}}}
	if _, err := a.Union(malformed); err == nil {
		t.Fatal("union installed malformed grant")
	}
}
