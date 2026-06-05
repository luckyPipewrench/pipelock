//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import "testing"

func TestNormalizeEmail(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"lowercases address and domain", "Buyer@Example.COM", "buyer@example.com", false},
		{"trims surrounding whitespace", "  buyer@example.com  ", "buyer@example.com", false},
		{"preserves plus tags", "buyer+eval@example.com", "buyer+eval@example.com", false},
		{"preserves dots in local part", "first.last@example.com", "first.last@example.com", false},
		{"strips display name", "Jane Buyer <jane@example.com>", "jane@example.com", false},
		{"empty is rejected", "", "", true},
		{"whitespace only is rejected", "   ", "", true},
		{"no at-sign is rejected", "not-an-email", "", true},
		{"multiple addresses rejected", "a@example.com, b@example.com", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeEmail(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NormalizeEmail(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Errorf("NormalizeEmail(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestNormalizeEmail_NoProviderSpecificAliasing documents the deliberate decision
// NOT to apply Gmail-style dot/plus collapsing: provider-specific alias rules are
// false security and break corporate mail. Two addresses that Gmail would treat as
// equivalent must normalize to DISTINCT canonical forms here.
func TestNormalizeEmail_NoProviderSpecificAliasing(t *testing.T) {
	a, err := NormalizeEmail("first.last+tag@gmail.com")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	b, err := NormalizeEmail("firstlast@gmail.com")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if a == b {
		t.Errorf("expected distinct canonical forms, both normalized to %q", a)
	}
}
