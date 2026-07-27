// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contententropy

import (
	"strings"
	"testing"
)

// A high-entropy, non-credential-shaped opaque marker (>4.5 bits/char).
const highEntropy = "k9Wp2XvR7mQ4tZ1nL8bY6cJ3fA0dH5sE2gT9uN4wK7pM1xQ8rV3jB6oD0iS5aZ"

// A 64-char all-hex blob: entropy tops out near 4.0 (below a 4.5 threshold),
// so only the opaque-hex branch catches it.
const hexBlob = "9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0"

func TestFind(t *testing.T) {
	tests := []struct {
		name      string
		text      string
		threshold float64
		minLen    int
		wantHit   bool
		wantEnc   string
	}{
		{"below min length", highEntropy[:10], 4.5, 32, false, ""},
		{"high entropy trips", highEntropy, 4.5, 32, true, ""},
		{"low entropy clean", strings.Repeat("a", 40), 4.5, 32, false, ""},
		{"hex below threshold trips via opaque-hex", hexBlob, 4.5, 32, true, "hex"},
		{"whitespace trimmed below min length", "   " + highEntropy[:8] + "   ", 4.5, 32, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := Find(tt.text, tt.threshold, tt.minLen)
			if tt.wantHit != (f != nil) {
				t.Fatalf("Find hit = %v, want %v (f=%+v)", f != nil, tt.wantHit, f)
			}
			if f != nil && f.Encoding != tt.wantEnc {
				t.Fatalf("encoding = %q, want %q", f.Encoding, tt.wantEnc)
			}
		})
	}
}

func TestScanTexts(t *testing.T) {
	base := Options{Enabled: true, Threshold: 4.5, MinLength: 32, Host: "exfil.vendor.example"}
	tests := []struct {
		name    string
		texts   []string
		mutate  func(*Options)
		wantHit bool
	}{
		{"disabled", []string{highEntropy}, func(o *Options) { o.Enabled = false }, false},
		{"non-positive threshold", []string{highEntropy}, func(o *Options) { o.Threshold = 0 }, false},
		{"non-positive min length", []string{highEntropy}, func(o *Options) { o.MinLength = 0 }, false},
		{"trusted host exempt", []string{highEntropy}, func(o *Options) { o.Trusted = []string{"exfil.vendor.example"} }, false},
		{"exclusion host exempt", []string{highEntropy}, func(o *Options) { o.Exclusions = []string{"exfil.vendor.example"} }, false},
		{"per-field hit", []string{"short", highEntropy}, nil, true},
		{"joined hit when each field below min length", []string{highEntropy[:16], highEntropy[16:32]}, func(o *Options) { o.MinLength = 32 }, true},
		{"separatorless hex hit when each field below min length", []string{hexBlob[:16], hexBlob[16:32], hexBlob[32:48], hexBlob[48:]}, func(o *Options) { o.MinLength = 64 }, true},
		{"clean short fields", []string{"a", "b"}, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := base
			if tt.mutate != nil {
				tt.mutate(&opts)
			}
			f := ScanTexts(tt.texts, opts)
			if tt.wantHit != (f != nil) {
				t.Fatalf("ScanTexts hit = %v, want %v (f=%+v)", f != nil, tt.wantHit, f)
			}
		})
	}
}

func TestScanTexts_CustomSeparator(t *testing.T) {
	// A non-default separator must still produce a joined view that trips.
	opts := Options{Enabled: true, Threshold: 4.5, MinLength: 32, Host: "exfil.vendor.example", Separator: "|"}
	if ScanTexts([]string{highEntropy[:16], highEntropy[16:32]}, opts) == nil {
		t.Fatal("expected joined scan with custom separator to trip")
	}
}

func TestReason(t *testing.T) {
	if got := Reason(nil); got != "high entropy request body content" {
		t.Fatalf("nil reason = %q", got)
	}
	hex := Reason(&Finding{Encoding: "hex", Entropy: 3.94, Threshold: 4.5, Length: 64})
	if !strings.Contains(hex, "opaque hex request body content") {
		t.Fatalf("hex reason = %q", hex)
	}
	plain := Reason(&Finding{Entropy: 5.1, Threshold: 4.5, Length: 60})
	if !strings.Contains(plain, "high entropy request body content") || !strings.Contains(plain, ">") {
		t.Fatalf("plain reason = %q", plain)
	}
}

func TestLooksOpaqueHexContent(t *testing.T) {
	tests := []struct {
		name    string
		text    string
		entropy float64
		minLen  int
		want    bool
	}{
		{"all hex 64", hexBlob, 3.9, 32, true},
		{"uppercase hex", strings.ToUpper(hexBlob), 3.9, 32, true},
		{"too short under 32", "9f8e7d6c5b4a3928", 3.9, 8, false},
		{"entropy under 3.5", strings.Repeat("ab", 20), 2.0, 32, false},
		{"non-hex char present", strings.Repeat("g", 40), 4.0, 32, false},
		{"below configured min length", hexBlob, 3.9, 128, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := looksOpaqueHexContent(tt.text, tt.entropy, tt.minLen); got != tt.want {
				t.Fatalf("looksOpaqueHexContent = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsDomainExempt(t *testing.T) {
	if !isDomainExempt("api.vendor.example", []string{"api.vendor.example"}) {
		t.Fatal("exact host should be exempt")
	}
	if !isDomainExempt("API.VENDOR.EXAMPLE.:443", []string{"api.vendor.example"}) {
		t.Fatal("host matching should canonicalize case, trailing dot, and port")
	}
	if isDomainExempt("api.vendor.example", []string{"other.example"}) {
		t.Fatal("non-matching host should not be exempt")
	}
	if isDomainExempt("api.vendor.example", nil) {
		t.Fatal("empty exemption list should not match")
	}
}

func TestSortedTexts_DoesNotMutateInput(t *testing.T) {
	in := []string{"c", "a", "b"}
	out := sortedTexts(in)
	if in[0] != "c" {
		t.Fatalf("input mutated: %v", in)
	}
	if out[0] != "a" || out[1] != "b" || out[2] != "c" {
		t.Fatalf("not sorted: %v", out)
	}
}

func TestFindSeparatorlessOpaqueHex(t *testing.T) {
	// Fewer than two fields: nothing to concatenate, returns nil.
	if findSeparatorlessOpaqueHex([]string{hexBlob}, 4.5, 32) != nil {
		t.Fatal("single field should not produce a separatorless finding")
	}
	// Hex split across short fields concatenates to an opaque-hex hit.
	f := findSeparatorlessOpaqueHex([]string{hexBlob[:16], hexBlob[16:32], hexBlob[32:48], hexBlob[48:]}, 4.5, 64)
	if f == nil || f.Encoding != "hex" {
		t.Fatalf("expected separatorless opaque-hex finding, got %+v", f)
	}
	// Concatenation that is not all-hex is not an opaque-hex finding.
	if findSeparatorlessOpaqueHex([]string{"not", "hex", "content", "here"}, 4.5, 4) != nil {
		t.Fatal("non-hex concatenation should not be an opaque-hex finding")
	}
}
