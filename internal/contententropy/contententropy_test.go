// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contententropy

import (
	"strconv"
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
		{"single-character field split cannot dilute entropy", strings.Split(highEntropy, ""), func(o *Options) { o.MinLength = 32 }, true},
		{"repeated structure cannot dilute split entropy", entropyFieldsWithRepeatedStructure(), func(o *Options) { o.MinLength = 32 }, true},
		{"separatorless hex hit when each field below min length", []string{hexBlob[:16], hexBlob[16:32], hexBlob[32:48], hexBlob[48:]}, func(o *Options) { o.MinLength = 64 }, true},
		{"whitespace-padded hex shards still hit", []string{hexBlob[:16] + " ", hexBlob[16:32] + " ", hexBlob[32:48] + " ", hexBlob[48:] + " "}, func(o *Options) { o.MinLength = 64 }, true},
		{"clean short fields", []string{"a", "b"}, nil, false},
		{"clean repeated structure", []string{strings.Repeat("a", 40), strings.Repeat("a", 40), strings.Repeat("b", 40), strings.Repeat("b", 40)}, nil, false},
		{"clean distinct key-rich structure", cleanDistinctStructure(), nil, false},
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

func entropyFieldsWithRepeatedStructure() []string {
	fields := make([]string, 0, len(highEntropy)*2)
	for _, character := range highEntropy {
		fields = append(fields, string(character), "text")
	}
	return fields
}

func cleanDistinctStructure() []string {
	fields := make([]string, 0, 60)
	for i := range 60 {
		fields = append(fields, "status_field_"+strconv.Itoa(i))
	}
	return fields
}

func TestScanTexts_CustomSeparator(t *testing.T) {
	// The separator-joined view is the last one ScanTexts tries, so a fixture
	// that any earlier view already catches would pass without ever using the
	// separator. Five 6-character fields make every separatorless view 30 bytes
	// (under the 36-byte minimum, so they return nil on length alone). Four
	// two-byte custom separators make the joined view 38 bytes, while the
	// default one-byte separators leave it at 34. That leaves the configured
	// separator load-bearing for this assertion.
	fields := []string{highEntropy[0:6], highEntropy[6:12], highEntropy[12:18], highEntropy[18:24], highEntropy[24:30]}
	opts := Options{Enabled: true, Threshold: 4.5, MinLength: 36, Host: "exfil.vendor.example", Separator: "::"}
	if ScanTexts(fields, opts) == nil {
		t.Fatal("expected joined scan with custom separator to trip")
	}
	// Same fields, no separator configured: the default "." separator keeps the
	// joined view below MinLength.
	opts.Separator = ""
	if finding := ScanTexts(fields, opts); finding != nil {
		t.Fatalf("default separator should stay below MinLength, got %+v", finding)
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
	in := []string{" c ", "a", "b"}
	out := sortedTexts(in)
	if in[0] != " c " {
		t.Fatalf("input mutated: %v", in)
	}
	if out[0] != "a" || out[1] != "b" || out[2] != "c" {
		t.Fatalf("not sorted: %v", out)
	}
}

// TestScanTexts_ShardedHexReassembles keeps end-to-end coverage for a hex blob
// split below the minimum length. The dedicated helper this used to exercise was
// removed as unreachable; the separatorless view in ScanTexts covers it, and the
// encoding must still be reported as hex so the operator reason text is right.
func TestScanTexts_ShardedHexReassembles(t *testing.T) {
	opts := Options{Enabled: true, Threshold: 4.5, MinLength: 64, Host: "exfil.vendor.example"}
	f := ScanTexts([]string{hexBlob[32:48], hexBlob[:16], hexBlob[48:], hexBlob[16:32]}, opts)
	if f == nil || f.Encoding != "hex" {
		t.Fatalf("expected sharded opaque-hex finding, got %+v", f)
	}
	// Non-hex short fields must stay clean rather than reporting a hex encoding.
	if f := ScanTexts([]string{"not", "hex", "content", "here"}, opts); f != nil {
		t.Fatalf("non-hex concatenation should be clean, got %+v", f)
	}
}
