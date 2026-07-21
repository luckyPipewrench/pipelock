// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package emitformat

import "testing"

func TestSupported(t *testing.T) {
	tests := []struct {
		name   string
		format string
		want   bool
	}{
		{name: "json", format: JSON, want: true},
		{name: "cef", format: CEF, want: true},
		{name: "ocsf", format: OCSF, want: true},
		{name: "empty", format: "", want: false},
		{name: "unsupported", format: "xml", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Supported(tt.format); got != tt.want {
				t.Fatalf("Supported(%q) = %v, want %v", tt.format, got, tt.want)
			}
		})
	}
}

func TestSupportedFormats(t *testing.T) {
	got := SupportedFormats()
	want := []string{JSON, CEF, OCSF}
	if len(got) != len(want) {
		t.Fatalf("SupportedFormats() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("SupportedFormats() = %v, want %v", got, want)
		}
	}

	got[0] = "mutated"
	if !Supported(JSON) {
		t.Fatal("mutating returned SupportedFormats slice changed Supported(JSON)")
	}
}

func TestAllowedSet(t *testing.T) {
	if got := AllowedSet(); got != "json, cef or ocsf" {
		t.Fatalf("AllowedSet() = %q, want %q", got, "json, cef or ocsf")
	}
}

func TestAllowedSetSmallLists(t *testing.T) {
	orig := supportedFormats
	t.Cleanup(func() { supportedFormats = orig })

	tests := []struct {
		name    string
		formats []string
		want    string
	}{
		{name: "empty", formats: nil, want: ""},
		{name: "single", formats: []string{JSON}, want: JSON},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			supportedFormats = tt.formats
			if got := AllowedSet(); got != tt.want {
				t.Fatalf("AllowedSet() = %q, want %q", got, tt.want)
			}
		})
	}
}
