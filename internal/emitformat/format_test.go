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
