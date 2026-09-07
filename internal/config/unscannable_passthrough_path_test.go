// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

func TestCanonicalUnscannablePassthroughPathDecodeBoundaries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		raw    string
		want   string
		wantOK bool
	}{
		{
			name:   "plain canonical path",
			raw:    "/packages/item.bin",
			want:   "/packages/item.bin",
			wantOK: true,
		},
		{
			name:   "surrounding whitespace is trimmed",
			raw:    " \t/packages/item.bin\n",
			want:   "/packages/item.bin",
			wantOK: true,
		},
		{
			name:   "single encoded ordinary byte",
			raw:    "/packages/%41rchive.bin",
			want:   "/packages/Archive.bin",
			wantOK: true,
		},
		{
			name:   "four decode passes consume nested ordinary byte",
			raw:    "/packages/%25252570ayload.bin",
			want:   "/packages/payload.bin",
			wantOK: true,
		},
		{
			name: "empty after trimming",
			raw:  " \t\n",
		},
		{
			name: "query delimiter",
			raw:  "/packages/item.bin?download",
		},
		{
			name: "empty path segment",
			raw:  "/packages//item.bin",
		},
		{
			name: "dot path segment",
			raw:  "/packages/./item.bin",
		},
		{
			name: "encoded slash",
			raw:  "/packages/item%2fchild.bin",
		},
		{
			name: "nested encoded slash",
			raw:  "/packages/item%252fchild.bin",
		},
		{
			name: "encoded backslash",
			raw:  "/packages/item%5cchild.bin",
		},
		{
			name: "nested encoded backslash",
			raw:  "/packages/item%255cchild.bin",
		},
		{
			name: "encoded dot segment",
			raw:  "/packages/%2e/item.bin",
		},
		{
			name: "nested encoded dot segment",
			raw:  "/packages/%252e/item.bin",
		},
		{
			name: "encoded path parameter",
			raw:  "/packages/item%3bdownload",
		},
		{
			name: "nested encoded path parameter",
			raw:  "/packages/item%253bdownload",
		},
		{
			name: "raw newline control",
			raw:  "/packages/item\n.bin",
		},
		{
			name: "raw delete control",
			raw:  "/packages/item\x7f.bin",
		},
		{
			name: "decoded newline control",
			raw:  "/packages/item%0A.bin",
		},
		{
			name: "decoded delete control",
			raw:  "/packages/item%7f.bin",
		},
		{
			name: "malformed short percent escape",
			raw:  "/packages/item%2",
		},
		{
			name: "malformed non hexadecimal percent escape",
			raw:  "/packages/item%q0",
		},
		{
			name: "residual percent after four decode passes",
			raw:  "/packages/%2525252570ayload.bin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := CanonicalUnscannablePassthroughPath(tt.raw)
			if ok != tt.wantOK {
				t.Fatalf("CanonicalUnscannablePassthroughPath(%q) ok = %v, want %v (path %q)", tt.raw, ok, tt.wantOK, got)
			}
			if got != tt.want {
				t.Errorf("CanonicalUnscannablePassthroughPath(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}
