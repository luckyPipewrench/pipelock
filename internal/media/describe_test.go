// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package media

import "testing"

func TestDescribeBytes(t *testing.T) {
	for _, tc := range []struct {
		name string
		body []byte
		want string
	}{
		{"empty", nil, "empty"},
		{"webp", append([]byte("RIFF\x00\x00\x00\x00WEBPVP8 "), make([]byte, 8)...), "image/webp"},
		{"png", []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR"), "image/png"},
		{"html", []byte("<!DOCTYPE html><html><body>x</body></html>"), "text/html"},
		{"svg as xml", []byte(`<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"/>`), "text/xml"},
		{"ico", []byte("\x00\x00\x01\x00\x01\x00\x10\x10"), "image/x-icon"},
	} {
		if got := DescribeBytes(tc.body); got != tc.want {
			t.Errorf("%s: DescribeBytes = %q, want %q", tc.name, got, tc.want)
		}
	}
}
