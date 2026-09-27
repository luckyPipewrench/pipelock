// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package media

import "testing"

func webpBody() []byte {
	b := []byte("RIFF\x24\x00\x00\x00WEBPVP8 \x18\x00\x00\x00")
	return append(b, make([]byte, 24)...)
}

func TestStripTypeReclassifiesOnlyAllowedRasterBytes(t *testing.T) {
	gif := append([]byte("GIF89a"), make([]byte, 16)...)
	allowAll := func(string) bool { return true }
	noWebP := func(mt string) bool { return mt != "image/webp" }
	for _, tc := range []struct {
		name, declared string
		body           []byte
		allowed        func(string) bool
		want           string
	}{
		{"webp labeled png", "image/png", webpBody(), allowAll, "image/webp"},
		{"gif labeled jpeg with params", "image/jpeg; q=1", gif, allowAll, "image/gif"},
		{"webp not allowed keeps declared", "image/png", webpBody(), noWebP, "image/png"},
		{"html labeled png keeps declared", "image/png", []byte("<!DOCTYPE html><html><body>x</body></html>"), allowAll, "image/png"},
		{"svg labeled png keeps declared", "image/png", []byte(`<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"></svg>`), allowAll, "image/png"},
		{"unknown bytes keep declared", "image/png", []byte{1, 2, 3, 4, 5, 6, 7, 8}, allowAll, "image/png"},
		{"matching png keeps declared", "image/png", append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 16)...), allowAll, "image/png"},
		{"jpg alias of real jpeg keeps declared", "image/jpg", append([]byte{0xFF, 0xD8, 0xFF, 0xE0}, make([]byte, 16)...), allowAll, "image/jpg"},
		{"undeclared stripped type untouched", "image/webp", gif, allowAll, "image/webp"},
		{"nil allow func keeps declared", "image/png", webpBody(), nil, "image/png"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := StripType(tc.declared, tc.body, tc.allowed); got != tc.want {
				t.Fatalf("StripType(%q) = %q, want %q", tc.declared, got, tc.want)
			}
		})
	}
}

func TestStripMetadataOfRelabeledWebPPassesThrough(t *testing.T) {
	body := webpBody()
	if _, err := StripMetadata("image/png", body); err == nil {
		t.Fatal("control: a WebP body parsed as PNG must fail its signature check")
	}
	sr, err := StripMetadata(StripType("image/png", body, func(string) bool { return true }), body)
	if err != nil {
		t.Fatalf("relabeled WebP: %v", err)
	}
	if string(sr.Data) != string(body) {
		t.Fatal("relabeled WebP body changed")
	}
}
