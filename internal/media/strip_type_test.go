// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package media

import "testing"

func webpBody() []byte {
	b := []byte("RIFF\x24\x00\x00\x00WEBPVP8 \x18\x00\x00\x00")
	return append(b, make([]byte, 24)...)
}

func TestStripTypeReclassifiesOnlyAllowedRasterBytes(t *testing.T) {
	// GIF89a, 1x1 logical screen, no color table, then an image descriptor (0x2c).
	gif := append([]byte("GIF89a\x01\x00\x01\x00\x00\x00\x00\x2c"), make([]byte, 16)...)
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
		// Short WHATWG prefixes followed by markup must not be reclassified.
		{"loose webp prefix with svg keeps declared", "image/png", append([]byte("RIFF\x00\x00\x00\x00WEBPVP"), []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>x()</script></svg>`)...), allowAll, "image/png"},
		{"loose gif prefix with html keeps declared", "image/png", []byte("GIF89a<html><body>x</body></html>"), allowAll, "image/png"},
		{"loose bmp prefix with html keeps declared", "image/png", []byte("BM<html><body>x</body></html>"), allowAll, "image/png"},
		{"ico signature with script keeps declared", "image/png", append([]byte{0, 0, 1, 0}, []byte("<script>x()</script>")...), allowAll, "image/png"},
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

func TestMislabeledDisallowed(t *testing.T) {
	webp := append([]byte("RIFF\x24\x00\x00\x00WEBPVP8 \x18\x00\x00\x00"), make([]byte, 24)...)
	onlyPNG := func(mt string) bool { return mt == "image/png" }
	all := func(string) bool { return true }
	if got, bad := MislabeledDisallowed("image/png", webp, onlyPNG); !bad || got != "image/webp" {
		t.Fatalf("disallowed WebP labeled PNG: got %q bad=%v", got, bad)
	}
	for name, tc := range map[string]struct {
		declared string
		body     []byte
		allowed  func(string) bool
	}{
		"allowed proven type":        {"image/png", webp, all},
		"declared type not stripped": {"image/gif", webp, onlyPNG},
		"unrecognized bytes":         {"image/png", []byte("<html></html>"), onlyPNG},
		"nil allow func":             {"image/png", webp, nil},
	} {
		if _, bad := MislabeledDisallowed(tc.declared, tc.body, tc.allowed); bad {
			t.Errorf("%s: flagged", name)
		}
	}
}
