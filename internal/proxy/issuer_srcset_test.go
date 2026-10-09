// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSrcsetURLs(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{"single with descriptor", "/a.png 1x", []string{"/a.png"}},
		{"no descriptor", "/a.png", []string{"/a.png"}},
		{"two candidates", "/a.png 1x, /b.png 2x", []string{"/a.png", "/b.png"}},
		{"no space after comma", "/e.png 640w,/f.png 1280w", []string{"/e.png", "/f.png"}},
		{"comma inside url", "/media/first,second.webp 1x", []string{"/media/first,second.webp"}},
		{"data url keeps its comma", "data:image/png;base64,AAAA,/tail.webp 1x", []string{"data:image/png;base64,AAAA,/tail.webp"}},
		{"trailing comma stripped", "/a.png, /b.png", []string{"/a.png", "/b.png"}},
		{"several trailing commas", "/a.png,,, /b.png 2x", []string{"/a.png", "/b.png"}},
		{"leading commas and space", " ,, /a.png 1x", []string{"/a.png"}},
		{"newline separated", "/a.png 1x,\n/b.png\t2x", []string{"/a.png", "/b.png"}},
		{"comma in descriptor parentheses", "/a.png (x,y) 1x, /b.png", []string{"/a.png", "/b.png"}},
		{"only commas", " , ,, ", nil},
		{"empty", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := srcsetURLs(tt.input)
			if strings.Join(got, "|") != strings.Join(tt.want, "|") || len(got) != len(tt.want) {
				t.Fatalf("srcsetURLs(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// All three srcset attributes share one parser, so each is checked against the
// data: URL case that used to invent a link.
func TestHTMLLinkValuesSrcsetAttributes(t *testing.T) {
	for _, attr := range []string{"srcset", "data-srcset", "imagesrcset"} {
		t.Run(attr, func(t *testing.T) {
			raw := `<img ` + attr + `="data:image/png;base64,AAAA,/phantom-Qm27nB5wL9yP.webp 1x, /real,one.webp 2x">`
			got := htmlLinkValues([]byte(raw), 16)
			want := []string{"data:image/png;base64,AAAA,/phantom-Qm27nB5wL9yP.webp", "/real,one.webp"}
			if strings.Join(got, "|") != strings.Join(want, "|") {
				t.Fatalf("links = %q, want %q", got, want)
			}
		})
	}
}

// A data: URL in a srcset is one candidate. The path after its second comma is
// not a link the page issued, so asking for it stays blocked; a candidate URL
// that itself contains a comma is issued exactly as written.
func TestInterceptSrcsetCandidateBoundaries(t *testing.T) {
	const commaPath = "/media/first,img-headshot-PriscillaMontgomery.Zk93mQ4vR7xT.webp"
	for _, tt := range []struct {
		name   string
		page   string
		target string
		want   int
	}{
		{"data url tail is not issued", `<img srcset="data:image/png;base64,AAAA,` + webMediaPath + ` 1x">`, webMediaPath, http.StatusForbidden},
		{"data url tail in imagesrcset is not issued", `<link rel="preload" imagesrcset="data:image/png;base64,AAAA,` + webMediaPath + ` 1x">`, webMediaPath, http.StatusForbidden},
		{"candidate url with a comma is issued", `<img srcset="` + commaPath + ` 1x">`, commaPath, http.StatusOK},
		{"second candidate is issued", `<img srcset="/x.png 1x,` + webMediaPath + ` 2x">`, webMediaPath, http.StatusOK},
		{"comma split fragment of an issued url stays blocked", `<img srcset="` + commaPath + ` 1x">`, "/img-headshot-PriscillaMontgomery.Zk93mQ4vR7xT.webp", http.StatusForbidden},
	} {
		t.Run(tt.name, func(t *testing.T) {
			site := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				if r.URL.Path == "/" {
					_, _ = io.WriteString(w, tt.page)
					return
				}
				_, _ = io.WriteString(w, "ok")
			}))
			defer site.Close()
			h := newWebPlatformHarness(t)
			if got := h.do(site, "/", "agent-one", nil); got != http.StatusOK {
				t.Fatalf("page status=%d", got)
			}
			if got := h.do(site, tt.target, "agent-one", nil); got != tt.want {
				t.Fatalf("status=%d, want %d", got, tt.want)
			}
		})
	}
}
