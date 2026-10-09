// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const baseHrefAsset = "img-headshot-PriscillaMontgomery.Zk93mQ4vR7xT.webp"

func TestHTMLLinksAndBase(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantBase  string
		wantLinks string
		limit     int
		unknown   bool
	}{
		{"no base", `<img src="a.png">`, "", "a.png", 0, false},
		{"base is not a link", `<base href="/assets/"><img src="a.png">`, "/assets/", "a.png", 0, false},
		{"two base tags are ambiguous even if one has no href", `<base target="_blank"><base href="/b/">`, "/b/", "", 0, true},
		{"base target only, no href", `<base target="_blank"><img src="a.png">`, "", "a.png", 0, true},
		{"base after the link still applies", `<img src="a.png"><base href="/late/">`, "/late/", "a.png", 0, false},
		{"upper case tag and attribute", `<BASE HREF=" /x/ "><img src=a.png>`, "/x/", "a.png", 0, false},
		{"base spelled in a comment is treated as ambiguous", `<!-- <base href="/c/"> --><img src="a.png">`, "", "a.png", 0, true},
		{"base after the link limit still counts", `<img src="a.png"><img src="b.png"><base href="/late/">`, "/late/", "a.png", 1, false},
		// Ambiguous documents: the browser's choice depends on parse state
		// Pipelock does not share, so the base is unknown.
		{"two bases are ambiguous", `<base href="/a/"><base href="/b/"><img src="a.png">`, "/a/", "a.png", 0, true},
		{"inert template base is ambiguous", `<template><base href="/t/"></template><img src="a.png">`, "", "a.png", 0, true},
		{"nested template", `<template><template></template><base href="/t/"></template><base href="/real/">`, "/real/", "", 0, true},
		{"noscript base depends on scripting", `<noscript><base href="/n/"></noscript><img src="a.png">`, "", "a.png", 0, true},
		{"svg decoy base", `<svg><base href="/p/"></svg><base href="/real/">`, "/real/", "", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limit := tt.limit
			if limit == 0 {
				limit = 16
			}
			links, base, known := htmlLinksAndBase([]byte(tt.body), limit)
			if known == tt.unknown {
				t.Fatalf("known=%v, want %v", known, !tt.unknown)
			}
			if base != tt.wantBase || strings.Join(links, "|") != tt.wantLinks {
				t.Fatalf("base=%q links=%q, want base=%q links=%q", base, links, tt.wantBase, tt.wantLinks)
			}
		})
	}
}

// A document cut at the inspection limit with no base in the inspected part
// may have one later, so relative links cannot be trusted to resolve against
// the response URL.
func TestHTMLLinksAndBaseTruncated(t *testing.T) {
	big := []byte(`<img src="a.png">` + strings.Repeat(" ", issuerQueryMaxHTMLBytes))
	if _, _, known := htmlLinksAndBase(big, 4); known {
		t.Fatal("truncated document without a base reported its base as known")
	}
	// The same holds when the link limit is reached before the end of the
	// inspected part.
	manyLinks := []byte(`<img src="a.png"><img src="b.png">` + strings.Repeat(" ", issuerQueryMaxHTMLBytes))
	if _, _, known := htmlLinksAndBase(manyLinks, 1); known {
		t.Fatal("truncated document at the link limit reported its base as known")
	}
	withBase := []byte(`<base href="/b/"><img src="a.png">` + strings.Repeat(" ", issuerQueryMaxHTMLBytes))
	if _, base, known := htmlLinksAndBase(withBase, 4); !known || base != "/b/" {
		t.Fatalf("truncated document with an early base: base=%q known=%v", base, known)
	}
}

// The base a browser uses is decided by the document tree, not by the first
// tag spelled <base>: one in SVG or MathML is a foreign element, template and
// noscript content is inert, and a self-closing flag does not close a
// <template>. Each case pairs a decoy base with the real one a browser uses.
func TestDocumentBaseFollowsTreeConstruction(t *testing.T) {
	const realBase = "https://other.vendor.example/real/"
	for _, tt := range []struct{ name, body, want string }{
		{"svg base is foreign", `<svg><base href="/phantom/"></svg><base href="` + realBase + `">`, realBase},
		{"mathml base is foreign", `<math><base href="/phantom/"></math><base href="` + realBase + `">`, realBase},
		{"self closing template still opens", `<template/><base href="/phantom/"></template><base href="` + realBase + `">`, realBase},
		{"template in svg is foreign", `<svg><template></svg><base href="` + realBase + `">`, realBase},
		{"template in mathml is foreign", `<math><template></math><base href="` + realBase + `">`, realBase},
		{"noscript content is inert", `<noscript><base href="/phantom/"></noscript><base href="` + realBase + `">`, realBase},
		{"stray template end", `</template><base href="` + realBase + `">`, realBase},
		{"head template", `<head><template><base href="/phantom/"></template></head><base href="` + realBase + `">`, realBase},
		{"base in body", `<body><div><base href="` + realBase + `"></div>`, realBase},
		{"malformed template", `<template><div></template></template><base href="` + realBase + `">`, realBase},
		{"base without href is skipped", `<base target="x"><base href="/b/">`, "/b/"},
		{"html base inside svg foreignObject counts", `<svg><foreignObject><div><base href="/fo/"></div></foreignObject></svg><base href="` + realBase + `">`, "/fo/"},
		{"html base inside mathml annotation-xml html counts", `<math><annotation-xml encoding="text/html"><div><base href="/ax/"></div></annotation-xml></math>`, "/ax/"},
		{"no base", `<img src="a.png">`, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := documentBase([]byte(tt.body))
			if got != tt.want {
				t.Fatalf("documentBase = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestASCIITransparentDocument(t *testing.T) {
	pad := strings.Repeat(" ", 1100)
	for _, tt := range []struct {
		name, ct, body string
		want           bool
	}{
		{"declared utf-8", "text/html; charset=utf-8", "<p>x", true},
		{"declared utf-8 wins over escape bytes", "text/html; charset=utf-8", "<p>\x1b$B", true},
		{"undeclared plain ascii", "text/html", "<p>x", true},
		{"early meta utf-8", "text/html", `<meta charset="utf-8"><p>x`, true},
		{"declared shift encoding", "text/html; charset=iso-2022-jp", "<p>x", false},
		{"declared utf-16", "text/html; charset=utf-16le", "<p>x", false},
		{"utf-16 bom", "text/html", "\xff\xfe<\x00p\x00", false},
		{"undeclared escape byte", "text/html", "<p>\x1b$B", false},
		{"undeclared nul byte", "text/html", "<\x00p\x00", false},
		{"late meta charset", "text/html", "<p>" + pad + `<meta charset="iso-2022-jp">`, false},
		{"long undeclared page without a late declaration", "text/html", "<p>" + pad + "<p>y", true},
		{"late meta on a declared page", "text/html; charset=utf-8", "<p>" + pad + `<meta charset="iso-2022-jp">`, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := asciiTransparentDocument([]byte(tt.body), tt.ct); got != tt.want {
				t.Fatalf("asciiTransparentDocument = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSameOriginBase(t *testing.T) {
	response := mustIssuerQueryURL(t, "https://app.vendor.example/dir/page")
	tests := []struct {
		name string
		href string
		want string
	}{
		{"empty", "", "https://app.vendor.example/dir/page"},
		{"rooted path", "/assets/", "https://app.vendor.example/assets/"},
		{"relative path", "sub/", "https://app.vendor.example/dir/sub/"},
		{"absolute same origin", "https://app.vendor.example/assets/", "https://app.vendor.example/assets/"},
		{"explicit default port", "https://app.vendor.example:443/assets/", "https://app.vendor.example:443/assets/"},
		{"mixed case host", "https://APP.vendor.example/assets/", "https://APP.vendor.example/assets/"},
		{"other host", "https://evil.vendor.example/assets/", ""},
		{"protocol relative other host", "//evil.vendor.example/assets/", ""},
		{"other port", "https://app.vendor.example:8443/assets/", ""},
		{"other scheme", "http://app.vendor.example/assets/", ""},
		{"userinfo", "https://user@app.vendor.example/assets/", ""},
		{"non http scheme", "data:text/html,x", ""},
		{"unparsable", "https://app.vendor.example/%zz", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, usable := sameOriginBase(response, tt.href)
			if usable != (tt.want != "") || (usable && got.String() != tt.want) {
				t.Fatalf("sameOriginBase(%q) = %v, %v; want %q", tt.href, got, usable, tt.want)
			}
		})
	}
}

// A same-origin <base href> moves where relative links resolve, so the asset
// the browser fetches is the one the page issued. A base on another origin is
// ignored: it must not grant issuance on either host.
func TestInterceptBaseHref(t *testing.T) {
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer other.Close()
	siteURL := ""
	site := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path != "/dir/page" {
			_, _ = io.WriteString(w, "ok")
			return
		}
		base := r.URL.Query().Get("base")
		base = strings.ReplaceAll(base, "SITE", siteURL)
		base = strings.ReplaceAll(base, "OTHER", other.URL)
		page := `<base href="` + base + `"><img src="` + baseHrefAsset + `"><img src="` + siteURL + `/abs/` + baseHrefAsset + `">`
		if base == "SVGDECOY" {
			page = `<svg><base href="/phantom/"></svg><base href="` + other.URL + `/real/"><img src="` + baseHrefAsset + `"><img src="` + siteURL + `/abs/` + baseHrefAsset + `">`
		}
		if base == "ISO2022JP" || base == "UTF8" {
			cs := map[string]string{"ISO2022JP": "iso-2022-jp", "UTF8": "utf-8"}[base]
			w.Header().Set("Content-Type", "text/html; charset="+cs)
			page = `<img src="` + baseHrefAsset + `"><img src="` + siteURL + `/abs/` + baseHrefAsset + `">`
		}
		if base == "METAJIS" {
			page = `<meta charset="iso-2022-jp"><img src="` + baseHrefAsset + `">`
		}
		if base == "XHTML" {
			w.Header().Set("Content-Type", "application/xhtml+xml")
			page = `<html xmlns="http://www.w3.org/1999/xhtml"><body><img src="` + baseHrefAsset + `"/><img src="` + siteURL + `/abs/` + baseHrefAsset + `"/></body></html>`
		}
		if base == "TEMPLATE" {
			page = `<template><base href="/assets/"></template><img src="` + baseHrefAsset + `">`
		}
		_, _ = io.WriteString(w, page)
	}))
	defer site.Close()
	siteURL = site.URL
	siteHTTP := "http" + strings.TrimPrefix(site.URL, "https")

	for _, tt := range []struct {
		name   string
		base   string
		server *httptest.Server
		target string
		want   int
	}{
		{"rooted base issues the asset under it", "/assets/", site, "/assets/" + baseHrefAsset, http.StatusOK},
		{"rooted base does not issue the response directory", "/assets/", site, "/dir/" + baseHrefAsset, http.StatusForbidden},
		{"absolute same origin base", "SITE/assets/", site, "/assets/" + baseHrefAsset, http.StatusOK},
		{"absolute same origin base other directory", "SITE/assets/", site, "/dir/" + baseHrefAsset, http.StatusForbidden},
		{"no base resolves against the response", "", site, "/dir/" + baseHrefAsset, http.StatusOK},
		{"cross origin base issues no relative link on the page host", "OTHER/assets/", site, "/dir/" + baseHrefAsset, http.StatusForbidden},
		{"cross origin base issues nothing on the page host", "OTHER/assets/", site, "/assets/" + baseHrefAsset, http.StatusForbidden},
		{"cross origin base issues nothing on its own host", "OTHER/assets/", other, "/assets/" + baseHrefAsset, http.StatusForbidden},
		{"cross origin base issues nothing on its host at the response path", "OTHER/assets/", other, "/dir/" + baseHrefAsset, http.StatusForbidden},
		{"absolute link still issues under a cross origin base", "OTHER/assets/", site, "/abs/" + baseHrefAsset, http.StatusOK},
		{"absolute link still issues under an ambiguous base", "SVGDECOY", site, "/abs/" + baseHrefAsset, http.StatusOK},
		{"iso-2022-jp relative link is untrusted", "ISO2022JP", site, "/dir/" + baseHrefAsset, http.StatusForbidden},
		{"iso-2022-jp absolute link issues", "ISO2022JP", site, "/abs/" + baseHrefAsset, http.StatusOK},
		{"meta charset shift encoding relative link is untrusted", "METAJIS", site, "/dir/" + baseHrefAsset, http.StatusForbidden},
		{"utf-8 declared relative link issues", "UTF8", site, "/dir/" + baseHrefAsset, http.StatusOK},
		{"xhtml relative link is untrusted", "XHTML", site, "/dir/" + baseHrefAsset, http.StatusForbidden},
		{"xhtml absolute link issues", "XHTML", site, "/abs/" + baseHrefAsset, http.StatusOK},
		{"svg decoy base issues nothing", "SVGDECOY", site, "/phantom/" + baseHrefAsset, http.StatusForbidden},
		{"svg decoy base issues nothing in the response directory", "SVGDECOY", site, "/dir/" + baseHrefAsset, http.StatusForbidden},
		{"inert template base makes relative links untrusted", "TEMPLATE", site, "/dir/" + baseHrefAsset, http.StatusForbidden},
		{"template base issues nothing under it", "TEMPLATE", site, "/assets/" + baseHrefAsset, http.StatusForbidden},
		{"other scheme base is ignored", siteHTTP + "/assets/", site, "/assets/" + baseHrefAsset, http.StatusForbidden},
		{"other scheme base issues no relative link", siteHTTP + "/assets/", site, "/dir/" + baseHrefAsset, http.StatusForbidden},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := newWebPlatformHarness(t)
			if got := h.do(site, "/dir/page?base="+url.QueryEscape(tt.base), "agent-one", nil); got != http.StatusOK {
				t.Fatalf("page status=%d", got)
			}
			if got := h.do(tt.server, tt.target, "agent-one", nil); got != tt.want {
				t.Fatalf("status=%d, want %d", got, tt.want)
			}
		})
	}
}
