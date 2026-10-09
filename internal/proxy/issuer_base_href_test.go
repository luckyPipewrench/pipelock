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
	}{
		{"no base", `<img src="a.png">`, "", "a.png", 0},
		{"base is not a link", `<base href="/assets/"><img src="a.png">`, "/assets/", "a.png", 0},
		{"first base wins", `<base href="/a/"><base href="/b/"><img src="a.png">`, "/a/", "a.png", 0},
		{"base without href does not count", `<base target="_blank"><base href="/b/">`, "/b/", "", 0},
		{"base after the link still applies", `<img src="a.png"><base href="/late/">`, "/late/", "a.png", 0},
		{"upper case tag and attribute", `<BASE HREF=" /x/ "><img src=a.png>`, "/x/", "a.png", 0},
		{"base inside a comment is ignored", `<!-- <base href="/c/"> --><img src="a.png">`, "", "a.png", 0},
		{"base inside template content is inert", `<template><base href="/t/"></template><img src="a.png">`, "", "a.png", 0},
		{"nested template", `<template><template></template><base href="/t/"></template><base href="/real/">`, "/real/", "", 0},
		{"base after the link limit still counts", `<img src="a.png"><img src="b.png"><base href="/late/">`, "/late/", "a.png", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limit := tt.limit
			if limit == 0 {
				limit = 16
			}
			links, base, known := htmlLinksAndBase([]byte(tt.body), limit)
			if !known {
				t.Fatal("base unknown for an untruncated document")
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
	withBase := []byte(`<base href="/b/"><img src="a.png">` + strings.Repeat(" ", issuerQueryMaxHTMLBytes))
	if _, base, known := htmlLinksAndBase(withBase, 4); !known || base != "/b/" {
		t.Fatalf("truncated document with an early base: base=%q known=%v", base, known)
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
		{"template base is inert", "TEMPLATE", site, "/dir/" + baseHrefAsset, http.StatusOK},
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
