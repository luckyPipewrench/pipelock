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
	}{
		{"no base", `<img src="a.png">`, "", "a.png"},
		{"base is not a link", `<base href="/assets/"><img src="a.png">`, "/assets/", "a.png"},
		{"first base wins", `<base href="/a/"><base href="/b/"><img src="a.png">`, "/a/", "a.png"},
		{"base without href does not count", `<base target="_blank"><base href="/b/">`, "/b/", ""},
		{"base after the link still applies", `<img src="a.png"><base href="/late/">`, "/late/", "a.png"},
		{"upper case tag and attribute", `<BASE HREF=" /x/ "><img src=a.png>`, "/x/", "a.png"},
		{"base inside a comment is ignored", `<!-- <base href="/c/"> --><img src="a.png">`, "", "a.png"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			links, base := htmlLinksAndBase([]byte(tt.body), 16)
			if base != tt.wantBase || strings.Join(links, "|") != tt.wantLinks {
				t.Fatalf("base=%q links=%q, want base=%q links=%q", base, links, tt.wantBase, tt.wantLinks)
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
		{"other host", "https://evil.vendor.example/assets/", "https://app.vendor.example/dir/page"},
		{"protocol relative other host", "//evil.vendor.example/assets/", "https://app.vendor.example/dir/page"},
		{"other port", "https://app.vendor.example:8443/assets/", "https://app.vendor.example/dir/page"},
		{"other scheme", "http://app.vendor.example/assets/", "https://app.vendor.example/dir/page"},
		{"userinfo", "https://user@app.vendor.example/assets/", "https://app.vendor.example/dir/page"},
		{"non http scheme", "data:text/html,x", "https://app.vendor.example/dir/page"},
		{"unparsable", "https://app.vendor.example/%zz", "https://app.vendor.example/dir/page"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sameOriginBase(response, tt.href).String(); got != tt.want {
				t.Fatalf("sameOriginBase(%q) = %q, want %q", tt.href, got, tt.want)
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
		_, _ = io.WriteString(w, `<base href="`+base+`"><img src="`+baseHrefAsset+`">`)
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
		{"cross origin base falls back to the response directory", "OTHER/assets/", site, "/dir/" + baseHrefAsset, http.StatusOK},
		{"cross origin base issues nothing on the page host", "OTHER/assets/", site, "/assets/" + baseHrefAsset, http.StatusForbidden},
		{"cross origin base issues nothing on its own host", "OTHER/assets/", other, "/assets/" + baseHrefAsset, http.StatusForbidden},
		{"cross origin base issues nothing on its host at the response path", "OTHER/assets/", other, "/dir/" + baseHrefAsset, http.StatusForbidden},
		{"other scheme base is ignored", siteHTTP + "/assets/", site, "/assets/" + baseHrefAsset, http.StatusForbidden},
		{"other scheme base falls back to the response directory", siteHTTP + "/assets/", site, "/dir/" + baseHrefAsset, http.StatusOK},
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
