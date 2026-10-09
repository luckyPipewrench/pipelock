// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// issuerQueryPageOrigin names the rule that admitted a value that is only the
// request's own Referer or Origin origin, base64 encoded. It carries nothing
// the destination does not already receive in that header.
const issuerQueryPageOrigin issuerQueryKind = "page_origin_echo"

// issuerQueryMaxHTMLBytes bounds how much of one HTML response is tokenized
// for links. A page past the bound issues links only from its first bytes;
// the rest keep the ordinary entropy gate.
const issuerQueryMaxHTMLBytes = 4 << 20

// htmlLinkAttrs are the HTML attributes whose value the document declares to
// be a URL the browser will fetch or navigate to.
var htmlLinkAttrs = map[string]bool{
	"src": true, "href": true, "poster": true, "data-src": true,
}

// htmlSrcsetAttrs hold image candidates in the WHATWG srcset syntax.
var htmlSrcsetAttrs = map[string]bool{
	"srcset": true, "data-srcset": true, "imagesrcset": true,
}

// htmlLinkValues returns up to limit URL references an HTML document declares
// in its link attributes, in document order. The WHATWG tokenizer decides
// what is an attribute, so a URL in text, a comment, a script or a style
// block is not a link.
func htmlLinkValues(body []byte, limit int) []string {
	links, _ := htmlLinksAndBase(body, limit)
	return links
}

// htmlLinksAndBase is htmlLinkValues plus the href of the document's first
// <base> element that carries one, which is the base every relative reference
// resolves against. A <base> is not itself a link.
func htmlLinksAndBase(body []byte, limit int) (links []string, base string) {
	if limit <= 0 || len(body) == 0 {
		return nil, ""
	}
	if len(body) > issuerQueryMaxHTMLBytes {
		body = body[:issuerQueryMaxHTMLBytes]
	}
	var out []string
	baseSeen := false
	z := html.NewTokenizer(bytes.NewReader(body))
	for len(out) < limit {
		switch z.Next() {
		case html.ErrorToken:
			return out, base
		case html.StartTagToken, html.SelfClosingTagToken:
			tag, _ := z.TagName()
			isBase := string(tag) == "base"
			for {
				key, val, more := z.TagAttr()
				name := strings.ToLower(string(key))
				switch {
				case isBase:
					if name == "href" && !baseSeen {
						baseSeen = true
						base = strings.TrimSpace(string(val))
					}
				case htmlLinkAttrs[name]:
					if v := strings.TrimSpace(string(val)); v != "" && len(out) < limit {
						out = append(out, v)
					}
				case htmlSrcsetAttrs[name]:
					for _, candidate := range srcsetURLs(string(val)) {
						if len(out) < limit {
							out = append(out, candidate)
						}
					}
				}
				if !more {
					break
				}
			}
		}
	}
	return out, base
}

// srcsetURLs returns the candidate URLs of a srcset attribute value, following
// the WHATWG "parse a srcset attribute" algorithm: a candidate URL runs to the
// next ASCII whitespace, so a comma inside it belongs to the URL, trailing
// commas are separators and are stripped, and descriptors (w, x, h) are
// skipped. Splitting on every comma instead would invent a URL out of the tail
// of a data: URL and miss a real URL that contains a comma.
func srcsetURLs(input string) []string {
	isSpace := func(c byte) bool {
		return c == ' ' || c == '\t' || c == '\n' || c == '\f' || c == '\r'
	}
	var out []string
	pos := 0
	for pos < len(input) {
		for pos < len(input) && (isSpace(input[pos]) || input[pos] == ',') {
			pos++
		}
		if pos >= len(input) {
			break
		}
		start := pos
		for pos < len(input) && !isSpace(input[pos]) {
			pos++
		}
		candidate := input[start:pos]
		if trimmed := strings.TrimRight(candidate, ","); trimmed != candidate {
			// The URL ended in commas: the candidate has no descriptors.
			if trimmed != "" {
				out = append(out, trimmed)
			}
			continue
		}
		out = append(out, candidate)
		// Skip the descriptors up to the comma that ends the candidate; a
		// comma inside parentheses does not end it.
		inParens := false
		for pos < len(input) {
			c := input[pos]
			pos++
			if inParens {
				inParens = c != ')'
			} else if c == '(' {
				inParens = true
			} else if c == ',' {
				break
			}
		}
	}
	return out
}

// pageOriginEchoed reports whether value is exactly the base64 encoding of the
// origin of this request's own Referer or Origin header. The destination
// already receives that header unchanged, so the value tells it nothing new
// and is not a channel for data the agent holds. Only the origin form is
// accepted: scheme, host and port, with no path, query or userinfo. A value
// that decodes to anything else, or that is absent a single such header, is
// scored normally.
//
// The encoding is not chosen by name. Standard and URL alphabets, padded or
// not, are accepted, as is "." for padding, because that is how a widely
// embedded captcha frame spells it. Strict decoding rejects non-zero trailing
// bits, so one origin has a handful of spellings and no more.
func pageOriginEchoed(h http.Header, value string) bool {
	if len(value) < 8 || len(value) > 512 {
		return false
	}
	origins := headerOrigins(h)
	if len(origins) == 0 {
		return false
	}
	padded := strings.TrimRight(value, ".")
	if pad := len(value) - len(padded); pad > 0 {
		padded += strings.Repeat("=", pad)
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding.Strict(), base64.RawStdEncoding.Strict(),
		base64.URLEncoding.Strict(), base64.RawURLEncoding.Strict(),
	} {
		decoded, err := enc.DecodeString(padded)
		if err != nil {
			continue
		}
		for _, origin := range origins {
			if string(decoded) == origin {
				return true
			}
		}
	}
	return false
}

// headerOrigins returns the canonical origin spellings of the request's single
// Referer and single Origin header: with and without an explicit default port.
// A header that appears twice, is not an absolute http(s) URL, or carries
// userinfo contributes nothing.
func headerOrigins(h http.Header) []string {
	var out []string
	for _, name := range []string{"Referer", "Origin"} {
		values := h.Values(name)
		if len(values) != 1 {
			continue
		}
		u, err := url.Parse(strings.TrimSpace(values[0]))
		if err != nil || u.User != nil || u.Hostname() == "" {
			continue
		}
		scheme := strings.ToLower(u.Scheme)
		def := map[string]string{"http": "80", "https": "443"}[scheme]
		if def == "" {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		port := u.Port()
		out = append(out, scheme+"://"+host+":"+orDefault(port, def))
		if port == "" || port == def {
			out = append(out, scheme+"://"+host)
		}
	}
	return out
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
