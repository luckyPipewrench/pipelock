// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// issuerQueryPageOrigin names the rule that admitted a value that is only the
// request's own Referer or Origin origin, base64 encoded, for an origin that
// served this session an HTML document. It carries nothing the destination
// does not already receive in that header.
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

// baseTagSpelling matches anything an HTML parser could read as a <base>
// start tag.
var baseTagSpelling = regexp.MustCompile(`(?i)<base[\t\n\f\r />]`)

// htmlSrcsetAttrs hold image candidates in the WHATWG srcset syntax.
var htmlSrcsetAttrs = map[string]bool{
	"srcset": true, "data-srcset": true, "imagesrcset": true,
}

// htmlLinkValues returns up to limit URL references an HTML document declares
// in its link attributes, in document order. The WHATWG tokenizer decides
// what is an attribute, so a URL in text, a comment, a script or a style
// block is not a link.
func htmlLinkValues(body []byte, limit int) []string {
	links, _, _ := htmlLinksAndBase(body, limit)
	return links
}

// htmlLinksAndBase is htmlLinkValues plus the href of the document's
// effective <base>, which is the base every relative reference resolves
// against. A <base> is not itself a link. baseKnown is false when the document
// was cut at the inspection limit without a base in the inspected part: a
// base past the cut cannot be ruled out, so the caller must not resolve
// relative links against the response URL.
func htmlLinksAndBase(body []byte, limit int) (links []string, base string, baseKnown bool) {
	if limit <= 0 || len(body) == 0 {
		return nil, "", true
	}
	truncated := len(body) > issuerQueryMaxHTMLBytes
	if truncated {
		body = body[:issuerQueryMaxHTMLBytes]
	}
	// Count base tags in the raw bytes, not the token stream: the tokenizer
	// reads <noscript> as text, yet a browser with scripting off honors a
	// <base> inside it. A spelling in a comment or script also counts, which
	// can only make the answer more cautious. The full tree parse runs only
	// when exactly one spelling exists; otherwise the base is unknown anyway.
	tags := len(baseTagSpelling.FindAllIndex(body, 2))
	var baseSeen bool
	if tags == 1 {
		base, baseSeen = documentBase(body)
	}
	var out []string
	z := html.NewTokenizer(bytes.NewReader(body))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		tag, hasAttr := z.TagName()
		if string(tag) == "base" {
			// A <base> is not a link; documentBase reads it.
			continue
		}
		if len(out) >= limit {
			continue
		}
		for hasAttr {
			key, val, more := z.TagAttr()
			hasAttr = more
			attr := strings.ToLower(string(key))
			switch {
			case htmlLinkAttrs[attr]:
				if v := strings.TrimSpace(string(val)); v != "" && len(out) < limit {
					out = append(out, v)
				}
			case htmlSrcsetAttrs[attr]:
				for _, candidate := range srcsetURLs(string(val)) {
					if len(out) < limit {
						out = append(out, candidate)
					}
				}
			}
		}
	}
	// Which <base> a browser uses depends on the parse: scripting turns
	// <noscript> content inert or live, foreign content and integration
	// points move elements in and out of the HTML namespace. A document with
	// exactly one base tag that the tree selected is trusted; anything else
	// is treated as unknown, so only absolute links are issued.
	known := !truncated || baseSeen
	switch {
	case tags == 0:
	case tags == 1 && baseSeen:
	default:
		known = false
	}
	return out, base, known
}

// documentBase returns the href of the first <base> element with an href in
// the document tree, the one a browser resolves relative links against. It
// runs the WHATWG tree-construction algorithm rather than scanning tags,
// because where a <base> sits decides whether it counts: one parsed as an SVG
// or MathML element is foreign, one inside <template> content is inert, and a
// self-closing flag does not close a <template>.
// Only those structural rules separate the base a browser uses from a tag
// that merely looks like one.
func documentBase(body []byte) (string, bool) {
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return "", false
	}
	var find func(*html.Node) (string, bool)
	find = func(n *html.Node) (string, bool) {
		if n.Type == html.ElementNode {
			if n.Namespace == "" && n.DataAtom == atom.Template {
				return "", false
			}
			// A foreign (SVG or MathML) element is never the base, but an
			// integration point such as <foreignObject> puts HTML elements
			// back under it, so its subtree is still searched.
			if n.Namespace == "" && n.DataAtom == atom.Base {
				for _, a := range n.Attr {
					if a.Namespace == "" && a.Key == "href" {
						return strings.TrimSpace(a.Val), true
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if href, ok := find(c); ok {
				return href, true
			}
		}
		return "", false
	}
	return find(doc)
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
// origin of this request's own Referer or Origin header, and returns that
// origin. Only the origin form is accepted: scheme, host and port, with no
// path, query or userinfo. A value that decodes to anything else, or that is
// absent a single such header, is scored normally.
//
// The header is written by the agent, so matching it proves nothing about the
// page. The caller must also confirm the returned origin served this session
// an HTML document (issuerQueryStore.documentServed) before skipping the
// entropy gate; with that, the value names an origin the session actually
// navigated to and the destination already receives in the header.
//
// The encoding is not chosen by name. Standard and URL alphabets, padded or
// not, are accepted, as is "." for padding, because that is how a widely
// embedded captcha frame spells it. Strict decoding rejects non-zero trailing
// bits, so one origin has a handful of spellings and no more.
func pageOriginEchoed(h http.Header, value string) (*url.URL, bool) {
	if len(value) < 8 || len(value) > 512 {
		return nil, false
	}
	origins := headerOrigins(h)
	if len(origins) == 0 {
		return nil, false
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
			if string(decoded) != origin {
				continue
			}
			parsed, err := url.Parse(origin)
			if err != nil {
				return nil, false
			}
			return parsed, true
		}
	}
	return nil, false
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
