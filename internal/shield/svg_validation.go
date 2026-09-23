// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package shield

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	svgNamespace    = "http://www.w3.org/2000/svg"
	xlinkNamespace  = "http://www.w3.org/1999/xlink"
	xmlNamespace    = "http://www.w3.org/XML/1998/namespace"
	xmlnsNamespace  = "xmlns"
	xhtmlNamespace  = "http://www.w3.org/1999/xhtml"
	mathMLNamespace = "http://www.w3.org/1998/Math/MathML"
)

// ValidateSVG establishes the delivery contract for an SVG response. The
// regex rewriter remains useful for browser-shield transformations, but it is
// not proof that arbitrary XML was parsed or that every active SVG construct
// was removed. SVG is delivered only after this strict, complete parse.
func ValidateSVG(document string) error {
	dec := xml.NewDecoder(strings.NewReader(document))
	// The caller hands over text that is already decoded (UTF-16 responses
	// are strictly decoded before Shield sees them), so a UTF-8 or UTF-16
	// declaration describes bytes that no longer exist and is accepted as a
	// pass-through. Any other declared charset is refused: validating bytes
	// under a different decoding than the browser uses is not a proof.
	dec.CharsetReader = func(label string, input io.Reader) (io.Reader, error) {
		switch strings.ToLower(strings.TrimSpace(label)) {
		case "utf-8", "utf8", "utf-16", "utf-16le", "utf-16be":
			return input, nil
		default:
			return nil, errors.New("unsupported SVG charset declaration")
		}
	}
	var elements []xml.Name
	// styleText accumulates each open <style> element's direct text children.
	// A browser applies their concatenation, so a CDATA section or comment
	// can split "@import" or "url(" across tokens; the check must run on the
	// joined text, at the element's end.
	var styleText []*strings.Builder
	rootSeen := false

	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			if !rootSeen || len(elements) != 0 {
				return fmt.Errorf("malformed SVG document")
			}
			return nil
		}
		if err != nil {
			// Report only the line: the parser's message quotes element and
			// entity names from the response, and this reason reaches the
			// client and the audit log.
			var syntaxErr *xml.SyntaxError
			if errors.As(err, &syntaxErr) {
				return fmt.Errorf("malformed SVG document at line %d", syntaxErr.Line)
			}
			return errors.New("malformed SVG document")
		}

		switch node := tok.(type) {
		case xml.StartElement:
			if rootSeen && len(elements) == 0 {
				return errors.New("SVG document has more than one root element")
			}
			if !rootSeen {
				rootSeen = true
				if node.Name.Local != "svg" || node.Name.Space != svgNamespace {
					return fmt.Errorf("SVG root must use the SVG namespace")
				}
			}
			// A non-SVG-namespace element (metadata, RDF, editor state) is not
			// rendered by an SVG user agent, and refusing them rejected most
			// real documents. svgActiveElement below is namespace-agnostic on
			// the local name, so script/foreignObject/handler stay blocked
			// however they are prefixed.
			// XHTML and MathML elements are live in an XML document even
			// outside foreignObject: an XHTML img or link fetches as soon as
			// the element is created, whether or not it is rendered.
			if node.Name.Space == xhtmlNamespace || node.Name.Space == mathMLNamespace {
				return errors.New("SVG contains an XHTML or MathML element")
			}
			if svgActiveElement(node.Name.Local) {
				// Only a fixed, known element name reaches the message.
				return fmt.Errorf("SVG contains active element %q", strings.ToLower(node.Name.Local))
			}
			for _, attr := range node.Attr {
				if err := validateSVGAttribute(node.Name.Local, attr); err != nil {
					return err
				}
			}
			elements = append(elements, node.Name)
			if node.Name.Local == "style" {
				styleText = append(styleText, &strings.Builder{})
			} else {
				styleText = append(styleText, nil)
			}
		case xml.EndElement:
			if len(elements) == 0 {
				return fmt.Errorf("malformed SVG document")
			}
			if text := styleText[len(styleText)-1]; text != nil && svgUnsafeCSS(text.String(), true) {
				return fmt.Errorf("SVG stylesheet contains an external or executable reference")
			}
			elements = elements[:len(elements)-1]
			styleText = styleText[:len(styleText)-1]
		case xml.CharData:
			if len(styleText) > 0 && styleText[len(styleText)-1] != nil {
				styleText[len(styleText)-1].Write(node)
			}
		case xml.Directive:
			// <!DOCTYPE svg PUBLIC ...> is ordinary SVG 1.1 boilerplate. An
			// INTERNAL SUBSET is the dangerous form, because that is where
			// entity declarations live, so it stays refused.
			directive := strings.TrimSpace(string(node))
			if !strings.HasPrefix(strings.ToUpper(directive), "DOCTYPE") {
				return fmt.Errorf("SVG directives are not allowed")
			}
			if strings.ContainsAny(directive, "[]") || strings.Contains(strings.ToUpper(directive), "ENTITY") {
				return fmt.Errorf("SVG doctype declares an internal subset")
			}
		case xml.ProcInst:
			if !strings.EqualFold(node.Target, "xml") {
				return fmt.Errorf("SVG processing instructions are not allowed")
			}
		}
	}
}

func svgActiveElement(local string) bool {
	switch strings.ToLower(local) {
	case "script", "foreignobject", "iframe", "object", "embed", "frame", "audio", "video",
		"animate", "animatemotion", "animatetransform", "set", "handler", "listener":
		return true
	default:
		return false
	}
}

// svgFetchesExternalHref reports whether an href on this element causes the
// user agent to RETRIEVE the referenced resource and fold it into the document.
// Those must stay fragment-only. A plain <a> hyperlink retrieves nothing until
// a human follows it, and refusing it rejected ordinary documents including
// W3C's own SVG logo.
func svgFetchesExternalHref(element string) bool {
	switch strings.ToLower(element) {
	case "a":
		return false
	default:
		return true
	}
}

func validateSVGAttribute(element string, attr xml.Attr) error {
	// A namespace DECLARATION is inert: it binds a prefix and renders nothing.
	// Go surfaces xmlns:foo="..." as an attribute in the "xmlns" space, so
	// rejecting unknown spaces here refused every SVG declaring xlink, RDF or
	// an editor namespace. The checks below are what actually carry the
	// security property, and they apply in EVERY namespace.
	if attr.Name.Space == xmlnsNamespace || attr.Name.Local == "xmlns" {
		return nil
	}
	local := strings.ToLower(attr.Name.Local)
	if strings.HasPrefix(local, "on") {
		return errors.New("SVG contains an event handler attribute")
	}
	if local == "href" && !strings.HasPrefix(strings.TrimSpace(attr.Value), "#") {
		if svgFetchesExternalHref(element) {
			return errors.New("SVG contains an external reference on an element that fetches it")
		}
		// A hyperlink retrieves nothing, but its SCHEME can still execute:
		// javascript: and vbscript: run on click and data: can carry a whole
		// HTML document. Retrieval and execution are different properties and
		// this href is only exempt from the first.
		if !svgHyperlinkSchemeAllowed(attr.Value) {
			return fmt.Errorf("SVG hyperlink uses a disallowed scheme")
		}
	}
	// Presentation attributes (fill, stroke, filter, mask, clip-path,
	// marker-*, cursor) are parsed as CSS values, so an external url() there
	// fetches exactly as it does in a style attribute. Only unprefixed
	// attributes are CSS; a foreign-namespace attribute such as an editor's
	// export path is not interpreted by the user agent.
	if (attr.Name.Space == "" || attr.Name.Space == svgNamespace) && svgUnsafeCSS(attr.Value, local == "style") {
		return fmt.Errorf("SVG attribute contains an external or executable reference")
	}
	return nil
}

// svgHyperlinkSchemeAllowed reports whether an <a> href may be delivered.
// Normalisation mirrors what a browser does before it parses a URL: ASCII
// whitespace and control characters are stripped, so "java\tscript:" cannot
// hide behind a tab. A value with no scheme is a relative reference and is
// allowed; a value with one must name a scheme that cannot execute.
func svgHyperlinkSchemeAllowed(value string) bool {
	var b strings.Builder
	for _, r := range value {
		if r <= 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	normalized := strings.ToLower(b.String())

	colon := strings.IndexByte(normalized, ':')
	if colon <= 0 {
		return true // relative reference, no scheme to abuse
	}
	scheme := normalized[:colon]
	// RFC 3986 scheme charset. Anything outside it is not a scheme, so the
	// colon belongs to a relative path such as "a:b" in a filename.
	for i := 0; i < len(scheme); i++ {
		c := scheme[i]
		valid := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.'
		if !valid {
			return true
		}
	}
	switch scheme {
	case "http", "https", "mailto":
		return true
	default:
		return false
	}
}

// svgUnsafeCSS reports whether a CSS value can fetch or execute. A url()
// that names an in-document fragment (fill="url(#gradient)") is how every
// editor references gradients, clip paths and filters, and is allowed; any
// other url() target fetches. stylesheet is true for a style attribute or a
// <style> element, where a backslash escape can spell "url" or "@import"
// without the literal text, so escapes are refused there.
func svgUnsafeCSS(value string, stylesheet bool) bool {
	v := strings.ToLower(value)
	if stylesheet && strings.Contains(v, "\\") {
		return true
	}
	if stylesheet {
		// Stylesheet-only constructs. A presentation attribute such as fill
		// takes only a url() reference, and checking these there would
		// refuse ordinary label text like "image(s)".
		for _, fn := range []string{"@import", "expression(", "image(", "image-set(", "cross-fade(", "src("} {
			if strings.Contains(v, fn) {
				return true
			}
		}
	}
	for rest := v; ; {
		idx := strings.Index(rest, "url(")
		if idx < 0 {
			return false
		}
		rest = rest[idx+len("url("):]
		target := strings.TrimLeft(rest, " \t\n\r\f")
		target = strings.TrimLeft(target, "\"'")
		if !strings.HasPrefix(target, "#") {
			return true
		}
	}
}
