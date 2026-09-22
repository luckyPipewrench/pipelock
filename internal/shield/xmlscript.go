// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package shield

import (
	"encoding/xml"
	"errors"
	"io"
	"strings"
)

// scriptSpan is a complete script element, as byte offsets into the document
// it was found in. Offsets are used rather than rewritten text because the
// shield must return the original bytes for everything it does not remove.
type scriptSpan struct {
	start   int // first byte of the opening tag
	content int // first byte after the opening tag
	closing int // first byte of the closing tag, == end for a self-closing element
	end     int // first byte after the closing tag
}

// xmlScriptSpans locates every script element in an XML document by parsing it,
// so a namespace prefix, its case, and CDATA content cannot hide one.
//
// A regular expression cannot do this job. The prefix is an XML Name, whose
// grammar is far wider than any ASCII character class; element names are case
// sensitive; and a closing-tag sequence inside a CDATA section is character
// data rather than markup, so a textual search for it ends the element in the
// wrong place. Each of those produced a separate bypass while this was matched
// with patterns.
//
// ok is false when the document cannot be parsed far enough to trust the
// result, and the caller keeps its previous behaviour. Note that a document
// which fails XML parsing here is also rejected by a browser parsing SVG or
// XHTML as XML, so the fallback is not a silent hole.
func xmlScriptSpans(doc string) (spans []scriptSpan, ok bool) {
	dec := xml.NewDecoder(strings.NewReader(doc))
	// Unbound prefixes and other real-world sloppiness must not abort the scan:
	// refusing to look is how content slips past.
	dec.Strict = false
	dec.AutoClose = xml.HTMLAutoClose
	dec.Entity = xml.HTMLEntity

	type open struct {
		name  xml.Name
		start int
		body  int
	}
	var stack []open
	// Index in the stack of the OUTERMOST script currently open, or -1. A script
	// element may legally contain another one, and recording both produced spans
	// in closing order: the inner span came first and the outer span started
	// before it ended, so slicing the document walked backwards and panicked.
	// Only the outermost element is recorded, which is also the correct unit to
	// remove or mask, since it contains the inner one.
	outermostScript := -1

	for {
		tokenStart := int(dec.InputOffset())
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			// Partial results are not trustworthy: an element the parser never
			// reached could be a script, and reporting the spans found so far
			// would claim coverage this did not have.
			return nil, false
		}

		switch t := tok.(type) {
		case xml.StartElement:
			if outermostScript < 0 && isScriptName(t.Name) {
				outermostScript = len(stack)
			}
			stack = append(stack, open{name: t.Name, start: tokenStart, body: int(dec.InputOffset())})
		case xml.EndElement:
			if len(stack) == 0 {
				continue
			}
			depth := len(stack) - 1
			top := stack[depth]
			stack = stack[:depth]
			if !isScriptName(top.name) || depth != outermostScript {
				continue
			}
			outermostScript = -1
			end := int(dec.InputOffset())
			closing := end
			// Find where the closing tag starts so the caller can keep it, or
			// drop it, without re-scanning. A self-closing element reports the
			// same offset for both, which leaves an empty content range.
			if idx := strings.LastIndex(doc[top.body:end], "</"); idx >= 0 {
				closing = top.body + idx
			}
			if closing < top.body {
				closing = end
			}
			spans = append(spans, scriptSpan{start: top.start, content: top.body, closing: closing, end: end})
		}
	}

	// An element left open at the end means the parser recovered its way to EOF
	// rather than reading a complete document. Reporting success there would
	// claim coverage this did not have: an unclosed script would be missed and
	// the fallback scan suppressed.
	if len(stack) != 0 {
		return nil, false
	}

	return spans, true
}

// isScriptName reports whether an element is a script element. The local name
// is compared exactly, because XML element names are case sensitive, and the
// namespace is not required to match: an element whose local name is script is
// treated as active content wherever it appears, which errs toward removing
// something inert rather than leaving something executable.
func isScriptName(name xml.Name) bool {
	return name.Local == "script"
}
