// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package shield

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// TestSVGScriptRemovalIsNamespaceAndCDATAAware covers the class of bypasses
// that defeated pattern matching on this path. Each case is a valid document
// whose script element executes in a browser, and each one survived a pattern
// that the previous case had just been widened to catch.
func TestSVGScriptRemovalIsNamespaceAndCDATAAware(t *testing.T) {
	cfg := config.Defaults().BrowserShield
	e := NewEngine(nil)

	for name, doc := range map[string]string{
		"ascii prefix":   `<svg xmlns:x="http://www.w3.org/2000/svg"><x:script>alert(1)</x:script></svg>`,
		"dotted prefix":  `<svg xmlns:x.y="http://www.w3.org/2000/svg"><x.y:script>alert(1)</x.y:script></svg>`,
		"unicode prefix": `<svg xmlns:π="http://www.w3.org/2000/svg"><π:script>alert(1)</π:script></svg>`,
		"quoted bracket": `<svg xmlns="http://www.w3.org/2000/svg"><script data-n="&gt;" href="app.js"/></svg>`,
	} {
		t.Run(name, func(t *testing.T) {
			res := e.Rewrite(doc, PipelineSVG, &cfg)
			if strings.Contains(res.Content, "alert(1)") || strings.Contains(res.Content, "app.js") {
				t.Errorf("script survived: %s", res.Content)
			}
			if res.SVGScriptHits == 0 {
				t.Error("SVGScriptHits = 0, so the element was never matched as active content")
			}
		})
	}

	t.Run("closing tag inside CDATA does not end the element", func(t *testing.T) {
		doc := `<svg xmlns="http://www.w3.org/2000/svg"><script><![CDATA[ var s = "</script>"; alert(1) ]]></script><text>after</text></svg>`
		res := e.Rewrite(doc, PipelineSVG, &cfg)
		if strings.Contains(res.Content, "alert(1)") {
			t.Errorf("script content survived past a CDATA closing sequence: %s", res.Content)
		}
		// The element after the real close must remain, so the fix cannot be
		// "remove everything from the first script onwards".
		if !strings.Contains(res.Content, "after") {
			t.Errorf("content after the script element was removed too: %s", res.Content)
		}
	})

	t.Run("uppercase element is not a script in XML", func(t *testing.T) {
		// XML element names are case sensitive, so this does not execute and
		// must not be treated as active content.
		doc := `<svg xmlns="http://www.w3.org/2000/svg"><SCRIPT>alert(1)</SCRIPT></svg>`
		if res := e.Rewrite(doc, PipelineSVG, &cfg); res.SVGScriptHits != 0 {
			t.Errorf("SVGScriptHits = %d for an uppercase element: %s", res.SVGScriptHits, res.Content)
		}
	})
}

// TestXHTMLMaskingIsNamespaceAndCDATAAware is the masking counterpart: the
// script body must survive byte for byte however the element is written, while
// markup outside it is still rewritten.
func TestXHTMLMaskingIsNamespaceAndCDATAAware(t *testing.T) {
	cfg := config.Defaults().BrowserShield
	e := NewEngine(nil)
	const js = `var probe = "chrome-extension://abcdefghijklmnopqrstuvwxyzabcdef/p"; var a = 1;`
	const pixel = `<img width="1" height="1" src="https://track.example.com/px"/>`

	for name, doc := range map[string]string{
		"unprefixed":     `<html xmlns="http://www.w3.org/1999/xhtml"><body><script>` + js + `</script>` + pixel + `</body></html>`,
		"ascii prefix":   `<html xmlns:h="http://www.w3.org/1999/xhtml"><body><h:script>` + js + `</h:script>` + pixel + `</body></html>`,
		"unicode prefix": `<html xmlns:π="http://www.w3.org/1999/xhtml"><body><π:script>` + js + `</π:script>` + pixel + `</body></html>`,
		"cdata":          `<html xmlns="http://www.w3.org/1999/xhtml"><body><script><![CDATA[` + js + ` var s = "</script>";]]></script>` + pixel + `</body></html>`,
	} {
		t.Run(name, func(t *testing.T) {
			res := e.Rewrite(doc, PipelineXHTML, &cfg)
			if !strings.Contains(res.Content, js) {
				t.Errorf("script bytes were modified: %s", res.Content)
			}
			if strings.Contains(res.Content, "track.example.com") {
				t.Errorf("markup outside the script was not rewritten: %s", res.Content)
			}
		})
	}

	t.Run("uppercase container is not a script", func(t *testing.T) {
		doc := `<html xmlns="http://www.w3.org/1999/xhtml"><body><SCRIPT>` + pixel + `</SCRIPT></body></html>`
		if res := e.Rewrite(doc, PipelineXHTML, &cfg); strings.Contains(res.Content, "track.example.com") {
			t.Errorf("child markup of an uppercase container survived: %s", res.Content)
		}
	})
}

// TestMalformedXMLFallsBackToScanning covers the path taken when the document
// cannot be parsed as XML. The parser is the primary answer, but refusing to
// touch a malformed document would silently stop shielding it, so the previous
// scanner remains as the fallback and has to keep working.
//
// A browser parsing SVG or XHTML as XML rejects these documents too, so the
// fallback protects a case the browser will not render rather than one an
// attacker can rely on. It is exercised here so it cannot rot unnoticed.
func TestMalformedXMLFallsBackToScanning(t *testing.T) {
	cfg := config.Defaults().BrowserShield
	e := NewEngine(nil)

	// A bare `<` in character data is not well-formed, so the decoder stops and
	// the caller falls back.
	if _, ok := xmlScriptSpans(`<svg><text>1 < 2</text></svg>`); ok {
		t.Fatal("control: this document was expected to defeat the XML parser")
	}
	if _, ok := xmlScriptSpans(`<svg xmlns="http://www.w3.org/2000/svg"><script>ok()</script></svg>`); !ok {
		t.Fatal("control: a well-formed document must parse, or the test below proves nothing")
	}

	t.Run("svg removal still strips the script", func(t *testing.T) {
		doc := `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script><text>1 < 2</text></svg>`
		res := e.Rewrite(doc, PipelineSVG, &cfg)
		if strings.Contains(res.Content, "alert(1)") {
			t.Errorf("script survived the fallback path: %s", res.Content)
		}
		if res.SVGScriptHits == 0 {
			t.Error("SVGScriptHits = 0 on the fallback path")
		}
	})

	t.Run("xhtml masking still preserves script bytes", func(t *testing.T) {
		js := `var probe = "chrome-extension://abcdefghijklmnopqrstuvwxyzabcdef/p";`
		doc := `<html xmlns="http://www.w3.org/1999/xhtml"><body><script>` + js + `</script>` +
			`<p>1 < 2</p>` +
			`<img width="1" height="1" src="https://track.example.com/px"/></body></html>`
		res := e.Rewrite(doc, PipelineXHTML, &cfg)
		if !strings.Contains(res.Content, js) {
			t.Errorf("script bytes were modified on the fallback path: %s", res.Content)
		}
		if strings.Contains(res.Content, "track.example.com") {
			t.Errorf("tracking pixel survived on the fallback path: %s", res.Content)
		}
	})

	t.Run("closing tag inside CDATA is still honoured by the fallback", func(t *testing.T) {
		js := `var s = "</script>"; var a = 1;`
		doc := `<html xmlns="http://www.w3.org/1999/xhtml"><body><script><![CDATA[` + js + `]]></script>` +
			`<p>1 < 2</p></body></html>`
		res := e.Rewrite(doc, PipelineXHTML, &cfg)
		if !strings.Contains(res.Content, js) {
			t.Errorf("CDATA content was modified on the fallback path: %s", res.Content)
		}
	})
}

// TestNestedScriptElementsDoNotPanic covers a crash on the request path. A
// script element may legally contain another one, and recording both produced
// spans in closing order, so the inner span came first while the outer span
// started before it ended. Slicing the document then walked backwards and
// panicked on well-formed, attacker-supplied XML.
func TestNestedScriptElementsDoNotPanic(t *testing.T) {
	cfg := config.Defaults().BrowserShield
	e := NewEngine(nil)

	doc := `<svg xmlns="http://www.w3.org/2000/svg"><script><script>alert(1)</script></script></svg>`

	spans, ok := xmlScriptSpans(doc)
	if !ok {
		t.Fatal("control: this document is well formed and must parse")
	}
	if len(spans) != 1 {
		t.Errorf("got %d spans, want 1: only the outermost element is the unit to remove", len(spans))
	}

	res := e.Rewrite(doc, PipelineSVG, &cfg)
	if strings.Contains(res.Content, "alert(1)") {
		t.Errorf("nested script survived: %s", res.Content)
	}

	// The same shape on the masking path, which slices with the same offsets.
	xdoc := `<html xmlns="http://www.w3.org/1999/xhtml"><body><script><script>var a = 1;</script></script></body></html>`
	if out := e.Rewrite(xdoc, PipelineXHTML, &cfg); !strings.Contains(out.Content, "var a = 1;") {
		t.Errorf("nested script content was not preserved on the masking path: %s", out.Content)
	}
}

// TestUnclosedElementSuppressesTheParsedAnswer covers the honesty of the ok
// flag. Permissive parsing recovers its way to EOF, so a document that leaves
// an element open is not a document this read completely, and claiming success
// would miss an unclosed script while suppressing the fallback scan.
func TestUnclosedElementSuppressesTheParsedAnswer(t *testing.T) {
	if _, ok := xmlScriptSpans(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)`); ok {
		t.Error("an unclosed element reported a complete parse")
	}
	// Control: the closed form of the same document parses.
	if _, ok := xmlScriptSpans(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`); !ok {
		t.Error("control: the well-formed form must parse")
	}
}
