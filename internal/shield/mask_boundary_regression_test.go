// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package shield

import (
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// TestXHTMLScriptNameBoundary_DoesNotMaskRestOfDocument covers a fail-open in
// the XHTML masking scanner: an element whose name merely STARTS with "script"
// must not open a script region. When it did, the scanner found no closing
// </script>, masked the entire remainder, and every rewrite pass skipped it.
func TestXHTMLScriptNameBoundary_DoesNotMaskRestOfDocument(t *testing.T) {
	cfg := config.Defaults().BrowserShield
	e := NewEngine(nil)

	payload := `<html xmlns="http://www.w3.org/1999/xhtml"><body>` +
		`<script-proxy>harmless</script-proxy>` +
		`<img width="1" height="1" src="https://track.example.com/px"/>` +
		`</body></html>`

	res := e.Rewrite(payload, PipelineXHTML, &cfg)
	if strings.Contains(res.Content, "track.example.com") {
		t.Errorf("tracking pixel survived after a <script-proxy> element; the rest of the document was masked.\ngot: %s", res.Content)
	}
	if !strings.Contains(res.Content, "script-proxy") {
		t.Errorf("the non-script element itself should be preserved, got: %s", res.Content)
	}
}

// TestSVGScriptQuotedAngleBracket_IsRemoved covers a fail-open in SVG active
// content removal: an attribute value containing '>' ended the tag match early,
// so a self-closing script element survived and could still load code.
func TestSVGScriptQuotedAngleBracket_IsRemoved(t *testing.T) {
	cfg := config.Defaults().BrowserShield
	e := NewEngine(nil)

	payload := `<svg xmlns="http://www.w3.org/2000/svg"><script data-note=">" href="app.js"/></svg>`

	// Assert on the ELEMENT, not on the href value: a separate rule rewrites
	// external hrefs, so checking for "app.js" alone reports a pass while the
	// script element is still there.
	res := e.Rewrite(payload, PipelineSVG, &cfg)
	if strings.Contains(res.Content, "<script") {
		t.Errorf("SVG script element survived a quoted '>' in an attribute value.\ngot: %s", res.Content)
	}
	if res.SVGScriptHits == 0 {
		t.Error("SVGScriptHits = 0, so the script element was never matched as active content")
	}

	// Positive control: the same element without the quoted '>' must already be
	// removed, so a failure above means the quoting is what broke it.
	plain := `<svg xmlns="http://www.w3.org/2000/svg"><script href="app.js"/></svg>`
	if ctrl := e.Rewrite(plain, PipelineSVG, &cfg); strings.Contains(ctrl.Content, "<script") {
		t.Errorf("positive control failed: a plain self-closing SVG script was not removed either: %s", ctrl.Content)
	}
}

// TestRestoreHTMLScripts_ManyScriptsRoundTrip pins that restoration is exact
// for a document with many inline scripts, which is the shape whose restoration
// cost scaled with document size times script count.
func TestRestoreHTMLScripts_ManyScriptsRoundTrip(t *testing.T) {
	cfg := config.Defaults().BrowserShield
	e := NewEngine(nil)

	var b strings.Builder
	b.WriteString("<html><body>")
	for i := 0; i < 200; i++ {
		b.WriteString(`<script>var a` + strings.Repeat("x", 3) + `=` + strings.Repeat("1", 3) + `;</script>`)
	}
	b.WriteString(`<img width="1" height="1" src="https://track.example.com/px">`)
	b.WriteString("</body></html>")
	payload := b.String()

	res := e.Rewrite(payload, PipelineHTML, &cfg)
	if strings.Contains(res.Content, "PIPELOCK") || strings.Contains(res.Content, "placeholder") {
		t.Errorf("a masking placeholder leaked into output: %s", res.Content[:200])
	}
	// At least the 200 originals; the engine may also inject its own shim.
	if got := strings.Count(res.Content, "<script>"); got < 200 {
		t.Errorf("script count after restore = %d, want at least 200", got)
	}
	if got := strings.Count(res.Content, "var axxx=111;"); got != 200 {
		t.Errorf("restored script bodies = %d, want 200 exact", got)
	}
	if strings.Contains(res.Content, "track.example.com") {
		t.Error("tracking pixel survived alongside many scripts")
	}
}

// TestSVGDottedNamespacePrefixScriptIsRemoved covers a namespace-grammar gap:
// an XML NCName permits a dot, so a document declaring xmlns:x.y and writing
// <x.y:script> is valid and executes. A prefix pattern of [\w-]+ rejects the
// dot, so the element was left in place as active content.
func TestSVGDottedNamespacePrefixScriptIsRemoved(t *testing.T) {
	cfg := config.Defaults().BrowserShield
	e := NewEngine(nil)

	// Positive control: the undotted form must already be removed, so a failure
	// below is about the prefix grammar and not about script removal generally.
	plain := `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`
	if ctrl := e.Rewrite(plain, PipelineSVG, &cfg); strings.Contains(ctrl.Content, "alert(1)") {
		t.Fatalf("control: a plain SVG script was not removed: %s", ctrl.Content)
	}

	dotted := `<svg xmlns="http://www.w3.org/2000/svg" xmlns:x.y="http://www.w3.org/2000/svg">` +
		`<x.y:script>alert(1)</x.y:script></svg>`
	res := e.Rewrite(dotted, PipelineSVG, &cfg)
	if strings.Contains(res.Content, "alert(1)") {
		t.Errorf("namespaced SVG script with a dotted prefix survived: %s", res.Content)
	}
	if res.SVGScriptHits == 0 {
		t.Error("SVGScriptHits = 0, so the dotted-prefix element was never matched as active content")
	}
}

// TestExtensionProbeInScriptTagIsStripped covers the cost of masking scripts:
// the opening tag is markup rather than JavaScript, and masking it hid the tag
// from every HTML pass, so a probe written as a script src survived.
func TestExtensionProbeInScriptTagIsStripped(t *testing.T) {
	cfg := config.Defaults().BrowserShield
	e := NewEngine(nil)
	const probe = "chrome-extension://abcdefghijklmnopqrstuvwxyzabcdef/probe"

	// Positive control: the same probe in ordinary markup is stripped today.
	ctrl := e.Rewrite(`<html><body><img src="`+probe+`"></body></html>`, PipelineHTML, &cfg)
	if strings.Contains(ctrl.Content, "chrome-extension://") {
		t.Fatalf("control: probe in an img src was not stripped: %s", ctrl.Content)
	}

	res := e.Rewrite(`<html><body><script src="`+probe+`"></script></body></html>`, PipelineHTML, &cfg)
	if strings.Contains(res.Content, "chrome-extension://") {
		t.Errorf("extension probe in a script src survived: %s", res.Content)
	}
	if res.ExtensionHits == 0 {
		t.Error("ExtensionHits = 0, so the script tag was never scanned")
	}
}

// TestInlineScriptBytesStillPreserved is the guard on the guard: masking only
// the script CONTENT must not reopen the JavaScript rewriting this branch
// exists to stop, while markup around it is still rewritten.
func TestInlineScriptBytesStillPreserved(t *testing.T) {
	cfg := config.Defaults().BrowserShield
	e := NewEngine(nil)
	const js = `var a = 1 < 2 && 3 > 2; navigator.sendBeacon("/x", "y");`

	res := e.Rewrite(`<html><body><script>`+js+`</script>`+
		`<img width="1" height="1" src="https://track.example.com/px"></body></html>`, PipelineHTML, &cfg)

	if !strings.Contains(res.Content, js) {
		t.Errorf("inline JavaScript was modified.\nwant substring: %s\ngot: %s", js, res.Content)
	}
	if strings.Contains(res.Content, "track.example.com") {
		t.Error("tracking pixel outside the script was not removed")
	}
}

// TestExtensionProbeInXHTMLScriptTagIsStripped is the XHTML counterpart of
// TestExtensionProbeInScriptTagIsStripped. The HTML masker was corrected to keep
// script opening tags visible to attribute enforcement and the XHTML masker was
// not, so the same probe survived on the XHTML path: the instance was fixed and
// the class was not.
func TestExtensionProbeInXHTMLScriptTagIsStripped(t *testing.T) {
	cfg := config.Defaults().BrowserShield
	e := NewEngine(nil)
	const probe = "chrome-extension://abcdefghijklmnopqrstuvwxyzabcdef/probe"

	doc := `<html xmlns="http://www.w3.org/1999/xhtml"><body><script src="` + probe + `"></script></body></html>`
	res := e.Rewrite(doc, PipelineXHTML, &cfg)
	if strings.Contains(res.Content, "chrome-extension://") {
		t.Errorf("extension probe in an XHTML script src survived: %s", res.Content)
	}
	if res.ExtensionHits == 0 {
		t.Error("ExtensionHits = 0, so the XHTML script tag was never scanned")
	}
}

// TestPlaceholderPrefixSearchIsLinear covers a request-path cost: the previous
// prefix search appended one character per collision and rescanned the whole
// document each time, so a body carrying the placeholder prefix followed by a
// long run of the pad character cost time quadratic in its own length.
func TestPlaceholderPrefixSearchIsLinear(t *testing.T) {
	cfg := config.Defaults().BrowserShield
	e := NewEngine(nil)

	// The prefix, then a long run of the pad character the old loop appended.
	hostile := "<html><body>" + "\x00pipelock-inline-script-" + strings.Repeat("x", 20000) +
		"<script>var a = 1;</script></body></html>"

	done := make(chan Result, 1)
	go func() { done <- e.Rewrite(hostile, PipelineHTML, &cfg) }()
	select {
	case res := <-done:
		if !strings.Contains(res.Content, "var a = 1;") {
			t.Errorf("script content was not preserved: %s", res.Content[:80])
		}
	case <-time.After(testwait.Deadline(20 * time.Second)):
		t.Fatal("rewrite did not finish: the placeholder search is still superlinear")
	}
}

// TestXHTMLScriptCDATACloseDoesNotEndMasking covers a JavaScript-corruption
// path. A closing script tag written INSIDE a CDATA section is legal script
// content, but the raw close search stopped there, so the rest of the script
// became visible to the rewrite passes and an extension URL after that point was
// stripped out of the code the browser would run.
func TestXHTMLScriptCDATACloseDoesNotEndMasking(t *testing.T) {
	cfg := config.Defaults().BrowserShield
	e := NewEngine(nil)

	js := `var s = "</script>"; var probe = "chrome-extension://abcdefghijklmnopqrstuvwxyzabcdef/p";`
	doc := `<html xmlns="http://www.w3.org/1999/xhtml"><body><script><![CDATA[` + js + `]]></script>` +
		`<img width="1" height="1" src="https://track.example.com/px"/></body></html>`

	res := e.Rewrite(doc, PipelineXHTML, &cfg)
	if !strings.Contains(res.Content, js) {
		t.Errorf("script bytes were modified.\nwant substring: %s\ngot: %s", js, res.Content)
	}
	// Markup after the real closing tag must still be rewritten, so the fix
	// cannot be "mask everything to the end of the document".
	if strings.Contains(res.Content, "track.example.com") {
		t.Error("tracking pixel after the real closing tag was not removed")
	}
}

// TestXHTMLUppercaseContainerIsNotAScript covers the case-sensitivity of XML
// element names. <SCRIPT> in XHTML is an ordinary unknown element, so its child
// markup must still be rewritten; matching it case-insensitively masked that
// markup out of every pass.
func TestXHTMLUppercaseContainerIsNotAScript(t *testing.T) {
	cfg := config.Defaults().BrowserShield
	e := NewEngine(nil)

	pixel := `<img width="1" height="1" src="https://track.example.com/px"/>`
	xhtml := `<html xmlns="http://www.w3.org/1999/xhtml"><body><SCRIPT>` + pixel + `</SCRIPT></body></html>`
	if res := e.Rewrite(xhtml, PipelineXHTML, &cfg); strings.Contains(res.Content, "track.example.com") {
		t.Errorf("child markup of an uppercase XHTML container survived: %s", res.Content)
	}

	// Positive control for the other direction: in HTML the element name is
	// case insensitive, so <SCRIPT> IS a script and its content must be left
	// alone. A fix that simply made everything case sensitive would break this.
	html := `<html><body><SCRIPT>` + pixel + `</SCRIPT></body></html>`
	if res := e.Rewrite(html, PipelineHTML, &cfg); !strings.Contains(res.Content, "track.example.com") {
		t.Errorf("HTML script content was rewritten; case insensitivity is required there: %s", res.Content)
	}
}
