// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package shield

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
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
