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
