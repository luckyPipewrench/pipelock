// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package shield

import (
	"encoding/xml"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// parsesAsXML reports whether the document is well-formed XML, which is the
// bar an application/xhtml+xml response has to clear in a browser.
func parsesAsXML(t *testing.T, doc string) error {
	t.Helper()
	dec := xml.NewDecoder(strings.NewReader(doc))
	dec.Strict = true
	for {
		_, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// TestXHTMLInjectionStaysWellFormed covers an availability failure: the shield
// injects JavaScript containing `&&` and `<`, which are not well-formed inside
// an XML script element, so an XHTML page could be made unrenderable by the
// very pass meant to protect it.
func TestXHTMLInjectionStaysWellFormed(t *testing.T) {
	cfg := config.Defaults().BrowserShield
	e := NewEngine(nil)

	doc := `<html xmlns="http://www.w3.org/1999/xhtml"><head></head><body><p>hi</p></body></html>`

	// Positive control: the input is well-formed before the shield touches it.
	if err := parsesAsXML(t, doc); err != nil {
		t.Fatalf("control: fixture is not well-formed XML to begin with: %v", err)
	}

	// Ask for the injection explicitly rather than depending on what the
	// default config happens to enable. Skipping when nothing was injected let
	// this test pass without ever exercising the CDATA path it exists to cover.
	cfg.InjectFingerprintShims = true

	res := e.Rewrite(doc, PipelineXHTML, &cfg)
	if !res.ShimInjected {
		t.Fatal("expected XHTML shim injection, so the CDATA guard is unverified")
	}
	if !strings.Contains(res.Content, "CDATA") {
		t.Error("injected XHTML script is not CDATA-guarded")
	}
	if err := parsesAsXML(t, res.Content); err != nil {
		t.Errorf("shield made the XHTML document not well-formed: %v\ncontent: %s", err, res.Content)
	}
}

// TestXHTMLNonceWithAngleBracketStaysWellFormed pins the nonce validation. A
// nonce is copied from the upstream document so the browser's own CSP accepts
// the injected shim. buildShimBlockXML locates the end of the start tag by
// finding the first `>`, so a nonce carrying one moved that boundary into the
// middle of the attribute value, the CDATA guard was written inside the quotes,
// and the document stopped being XML. A browser refuses to render a malformed
// application/xhtml+xml response, so the shield broke the page it protects.
//
// The nonce is delivered percent-free and inside a well-formed document: the
// attacker-controlled part is the VALUE, and a fixture that is itself malformed
// proves nothing about what the shield did.
func TestXHTMLNonceWithAngleBracketStaysWellFormed(t *testing.T) {
	cfg := config.Defaults().BrowserShield
	cfg.InjectFingerprintShims = true
	e := NewEngine(nil)

	for _, tc := range []struct {
		name      string
		nonce     string
		wantNonce bool
	}{
		{name: "base64 nonce is kept", nonce: "abc123+/=", wantNonce: true},
		{name: "nonce carrying a close bracket is dropped", nonce: "a&gt;b"},
		{name: "nonce carrying a space is dropped", nonce: "a b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := `<html xmlns="http://www.w3.org/1999/xhtml"><head><script nonce="` + tc.nonce +
				`">var a = 1;</script></head><body><p>hi</p></body></html>`

			// Positive control: whatever the shield does next, it did not
			// inherit a broken fixture.
			if err := parsesAsXML(t, doc); err != nil {
				t.Fatalf("control: fixture is not well-formed XML to begin with: %v", err)
			}

			res := e.Rewrite(doc, PipelineXHTML, &cfg)
			if !res.ShimInjected {
				t.Fatal("expected XHTML shim injection, so the nonce path is unverified")
			}
			if err := parsesAsXML(t, res.Content); err != nil {
				t.Fatalf("shield produced malformed XHTML: %v\n%s", err, res.Content)
			}

			injected := injectedShimStartTag(t, res.Content)
			gotNonce := strings.Contains(injected, "nonce=")
			if gotNonce != tc.wantNonce {
				t.Errorf("injected start tag %q carries a nonce = %v, want %v", injected, gotNonce, tc.wantNonce)
			}
		})
	}
}

// injectedShimStartTag returns the start tag of the shield's own injected
// script, which is the one guarding its body with CDATA. Reading the whole
// document instead would match the upstream script tag the fixture supplies.
func injectedShimStartTag(t *testing.T, content string) string {
	t.Helper()
	marker := strings.Index(content, "//<![CDATA[")
	if marker < 0 {
		t.Fatalf("no CDATA-guarded shim found in output:\n%s", content)
	}
	open := strings.LastIndex(content[:marker], "<script")
	if open < 0 {
		t.Fatalf("CDATA guard is not inside a script element:\n%s", content)
	}
	return content[open:marker]
}
