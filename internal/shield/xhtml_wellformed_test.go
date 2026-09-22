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
