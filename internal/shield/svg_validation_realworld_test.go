// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package shield

import (
	"strings"
	"testing"
)

// The enumeration of LEGITIMATE input forms is part of this validator's design,
// not an afterthought. An SVG gate that refuses ordinary documents is not a
// safe gate, it is one the operator turns off. Every case below is benign and
// appears in SVGs produced by real tools; each must be delivered.
func TestValidateSVG_AcceptsRealWorldDocuments(t *testing.T) {
	cases := map[string]string{
		"plain":              `<svg xmlns="http://www.w3.org/2000/svg"><rect width="10" height="10"/></svg>`,
		"xml declaration":    `<?xml version="1.0" encoding="UTF-8"?><svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>`,
		"svg 1.1 doctype":    `<?xml version="1.0"?><!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"><svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>`,
		"comment":            `<svg xmlns="http://www.w3.org/2000/svg"><!-- generated --><rect/></svg>`,
		"rdf metadata":       `<svg xmlns="http://www.w3.org/2000/svg" xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:dc="http://purl.org/dc/elements/1.1/"><metadata><rdf:RDF><dc:title>x</dc:title></rdf:RDF></metadata><rect/></svg>`,
		"editor namespace":   `<svg xmlns="http://www.w3.org/2000/svg" xmlns:inkscape="http://www.inkscape.org/namespaces/inkscape" inkscape:version="1.0"><rect/></svg>`,
		"internal use ref":   `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><use xlink:href="#a"/></svg>`,
		"stylesheet no url":  `<svg xmlns="http://www.w3.org/2000/svg"><style>.a{fill:red}</style><rect class="a"/></svg>`,
		"gradient paint ref": `<svg xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="g"/></defs><rect fill="url(#g)"/></svg>`,
		"hyperlink":          `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><a xlink:href="https://www.w3.org/"><rect/></a></svg>`,
		"plain href link":    `<svg xmlns="http://www.w3.org/2000/svg"><a href="https://www.w3.org/"><rect/></a></svg>`,
		"relative link":      `<svg xmlns="http://www.w3.org/2000/svg"><a href="/docs/page"><rect/></a></svg>`,
		"mailto link":        `<svg xmlns="http://www.w3.org/2000/svg"><a href="mailto:x@example.com"><rect/></a></svg>`,
	}
	for name, doc := range cases {
		if err := ValidateSVG(doc); err != nil {
			t.Errorf("legitimate SVG %q was rejected: %v", name, err)
		}
	}
}

// The negative half. Relaxing namespaces to admit metadata must not admit
// active content wearing a prefix, so several of these are the hostile twin of
// a case accepted above.
func TestValidateSVG_RefusesActiveContent(t *testing.T) {
	cases := map[string]string{
		"inline script":            `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`,
		"prefixed script":          `<svg xmlns="http://www.w3.org/2000/svg" xmlns:s="http://www.w3.org/2000/svg"><s:script>alert(1)</s:script></svg>`,
		"foreign namespace script": `<svg xmlns="http://www.w3.org/2000/svg" xmlns:h="http://www.w3.org/1999/xhtml"><h:script>alert(1)</h:script></svg>`,
		"event handler":            `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><rect/></svg>`,
		"handler on child":         `<svg xmlns="http://www.w3.org/2000/svg"><rect onclick="alert(1)"/></svg>`,
		"foreignObject":            `<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><p>x</p></foreignObject></svg>`,
		"prefixed foreignObject":   `<svg xmlns="http://www.w3.org/2000/svg" xmlns:s="http://www.w3.org/2000/svg"><s:foreignObject/></svg>`,
		"external href":            `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><use xlink:href="https://evil.example/x.svg#a"/></svg>`,
		"external image href":      `<svg xmlns="http://www.w3.org/2000/svg"><image href="https://evil.example/x.png"/></svg>`,
		"external pattern href":    `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><pattern xlink:href="https://evil.example/p.svg#p"/></svg>`,
		"external feimage href":    `<svg xmlns="http://www.w3.org/2000/svg"><filter><feImage href="https://evil.example/f.png"/></filter></svg>`,
		"external textpath href":   `<svg xmlns="http://www.w3.org/2000/svg"><text><textPath href="https://evil.example/t.svg#p">x</textPath></text></svg>`,
		// A hyperlink retrieves nothing, but these SCHEMES execute. Found by
		// an automated review after the retrieval exemption was added, and
		// confirmed by reproduction before the fix.
		"javascript hyperlink":    `<svg xmlns="http://www.w3.org/2000/svg"><a href="javascript:alert(1)"><rect/></a></svg>`,
		"javascript mixed case":   `<svg xmlns="http://www.w3.org/2000/svg"><a href="JaVaScRiPt:alert(1)"><rect/></a></svg>`,
		"javascript tab evasion":  `<svg xmlns="http://www.w3.org/2000/svg"><a href=" java&#9;script:alert(1)"><rect/></a></svg>`,
		"javascript newline":      `<svg xmlns="http://www.w3.org/2000/svg"><a href="java&#10;script:alert(1)"><rect/></a></svg>`,
		"vbscript hyperlink":      `<svg xmlns="http://www.w3.org/2000/svg"><a href="vbscript:msgbox(1)"><rect/></a></svg>`,
		"data uri hyperlink":      `<svg xmlns="http://www.w3.org/2000/svg"><a href="data:text/html;base64,PHNjcmlwdD4="><rect/></a></svg>`,
		"xlink javascript":        `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><a xlink:href="javascript:alert(1)"><rect/></a></svg>`,
		"css external url":        `<svg xmlns="http://www.w3.org/2000/svg"><style>.a{background:url(https://evil.example/x)}</style></svg>`,
		"style attr url":          `<svg xmlns="http://www.w3.org/2000/svg"><rect style="fill:url(https://evil.example/x)"/></svg>`,
		"doctype internal subset": `<!DOCTYPE svg [<!ENTITY x "y">]><svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>`,
		"animate retargets href":  `<svg xmlns="http://www.w3.org/2000/svg"><a href="#x"><set attributeName="href" to="javascript:alert(1)"/></a></svg>`,
		"not svg root":            `<html xmlns="http://www.w3.org/1999/xhtml"><body/></html>`,
		"truncated document":      `<svg xmlns="http://www.w3.org/2000/svg"><rect>`,
	}
	for name, doc := range cases {
		if err := ValidateSVG(doc); err == nil {
			t.Errorf("hostile SVG %q was ACCEPTED; it must be refused", name)
		}
	}
}

// Forms added after the rebase onto the UTF-16 decoding boundary and the
// presentation-attribute audit. Each hostile case is the twin of an accepted
// one, so neither half can pass by refusing or admitting everything.
func TestValidateSVG_CSSAndNamespaceForms(t *testing.T) {
	t.Parallel()
	accepted := map[string]string{
		"style fragment url":       `<svg xmlns="http://www.w3.org/2000/svg"><rect style="fill:url(#g)"/></svg>`,
		"quoted fragment url":      `<svg xmlns="http://www.w3.org/2000/svg"><rect style="fill:url( '#g' )"/></svg>`,
		"stylesheet fragment url":  `<svg xmlns="http://www.w3.org/2000/svg"><style><![CDATA[.a{clip-path:url(#c)}]]></style></svg>`,
		"presentation fragment":    `<svg xmlns="http://www.w3.org/2000/svg"><rect filter="url(#f)" mask="url(#m)"/></svg>`,
		"utf-16 declaration":       `<?xml version="1.0" encoding="UTF-16"?><svg xmlns="http://www.w3.org/2000/svg"/>`,
		"editor path backslash":    `<svg xmlns="http://www.w3.org/2000/svg" xmlns:inkscape="http://www.inkscape.org/namespaces/inkscape" inkscape:export-filename="C:\out\a.png"/>`,
		"label mentioning image()": `<svg xmlns="http://www.w3.org/2000/svg" aria-label="image(s) of cats"/>`,
		"spinner animation":        `<svg xmlns="http://www.w3.org/2000/svg"><circle r="4"><animateTransform attributeName="transform" type="rotate" from="0" to="360" dur="1s" repeatCount="indefinite"/><animate attributeName="opacity" values="1;0;1" dur="1s"/></circle></svg>`,
		"inline png image":         `<svg xmlns="http://www.w3.org/2000/svg"><image href="data:image/png;base64,iVBORw0KGgo="/></svg>`,
		"behavior-named class":     `<svg xmlns="http://www.w3.org/2000/svg"><style>.behavior-note{fill:red}</style></svg>`,
		"filter and clip":          `<svg xmlns="http://www.w3.org/2000/svg"><defs><filter id="f"><feGaussianBlur stdDeviation="2"/><feOffset dx="1"/></filter><clipPath id="c"><circle r="3"/></clipPath><mask id="m"><rect/></mask></defs><g filter="url(#f)" clip-path="url(#c)" mask="url( '#m' )"><rect/></g></svg>`,
		"text and symbol":          `<svg xmlns="http://www.w3.org/2000/svg"><symbol id="s"><path d="M0 0"/></symbol><use href="#s"/><text><tspan>hi</tspan></text></svg>`,
		"animated dash offset":     `<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0"><animate attributeName="stroke-dashoffset" values="0;10"/></path></svg>`,
		"backslash in label text":  `<svg xmlns="http://www.w3.org/2000/svg"><rect aria-label="C:\files\icon"/></svg>`,
	}
	for name, doc := range accepted {
		if err := ValidateSVG(doc); err != nil {
			t.Errorf("legitimate SVG %q was rejected: %v", name, err)
		}
	}
	refused := map[string]string{
		"presentation external fill":  `<svg xmlns="http://www.w3.org/2000/svg"><rect fill="url(https://evil.example/p.svg#p)"/></svg>`,
		"presentation external mask":  `<svg xmlns="http://www.w3.org/2000/svg"><rect mask="url('//evil.example/m.svg#m')"/></svg>`,
		"import split by cdata":       `<svg xmlns="http://www.w3.org/2000/svg"><style>@im<![CDATA[port "https://evil.example/x.css";]]></style></svg>`,
		"import split by comment":     `<svg xmlns="http://www.w3.org/2000/svg"><style>@im<!-- x -->port "https://evil.example/x.css";</style></svg>`,
		"css escape spelling url":     `<svg xmlns="http://www.w3.org/2000/svg"><style>.a{fill:\75 rl(https://evil.example/x)}</style></svg>`,
		"image-set string":            `<svg xmlns="http://www.w3.org/2000/svg"><rect style="background:image-set('https://evil.example/x.png' 1x)"/></svg>`,
		"xhtml img beacon":            `<svg xmlns="http://www.w3.org/2000/svg" xmlns:h="http://www.w3.org/1999/xhtml"><h:img src="https://evil.example/b.png"/></svg>`,
		"xhtml style":                 `<svg xmlns="http://www.w3.org/2000/svg" xmlns:h="http://www.w3.org/1999/xhtml"><h:link rel="stylesheet" href="x.css"/></svg>`,
		"second root element":         `<svg xmlns="http://www.w3.org/2000/svg"/><svg xmlns="http://www.w3.org/2000/svg"/>`,
		"non-utf charset declaration": `<?xml version="1.0" encoding="ISO-8859-1"?><svg xmlns="http://www.w3.org/2000/svg"/>`,
		"set xlink href":              `<svg xmlns="http://www.w3.org/2000/svg"><a href="#x"><set attributeName="xlink:href" to="https://evil.example/"/></a></svg>`,
		"animate handler":             `<svg xmlns="http://www.w3.org/2000/svg"><rect><set attributeName="onclick" to="x()"/></rect></svg>`,
		"xml base reroot":             `<svg xmlns="http://www.w3.org/2000/svg" xml:base="https://evil.example/"><use href="#a"/></svg>`,
		"svg data image":              `<svg xmlns="http://www.w3.org/2000/svg"><image href="data:image/svg+xml;base64,PHN2Zz4="/></svg>`,
		"text outside root":           `<svg xmlns="http://www.w3.org/2000/svg"/>trailing`,
		"moz binding":                 `<svg xmlns="http://www.w3.org/2000/svg"><rect style="-moz-binding:url(#x)"/></svg>`,
		"behavior property":           `<svg xmlns="http://www.w3.org/2000/svg"><style>rect{behavior:url(#x)}</style></svg>`,
		"url with whitespace":         `<svg xmlns="http://www.w3.org/2000/svg"><rect style="fill:url ( 'https://evil.example/p' )"/></svg>`,
		"element case variant":        `<svg xmlns="http://www.w3.org/2000/svg"><Script>alert(1)</Script></svg>`,
		"unlisted fetching element":   `<svg xmlns="http://www.w3.org/2000/svg"><cursor href="https://evil.example/c.png"/></svg>`,
		"unknown svg element":         `<svg xmlns="http://www.w3.org/2000/svg"><widget src="https://evil.example/w"/></svg>`,
		"animate style":               `<svg xmlns="http://www.w3.org/2000/svg"><rect><set attributeName="style" to="fill:red"/></rect></svg>`,
		"animate xml base":            `<svg xmlns="http://www.w3.org/2000/svg"><g><set attributeName="xml:base" to="https://evil.example/"/></g></svg>`,
		"animate to external paint":   `<svg xmlns="http://www.w3.org/2000/svg"><rect><animate attributeName="fill" to="url(https://evil.example/p#p)"/></rect></svg>`,
		"escaped presentation url":    `<svg xmlns="http://www.w3.org/2000/svg"><rect fill="\75rl(https://evil.example/p#p)"/></svg>`,
		"escaped animation url":       `<svg xmlns="http://www.w3.org/2000/svg"><rect><set attributeName="fill" to="\75 \72 l(https://evil.example/p)"/></rect></svg>`,
		"stylesheet pi":               `<?xml-stylesheet href="https://evil.example/x.css"?><svg xmlns="http://www.w3.org/2000/svg"/>`,
	}
	for name, doc := range refused {
		if err := ValidateSVG(doc); err == nil {
			t.Errorf("hostile SVG %q was ACCEPTED; it must be refused", name)
		}
	}
}

// Refusal reasons reach the client and the audit log, so they must not echo
// attacker-chosen names from the document.
func TestValidateSVG_ReasonsDoNotEchoContent(t *testing.T) {
	t.Parallel()
	const marker = "zqxmarker"
	docs := []string{
		`<svg xmlns="http://www.w3.org/2000/svg"><rect on` + marker + `="x"/></svg>`,
		`<svg xmlns="http://www.w3.org/2000/svg"><` + marker + ` href="https://evil.example/x"/></svg>`,
		`<svg xmlns="http://www.w3.org/2000/svg"><` + marker + `></svg>`,
		`<?xml version="1.0" encoding="` + marker + `"?><svg xmlns="http://www.w3.org/2000/svg"/>`,
	}
	for _, doc := range docs {
		err := ValidateSVG(doc)
		if err == nil {
			t.Fatalf("document was accepted: %s", doc)
		}
		if strings.Contains(err.Error(), marker) {
			t.Errorf("reason echoes document content: %v", err)
		}
	}
}
