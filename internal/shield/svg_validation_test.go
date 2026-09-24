// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package shield

import "testing"

func TestValidateSVG_DeliveryContract(t *testing.T) {
	t.Parallel()

	const benign = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M2 2h20v20H2z"/></svg>`
	tests := []struct {
		name string
		svg  string
		want bool
	}{
		{name: "benign icon", svg: benign, want: true},
		{name: "inline script", svg: `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`},
		{name: "event handler", svg: `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>`},
		{name: "foreign object", svg: `<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><div xmlns="http://www.w3.org/1999/xhtml">unsafe</div></foreignObject></svg>`},
		{name: "prefixed foreign object", svg: `<svg:svg xmlns:svg="http://www.w3.org/2000/svg"><svg:foreignObject><svg:path/></svg:foreignObject></svg:svg>`},
		{name: "external reference", svg: `<svg xmlns="http://www.w3.org/2000/svg"><use href="https://attacker.example/icon.svg"/></svg>`},
		{name: "unsafe style attribute", svg: `<svg xmlns="http://www.w3.org/2000/svg"><path style="fill:url(https://attacker.example/fill)"/></svg>`},
		{name: "unsafe stylesheet", svg: `<svg xmlns="http://www.w3.org/2000/svg"><style>path { fill: url(https://attacker.example/fill) }</style></svg>`},
		// A foreign-namespace element is ACCEPTED: an SVG user agent does not
		// render it, and refusing them rejected ordinary metadata (RDF,
		// Dublin Core, editor state) present in most real documents. What
		// carries the security property is svgActiveElement, which matches on
		// the local name in ANY namespace, so the prefixed-script and
		// prefixed-foreignObject cases above still fail.
		{name: "foreign namespace element", svg: `<svg xmlns="http://www.w3.org/2000/svg"><x:widget xmlns:x="https://attacker.example/ns"/></svg>`, want: true},
		// A bare DOCTYPE is SVG 1.1 boilerplate and is accepted. An INTERNAL
		// SUBSET is where entity declarations live, so it stays refused.
		{name: "bare doctype", svg: `<!DOCTYPE svg><svg xmlns="http://www.w3.org/2000/svg"/>`, want: true},
		{name: "doctype internal subset", svg: `<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"/>`},
		{name: "non-doctype directive", svg: `<!ENTITY x "y"><svg xmlns="http://www.w3.org/2000/svg"/>`},
		{name: "malformed", svg: `<svg xmlns="http://www.w3.org/2000/svg"><path></svg>`},
		// CSS treats CR LF as one whitespace, which an escape consumes, so
		// each of these spells url( for a browser; the character references
		// survive XML attribute normalization.
		{name: "css escape then crlf spells url", svg: `<svg xmlns="http://www.w3.org/2000/svg"><path fill="\75&#xD;&#xA;rl(https://attacker.example/fill)"/></svg>`},
		{name: "css escape then lone cr spells url", svg: `<svg xmlns="http://www.w3.org/2000/svg"><path fill="\000075&#xD;rl(https://attacker.example/fill)"/></svg>`},
		{name: "css escape then form feed spells url", svg: `<svg xmlns="http://www.w3.org/2000/svg"><path fill="\75&#xC;rl(https://attacker.example/fill)"/></svg>`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSVG(tc.svg)
			if (err == nil) != tc.want {
				t.Fatalf("ValidateSVG() error = %v, want accepted=%t", err, tc.want)
			}
		})
	}
}
