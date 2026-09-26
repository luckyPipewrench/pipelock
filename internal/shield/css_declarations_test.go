// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package shield

import (
	"strings"
	"testing"
)

func TestStyleValueHidesCSSSyntax(t *testing.T) {
	tests := []struct {
		name, style string
		hide        bool
	}{
		{"plain", `display:none`, true},
		{"hex in name", `displ\61 y:none`, true},
		{"hex spells different name", `disp\61 lay:none`, false},
		{"hex at start", `\64 isplay:none`, true},
		{"six hex and whitespace", `\000064 isplay:none`, true},
		{"hex in value", `display:\6e one`, true},
		{"escaped newline name", "disp\\\nlay:none", false},
		{"escaped newline control", "display:none; x: a\\\nb", true},
		{"comment between tokens", `display/**/:/*x*/none`, true},
		{"comment inside name", `dis/**/play:none`, false},
		{"important comments", `display:none ! /*x*/ important; display:block`, true},
		{"important control", `display:none ! /*x*/ important; display:block!important`, false},
		{"string semicolon colon", `content:"a;b:c"; display:none`, true},
		{"string control", `content:"display:none;a:b"`, false},
		{"quoted hide value", `display:"none"`, false},
		{"quoted hide control", `display:none`, true},
		{"url hide value", `display:url(none)`, false},
		{"url hide control", `display:none`, true},
		{"function semicolon", `background:url(a;b);display:none`, true},
		{"function control", `background:url(display:none;a;b)`, false},
		{"uppercase", `DISPLAY:NONE`, true},
		{"uppercase control", `DISPLAY:BLOCK`, false},
		{"bad declaration recovery", `? display:none;display:none`, true},
		{"bad declaration control", `? display:none;display:block`, false},
		{"unterminated string", `content:"x;display:none`, false},
		{"string after complete", `display:none;content:"x`, true},
		{"unterminated comment", `color:red;/*display:none`, false},
		{"comment after complete", `display:none;/*x`, true},
		{"nul in name", "dis\x00play:none", false},
		{"nul control", "display:none; x:\x00", true},
		{"crlf escape", "\\64\r\nisplay:none", true},
		{"crlf control", "dis\\\r\nplay:none", false},
		{"too long", `display:none;` + strings.Repeat("x", maxCSSStyleBytes), false},
		{"length control", `display:none;` + strings.Repeat("x", 64), true},
		{"surrogate", `\d800 isplay:none`, false},
		{"surrogate control", `display:none; x:\d800`, true},
		{"cdo", `<!--display:none`, false},
		{"cdo control", `<!--;display:none`, true},
		{"nested block", `x:{a;b};display:none`, true},
		{"nested block control", `x:{display:none;a;b}`, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := styleValueHides(tc.style); got != tc.hide {
				t.Fatalf("styleValueHides(%q)=%v, want %v", tc.style, got, tc.hide)
			}
		})
	}
}

func FuzzStyleValueHidesCSS(f *testing.F) {
	for _, s := range []string{`display:none`, `content:"a;b";display:none`, `background:url(a;b)`, `\\64 isplay:none`, `x:{a;b};display:none`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > maxCSSStyleBytes {
			s = s[:maxCSSStyleBytes+1]
		}
		_ = styleValueHides(s)
	})
}

func TestStyleValueHidesCSSDeclarationEdges(t *testing.T) {
	tests := []struct {
		name, style string
		hide bool
	}{
		{"form feed whitespace", "\fdisplay\t:\nnone", true},
		{"null replacement", "display:none; dis\x00play:block", true},
		{"invalid utf8 in property", "dis\xffplay:none", false},
		{"escaped punctuation in name", `dis\70 lay:none`, true},
		{"nonhex escape in value", `display:n\one`, true},
		{"escaped invalid scalar", `display:none; x:\110000`, true},
		{"escaped zero scalar", `display:n\0 one`, false},
		{"escaped uppercase hex", `display:\4E one`, true},
		{"trailing backslash", `display:none; x:\`, true},
		{"bad url quote", `background:url(a"b);display:none`, true},
		{"bad url open paren", `background:url(a(b);display:none`, true},
		{"bad url whitespace", `background:url(a b);display:none`, true},
		{"bad url newline escape", "background:url(a\\\nb);display:none", true},
		{"url quoted semicolon", `background:url("a;b");display:none`, true},
		{"url unclosed", `background:url(a;display:none`, false},
		{"string escaped newline", "content:'a\\\nb';display:none", true},
		{"string escaped quote", `content:'a\'b;c';display:none`, true},
		{"string newline recovery", "content:'a\nb';display:none", false},
		{"at rule skipped", `@media screen {display:none};display:block`, false},
		{"at rule followed by hide", `@x(a;b);display:none`, true},
		{"hash not property", `#display:none;display:block`, false},
		{"dimension not property", `2px: none;display:block`, false},
		{"percentage not property", `2%:none;display:none`, true},
		{"exponent not property", `2e+3:none;display:block`, false},
		{"signed decimal not property", `-.5:none;display:none`, true},
		{"nested bracket semicolon", `x:[a;b];display:none`, true},
		{"mismatched bracket", `display:none];display:block`, false},
		{"unclosed function", `display:none; x:f(a;b`, true},
		{"malformed hide function", `display:f(a;b`, false},
		{"important uppercase", `display:none !IMPORTANT;display:block`, true},
		{"important in string", `display:none !"important";display:block`, false},
		{"important without bang", `display:none important;display:block`, false},
		{"bang without important", `display:none !;display:block`, false},
		{"trailing semicolon", `display:none;`, true},
		{"missing colon at end", `display`, false},
		{"missing colon then hide", `display x;display:none`, true},
		{"cdc recovery", `-->;display:none`, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := styleValueHides(tc.style); got != tc.hide {
				t.Fatalf("styleValueHides(%q)=%v, want %v", tc.style, got, tc.hide)
			}
		})
	}
}

func TestCSSDeclarationTokenOutput(t *testing.T) {
	tests := []struct {
		style string
		want []cssDeclaration
	}{
		{`x:+.5e-2%;display:none`, []cssDeclaration{{name: "x", value: "+.5e-2%"}, {name: "display", value: "none"}}},
		{`x:2px #abc @foo;display:none`, []cssDeclaration{{name: "x", value: "2px abc foo"}, {name: "display", value: "none"}}},
		{`x:url(a\)b);display:none`, []cssDeclaration{{name: "x", value: "url(a)b)"}, {name: "display", value: "none"}}},
		{`x:"a\22 b";display:none`, []cssDeclaration{{name: "x", value: `"a"b"`}, {name: "display", value: "none"}}},
	}
	for _, tc := range tests {
		t.Run(tc.style, func(t *testing.T) {
			got := cssDeclarations(tc.style)
			if len(got) != len(tc.want) {
				t.Fatalf("cssDeclarations(%q)=%+v, want %+v", tc.style, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("cssDeclarations(%q)[%d]=%+v, want %+v", tc.style, i, got[i], tc.want[i])
				}
			}
		})
	}
}
