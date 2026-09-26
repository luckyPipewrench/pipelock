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
