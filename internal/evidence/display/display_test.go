// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package display

import (
	"strings"
	"testing"
)

func TestSanitizeCleanString(t *testing.T) {
	got := Sanitize("https://api.vendor.example/path")
	if got.Suspicious {
		t.Fatalf("Suspicious = true for clean string: %+v", got)
	}
	if got.Raw != got.Safe {
		t.Fatalf("Safe = %q, want raw", got.Safe)
	}
}

func TestSanitizeClasses(t *testing.T) {
	tests := []struct {
		name  string
		input string
		class Class
		want  string
	}{
		{"bidi", "abc\u202Edef", ClassBidi, "U+202E"},
		{"zero_width", "ab\u200Bcd", ClassZeroWidth, "U+200B"},
		{"control", "ab\u0007cd", ClassControl, "U+0007"},
		{"combining_mark", "a\u0338.example", ClassCombining, "U+0338"},
		{"confusable", "p\u0430ypal.com", ClassConfusable, "confusable"},
		{"mixed_script", "p\u0430ypal.com", ClassMixedScript, "mixed"},
		{"mixed_script_arabic", "paypa\u0644.com", ClassMixedScript, "mixed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Sanitize(tt.input)
			if got.Raw != tt.input {
				t.Fatalf("Raw = %q, want identity", got.Raw)
			}
			if !got.Suspicious {
				t.Fatalf("Suspicious = false")
			}
			if !strings.Contains(got.Safe, tt.want) {
				t.Fatalf("Safe = %q, want %q", got.Safe, tt.want)
			}
			if !hasClass(got.Annotations, tt.class) {
				t.Fatalf("annotations = %+v, want class %s", got.Annotations, tt.class)
			}
		})
	}
}

func TestSanitizeHostPunycode(t *testing.T) {
	got := SanitizeHost("xn--pple-43d.com")
	if !got.Suspicious {
		t.Fatal("Suspicious = false")
	}
	if got.PunycodeASCII == "" || got.PunycodeUnicode == "" || got.PunycodeASCII == got.PunycodeUnicode {
		t.Fatalf("punycode forms = %q/%q, want differing forms", got.PunycodeASCII, got.PunycodeUnicode)
	}
	if !hasClass(got.Annotations, ClassPunycode) {
		t.Fatalf("annotations = %+v, want punycode", got.Annotations)
	}
}

func TestSanitizeHostIDNAFailure(t *testing.T) {
	got := SanitizeHost("bad host")
	if !got.Suspicious {
		t.Fatal("Suspicious = false")
	}
	if got.PunycodeASCII != "bad host" || got.PunycodeUnicode != "bad host" {
		t.Fatalf("punycode forms = %q/%q, want raw fallback", got.PunycodeASCII, got.PunycodeUnicode)
	}
	if !strings.Contains(got.Annotations[len(got.Annotations)-1].Detail, "punycode decode failed") {
		t.Fatalf("annotations = %+v, want decode failure", got.Annotations)
	}
}

func TestSanitizeMalformedInputsRender(t *testing.T) {
	tests := []string{
		string([]byte{0xff, 'a'}),
		"\u202E\u202D\u202C",
		"a" + strings.Repeat("\u0301", 128),
		string(rune(0xD800)),
	}
	for _, input := range tests {
		got := Sanitize(input)
		if got.Raw != input {
			t.Fatalf("Raw = %q, want identity", got.Raw)
		}
		if got.Safe == "" && input != "" {
			t.Fatalf("Safe empty for %q", input)
		}
	}
}

func TestHexdump(t *testing.T) {
	got := Hexdump("A\nB")
	if !strings.Contains(got, "00000000") || !strings.Contains(got, "41 0a 42") || !strings.Contains(got, "|A.B|") {
		t.Fatalf("unexpected hexdump:\n%s", got)
	}
}

func TestHexdumpEmptyAndWrapped(t *testing.T) {
	got := Hexdump(strings.Repeat("A", 17))
	if !strings.Contains(got, "00000000") || !strings.Contains(got, "00000010") {
		t.Fatalf("expected second hexdump line, got:\n%s", got)
	}
	if !strings.Contains(got, "|AAAAAAAAAAAAAAAA|") || !strings.Contains(got, "|A|") {
		t.Fatalf("expected ASCII gutter for wrapped dump, got:\n%s", got)
	}
}

func TestSanitizePreservesPlainWhitespace(t *testing.T) {
	got := Sanitize("a\tb\nc\rd")
	if got.Suspicious {
		t.Fatalf("tab/newline/cr marked suspicious: %+v", got)
	}
	if got.Safe != "a\tb\nc\rd" {
		t.Fatalf("Safe = %q, want original whitespace preserved", got.Safe)
	}
}

func TestSanitizeControlDELAndC1(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input string
		want  string
	}{
		{name: "del", input: "a\u007fb", want: "U+007F"},
		{name: "c1", input: "a\u009fb", want: "U+009F"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := Sanitize(tt.input)
			if !got.Suspicious || !hasClass(got.Annotations, ClassControl) {
				t.Fatalf("annotations = %+v, want control", got.Annotations)
			}
			if !strings.Contains(got.Safe, tt.want) {
				t.Fatalf("Safe = %q, want %q", got.Safe, tt.want)
			}
		})
	}
}

func TestSanitizeHostCleanASCII(t *testing.T) {
	got := SanitizeHost("api.vendor.example")
	if got.Suspicious {
		t.Fatalf("clean host marked suspicious: %+v", got)
	}
	if got.PunycodeASCII != "api.vendor.example" || got.PunycodeUnicode != "api.vendor.example" {
		t.Fatalf("punycode forms = %q/%q", got.PunycodeASCII, got.PunycodeUnicode)
	}
}

func TestHasPunycodeLabel(t *testing.T) {
	if !hasPunycodeLabel("xn--pple-43d.com") {
		t.Fatal("missing punycode label on xn-- prefix")
	}
	if !hasPunycodeLabel("FOO.XN--ABC") {
		t.Fatal("punycode prefix should be case-insensitive")
	}
	if hasPunycodeLabel("api.vendor.example") {
		t.Fatal("plain host reported as punycode")
	}
}

func TestHasNonASCII(t *testing.T) {
	if !hasNonASCII("münchen.example") {
		t.Fatal("non-ASCII host reported as ASCII")
	}
	if hasNonASCII("api.vendor.example") {
		t.Fatal("ASCII host reported as non-ASCII")
	}
}

func TestSentinelUnknownName(t *testing.T) {
	got := sentinel('\u0378')
	if !strings.Contains(got, "UNKNOWN") {
		t.Fatalf("sentinel = %q, want UNKNOWN fallback", got)
	}
}

func TestRawIdentityFuzzCorpus(t *testing.T) {
	corpus := []string{"", "abc", "p\u0430ypal.com", "\u202E", "\u200B", string([]byte{0, 1, 0xff})}
	for _, s := range corpus {
		if got := Sanitize(s); got.Raw != s {
			t.Fatalf("Raw = %q, want %q", got.Raw, s)
		}
	}
}

func hasClass(anns []Annotation, class Class) bool {
	for _, ann := range anns {
		if ann.Class == class {
			return true
		}
	}
	return false
}
