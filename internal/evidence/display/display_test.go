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
