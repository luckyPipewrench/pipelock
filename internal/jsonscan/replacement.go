// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package jsonscan

import (
	"bytes"
	"strings"
	"unicode/utf8"
)

// replacementEscape is the six-byte escape backslash, u, f, f, f, d.
var replacementEscape = []byte{'\\', 'u', 'f', 'f', 'f', 'd'}

// NormalizeReplacementEscapes rewrites each backslash-u-fffd escape in encoding/json
// output into the raw U+FFFD character.
//
// encoding/json replaces each invalid UTF-8 byte in a Go string with U+FFFD.
// Go 1.26 and earlier write that replacement as the six-byte escape backslash-u-fffd;
// Go 1.27, with the jsonv2 implementation on by default, writes the raw
// character. A valid U+FFFD is written raw by both. A verifier that parses
// signed JSON and re-encodes it therefore reproduces the raw form, so any
// signing preimage built with json.Marshal must use the raw form too, or a
// string holding invalid UTF-8 produces a signature that no verifier, and no
// other Go release, can reproduce.
//
// Only encoding/json output is supported: it never emits the uppercase form
// of that escape, and a literal backslash is always escaped as \\, so the escape pair
// scan below cannot misread a string that contains that escape as literal text.
func NormalizeReplacementEscapes(b []byte) []byte {
	if !bytes.Contains(b, replacementEscape) {
		return b
	}
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] != '\\' || i+1 >= len(b) {
			out = append(out, b[i])
			continue
		}
		if bytes.HasPrefix(b[i:], replacementEscape) {
			out = append(out, "\uFFFD"...)
			i += len(replacementEscape) - 1
			continue
		}
		out = append(out, b[i], b[i+1])
		i++
	}
	return out
}

// ReplaceInvalidUTF8 replaces each invalid UTF-8 byte in s with U+FFFD, one
// replacement per byte, exactly as encoding/json does when it marshals a
// string. A value hashed or signed as a raw Go string and then stored as
// JSON must be passed through this first, or the stored text no longer
// matches the bytes the hash or signature covered. strings.ToValidUTF8 is not
// equivalent: it collapses a run of invalid bytes into one replacement.
func ReplaceInvalidUTF8(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			b.WriteString("\uFFFD")
		} else {
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}
