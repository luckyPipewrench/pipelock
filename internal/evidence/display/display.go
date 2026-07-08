// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package display builds human-facing representations of evidence strings.
// It never verifies, signs, hashes, mutates, or normalizes machine evidence.
package display

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"
	"golang.org/x/text/unicode/runenames"

	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

type Class string

const (
	ClassBidi        Class = "bidi"
	ClassZeroWidth   Class = "zero_width"
	ClassControl     Class = "control"
	ClassCombining   Class = "combining_mark"
	ClassConfusable  Class = "confusable"
	ClassMixedScript Class = "mixed_script"
	ClassPunycode    Class = "punycode"
)

type Annotation struct {
	Class      Class  `json:"class"`
	Offset     int    `json:"offset"`
	Length     int    `json:"length"`
	Codepoints []rune `json:"codepoints,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

type Result struct {
	Raw             string       `json:"raw"`
	Safe            string       `json:"safe"`
	Annotations     []Annotation `json:"annotations,omitempty"`
	PunycodeASCII   string       `json:"punycode_ascii,omitempty"`
	PunycodeUnicode string       `json:"punycode_unicode,omitempty"`
	Suspicious      bool         `json:"suspicious"`
}

type runeSpan struct {
	r      rune
	offset int
	length int
}

func Sanitize(s string) Result {
	res := Result{Raw: s}
	spans := runeSpans(s)
	var safe strings.Builder
	for _, span := range spans {
		switch {
		case span.r == utf8.RuneError && span.length == 1 && !utf8.ValidString(s[span.offset:span.offset+span.length]):
			safe.WriteString(sentinel(span.r))
			res.Annotations = append(res.Annotations, Annotation{
				Class:      ClassControl,
				Offset:     span.offset,
				Length:     span.length,
				Codepoints: []rune{span.r},
				Detail:     "invalid UTF-8 byte rendered as replacement sentinel",
			})
		case isBidi(span.r):
			safe.WriteString(sentinel(span.r))
			res.Annotations = append(res.Annotations, annotationFor(span, ClassBidi, "bidirectional formatting control"))
		case isZeroWidth(span.r):
			safe.WriteString(sentinel(span.r))
			res.Annotations = append(res.Annotations, annotationFor(span, ClassZeroWidth, "zero-width or invisible formatting character"))
		case isControl(span.r):
			safe.WriteString(sentinel(span.r))
			res.Annotations = append(res.Annotations, annotationFor(span, ClassControl, "non-printing control character"))
		case isCombiningMark(span.r):
			safe.WriteString(sentinel(span.r))
			res.Annotations = append(res.Annotations, annotationFor(span, ClassCombining, "combining mark rendered explicitly to prevent glyph spoofing"))
		default:
			safe.WriteRune(span.r)
			skeleton := normalize.ConfusableToASCII(string(span.r))
			if skeleton != string(span.r) {
				res.Annotations = append(res.Annotations, Annotation{
					Class:      ClassConfusable,
					Offset:     span.offset,
					Length:     span.length,
					Codepoints: []rune{span.r},
					Detail:     fmt.Sprintf("%s -> %s", string(span.r), skeleton),
				})
			}
		}
	}

	res.Safe = safe.String()
	mixed := mixedScriptAnnotations(spans)
	res.Annotations = append(res.Annotations, mixed...)
	if skeleton := normalize.ConfusableToASCII(s); skeleton != s {
		res.Safe += " ‹confusable: " + skeleton + "›"
	}
	for _, ann := range mixed {
		res.Safe += " ‹mixed: " + ann.Detail + "›"
	}
	res.Suspicious = len(res.Annotations) > 0 || res.PunycodeASCII != res.PunycodeUnicode
	return res
}

func SanitizeHost(host string) Result {
	res := Sanitize(host)
	res.PunycodeASCII = host
	res.PunycodeUnicode = host

	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		res.Annotations = append(res.Annotations, Annotation{
			Class:      ClassPunycode,
			Offset:     0,
			Length:     len(host),
			Codepoints: []rune(host),
			Detail:     "punycode decode failed: " + err.Error(),
		})
		res.Suspicious = true
		return res
	}
	unicodeHost, err := idna.Lookup.ToUnicode(ascii)
	if err != nil {
		res.Annotations = append(res.Annotations, Annotation{
			Class:      ClassPunycode,
			Offset:     0,
			Length:     len(host),
			Codepoints: []rune(host),
			Detail:     "punycode decode failed: " + err.Error(),
		})
		res.Suspicious = true
		return res
	}
	res.PunycodeASCII = ascii
	res.PunycodeUnicode = unicodeHost
	if ascii != unicodeHost || hasPunycodeLabel(host) || hasNonASCII(host) {
		res.Annotations = append(res.Annotations, Annotation{
			Class:      ClassPunycode,
			Offset:     0,
			Length:     len(host),
			Codepoints: []rune(host),
			Detail:     fmt.Sprintf("host display differs: ascii=%s unicode=%s", ascii, unicodeHost),
		})
		if ascii != unicodeHost && !strings.Contains(res.Safe, "‹punycode:") {
			res.Safe += " ‹punycode: " + ascii + " -> " + unicodeHost + "›"
		}
	}
	res.Suspicious = len(res.Annotations) > 0 || res.PunycodeASCII != res.PunycodeUnicode
	return res
}

func Hexdump(s string) string {
	data := []byte(s)
	if len(data) == 0 {
		return ""
	}
	var b strings.Builder
	for offset := 0; offset < len(data); offset += 16 {
		end := offset + 16
		if end > len(data) {
			end = len(data)
		}
		chunk := data[offset:end]
		_, _ = fmt.Fprintf(&b, "%08x  ", offset)
		hexed := make([]byte, hex.EncodedLen(len(chunk)))
		hex.Encode(hexed, chunk)
		for i := 0; i < 16; i++ {
			if i < len(chunk) {
				b.Write(hexed[i*2 : i*2+2])
			} else {
				b.WriteString("  ")
			}
			if i == 7 {
				b.WriteString("  ")
			} else {
				b.WriteByte(' ')
			}
		}
		b.WriteString(" |")
		for _, c := range chunk {
			if c >= 0x20 && c <= 0x7e {
				b.WriteByte(c)
			} else {
				b.WriteByte('.')
			}
		}
		b.WriteString("|\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

func runeSpans(s string) []runeSpan {
	spans := make([]runeSpan, 0, utf8.RuneCountInString(s))
	for offset := 0; offset < len(s); {
		r, size := utf8.DecodeRuneInString(s[offset:])
		if r == utf8.RuneError && size == 0 {
			break
		}
		spans = append(spans, runeSpan{r: r, offset: offset, length: size})
		offset += size
	}
	return spans
}

func annotationFor(span runeSpan, class Class, detail string) Annotation {
	return Annotation{
		Class:      class,
		Offset:     span.offset,
		Length:     span.length,
		Codepoints: []rune{span.r},
		Detail:     detail,
	}
}

func sentinel(r rune) string {
	name := runenames.Name(r)
	if name == "" {
		name = "UNKNOWN"
	}
	return fmt.Sprintf("‹U+%04X %s›", r, name)
}

func isBidi(r rune) bool {
	return (r >= 0x202A && r <= 0x202E) ||
		(r >= 0x2066 && r <= 0x2069) ||
		r == 0x200E || r == 0x200F || r == 0x061C
}

func isZeroWidth(r rune) bool {
	return (r >= 0x200B && r <= 0x200D) ||
		r == 0x2060 || r == 0xFEFF || r == 0x180E || r == 0x00AD
}

func isControl(r rune) bool {
	if r == '\t' || r == '\n' || r == '\r' {
		return false
	}
	return r == 0x7F || (r >= 0x00 && r <= 0x1F) || (r >= 0x80 && r <= 0x9F)
}

func isCombiningMark(r rune) bool {
	return unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Mc, r) || unicode.Is(unicode.Me, r)
}

func mixedScriptAnnotations(spans []runeSpan) []Annotation {
	var anns []Annotation
	for i := 0; i < len(spans); {
		for i < len(spans) && !isTokenRune(spans[i].r) {
			i++
		}
		start := i
		scripts := map[string]struct{}{}
		var token strings.Builder
		for i < len(spans) && isTokenRune(spans[i].r) {
			token.WriteRune(spans[i].r)
			if script := scriptName(spans[i].r); script != "" {
				scripts[script] = struct{}{}
			}
			i++
		}
		if len(scripts) < 2 || start == i {
			continue
		}
		first := spans[start]
		last := spans[i-1]
		names := make([]string, 0, len(scripts))
		for name := range scripts {
			names = append(names, name)
		}
		sort.Strings(names)
		anns = append(anns, Annotation{
			Class:      ClassMixedScript,
			Offset:     first.offset,
			Length:     last.offset + last.length - first.offset,
			Codepoints: []rune(token.String()),
			Detail:     fmt.Sprintf("%s -> %s (mixed %s)", token.String(), normalize.ConfusableToASCII(token.String()), strings.Join(names, "/")),
		})
	}
	return anns
}

func isTokenRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '-' || r == '_'
}

func scriptName(r rune) string {
	for name, table := range unicode.Scripts {
		switch name {
		case "Common", "Inherited":
			continue
		}
		if unicode.Is(table, r) {
			return name
		}
	}
	return ""
}

func hasPunycodeLabel(host string) bool {
	for _, label := range strings.Split(strings.ToLower(host), ".") {
		if strings.HasPrefix(label, "xn--") || strings.Contains(label, ".xn--") {
			return true
		}
	}
	return false
}

func hasNonASCII(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII {
			return true
		}
	}
	return false
}
