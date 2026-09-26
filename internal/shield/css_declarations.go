// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package shield

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// A style attribute over this many bytes is left intact. The bound applies
// before preprocessing, token allocation, or escape decoding.
const maxCSSStyleBytes = 64 << 10

// cssDeclaration is one parsed style declaration: its lowercased name, its
// value rebuilt from tokens, and whether it ended in !important.
type cssDeclaration struct {
	name, value string
	important   bool
}
// cssToken is one CSS Syntax Level 3 token: its kind, its decoded value, and
// whether a numeric token was written as an integer.
type cssToken struct {
	kind      byte
	value     string
	malformed bool
}

const (
	cssIdent      byte = 'i'
	cssSpace      byte = 'w'
	cssFunction   byte = 'f'
	cssString     byte = 's'
	cssURL        byte = 'u'
	cssBad        byte = 'x'
	cssNumber     byte = 'n'
	cssDimension  byte = 'd'
	cssPercentage byte = '%'
	cssAt         byte = 'a'
	cssHash       byte = 'h'
	cssCDO        byte = 'o'
	cssCDC        byte = 'c'
)

// cssLexer tokenizes one preprocessed style attribute (CSS Syntax 3, section 4).
type cssLexer struct {
	r   []rune
	i   int
	bad bool
}

// cssLexerFor preprocesses input per CSS Syntax 3 section 3.3: CR, FF and CRLF
// become LF, and NUL becomes U+FFFD.
func cssLexerFor(s string) cssLexer {
	r := make([]rune, 0, len(s))
	for i := 0; i < len(s); {
		c, n := utf8.DecodeRuneInString(s[i:])
		i += n
		switch c {
		case '\r':
			if i < len(s) && s[i] == '\n' {
				i++
			}
			c = '\n'
		case '\f':
			c = '\n'
		case 0:
			c = unicode.ReplacementChar
		}
		r = append(r, c)
	}
	return cssLexer{r: r}
}

// at returns the code point n positions ahead, or -1 at end of input.
func (l *cssLexer) at(n int) rune {
	if l.i+n >= len(l.r) {
		return -1
	}
	return l.r[l.i+n]
}
func cssWhite(c rune) bool { return c == ' ' || c == '\n' || c == '\t' }
func cssDigit(c rune) bool { return c >= '0' && c <= '9' }
func cssHex(c rune) bool   { return cssDigit(c) || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }
// cssNameStart reports whether c can start a CSS identifier.
func cssNameStart(c rune) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80 && c <= unicode.MaxRune
}
func cssName(c rune) bool        { return cssNameStart(c) || cssDigit(c) || c == '-' }
func (l *cssLexer) escape() bool { return l.at(0) == '\\' && l.at(1) != -1 && l.at(1) != '\n' }

// ident reports whether an identifier starts n positions ahead.
func (l *cssLexer) ident(n int) bool {
	a, b, c := l.at(n), l.at(n+1), l.at(n+2)
	if a == '-' {
		return cssNameStart(b) || b == '-' || b == '\\' && c != -1 && c != '\n'
	}
	return cssNameStart(a) || a == '\\' && b != -1 && b != '\n'
}

// number reports whether a number starts n positions ahead.
func (l *cssLexer) number(n int) bool {
	a, b, c := l.at(n), l.at(n+1), l.at(n+2)
	if a == '+' || a == '-' {
		return cssDigit(b) || b == '.' && cssDigit(c)
	}
	return cssDigit(a) || a == '.' && cssDigit(b)
}

// escaped consumes one escape after the backslash: up to six hex digits and
// one optional whitespace, with zero, surrogate and out-of-range values
// replaced by U+FFFD.
func (l *cssLexer) escaped() rune {
	l.i++ // backslash, only after valid-escape check
	if l.i >= len(l.r) {
		return unicode.ReplacementChar
	}
	if !cssHex(l.at(0)) {
		c := l.at(0)
		l.i++
		return c
	}
	var c rune
	for n := 0; n < 6 && cssHex(l.at(0)); n++ {
		h := l.at(0)
		l.i++
		switch {
		case h >= '0' && h <= '9':
			c = c*16 + h - '0'
		case h >= 'a' && h <= 'f':
			c = c*16 + h - 'a' + 10
		default:
			c = c*16 + h - 'A' + 10
		}
	}
	if cssWhite(l.at(0)) {
		l.i++
	}
	if c == 0 || c > unicode.MaxRune || c >= 0xd800 && c <= 0xdfff {
		return unicode.ReplacementChar
	}
	return c
}

// name consumes an identifier sequence, decoding escapes.
func (l *cssLexer) name() string {
	var b strings.Builder
	for cssName(l.at(0)) || l.escape() {
		if l.escape() {
			b.WriteRune(l.escaped())
		} else {
			b.WriteRune(l.at(0))
			l.i++
		}
	}
	return b.String()
}

// stringToken consumes a string closed by q; an unescaped newline makes it a
// bad string.
func (l *cssLexer) stringToken(q rune) cssToken {
	l.i++
	var b strings.Builder
	for {
		c := l.at(0)
		switch c {
		case -1:
			l.bad = true
			return cssToken{cssString, b.String(), true}
		case '\n':
			l.bad = true
			return cssToken{cssBad, "", true}
		case '\\':
			if l.at(1) == '\n' {
				l.i += 2
				continue
			}
			if l.at(1) == -1 {
				l.i++
				continue
			}
			b.WriteRune(l.escaped())
		default:
			l.i++
			if c == q {
				return cssToken{cssString, string(q) + b.String() + string(q), false}
			}
			b.WriteRune(c)
		}
	}
}

// url consumes the body of an unquoted url( ) token.
func (l *cssLexer) url() cssToken {
	for cssWhite(l.at(0)) {
		l.i++
	}
	var b strings.Builder
	bad := false
	for {
		c := l.at(0)
		switch {
		case c == ')':
			l.i++
			return cssToken{cssURL, "url(" + b.String() + ")", bad}
		case c == -1:
			l.bad = true
			return cssToken{cssURL, b.String(), true}
		case cssWhite(c):
			for cssWhite(l.at(0)) {
				l.i++
			}
			if l.at(0) == ')' {
				l.i++
				return cssToken{cssURL, "url(" + b.String() + ")", bad}
			}
			bad = true
		case c == '"' || c == '\'' || c == '(' || c < 0x20 && c != '\n' && c != '\t' || c == '\\' && !l.escape():
			bad = true
		case l.escape():
			b.WriteRune(l.escaped())
			continue
		default:
			if !bad {
				b.WriteRune(c)
			}
		}
		if bad {
			for l.at(0) != -1 && l.at(0) != ')' {
				if l.escape() {
					l.escaped()
				} else {
					l.i++
				}
			}
			if l.at(0) == ')' {
				l.i++
			}
			l.bad = true
			return cssToken{cssBad, "", true}
		}
		l.i++
	}
}

// token consumes and returns the next token.
func (l *cssLexer) token() cssToken {
	for l.at(0) == '/' && l.at(1) == '*' {
		l.i += 2
		for l.at(0) != -1 && (l.at(0) != '*' || l.at(1) != '/') {
			l.i++
		}
		if l.at(0) == -1 {
			l.bad = true
			return cssToken{cssBad, "", true}
		}
		l.i += 2
	}
	c := l.at(0)
	if c == -1 {
		return cssToken{0, "", false}
	}
	if cssWhite(c) {
		for cssWhite(l.at(0)) {
			l.i++
		}
		return cssToken{cssSpace, " ", false}
	}
	if c == '"' || c == '\'' {
		return l.stringToken(c)
	}
	if c == '<' && l.at(1) == '!' && l.at(2) == '-' && l.at(3) == '-' {
		l.i += 4
		return cssToken{cssCDO, "<!--", false}
	}
	if c == '-' && l.at(1) == '-' && l.at(2) == '>' {
		l.i += 3
		return cssToken{cssCDC, "-->", false}
	}
	if c == '@' {
		l.i++
		if l.ident(0) {
			return cssToken{cssAt, "@" + l.name(), false}
		}
		return cssToken{'@', "@", false}
	}
	if c == '#' {
		l.i++
		if cssName(l.at(0)) || l.escape() {
			return cssToken{cssHash, "#" + l.name(), false}
		}
		return cssToken{'#', "#", false}
	}
	if l.number(0) {
		start := l.i
		if c == '+' || c == '-' {
			l.i++
		}
		for cssDigit(l.at(0)) {
			l.i++
		}
		if l.at(0) == '.' && cssDigit(l.at(1)) {
			l.i++
			for cssDigit(l.at(0)) {
				l.i++
			}
		}
		if l.at(0) == 'e' || l.at(0) == 'E' {
			n := 1
			if l.at(1) == '+' || l.at(1) == '-' {
				n++
			}
			if cssDigit(l.at(n)) {
				l.i += n
				for cssDigit(l.at(0)) {
					l.i++
				}
			}
		}
		v := string(l.r[start:l.i])
		if l.ident(0) {
			return cssToken{cssDimension, v + l.name(), false}
		}
		if l.at(0) == '%' {
			l.i++
			return cssToken{cssPercentage, v + "%", false}
		}
		return cssToken{cssNumber, v, false}
	}
	if l.ident(0) {
		v := l.name()
		if l.at(0) == '(' {
			l.i++
			if strings.EqualFold(v, "url") {
				j := 0
				for cssWhite(l.at(j)) {
					j++
				}
				if l.at(j) != '"' && l.at(j) != '\'' {
					return l.url()
				}
			}
			return cssToken{cssFunction, v, false}
		}
		return cssToken{cssIdent, v, false}
	}
	if c == '\\' && !l.escape() {
		l.bad = true
	}
	l.i++
	if c > 127 {
		return cssToken{cssBad, "", true}
	}
	return cssToken{string(c)[0], string(c), c == '\\'}
}

// cssDeclarations parses a style attribute as a list of declarations
// (CSS Syntax 3, section 5.4.5). Malformed declarations are skipped to the
// next semicolon, and input over the size cap yields no declarations, so an
// unreadable style never counts as hiding.
func cssDeclarations(style string) []cssDeclaration {
	if len(style) > maxCSSStyleBytes {
		return nil
	}
	l := cssLexerFor(style)
	var out []cssDeclaration
	for {
		t := l.token()
		if t.kind == 0 {
			break
		}
		if t.kind == cssSpace || t.kind == ';' {
			continue
		}
		if t.kind == cssAt {
			cssSkip(&l)
			continue
		}
		if t.kind != cssIdent {
			cssSkip(&l)
			continue
		}
		name := t.value
		t = l.token()
		for t.kind == cssSpace {
			t = l.token()
		}
		if t.kind != ':' {
			if t.kind != 0 && t.kind != ';' {
				cssSkip(&l)
			}
			continue
		}
		var vals []cssToken
		malformed := false
		depth := []byte{}
		for {
			t = l.token()
			if t.kind == 0 || t.kind == ';' && len(depth) == 0 {
				break
			}
			if t.malformed {
				malformed = true
			}
			switch t.kind {
			case cssFunction, '(', '[', '{':
				end := byte(')')
				switch t.kind {
				case '[':
					end = ']'
				case '{':
					end = '}'
				}
				depth = append(depth, end)
			case ')', ']', '}':
				if len(depth) == 0 || depth[len(depth)-1] != t.kind {
					malformed = true
				} else {
					depth = depth[:len(depth)-1]
				}
			}
			vals = append(vals, t)
		}
		if len(depth) > 0 || malformed {
			continue
		}
		for len(vals) > 0 && vals[len(vals)-1].kind == cssSpace {
			vals = vals[:len(vals)-1]
		}
		important := false
		if len(vals) > 0 && vals[len(vals)-1].kind == cssIdent && strings.EqualFold(vals[len(vals)-1].value, "important") {
			j := len(vals) - 2
			for j >= 0 && vals[j].kind == cssSpace {
				j--
			}
			if j >= 0 && vals[j].kind == '!' {
				important = true
				vals = vals[:j]
				for len(vals) > 0 && vals[len(vals)-1].kind == cssSpace {
					vals = vals[:len(vals)-1]
				}
			}
		}
		var b strings.Builder
		for _, v := range vals {
			b.WriteString(v.value)
		}
		out = append(out, cssDeclaration{name: name, value: b.String(), important: important})
		if t.kind == 0 {
			break
		}
	}
	return out
}

// cssSkip discards tokens through the next top-level semicolon.
func cssSkip(l *cssLexer) {
	depth := []byte{}
	for {
		t := l.token()
		if t.kind == 0 {
			return
		}
		if t.kind == ';' && len(depth) == 0 {
			return
		}
		switch t.kind {
		case cssFunction, '(', '[', '{':
			end := byte(')')
			switch t.kind {
			case '[':
				end = ']'
			case '{':
				end = '}'
			}
			depth = append(depth, end)
		case ')', ']', '}':
			if len(depth) > 0 && depth[len(depth)-1] == t.kind {
				depth = depth[:len(depth)-1]
			}
		}
	}
}
