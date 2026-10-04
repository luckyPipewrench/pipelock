// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

func TestDecodingPreprocessingParity(t *testing.T) {
	inputs := []string{
		"", "a", "ab", "abc", "alpha beta", "plain sample body", "different sample body",
		"000x", "0a0xb", `\x61\X62`, "0x61 0X62", "61:62", "61-62", "61,62",
		"MY======!", "MY======!!", "MY=====!", "CP======!", "CP=====!",
		"YQ==", "YQ", "YWJj", "YWJj\r\n", "Y\rQ=\n=", "YQ==!", "-___", "+///",
		`\u0061\u0062`, `\uD83D\uDE00`, `\uD800`, `\u123`, `\uZZZZ`, "café",
		strings.Repeat("a", maxReassembledTokenLen-1) + "!",
		strings.Repeat("a", maxReassembledTokenLen) + "!",
		strings.Repeat("a", maxReassembledTokenLen+1) + "!",
	}
	for value := byte(0); ; value++ {
		byteText := string([]byte{value})
		inputs = append(inputs, byteText, "6162"+byteText, byteText+"YWJj", "MY======"+byteText)
		if value == 255 {
			break
		}
	}
	for i := 0; i < 256; i++ {
		digest := sha256.Sum256(fmt.Appendf(nil, "sample-%d", i))
		payload := make([]byte, i%65)
		for j := range payload {
			payload[j] = digest[j%len(digest)]
		}
		inputs = append(inputs, string(payload), hex.EncodeToString(payload))
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
			value := enc.EncodeToString(payload)
			inputs = append(inputs, value, value+"!", value[:len(value)/2]+"\r\n"+value[len(value)/2:])
		}
		for _, enc := range []*base32.Encoding{base32.StdEncoding, base32.HexEncoding, base32.StdEncoding.WithPadding(base32.NoPadding), base32.HexEncoding.WithPadding(base32.NoPadding)} {
			value := enc.EncodeToString(payload)
			inputs = append(inputs, value, strings.ToLower(value), value+"!", value+"!!")
		}
	}
	decodedCases := 0
	for i, input := range inputs {
		t.Run(fmt.Sprintf("case_%d", i), func(t *testing.T) {
			if got, want := normalizeHex(input), referenceNormalizeHex(input); got != want {
				t.Fatalf("hex normalization differs for %q: got %q, want %q", input, got, want)
			}
			if got, want := stripHexPrefixes(input), referenceStripHexPrefixes(input); got != want {
				t.Fatalf("hex prefixes differ for %q: got %q, want %q", input, got, want)
			}
			for _, kind := range []encodedTokenKind{encodedTokenBase64Std, encodedTokenBase64URL, encodedTokenBase32} {
				if got, want := normalizeEncodedToken(input, kind), referenceNormalizeEncodedToken(input, kind); got != want {
					t.Fatalf("token normalization %d differs for %q: got %q, want %q", kind, input, got, want)
				}
			}
			want := referenceDecodeEncodings(input)
			if len(want) > 0 {
				decodedCases++
			}
			if got := decodeEncodings(input); !reflect.DeepEqual(got, want) {
				t.Fatalf("ordered decoding differs for %q:\ngot %#v\nwant %#v", input, got, want)
			}
		})
	}
	if decodedCases < 256 {
		t.Fatalf("parity corpus exercised only %d successful inputs", decodedCases)
	}
}

func TestDecodingPreprocessingRequestIsolation(t *testing.T) {
	for _, text := range []string{"first body", "second body", "first body", "", "second body"} {
		input := base64.StdEncoding.EncodeToString([]byte(text))
		if got, want := decodeEncodings(input), referenceDecodeEncodings(input); !reflect.DeepEqual(got, want) {
			t.Fatalf("request %q reused another request's decoding: got %#v, want %#v", text, got, want)
		}
	}
}

func TestBase64ScratchPreservesOwnedOrderedViews(t *testing.T) {
	for _, size := range []int{0, 1, 2, 3, 254, 255, 256, 257, 1024, maxReassembledTokenLen} {
		payload := strings.Repeat("a", size)
		for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			encoded := encoding.EncodeToString([]byte(payload))
			for _, input := range []string{encoded, encoded + "!", "\r\n" + encoded} {
				want := referenceDecodeEncodings(input)
				got := decodeEncodings(input)
				// Later attempts and requests must not overwrite returned views.
				_ = decodeEncodings(base64.StdEncoding.EncodeToString([]byte(strings.Repeat("different body", size+1))))
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("scratch reuse changed ordered views at size %d: got %#v, want %#v", size, got, want)
				}
			}
		}
	}
}

func TestRecursiveDecodingPreprocessingParity(t *testing.T) {
	inputs := []string{"plain first body", "plain second body", "MY======!", "CP======!", `\u0061\u0062`, "a%20b"}
	for i := 1; i <= 12; i++ {
		value := strings.Repeat("sample", i)
		inputs = append(inputs, base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString([]byte(value)))))
		inputs = append(inputs, hex.EncodeToString([]byte(base32.HexEncoding.EncodeToString([]byte(value)))))
	}
	for _, input := range inputs {
		for _, includeURL := range []bool{false, true} {
			got := decodeEncodingsFixpoint(input, includeURL)
			want := referenceDecodeEncodingsFixpoint(input, includeURL)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("recursive views differ for %q (URL %v):\ngot %#v\nwant %#v", input, includeURL, got, want)
			}
		}
	}
}

func TestBase32PrefixPreservesDecoderPaddingBehavior(t *testing.T) {
	inputs := []string{"", "MY======!", "CP======!", "MY" + strings.Repeat("\xff", 6), "CP" + strings.Repeat("\xff", 6), "MZXW6YQ\xff"}
	for value := byte(0); ; value++ {
		for _, text := range []string{"MY======", "CP======", "MZXW6YQ="} {
			for pos := 0; pos <= len(text); pos++ {
				inputs = append(inputs, text[:pos]+string([]byte{value})+text[pos:])
			}
		}
		if value == 255 {
			break
		}
	}
	for _, input := range inputs {
		if got, want := appendBase32Decodes(nil, input), referenceAppendBase32Decodes(nil, input); !reflect.DeepEqual(got, want) {
			t.Fatalf("base32 helper differs for %q: got %#v, want %#v", input, got, want)
		}
	}
}

func referenceDecodeEncodingsFixpoint(s string, includeURL bool) []decodedResult {
	if s == "" || len(s) > maxDecodeTotalBytes {
		return nil
	}
	seen := map[string]struct{}{s: {}}
	var out []decodedResult
	queue := []string{s}
	consumed := 0
	for head := 0; head < len(queue) && len(out) < maxDecodeCandidates && consumed < maxDecodeTotalBytes; head++ {
		text := queue[head]
		candidates := referenceDecodeEncodings(text)
		if includeURL {
			if decoded := IterativeDecode(text); decoded != text && decoded != "" {
				candidates = append(candidates, decodedResult{decoded, encodingURL})
			}
		}
		for _, decoded := range candidates {
			if decoded.text == "" {
				continue
			}
			if _, ok := seen[decoded.text]; ok {
				continue
			}
			seen[decoded.text] = struct{}{}
			out = append(out, decoded)
			consumed += len(decoded.text)
			if len(out) >= maxDecodeCandidates || consumed >= maxDecodeTotalBytes {
				return out
			}
			queue = append(queue, decoded.text)
		}
	}
	return out
}

// These reference helpers freeze the pre-optimization transformations. The
// comparisons retain decoder order and duplicates, not only a set of views.
func referenceNormalizeHex(s string) string {
	if len(s) < 4 {
		return ""
	}

	// Consume a radix or escape prefix only when two hex digits follow it.
	// An unconditional replace ate the zero in a value such as "000x", which
	// both hid needle bytes from the matcher and reconstructed a different
	// view than the receipt replay builds from the same recipe.
	out := referenceStripHexPrefixes(s)

	// Strip separator bytes, but reject on an out-of-alphabet LETTER. A
	// separator an attacker can insert is punctuation or whitespace; it is
	// never a letter. That distinction is what keeps ordinary prose out:
	// stripping every non-hex byte turns "abcdefghijklmnopqrstuvwxyz0123456789!"
	// into a long run of a-f digits that is valid, even-length hex, so 74 KB of
	// English collapsed into a 32 KB token that decoded and rescanned for
	// seconds. Rejecting at the first g-z keeps the widened separator coverage
	// while prose fails immediately.
	var b strings.Builder
	b.Grow(len(out))
	for i := 0; i < len(out); i++ {
		switch c := out[i]; {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
			b.WriteByte(c)
		case c == 'x', c == 'X':
			// the radix/escape marker itself. A stray one is noise
			// rather than data, and rejecting it would reopen the swallow case
			// this profile exists to fix ("0a0xb" must still yield "0a0b").
		case c >= 'g' && c <= 'z', c >= 'G' && c <= 'Z':
			return ""
		}
	}
	out = b.String()

	// Validate: must be even-length, non-empty, and credential-sized.
	if len(out) == 0 || len(out)%2 != 0 || len(out) > maxReassembledTokenLen {
		return ""
	}
	return out
}

func referenceStripHexPrefixes(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if i+3 < len(s) &&
			(s[i] == '0' || s[i] == '\\') &&
			(s[i+1] == 'x' || s[i+1] == 'X') &&
			isHexDigitByte(s[i+2]) && isHexDigitByte(s[i+3]) {
			i += 2
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func referenceNormalizeEncodedToken(s string, kind encodedTokenKind) string {
	if len(s) < 4 {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	changed := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isEncodedTokenByte(c, kind) {
			b.WriteByte(c)
			continue
		}
		changed = true
	}
	if !changed {
		return ""
	}
	out := b.String()
	if len(out) < 4 || len(out) > maxReassembledTokenLen {
		return ""
	}
	return out
}

func referenceDecodeEncodings(s string) []decodedResult {
	var out []decodedResult
	if decoded, err := hex.DecodeString(s); err == nil && len(decoded) > 0 {
		out = append(out, decodedResult{string(decoded), encodingHex})
	} else if normalized := referenceNormalizeHex(s); normalized != "" {
		// Delimiter-separated hex (e.g., 73:6b:2d, \x73\x6b, 0x736b).
		if decoded, err := hex.DecodeString(normalized); err == nil && len(decoded) > 0 {
			out = append(out, decodedResult{string(decoded), encodingHex})
		}
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.RawURLEncoding,
	} {
		if decoded, err := enc.DecodeString(s); err == nil && len(decoded) > 0 {
			out = append(out, decodedResult{string(decoded), encodingBase64})
		}
	}
	if normalized := referenceNormalizeEncodedToken(s, encodedTokenBase64Std); normalized != "" {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
			if decoded, err := enc.DecodeString(normalized); err == nil && len(decoded) > 0 {
				out = append(out, decodedResult{string(decoded), encodingBase64})
			}
		}
	}
	if normalized := referenceNormalizeEncodedToken(s, encodedTokenBase64URL); normalized != "" {
		for _, enc := range []*base64.Encoding{base64.URLEncoding, base64.RawURLEncoding} {
			if decoded, err := enc.DecodeString(normalized); err == nil && len(decoded) > 0 {
				out = append(out, decodedResult{string(decoded), encodingBase64})
			}
		}
	}
	// RFC 4648 base32 and base32hex are case-insensitive. Folding to ASCII
	// uppercase before decode accepts lower and mixed case without treating
	// that fold as a separate base32 alphabet. Canonical recipe replay keeps
	// the fold as its own operation so older profiles stay case-sensitive.
	foldedBase32 := normalize.ASCIIUpper(s)
	out = referenceAppendBase32Decodes(out, foldedBase32)
	if normalized := referenceNormalizeEncodedToken(foldedBase32, encodedTokenBase32); normalized != "" && normalized != foldedBase32 {
		out = referenceAppendBase32Decodes(out, normalized)
	}
	if decoded := normalize.DecodeJSONUnicodeEscapes(s); decoded != s && decoded != "" {
		out = append(out, decodedResult{decoded, encodingJSONUnicode})
	}
	return out
}

func referenceAppendBase32Decodes(out []decodedResult, value string) []decodedResult {
	for _, enc := range []*base32.Encoding{
		base32.StdEncoding,
		base32.StdEncoding.WithPadding(base32.NoPadding),
		base32.HexEncoding,
		base32.HexEncoding.WithPadding(base32.NoPadding),
	} {
		decoded, err := enc.DecodeString(value)
		if err != nil || len(decoded) == 0 {
			continue
		}
		out = append(out, decodedResult{string(decoded), encodingBase32})
	}
	return out
}
