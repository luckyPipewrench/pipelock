// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// matchSecretEncodingSpanReference is matchSecretEncodingSpan as it was before
// encodings were precomputed: every form is built inside the call. Tests hold
// the current matcher to identical results.
func matchSecretEncodingSpanReference(secret string, windows knownValueWindowIndex, texts, lowerTexts []spanTextView) (knownSecretMatch, int, int, string, bool) {
	// Raw match.
	if start, end, viewLabel, ok := indexAnyView(secret, texts); ok {
		return knownSecretMatch{}, start, end, viewLabel, true
	}
	if start, end, length, viewLabel, ok := indexKnownValueSubstring(secret, windows, texts); ok {
		return knownSecretMatch{partialLen: length}, start, end, viewLabel, true
	}

	// Every encoding below is at least as long as the secret (base64 4/3,
	// base32 8/5, hex and its delimited forms 2x or more, decimal codes at
	// least one digit per byte), and the token matchers only skip text bytes,
	// so none can occur in a text shorter than the secret. Skipping them keeps
	// a long known value, such as an inline certificate in the environment,
	// from being re-encoded on every scan of a short request.
	if len(secret) > longestSpanTextView(texts, lowerTexts) {
		return knownSecretMatch{}, 0, 0, "", false
	}

	// Base64 standard (padded + unpadded).
	b64Std := base64.StdEncoding.EncodeToString([]byte(secret))
	b64StdNoPad := strings.TrimRight(b64Std, "=")
	if start, end, viewLabel, ok := indexAnyView(b64Std, texts); ok {
		return knownSecretMatch{encoding: encodingBase64}, start, end, viewLabel, true
	}
	if b64StdNoPad != b64Std {
		if start, end, viewLabel, ok := indexAnyView(b64StdNoPad, texts); ok {
			return knownSecretMatch{encoding: encodingBase64}, start, end, viewLabel, true
		}
	}
	if start, end, viewLabel, ok := indexEncodedTokenView(b64Std, texts, encodedTokenBase64Std); ok {
		return knownSecretMatch{encoding: encodingBase64}, start, end, viewLabel, true
	}
	if b64StdNoPad != b64Std {
		if start, end, viewLabel, ok := indexEncodedTokenView(b64StdNoPad, texts, encodedTokenBase64Std); ok {
			return knownSecretMatch{encoding: encodingBase64}, start, end, viewLabel, true
		}
	}

	// Base64 URL-safe (padded + unpadded).
	b64URL := base64.URLEncoding.EncodeToString([]byte(secret))
	b64URLNoPad := strings.TrimRight(b64URL, "=")
	if b64URL != b64Std {
		if start, end, viewLabel, ok := indexAnyView(b64URL, texts); ok {
			return knownSecretMatch{encoding: "base64url"}, start, end, viewLabel, true
		}
	}
	if b64URLNoPad != b64StdNoPad {
		if start, end, viewLabel, ok := indexAnyView(b64URLNoPad, texts); ok {
			return knownSecretMatch{encoding: "base64url"}, start, end, viewLabel, true
		}
	}
	if b64URL != b64Std {
		if start, end, viewLabel, ok := indexEncodedTokenView(b64URL, texts, encodedTokenBase64URL); ok {
			return knownSecretMatch{encoding: "base64url"}, start, end, viewLabel, true
		}
	}
	if b64URLNoPad != b64StdNoPad {
		if start, end, viewLabel, ok := indexEncodedTokenView(b64URLNoPad, texts, encodedTokenBase64URL); ok {
			return knownSecretMatch{encoding: "base64url"}, start, end, viewLabel, true
		}
	}

	// Hex (case-insensitive via pre-lowered texts).
	hexEnc := hex.EncodeToString([]byte(secret))
	if start, end, viewLabel, ok := indexAnyView(hexEnc, lowerTexts); ok {
		return knownSecretMatch{encoding: encodingHex}, start, end, viewLabel, true
	}

	// Delimiter-separated hex variants for env/file secret detection.
	// Matches all formats that normalizeHex can strip.
	colonHex := hexByteSep(hexEnc, ":")
	spaceHex := hexByteSep(hexEnc, " ")
	hyphenHex := hexByteSep(hexEnc, "-")
	commaHex := hexByteSep(hexEnc, ",")
	bsxHex := hexBytePrefix(hexEnc, `\x`)
	zxHex := hexBytePrefix(hexEnc, "0x")
	for _, candidate := range []string{colonHex, spaceHex, hyphenHex, commaHex, bsxHex, zxHex} {
		if start, end, viewLabel, ok := indexAnyView(candidate, lowerTexts); ok {
			return knownSecretMatch{encoding: encodingHex}, start, end, viewLabel, true
		}
	}
	if start, end, viewLabel, ok := indexHexTokenView(hexEnc, lowerTexts); ok {
		return knownSecretMatch{encoding: encodingHex}, start, end, viewLabel, true
	}

	for _, candidate := range []string{decimalCharacterCodes(secret, ","), decimalCharacterCodes(secret, " ")} {
		if start, end, viewLabel, ok := indexAnyView(candidate, texts); ok {
			return knownSecretMatch{encoding: encodingDecimal}, start, end, viewLabel, true
		}
	}

	// Base32 standard (padded + unpadded).
	b32Std := base32.StdEncoding.EncodeToString([]byte(secret))
	b32NoPad := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(secret))
	if start, end, viewLabel, ok := indexAnyView(b32Std, texts); ok {
		return knownSecretMatch{encoding: encodingBase32}, start, end, viewLabel, true
	}
	if b32NoPad != b32Std {
		if start, end, viewLabel, ok := indexAnyView(b32NoPad, texts); ok {
			return knownSecretMatch{encoding: encodingBase32}, start, end, viewLabel, true
		}
	}
	if start, end, viewLabel, ok := indexEncodedTokenView(b32Std, texts, encodedTokenBase32); ok {
		return knownSecretMatch{encoding: encodingBase32}, start, end, viewLabel, true
	}
	if b32NoPad != b32Std {
		if start, end, viewLabel, ok := indexEncodedTokenView(b32NoPad, texts, encodedTokenBase32); ok {
			return knownSecretMatch{encoding: encodingBase32}, start, end, viewLabel, true
		}
	}

	return knownSecretMatch{}, 0, 0, "", false
}
