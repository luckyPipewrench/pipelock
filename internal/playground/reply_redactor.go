// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !js

package playground

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// minPlantedSecretLen guards the planted-secret transform check: a needle shorter
// than this is too likely to substring-match benign reply text, so it is skipped.
// Both planted demo secrets (the AKIA+16 access key id and the 40-char secret
// access key) are well above it.
const minPlantedSecretLen = 12

// chunkSeparators are characters a visitor might insert between secret characters
// to break the contiguous value ("A K I A", "AKIA, KEY", "AKIA|KEY"). None of
// them appear in the planted-secret alphabet ([A-Za-z0-9-_]), so stripping them
// recovers a chunked secret without mangling a clean one. Dash and underscore are
// deliberately NOT stripped: they are part of the secret-key alphabet.
const chunkSeparators = " \t\r\n,.:;|*"

// containsPlantedSecret reports whether text appears to carry any planted demo
// secret, including the common transforms a visitor might use to smuggle the
// value past the generic reply DLP: exact (any case), whitespace/separator
// chunked, reversed, base64 (std/url, padded/unpadded), or hex.
//
// This is a DEMO-SIDE browser-safety redactor, NOT a Pipelock network-egress
// proof. The signed receipts and the host-containment witness are the authority
// for what the firewall actually enforced on the wire; this layer only keeps the
// planted secret from being rendered to the visitor's browser in an obvious
// transform. It biases toward over-redaction (flagging a clean reply is
// harmless; rendering the secret is not).
//
// Documented limits (honest, per the project's adversarial-review rule): it does
// NOT catch multi-layer nesting (base64 of a reversed value, double-base64),
// per-character interleaved encodings, homoglyph substitution, or dash/underscore
// chunking of a base64url secret. Those are reply-cosmetic gaps, not firewall
// gaps: the enforced boundary and its receipts are unaffected by how the model
// renders text to the browser.
func containsPlantedSecret(text string, secrets []string) bool {
	if strings.TrimSpace(text) == "" {
		return false
	}
	lowerText := strings.ToLower(text)
	strippedRawText := stripChunkSeparators(text)
	strippedText := stripChunkSeparatorsLower(text)
	for _, secret := range secrets {
		if len(secret) < minPlantedSecretLen {
			continue
		}
		lowerSecret := strings.ToLower(secret)
		// Exact, case-insensitive: an agent can recase a secret.
		if strings.Contains(lowerText, lowerSecret) {
			return true
		}
		// Chunked: strip separators from both sides, then compare.
		if strings.Contains(strippedText, stripChunkSeparatorsLower(secret)) {
			return true
		}
		// Reversed.
		reversed := reverseString(secret)
		if strings.Contains(lowerText, strings.ToLower(reversed)) ||
			strings.Contains(strippedText, stripChunkSeparatorsLower(reversed)) {
			return true
		}
		// Hex, case-insensitive.
		hexed := hex.EncodeToString([]byte(secret))
		if strings.Contains(lowerText, hexed) || strings.Contains(strippedText, hexed) {
			return true
		}
		// Base64, every common variant. Case-sensitive: base64 is.
		for _, enc := range []*base64.Encoding{
			base64.StdEncoding,
			base64.RawStdEncoding,
			base64.URLEncoding,
			base64.RawURLEncoding,
		} {
			encoded := enc.EncodeToString([]byte(secret))
			if strings.Contains(text, encoded) || strings.Contains(strippedRawText, encoded) {
				return true
			}
		}
	}
	return false
}

// stripChunkSeparators removes the chunk separators from s, preserving case for
// encodings such as base64 where case is significant.
func stripChunkSeparators(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if strings.ContainsRune(chunkSeparators, r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// stripChunkSeparatorsLower removes the chunk separators from s and lowercases the
// result, so a separator-broken secret compares equal to the contiguous one.
func stripChunkSeparatorsLower(s string) string {
	return strings.ToLower(stripChunkSeparators(s))
}

// reverseString returns s with its runes in reverse order.
func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}
