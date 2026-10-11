// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

// rawQuerySecurityPairs splits before decoding. Escaped separators remain
// value data, while literal ampersands and semicolons delimit recoverable pairs.
// Unlike ParseQuery, malformed percent escapes cannot remove a pair.
type rawQuerySecurityPair struct{ key, value string }

func rawQuerySecurityPairs(query string) []rawQuerySecurityPair {
	var values []rawQuerySecurityPair
	for _, pair := range strings.FieldsFunc(query, func(r rune) bool { return r == '&' || r == ';' }) {
		key, value, _ := strings.Cut(pair, "=")
		values = append(values, rawQuerySecurityPair{key: key, value: value})
	}
	return values
}

// recoverEncodingViews supplements strict decoding. Its bounds are shared with
// typed replay, and an output must contain a printable run long enough to hold
// a credential prefix. This avoids rescanning binary noise derived from prose.
func recoverEncodingViews(text string) []decodedResult {
	if len(text) < 10 {
		return nil
	}
	var out []decodedResult
	for _, alphabet := range []string{"hex", "standard", "url"} {
		if alphabet == "url" && !strings.ContainsAny(text, "+/-_") {
			continue // both base64 alphabets would produce identical views
		}
		encoding := encodingBase64
		if alphabet == "hex" {
			encoding = encodingHex
		}
		for _, decoded := range normalize.RecoveryViews(text, alphabet) {
			out = append(out, decodedResult{decoded, encoding})
		}
	}
	return out
}

// decodedKnownSecretViews shares the bounded candidate graph used for pattern
// DLP. Matching encoded representations alone misses secrets inside a carrier.
func decodedKnownSecretViews(text string, decodes *decodingMemo) []spanTextView {
	var views []spanTextView
	add := func(value string) {
		for _, decoded := range decodes.decode(value, true) {
			views = append(views, spanTextView{text: decoded.text, viewLabel: dlpViewLabel(decoded.encoding)})
		}
	}
	add(text)
	for _, segment := range strings.FieldsFunc(text, isTextDLPEncodingDelimiter) {
		if segment != text {
			add(segment)
		}
	}
	return views
}

// The fixpoint graph already provides encoding layers as separate views. Only
// plaintext and partial-secret matching remain; re-encoding every secret for
// every decoded view repeats work without adding a security view.
func matchDecodedKnownSecret(secret string, windows knownValueWindowIndex, views []spanTextView, hits *knownValueWindowHits) (knownSecretMatch, int, int, string, bool) {
	if start, end, label, ok := indexAnyView(secret, views); ok {
		return knownSecretMatch{encoding: strings.TrimPrefix(label, ViewDLPNormalized+":")}, start, end, label, true
	}
	if start, end, length, label, ok := indexKnownValueSubstringWithHits(secret, windows, views, hits); ok {
		return knownSecretMatch{encoding: strings.TrimPrefix(label, ViewDLPNormalized+":"), partialLen: length}, start, end, label, true
	}
	return knownSecretMatch{}, 0, 0, "", false
}
