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
type rawQuerySecurityPair struct {
	key, value string
	hasValue   bool
}

func rawQuerySecurityPairs(query string) []rawQuerySecurityPair {
	var values []rawQuerySecurityPair
	for _, pair := range strings.FieldsFunc(query, func(r rune) bool { return r == '&' || r == ';' }) {
		key, value, hasValue := strings.Cut(pair, "=")
		values = append(values, rawQuerySecurityPair{key: key, value: value, hasValue: hasValue})
	}
	return values
}

// decodedKnownSecretViews shares the bounded candidate graph used for pattern
// DLP. Matching encoded representations alone misses secrets inside a carrier.
func (s *Scanner) decodedKnownSecretViews(text string, decodes *decodingMemo) []spanTextView {
	var views []spanTextView
	minimum := min(minKnownSecretSubstringLen, s.minEnvSecretLen)
	add := func(value string) {
		// Decoding cannot grow a candidate; shorter input cannot contain a
		// whole configured secret or an eligible partial-secret window.
		if len(value) < minimum {
			return
		}
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

// queryDLPSecurityViews lets exemptions inspect the same raw components and
// decoding targets as query DLP. Trust validation remains separate and strict.
func queryDLPSecurityViews(rawQuery string) []string {
	var views []string
	for _, pair := range rawQuerySecurityPairs(rawQuery) {
		for _, raw := range []string{pair.key, pair.value} {
			once := normalize.QueryUnescapePartial(raw)
			decoded := IterativeDecode(raw)
			views = append(views, raw, once, decoded, stripURLNoise(decoded))
			for _, candidate := range queryValueDecodedTargets(once) {
				views = append(views, candidate.text)
			}
			for _, candidate := range queryValueDecodedTargets(decoded) {
				views = append(views, candidate.text)
			}
			if raw != decoded {
				for _, candidate := range queryValueDecodedTargets(raw) {
					views = append(views, candidate.text)
				}
			}
		}
	}
	return views
}
