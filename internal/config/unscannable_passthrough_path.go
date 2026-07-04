// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"net/url"
	"strings"
)

const maxUnscannablePassthroughPathDecodePasses = 4

// CanonicalUnscannablePassthroughPath returns the exact decoded path form used
// by the unscannable passthrough allowlist. It is intentionally stricter than
// normal URL routing: root paths, path parameters, control characters, double
// slashes, dot segments, encoded slashes/backslashes, and multi-encoded
// topology changes are rejected.
func CanonicalUnscannablePassthroughPath(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "/" || !strings.HasPrefix(raw, "/") || strings.ContainsAny(raw, "?#") {
		return "", false
	}
	if hasUnscannablePassthroughControl(raw) {
		return "", false
	}

	rawSegments := strings.Split(raw[1:], "/")
	segments := make([]string, 0, len(rawSegments))
	for _, rawSegment := range rawSegments {
		if rawSegment == "" {
			return "", false
		}
		segment, ok := canonicalUnscannablePassthroughSegment(rawSegment)
		if !ok {
			return "", false
		}
		segments = append(segments, segment)
	}
	return "/" + strings.Join(segments, "/"), true
}

func canonicalUnscannablePassthroughSegment(raw string) (string, bool) {
	segment := raw
	for range maxUnscannablePassthroughPathDecodePasses {
		hasEscape, invalidEscape := unscannablePassthroughPercentEscapeState(segment)
		if invalidEscape {
			return "", false
		}
		if !hasEscape {
			break
		}
		decoded, err := url.PathUnescape(segment)
		if err != nil {
			return "", false
		}
		if decoded == segment {
			break
		}
		segment = decoded
	}
	if hasEscape, invalidEscape := unscannablePassthroughPercentEscapeState(segment); hasEscape || invalidEscape {
		return "", false
	}
	if segment == "" || segment == "." || segment == ".." {
		return "", false
	}
	if strings.ContainsAny(segment, `/\;`) || hasUnscannablePassthroughControl(segment) {
		return "", false
	}
	return segment, true
}

func unscannablePassthroughPercentEscapeState(s string) (hasEscape bool, invalidEscape bool) {
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			continue
		}
		if i+2 >= len(s) || !isUnscannablePassthroughHex(s[i+1]) || !isUnscannablePassthroughHex(s[i+2]) {
			return false, true
		}
		hasEscape = true
		i += 2
	}
	return hasEscape, false
}

func isUnscannablePassthroughHex(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

func hasUnscannablePassthroughControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x1F || s[i] == 0x7F {
			return true
		}
	}
	return false
}
