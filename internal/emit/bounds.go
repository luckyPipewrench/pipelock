// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package emit

import "unicode/utf8"

// Audit sinks copy attacker-influenceable event fields into their output. A
// single oversized field (a hostile scanner reason, URL, or agent name) would
// otherwise be duplicated across several output fields and turn one audit event
// into a multi-megabyte record delivered to every configured sink. That is an
// amplification vector on the audit path itself, so every sink format bounds the
// strings it emits.
//
// The bound lives here rather than in each format so a new sink inherits it, and
// so the cap is stated once instead of drifting between formats.
const (
	// emitMaxStringBytes is the per-string byte cap applied by every sink format.
	emitMaxStringBytes = 8192

	// emitTruncationMarker is appended to any value the cap actually cut, so a
	// bounded value is at most emitMaxStringBytes plus this marker, and an
	// operator can tell truncation from a value that merely ends abruptly.
	emitTruncationMarker = "...[truncated]"
)

// boundEventString caps s at emitMaxStringBytes, appending emitTruncationMarker
// when it cuts. The cut backs off to a rune boundary so a multi-byte character
// is not split into an invalid sequence that renders as U+FFFD downstream.
func boundEventString(s string) string {
	if len(s) <= emitMaxStringBytes {
		return s
	}
	cut := emitMaxStringBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + emitTruncationMarker
}
