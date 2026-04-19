// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package redact

import "strings"

// RewriteString applies matches (pre-sorted by Start ascending, non-
// overlapping) to s, replacing each match with a typed placeholder from r.
// Returns the rewritten string. Matches are consumed in order; any match
// whose Start < previous.End is silently skipped (defensive — Scan should
// not emit overlapping matches).
func RewriteString(s string, matches []Match, r *Redactor) string {
	if len(matches) == 0 || s == "" {
		return s
	}
	var b strings.Builder
	// Rough capacity hint: original length plus slack for placeholders.
	b.Grow(len(s) + len(matches)*16)
	cursor := 0
	for _, m := range matches {
		if m.Start < cursor || m.Start < 0 || m.End > len(s) || m.End <= m.Start {
			continue
		}
		b.WriteString(s[cursor:m.Start])
		b.WriteString(r.Placeholder(m.Class, m.Original))
		cursor = m.End
	}
	b.WriteString(s[cursor:])
	return b.String()
}
