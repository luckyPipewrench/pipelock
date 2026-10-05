// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package normalize

import (
	"sync"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// inertRuneLimit bounds the precomputed tables. Every one- and two-byte UTF-8
// scalar is below it, which covers most scalars that decoding random bytes
// (hex, base64 and base32 views of signatures, keys and nonces) produces.
const inertRuneLimit = 0x800

// segmentTable precomputes one pipeline over every scalar below
// inertRuneLimit.
//
// A scalar is inert when it is a stable code point in the UAX #15 sense for
// every normalization form the pipeline uses (canonical combining class 0, no
// decomposition, normalization quick check Yes, and no composition with a
// preceding or following scalar), is neither a combining mark (Mn) nor in the
// confusable map, is not removed by the strip stage, and passes the full
// pipeline unchanged on its own. U+FFFD is inert, and the strip stage turns
// every invalid UTF-8 byte into it.
//
// No stage can carry state across an inert scalar: the strip, confusable,
// mark-strip and whitespace stages act per scalar, and NFKC, NFD and NFC never
// compose, decompose or reorder across a stable code point. So the pipeline
// output of a string is the concatenation of the pipeline output of each
// maximal run between inert scalars, with the inert scalars copied through.
// Removed scalars are not split points, because removing one makes its
// neighbours adjacent; they stay inside their run.
type segmentTable struct {
	inert [inertRuneLimit / 64]uint64
	// single is the full pipeline output of each scalar alone. It is the
	// output of a run that holds exactly that scalar, since the run is
	// bounded by inert scalars or the ends of the string.
	single [inertRuneLimit]string
}

type segmentTables struct {
	dlp      segmentTable
	matching [2]segmentTable // index 1 recomposes with NFC, index 0 does not
}

var segmentTablesOnce = sync.OnceValue(buildSegmentTables)

func buildSegmentTables() *segmentTables {
	t := &segmentTables{}
	for r := rune(0); r < inertRuneLimit; r++ {
		single := string(r)
		isolated := boundaryIsolated(r)
		t.dlp.fill(r, forDLPFull(single), isolated && !isDLPStripped(r))
		for i, recompose := range []bool{false, true} {
			t.matching[i].fill(r, matchingNormalizeFull(single, recompose), isolated && !isMatchingStripped(r))
		}
	}
	return t
}

func (t *segmentTable) fill(r rune, out string, eligible bool) {
	t.single[r] = out
	if eligible && out == string(r) {
		t.inert[r/64] |= uint64(1) << (r % 64)
	}
}

// boundaryIsolated reports whether r is a stable code point for NFKC, NFKD,
// NFC and NFD and is untouched by the confusable and mark-strip stages.
func boundaryIsolated(r rune) bool {
	if unicode.Is(unicode.Mn, r) {
		return false
	}
	if _, ok := confusableMap[r]; ok {
		return false
	}
	single := string(r)
	for _, form := range []norm.Form{norm.NFKC, norm.NFD, norm.NFC, norm.NFKD} {
		p := form.PropertiesString(single)
		if p.Size() != len(single) || p.CCC() != 0 || p.LeadCCC() != 0 || p.TrailCCC() != 0 ||
			len(p.Decomposition()) != 0 || !p.BoundaryBefore() || !p.BoundaryAfter() {
			return false
		}
		if !form.IsNormalString(single) {
			return false
		}
	}
	return true
}

func isMatchingStripped(r rune) bool {
	if r <= 0x1F && r != '\t' && r != '\n' && r != '\r' {
		return true
	}
	return r == 0x7F || (r >= 0x80 && r <= 0x9F) || unicode.Is(InvisibleRanges, r)
}

func isDLPStripped(r rune) bool {
	return isDLPControl(r) || isExoticWhitespace(r)
}

func (t *segmentTable) isInert(r rune) bool {
	if r == utf8.RuneError {
		return true
	}
	return r >= 0 && r < inertRuneLimit && t.inert[r/64]&(uint64(1)<<(r%64)) != 0
}

// normalizeSegmented returns full(s), computed run by run between inert
// scalars. Invalid UTF-8 bytes are split points that become U+FFFD. When the
// output equals s, s is returned without allocating.
func normalizeSegmented(s string, t *segmentTable, full func(string) string) string {
	var out []byte // nil until the output first differs from s
	runStart := -1
	flush := func(end int) {
		run := s[runStart:end]
		var normalized string
		if r, size := utf8.DecodeRuneInString(run); size == len(run) && r < inertRuneLimit {
			normalized = t.single[r]
		} else {
			normalized = full(run)
		}
		if out == nil && normalized != run {
			out = make([]byte, 0, len(s))
			out = append(out, s[:runStart]...)
		}
		if out != nil {
			out = append(out, normalized...)
		}
		runStart = -1
	}
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		invalid := r == utf8.RuneError && size == 1
		if !invalid && !t.isInert(r) {
			if runStart < 0 {
				runStart = i
			}
			i += size
			continue
		}
		if runStart >= 0 {
			flush(i)
		}
		if invalid {
			if out == nil {
				out = make([]byte, 0, len(s))
				out = append(out, s[:i]...)
			}
			out = utf8.AppendRune(out, utf8.RuneError)
		} else if out != nil {
			out = append(out, s[i:i+size]...)
		}
		i += size
	}
	if runStart >= 0 {
		flush(len(s))
	}
	if out == nil {
		return s
	}
	return string(out)
}
