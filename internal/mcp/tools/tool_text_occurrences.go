// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

// credentialRequestOccurrence is one match of a Credential Request Directive
// pattern, attributed to the single tool field that holds all of it.
type credentialRequestOccurrence struct {
	// Pointer is the RFC 6901 pointer of the field within the tool definition.
	Pointer string
	// Pattern is the index of the matching pattern among the family's
	// patterns, in toolPoisonPatterns order.
	Pattern int
	// Ordinal counts earlier occurrences with the same Pointer and Pattern.
	Ordinal int
	// Start and End are byte offsets of the match within the field's
	// normalized text.
	Start, End int
	// MatchSHA256 is the hex SHA-256 of the normalized matched text.
	MatchSHA256 string
}

// credentialRequestAttribution is the result of attributing every Credential
// Request Directive match in a tool's scan text to a source field.
type credentialRequestAttribution struct {
	// Attributable is true only when the per-field normalization reproduces
	// the detector's normalized text byte for byte and every match lies wholly
	// inside one pointer-bearing field. Anything else must enforce.
	Attributable bool
	// Occurrences lists the attributed matches in detector order.
	Occurrences []credentialRequestOccurrence
	// Unattributed counts matches that touch a separator, fall in text with no
	// single source field, or were found while the normalization gate failed.
	Unattributed int
}

// normalizedRegion locates one span's text inside the normalized scan text.
type normalizedRegion struct {
	pointer    string
	start, end int
}

// normalizedRegions normalizes each span and each separator on its own and
// concatenates the results. The regions are usable only when that
// concatenation is byte-identical to norm, the text the detector actually
// matched; normalization that interacts across a boundary fails the gate.
func normalizedRegions(text, norm string, spans []toolTextSpan) ([]normalizedRegion, bool) {
	var b strings.Builder
	regions := make([]normalizedRegion, 0, len(spans))
	prev := 0
	for _, sp := range spans {
		if sp.Start < prev || sp.End < sp.Start || sp.End > len(text) {
			return nil, false
		}
		b.WriteString(normalize.ForToolText(text[prev:sp.Start]))
		start := b.Len()
		b.WriteString(normalize.ForToolText(text[sp.Start:sp.End]))
		regions = append(regions, normalizedRegion{pointer: sp.Pointer, start: start, end: b.Len()})
		prev = sp.End
	}
	b.WriteString(normalize.ForToolText(text[prev:]))
	if b.String() != norm {
		return nil, false
	}
	return regions, true
}

// attributeCredentialRequests enumerates every Credential Request Directive
// match in the scan text and attributes each one to its source field.
//
// Continuation contract: it steps through matches exactly as checkToolPoison
// does, resuming the search on the remaining suffix after each match. "^"
// therefore matches again at every resume point, which FindAll would not
// allow, so a match can begin where the previous one consumed its clause
// boundary. checkToolPoison stops at the first match of the family; this
// continues with the same stepping, so the occurrences are what the detector
// would report if it kept going. It decides nothing about whether the wording
// is harmless.
func attributeCredentialRequests(text string, spans []toolTextSpan) credentialRequestAttribution {
	return attributeWithNorm(text, normalize.ForToolText(text), spans)
}

// attributeWithNorm is attributeCredentialRequests over an already normalized
// text. No input found so far makes per-field normalization differ from the
// whole, but that is an observation over finite probes, not a proof:
// correctness rests on the unconditional byte-equality check in
// normalizedRegions. Tests pass a mismatched norm to exercise that path.
func attributeWithNorm(text, norm string, spans []toolTextSpan) credentialRequestAttribution {
	regions, ok := normalizedRegions(text, norm, spans)

	var out credentialRequestAttribution
	type ordinalKey struct {
		pointer string
		pattern int
	}
	ordinals := make(map[ordinalKey]int)
	family := 0
	for _, p := range toolPoisonPatterns {
		if p.name != handoverRequestFinding {
			continue
		}
		pattern := family
		family++
		for offset := 0; offset < len(norm); {
			loc := p.re.FindStringIndex(norm[offset:])
			if loc == nil {
				break
			}
			start, end := loc[0]+offset, loc[1]+offset
			offset = end
			if end == start {
				offset++
			}
			region, found := normalizedRegion{}, false
			if ok {
				for _, r := range regions {
					if start >= r.start && end <= r.end {
						region, found = r, true
						break
					}
				}
			}
			if !found || region.pointer == "" {
				out.Unattributed++
				continue
			}
			key := ordinalKey{region.pointer, pattern}
			sum := sha256.Sum256([]byte(norm[start:end]))
			out.Occurrences = append(out.Occurrences, credentialRequestOccurrence{
				Pointer:     region.pointer,
				Pattern:     pattern,
				Ordinal:     ordinals[key],
				Start:       start - region.start,
				End:         end - region.start,
				MatchSHA256: hex.EncodeToString(sum[:]),
			})
			ordinals[key]++
		}
	}
	out.Attributable = ok && out.Unattributed == 0
	return out
}
