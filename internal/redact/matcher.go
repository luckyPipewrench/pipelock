// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var (
	errNilMatcher      = errors.New("redact: nil matcher")
	errEmptyDictionary = errors.New("redact: dictionary has no entries")
	errInvalidClass    = errors.New("redact: class must match [a-z0-9][a-z0-9_-]*")
)

// classNameRe enforces the placeholder-safe shape for operator-supplied
// class names. Shipped const classes already satisfy this. The constraint
// exists so `<pl:CLASS:N>` cannot be perturbed by adversarial class names
// (e.g. "foo>bar" produces `<pl:foo>bar:1>` which confuses downstream
// parsers that split on `>`).
var classNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// Match is a single redactable span inside a string scalar. Start and End
// are byte offsets into the scalar (half-open, [Start, End)). Original is
// the matched substring.
type Match struct {
	Class    Class
	Start    int
	End      int
	Original string
}

// Matcher scans a string for redactable spans using a fixed set of class
// patterns plus optional operator-supplied dictionaries. A Matcher is
// immutable after construction and safe for concurrent use across
// goroutines; each scan builds its own match list.
type Matcher struct {
	patterns []classPattern
	// dictionaries compiled into a single alternation regex per class.
	// Separate from patterns so dictionary matches can be disambiguated
	// from regex matches in telemetry and tests.
	dicts []dictPattern
}

// dictPattern is a compiled operator dictionary: one alternation regex
// across all entries for a single class, with a per-pattern priority so
// dictionary hits can dominate or defer to regex hits depending on operator
// preference.
type dictPattern struct {
	class    Class
	pattern  *regexp.Regexp
	priority int
}

// NewDefaultMatcher returns a Matcher configured with the shipped class
// registry and no operator dictionaries. Equivalent to a profile that
// enables every structured class but no contextual entities.
func NewDefaultMatcher() *Matcher {
	return &Matcher{patterns: defaultRegistry()}
}

// Dictionary is an operator-supplied named list of literal strings that
// should be redacted as a single semantic class. Each entry is escaped and
// compiled into one alternation regex; all matches for the dictionary are
// tagged with Class.
type Dictionary struct {
	// Class is the redaction class that dictionary hits are tagged with.
	// Callers typically use a domain-specific class string like "customer"
	// or "hostname" rather than a shipped const.
	Class Class
	// Entries is the literal set of strings to match. Empty entries are
	// ignored silently.
	Entries []string
	// CaseInsensitive toggles case-insensitive matching via the `(?i)`
	// regex flag. Defaults to false.
	CaseInsensitive bool
	// WordBoundary wraps the alternation in `\b...\b` so "corp" does not
	// match inside "incorporation". Defaults to false.
	WordBoundary bool
	// Priority places dictionary hits in the overlap-resolution order
	// relative to class regexes. A dictionary for "customer" that should
	// win over the generic FQDN class sets priority above 50. Zero = lowest.
	Priority int
}

// AddDictionary compiles d into a dictionary pattern and attaches it to
// the matcher. Returns an error if the entries list is empty or if the
// compiled regex would exceed RE2's implementation limits.
//
// Matcher is intended to be constructed once and then scanned against many
// inputs; AddDictionary is not safe to call concurrently with Scan. Build
// all dictionaries before handing the matcher to request handlers.
func (m *Matcher) AddDictionary(d Dictionary) error {
	if m == nil {
		return errNilMatcher
	}
	if !classNameRe.MatchString(string(d.Class)) {
		return fmt.Errorf("%w: got %q", errInvalidClass, string(d.Class))
	}
	// Strip empties and deduplicate while preserving order of first
	// occurrence for deterministic regex output (helps testing).
	seen := make(map[string]struct{}, len(d.Entries))
	pruned := make([]string, 0, len(d.Entries))
	for _, e := range d.Entries {
		if e == "" {
			continue
		}
		if _, ok := seen[e]; ok {
			continue
		}
		seen[e] = struct{}{}
		pruned = append(pruned, e)
	}
	if len(pruned) == 0 {
		return errEmptyDictionary
	}

	// Longest literals first prevents prefix entries from shadowing a longer
	// secret in the same alternation (e.g. "dc01" before "dc01.corp.local").
	sort.SliceStable(pruned, func(i, j int) bool {
		return len(pruned[i]) > len(pruned[j])
	})

	// Escape regex metachars in each entry, join with `|`.
	escaped := make([]string, len(pruned))
	for i, e := range pruned {
		escaped[i] = regexp.QuoteMeta(e)
	}
	body := strings.Join(escaped, "|")

	pattern := "(?:" + body + ")"
	if d.WordBoundary {
		pattern = `\b` + pattern + `\b`
	}
	if d.CaseInsensitive {
		pattern = "(?i)" + pattern
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	m.dicts = append(m.dicts, dictPattern{
		class:    d.Class,
		pattern:  re,
		priority: d.Priority,
	})
	return nil
}

// Scan returns all redactable matches in s, with overlapping spans resolved
// by priority (highest wins) then by leftmost-longest. Returned matches are
// sorted by Start ascending and do not overlap.
func (m *Matcher) Scan(s string) []Match {
	if s == "" || m == nil {
		return nil
	}

	var raw []Match
	for _, cp := range m.patterns {
		for _, loc := range cp.pattern.FindAllStringIndex(s, -1) {
			raw = append(raw, Match{
				Class:    cp.class,
				Start:    loc[0],
				End:      loc[1],
				Original: s[loc[0]:loc[1]],
			})
		}
	}
	for _, dp := range m.dicts {
		for _, loc := range dp.pattern.FindAllStringIndex(s, -1) {
			raw = append(raw, Match{
				Class:    dp.class,
				Start:    loc[0],
				End:      loc[1],
				Original: s[loc[0]:loc[1]],
			})
		}
	}

	return resolveOverlaps(raw, m.priorityLookup())
}

// priorityLookup returns a map from Class to priority for overlap
// resolution. Called per Scan so dictionaries added after construction (not
// supported in v1, but defensive) still resolve correctly.
func (m *Matcher) priorityLookup() map[Class]int {
	out := make(map[Class]int, len(m.patterns)+len(m.dicts))
	for _, cp := range m.patterns {
		// Keep the max priority seen for a class (same class can have
		// multiple underlying regexes in theory; use the strongest).
		if p, ok := out[cp.class]; !ok || cp.priority > p {
			out[cp.class] = cp.priority
		}
	}
	for _, dp := range m.dicts {
		if p, ok := out[dp.class]; !ok || dp.priority > p {
			out[dp.class] = dp.priority
		}
	}
	return out
}

// resolveOverlaps picks a non-overlapping subset of raw matches. The rule:
//  1. Sort by (priority desc, start asc, length desc).
//  2. Walk in that order, admitting a match if its span is free; otherwise
//     drop it.
//  3. Re-sort the admitted set by Start ascending so callers can rewrite
//     the string in a single left-to-right pass.
func resolveOverlaps(raw []Match, priorityOf map[Class]int) []Match {
	if len(raw) <= 1 {
		// Even a single match benefits from the Start-ascending sort.
		sort.SliceStable(raw, func(i, j int) bool { return raw[i].Start < raw[j].Start })
		return raw
	}
	sort.SliceStable(raw, func(i, j int) bool {
		pi, pj := priorityOf[raw[i].Class], priorityOf[raw[j].Class]
		if pi != pj {
			return pi > pj
		}
		if raw[i].Start != raw[j].Start {
			return raw[i].Start < raw[j].Start
		}
		return (raw[i].End - raw[i].Start) > (raw[j].End - raw[j].Start)
	})

	admitted := make([]Match, 0, len(raw))
	// Interval tree would be faster but overkill for this size; a simple
	// sorted list with linear check is fine for typical request bodies.
	for _, cand := range raw {
		if overlapsAny(cand, admitted) {
			continue
		}
		admitted = append(admitted, cand)
	}
	sort.SliceStable(admitted, func(i, j int) bool { return admitted[i].Start < admitted[j].Start })
	return admitted
}

func overlapsAny(c Match, adm []Match) bool {
	for _, a := range adm {
		if c.Start < a.End && a.Start < c.End {
			return true
		}
	}
	return false
}
