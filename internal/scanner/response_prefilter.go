// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"sort"
	"strings"
)

// responsePreFilter provides fast keyword-based pre-screening for response
// pattern matching. Before running expensive regex against the full content,
// it checks whether any literal keyword anchor from the pattern set appears
// in the text. If no keywords are found, regex matching is skipped entirely.
//
// This sits ahead of passes 1+2 (the primary bottleneck) and the opt-space
// pass. Content-based, not position-based: no blind spots.
//
// Conservative: false positives (running regex unnecessarily) are fine.
// False negatives (skipping regex when keywords exist) are not.
type responsePreFilter struct {
	// keywords maps lowercased keyword anchors to the pattern indices
	// in the parent Scanner.responsePatterns slice that share that keyword.
	keywords map[string][]int

	// alwaysRun holds indices of patterns with no extractable keyword.
	// These are always evaluated regardless of content. Typically cheap
	// patterns like the Pliny divider (short literal, fast regex failure).
	alwaysRun []int
}

// newResponsePreFilter builds a pre-filter from response patterns.
// Extracts keyword anchors from each pattern, handling literal prefixes
// and leading alternation groups.
func newResponsePreFilter(patterns []*compiledPattern) *responsePreFilter {
	pf := &responsePreFilter{
		keywords: make(map[string][]int),
	}

	for i, p := range patterns {
		keywords := extractResponseKeywords(p.re.String())
		if len(keywords) == 0 {
			pf.alwaysRun = append(pf.alwaysRun, i)
			continue
		}
		for _, kw := range keywords {
			lower := strings.ToLower(kw)
			pf.keywords[lower] = append(pf.keywords[lower], i)
		}
	}

	return pf
}

// patternsToCheck returns the combined set of pattern indices that should
// be evaluated: keyword-matched candidates plus alwaysRun patterns.
// Returns nil when no patterns need to run.
func (pf *responsePreFilter) patternsToCheck(content string) []int {
	lower := strings.ToLower(content)
	var hits []int
	seen := make(map[int]bool)
	for kw, indices := range pf.keywords {
		if strings.Contains(lower, kw) {
			for _, idx := range indices {
				if !seen[idx] {
					seen[idx] = true
					hits = append(hits, idx)
				}
			}
		}
	}
	for _, idx := range pf.alwaysRun {
		if !seen[idx] {
			seen[idx] = true
			hits = append(hits, idx)
		}
	}
	sort.Ints(hits)
	return hits
}

// extractResponseKeywords extracts keyword anchors from a response pattern
// regex. The shared syntax-tree extractor proves that every branch contains at
// least one returned anchor; otherwise the pattern stays in alwaysRun.
func extractResponseKeywords(regex string) []string {
	return extractConservativeLiteralAnchors(regex, false)
}

// hasEncodedRun checks whether content contains a contiguous run of
// base64 or hex alphabet characters long enough to be a meaningful
// encoded payload. Used to skip expensive decode attempts on content
// that is clearly not encoded. Set low (8) to catch short encoded
// payloads like base64("system:") = "c3lzdGVtOg==" (12 chars).
const minEncodedRunLen = 8

func hasEncodedRun(content string) bool {
	run := 0
	for i := 0; i < len(content); i++ {
		c := content[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '/' ||
			c == '-' || c == '_' || c == '=' {
			run++
			if run >= minEncodedRunLen {
				return true
			}
		} else {
			run = 0
		}
	}
	return false
}
