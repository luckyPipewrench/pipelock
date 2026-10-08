// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"regexp"
	"regexp/syntax"
)

import "github.com/luckyPipewrench/pipelock/internal/config"

// responsePreFilter applies necessary literal and distance conditions plus
// bounded negative proofs before matching response patterns on the full text.
//
// This sits ahead of passes 1+2 and the opt-space pass. Literal presence and
// regex-derived distance conditions are necessary conditions, never limits on
// which input positions the original matcher can inspect.
//
// Conservative: false positives (running regex unnecessarily) are fine.
// False negatives (skipping a real match) are not.
type responsePreFilter struct {
	gates           []*responseGate
	proofs          []*responseSuffixProof
	prefixes        []*responseSuffixProof
	companionProofs [][]*responseSuffixProof

	// alwaysRun holds indices of patterns with no extractable keyword gate.
	// A separate negative proof can still exclude these patterns.
	alwaysRun []int
}

// A view is owned by one sequential response scan and keyed by exact input
// bytes in its memo. It shares the gate's derived text across pattern groups.
type responsePreFilterView struct {
	folded, distance string
	literals         responseLiteralMemo
	ready            bool
}

// newResponsePreFilter builds a pre-filter from response patterns.
// Extracts keyword anchors from each pattern, handling literal prefixes
// and leading alternation groups.
func newResponsePreFilter(patterns []*compiledPattern) *responsePreFilter {
	pf := &responsePreFilter{
		gates:           make([]*responseGate, len(patterns)),
		proofs:          make([]*responseSuffixProof, len(patterns)),
		prefixes:        make([]*responseSuffixProof, len(patterns)),
		companionProofs: make([][]*responseSuffixProof, len(patterns)),
	}

	for i, p := range patterns {
		// Companion detectors need independent necessary conditions. A negative
		// for the main expression alone must never skip the companion arms.
		if p.name != externalDataTransferDirectivePatternName || p.re.String() != config.ExternalDataTransferDirectiveRegex {
			tree, err := syntax.Parse(p.re.String(), syntax.Perl)
			if err == nil {
				pf.gates[i] = responseLiteralGate(tree)
				pf.proofs[i] = newResponseSuffixProof(p.re)
				if p.responseMemoRegexp != nil && p.responseMemoRegexp == p.re {
					pf.prefixes[i] = newResponsePrefixProof(p.re)
				}
			}
		} else if p.responseMemoRegexp != nil && p.responseMemoRegexp == p.re {
			for _, re := range []*regexp.Regexp{p.re, externalTransferURLCandidateRE, externalTransferFileDirectiveRE} {
				pf.companionProofs[i] = append(pf.companionProofs[i], newResponsePrefixProof(re))
			}
		}
		if pf.gates[i] == nil {
			pf.alwaysRun = append(pf.alwaysRun, i)
		}
	}

	return pf
}

// patternsToCheck returns pattern indices not excluded by gates or proofs.
// Returns nil when no patterns need to run.
func (pf *responsePreFilter) patternsToCheck(content string) []int {
	return pf.patternsToCheckWithMemo(content, nil)
}

func (pf *responsePreFilter) patternsToCheckWithMemo(content string, cached *responsePreFilterView) []int {
	if cached == nil {
		cached = &responsePreFilterView{}
	}
	if !cached.ready {
		cached.folded = responseSimpleFold(content)
		cached.distance = responseDistanceText(cached.folded)
		cached.ready = true
	}
	if cached.literals == nil && len(content) >= responseMemoMinBytes && len(content) <= responseMemoMaxBytes {
		cached.literals = make(responseLiteralMemo)
	}
	folded, distanceText, literals := cached.folded, cached.distance, cached.literals
	var view *responseFoldView
	var forward *responseFoldView
	hits := make([]int, 0, len(pf.gates))
	for i, gate := range pf.gates {
		if gate != nil && !gate.matchesWithMemo(content, folded, distanceText, literals) {
			continue
		}
		if len(content) >= responseMemoMinBytes && len(content) <= responseMemoMaxBytes && i < len(pf.prefixes) && pf.prefixes[i] != nil {
			if forward == nil {
				forward = newResponseFoldView(content, folded)
				forward.literals = literals
			}
			if pf.prefixes[i].provesEmpty(forward) {
				continue
			}
		}
		if len(content) >= responseMemoMinBytes && len(content) <= responseMemoMaxBytes && i < len(pf.companionProofs) && len(pf.companionProofs[i]) == 3 {
			if forward == nil {
				forward = newResponseFoldView(content, folded)
				forward.literals = literals
			}
			allEmpty := true
			for _, proof := range pf.companionProofs[i] {
				if !proof.provesEmpty(forward) {
					allEmpty = false
					break
				}
			}
			if allEmpty {
				continue
			}
		}
		// Small bodies already match cheaply. Bound the additional text and offset
		// storage; every ineligible or inconclusive proof runs the ordinary matcher.
		if len(content) >= responseMemoMinBytes && len(content) <= responseMemoMaxBytes && i < len(pf.proofs) && pf.proofs[i] != nil {
			if view == nil {
				// Folding is per rune and maps invalid bytes to U+FFFD, so the
				// reversed fold equals the fold of the reversed text.
				view = newResponseFoldView(reverseResponseText(content), reverseResponseText(folded))
			}
			if pf.proofs[i].provesEmpty(view) {
				continue
			}
		}
		hits = append(hits, i)
	}
	return hits
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
