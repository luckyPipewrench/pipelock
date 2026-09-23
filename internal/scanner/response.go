// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

// ResponseScanResult describes the outcome of scanning response content.
type ResponseScanResult struct {
	Clean   bool
	Matches []ResponseMatch
	// ScanError records why scanning could not complete. It is deliberately
	// separate from Matches: an incomplete scan must fail closed, but it is not
	// evidence that response content matched a prompt-injection pattern.
	ScanError         string
	SuppressedMatches []ResponseMatch `json:"-"`
	// ObservedCoreMatches carries core-floor findings that an operator's
	// declared exception downgraded from block to observe. They are findings,
	// not misses: the scan ran and matched, and every one of these is emitted
	// as evidence under its own reason so it is distinguishable from an
	// ordinary suppression. A non-empty slice here with Clean true means the
	// operator accepted this exact risk on this exact host in writing.
	ObservedCoreMatches []ObservedCoreMatch `json:"-"`
	TransformedContent  string              // set for strip and ask actions

	// StegoDetected fires when the raw response carries combining-mark density
	// at or above normalize.ZalgoSuspiciousThreshold. The pattern-matching
	// pipeline already neutralizes combining marks via StripCombiningMarks, so
	// this is an exposure/provenance signal - Clean is NOT flipped on the
	// basis of this field alone. The taint/authority policy layer may key on
	// this signal in strict mode without changing the scanner's verdict
	// contract today. Maps to emit.EventTextStego.
	StegoDetected bool
	StegoDensity  int // raw combining-mark density on original content
}

// Failed reports whether the response could not be fully scanned. Failed
// results are fail-closed and must be reported as scan errors, never as
// injection detections.
func (r ResponseScanResult) Failed() bool {
	return r.ScanError != ""
}

// ResponseMatch describes a single pattern match in response content.
type ResponseMatch struct {
	PatternName   string `json:"pattern_name"`
	MatchText     string `json:"match_text"` // truncated to 100 chars
	Position      int    `json:"position"`
	Bundle        string `json:"bundle,omitempty"`
	BundleVersion string `json:"bundle_version,omitempty"`
	matchLength   int
	span          MatchSpan
	// crossesFragmentBoundary is set only when whole-content decoding joined
	// source text across a reconstructed opaque-response boundary. Decoded
	// match spans index decoded bytes, so they cannot prove this from offsets.
	crossesFragmentBoundary bool
	decodedSourceStart      int
	decodedSourceEnd        int
	hasDecodedSource        bool
}

type responseMatchSet struct {
	matches []ResponseMatch
	content string
}

// Span returns retained coordinates for this match in the normalized scanner
// view named by MatchSpan.ViewLabel. It never includes matched bytes.
func (m ResponseMatch) Span() MatchSpan {
	return m.span
}

// ScanResponse checks fetched content for prompt injection patterns.
// If scanning is disabled, returns Clean=true immediately.
// Zero-width Unicode characters are stripped before scanning to prevent
// evasion via invisible character insertion.
// For "strip" action, replaces matches with [REDACTED: PatternName].
func (s *Scanner) ScanResponse(ctx context.Context, content string) ResponseScanResult {
	return s.ScanResponseWithSuppress(ctx, content, "", nil)
}

// ScanResponseBodyWithSuppress scans a raw HTTP response body. For verified PNG
// and JPEG bodies it scans textual metadata but excludes compressed pixel data.
// Other opaque binary bodies are not treated as prose: arbitrary compressed
// bytes can contain accidental pattern-shaped sequences that have no prompt
// semantics. Declared Content-Type is not consulted, so mislabeled textual
// content still takes the ordinary scan path.
func (s *Scanner) ScanResponseBodyWithSuppress(ctx context.Context, body []byte, suppressTarget string, suppress []config.SuppressEntry) ResponseScanResult {
	if ctx != nil && ctx.Err() != nil {
		return s.ScanResponseWithSuppress(ctx, "", suppressTarget, suppress)
	}
	metadata, image, err := responseImageMetadata(body)
	if !image {
		if hasResponseImageSignature(body) {
			result := s.ScanResponseWithSuppress(ctx, string(body), suppressTarget, suppress)
			if !result.Clean {
				// An unverified image-shaped body cannot safely be rewritten from
				// a text scan view. Empty output makes strip callers fail closed.
				result.TransformedContent = ""
			}
			return result
		}
		textual, classifyErr := isTextualResponseBody(ctx, body)
		if classifyErr != nil {
			return ResponseScanResult{Clean: false, ScanError: classifyErr.Error()}
		}
		if !textual {
			decoded, decodedOK, decodeErr := decodeLikelyUTF16ResponseBody(ctx, body)
			if decodeErr != nil {
				return ResponseScanResult{Clean: false, ScanError: decodeErr.Error()}
			}
			if decodedOK {
				decodedResult := s.ScanResponseWithSuppress(ctx, decoded, suppressTarget, suppress)
				if !decodedResult.Clean {
					// A decoded view cannot safely replace the encoded body.
					decodedResult.TransformedContent = ""
					return decodedResult
				}
				rawResult := s.scanOpaqueResponseText(ctx, body, suppressTarget, suppress)
				rawResult.SuppressedMatches = append(decodedResult.SuppressedMatches, rawResult.SuppressedMatches...)
				rawResult.ObservedCoreMatches = append(decodedResult.ObservedCoreMatches, rawResult.ObservedCoreMatches...)
				if decodedResult.StegoDensity > rawResult.StegoDensity {
					rawResult.StegoDensity = decodedResult.StegoDensity
				}
				rawResult.StegoDetected = decodedResult.StegoDetected || rawResult.StegoDetected
				return rawResult
			}
			return s.scanOpaqueResponseText(ctx, body, suppressTarget, suppress)
		}
		return s.scanTextualResponseBody(ctx, body, suppressTarget, suppress)
	}
	if err != nil {
		return ResponseScanResult{
			Clean:     false,
			ScanError: fmt.Sprintf("image metadata inspection failed: %v", err),
		}
	}
	if len(metadata) == 0 {
		return ResponseScanResult{Clean: true}
	}
	result := s.ScanResponseWithSuppress(ctx, string(metadata), suppressTarget, suppress)
	if !result.Clean {
		// A metadata-only scan cannot safely transform the complete image body.
		// Leave this empty so strip callers fail closed instead of replacing the
		// image with redacted metadata bytes.
		result.TransformedContent = ""
	}
	return result
}

func (s *Scanner) scanTextualResponseBody(ctx context.Context, body []byte, suppressTarget string, suppress []config.SuppressEntry) ResponseScanResult {
	raw := string(body)
	rawResult := s.ScanResponseWithSuppress(ctx, raw, suppressTarget, suppress)
	if !rawResult.Clean || utf8.ValidString(raw) {
		return rawResult
	}

	separatorView := string(bytes.ToValidUTF8(body, []byte(" ")))
	separatorResult := s.ScanResponseWithSuppress(ctx, separatorView, suppressTarget, suppress)
	separatorResult.SuppressedMatches = append(rawResult.SuppressedMatches, separatorResult.SuppressedMatches...)
	separatorResult.ObservedCoreMatches = append(rawResult.ObservedCoreMatches, separatorResult.ObservedCoreMatches...)
	if rawResult.StegoDensity > separatorResult.StegoDensity {
		separatorResult.StegoDensity = rawResult.StegoDensity
	}
	separatorResult.StegoDetected = rawResult.StegoDetected || separatorResult.StegoDetected
	if !separatorResult.Clean {
		// A normalized separator view cannot safely transform the original bytes.
		separatorResult.TransformedContent = ""
	}
	return separatorResult
}

func (s *Scanner) scanOpaqueResponseText(ctx context.Context, body []byte, suppressTarget string, suppress []config.SuppressEntry) ResponseScanResult {
	views, extractErr := opaqueResponseTextView(ctx, body)
	if extractErr != nil {
		return ResponseScanResult{Clean: false, ScanError: extractErr.Error()}
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return ResponseScanResult{Clean: false, ScanError: err.Error()}
		}
	}
	if views.retained == "" && views.fragmented == "" && views.encoded == "" && views.decoded == "" {
		return ResponseScanResult{Clean: true}
	}
	result := ResponseScanResult{Clean: true}
	if views.retained != "" {
		result = s.ScanResponseWithSuppress(ctx, views.retained, suppressTarget, suppress)
		if !result.Clean {
			result.TransformedContent = ""
			return result
		}
	}
	seenReconstructed := make(map[string]struct{}, 3)
	for _, reconstructed := range []string{views.fragmented, views.encoded, views.decoded} {
		if reconstructed == "" {
			continue
		}
		if _, seen := seenReconstructed[reconstructed]; seen {
			continue
		}
		seenReconstructed[reconstructed] = struct{}{}
		reconstructedResult := s.scanResponseWithSuppress(ctx, reconstructed, suppressTarget, suppress, true)
		reconstructedResult = requireFragmentBoundaryMatch(reconstructed, reconstructedResult)
		reconstructedResult.SuppressedMatches = append(result.SuppressedMatches, reconstructedResult.SuppressedMatches...)
		reconstructedResult.ObservedCoreMatches = append(result.ObservedCoreMatches, reconstructedResult.ObservedCoreMatches...)
		if result.StegoDensity > reconstructedResult.StegoDensity {
			reconstructedResult.StegoDensity = result.StegoDensity
		}
		reconstructedResult.StegoDetected = result.StegoDetected || reconstructedResult.StegoDetected
		result = reconstructedResult
		if !result.Clean {
			break
		}
	}
	if !result.Clean {
		// An extracted view cannot safely replace the complete binary body.
		// Empty output makes strip and ask callers fail closed.
		result.TransformedContent = ""
	}
	return result
}

// requireFragmentBoundaryMatch limits the reconstructed view to findings that
// actually cross one of its synthetic newlines. Internal fragment whitespace is
// normalized to spaces before those newlines are inserted, so a surviving
// newline proves the match joined attacker-separated fragments. This preserves
// short structured and optional-whitespace matches when they cross a boundary
// without promoting an isolated DAN-like token from one fragment.
func requireFragmentBoundaryMatch(content string, result ResponseScanResult) ResponseScanResult {
	if result.Failed() {
		return result
	}
	views := map[string]string{
		ViewForMatching:     normalize.ForMatching(content),
		ViewInvisibleSpaced: normalize.ForMatching(normalize.ReplaceInvisibleWithSpace(content)),
	}
	views[ViewLeetspeak] = normalize.Leetspeak(views[ViewForMatching])
	views[ViewVowelFold] = normalize.FoldVowels(views[ViewForMatching])
	crossesBoundary := func(match ResponseMatch) bool {
		if match.crossesFragmentBoundary {
			return true
		}
		view, ok := views[match.span.ViewLabel]
		if !ok || match.span.ByteStart < 0 || match.span.ByteEnd > len(view) || match.span.ByteStart >= match.span.ByteEnd {
			return false
		}
		return strings.ContainsRune(view[match.span.ByteStart:match.span.ByteEnd], '\n')
	}
	kept := result.Matches[:0]
	for _, match := range result.Matches {
		if crossesBoundary(match) {
			kept = append(kept, match)
		}
	}
	result.Matches = kept
	suppressed := result.SuppressedMatches[:0]
	for _, match := range result.SuppressedMatches {
		if crossesBoundary(match) {
			suppressed = append(suppressed, match)
		}
	}
	result.SuppressedMatches = suppressed
	observed := result.ObservedCoreMatches[:0]
	for _, match := range result.ObservedCoreMatches {
		if crossesBoundary(match.Match) {
			observed = append(observed, match)
		}
	}
	result.ObservedCoreMatches = observed
	if len(kept) == 0 {
		result.Clean = true
		result.TransformedContent = ""
	}
	return result
}

// decodeLikelyUTF16ResponseBody recognizes BOM-marked UTF-16 and BOM-less
// ASCII-range UTF-16 whose NUL bytes consistently occupy one byte parity. The
// parity and density requirements keep arbitrary NUL-bearing binary data on the
// opaque-run path while preserving response scanning for common UTF-16 text.
func decodeLikelyUTF16ResponseBody(ctx context.Context, data []byte) (string, bool, error) {
	if len(data) < 2 {
		return "", false, nil
	}
	littleEndian := false
	offset := 0
	switch {
	case data[0] == 0xff && data[1] == 0xfe:
		littleEndian = true
		offset = 2
	case data[0] == 0xfe && data[1] == 0xff:
		offset = 2
	default:
		sample := data
		if len(sample) > 4096 {
			sample = sample[:4096]
		}
		if len(sample)%2 != 0 {
			sample = sample[:len(sample)-1]
		}
		if len(sample) < 4 {
			return "", false, nil
		}
		var evenNULs, oddNULs int
		for i, b := range sample {
			if i%responseBodyContextCheckBytes == 0 && ctx != nil {
				if err := ctx.Err(); err != nil {
					return "", false, err
				}
			}
			if b != 0 {
				continue
			}
			if i%2 == 0 {
				evenNULs++
			} else {
				oddNULs++
			}
		}
		totalNULs := evenNULs + oddNULs
		if totalNULs < 2 || (evenNULs != 0 && oddNULs != 0) || totalNULs*5 < len(sample)*2 {
			return "", false, nil
		}
		littleEndian = oddNULs > 0
	}

	encoded := data[offset:]
	if len(encoded) == 0 {
		return "", false, nil
	}
	if len(encoded)%2 != 0 {
		encoded = encoded[:len(encoded)-1]
	}
	readUnit := func(i int) uint16 {
		if littleEndian {
			return uint16(encoded[i]) | uint16(encoded[i+1])<<8
		}
		return uint16(encoded[i])<<8 | uint16(encoded[i+1])
	}
	var decoded strings.Builder
	decoded.Grow(len(encoded))
	for i := 0; i < len(encoded); i += 2 {
		if i%responseBodyContextCheckBytes == 0 && ctx != nil {
			if err := ctx.Err(); err != nil {
				return "", false, err
			}
		}
		unit := readUnit(i)
		if unit >= 0xd800 && unit <= 0xdbff && i+3 < len(encoded) {
			next := readUnit(i + 2)
			if next >= 0xdc00 && next <= 0xdfff {
				decoded.WriteRune(utf16.DecodeRune(rune(unit), rune(next)))
				i += 2
				continue
			}
		}
		if unit >= 0xd800 && unit <= 0xdfff {
			decoded.WriteRune(unicode.ReplacementChar)
			continue
		}
		decoded.WriteRune(rune(unit))
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return "", false, err
		}
	}
	return decoded.String(), true, nil
}

// ScanResponseWithSuppress checks fetched content like ScanResponse, but applies
// destination-scoped suppressions inside each normalization pass. This prevents
// a suppressed first-pass hit from masking a later unsuppressed encoded or
// normalized hit on the same content.
func (s *Scanner) ScanResponseWithSuppress(ctx context.Context, content, suppressTarget string, suppress []config.SuppressEntry) (out ResponseScanResult) {
	return s.scanResponseWithSuppress(ctx, content, suppressTarget, suppress, false)
}

func (s *Scanner) scanResponseWithSuppress(ctx context.Context, content, suppressTarget string, suppress []config.SuppressEntry, forceEncodedDecode bool) (out ResponseScanResult) {
	original := content
	content = exciseVerifiedImageDataURLs(content)
	var suppressedMatches []ResponseMatch
	var observedCoreMatches []ObservedCoreMatch
	suppressedSeen := make(map[string]struct{})
	observedSeen := make(map[string]struct{})
	observeHost := coreObserveHostFromTarget(suppressTarget)
	observeNow := time.Now().UTC()
	filterSuppressed := func(matches []ResponseMatch) []ResponseMatch {
		if len(matches) == 0 || suppressTarget == "" {
			return matches
		}
		canSuppress := len(suppress) > 0
		canObserve := len(s.coreObserveExceptions) > 0 && observeHost != ""
		if !canSuppress && !canObserve {
			return matches
		}
		kept := matches[:0]
		for _, match := range matches {
			if config.IsCoreResponsePatternName(match.PatternName) {
				// The immutable floor is never reachable by
				// response_scanning.suppress. It yields only to a declared,
				// unexpired, host-and-pattern-exact observe exception, and even
				// then the finding is retained as evidence rather than dropped.
				if canObserve {
					if entry, ok := config.MatchCoreObserveException(s.coreObserveExceptions, observeHost, match.PatternName, observeNow); ok {
						key := responseMatchLogicalKey(match)
						if _, seen := observedSeen[key]; !seen {
							observedSeen[key] = struct{}{}
							observedCoreMatches = append(observedCoreMatches, ObservedCoreMatch{
								Match:   match,
								Host:    entry.Host,
								Reason:  entry.Reason,
								Owner:   entry.Owner,
								Expires: entry.Expires,
							})
						}
						continue
					}
				}
				kept = append(kept, match)
				continue
			}
			if !canSuppress || !config.IsSuppressed(match.PatternName, suppressTarget, suppress) {
				kept = append(kept, match)
			} else {
				key := responseMatchLogicalKey(match)
				if _, ok := suppressedSeen[key]; !ok {
					suppressedSeen[key] = struct{}{}
					suppressedMatches = append(suppressedMatches, match)
				}
			}
		}
		return kept
	}

	// Stego exposure signal. Computed on the raw content before normalization
	// strips combining marks. The deferred setter stamps every return path -
	// including scan-error and clean fast paths - so downstream
	// consumers (taint/authority layer, audit emitters) can key on the
	// signal without re-scanning. The signal does NOT flip Clean: the
	// matching passes already neutralize combining marks via
	// StripCombiningMarks, so this is an exposure/provenance event, not a
	// block trigger.
	stegoDensity := normalize.ZalgoDensity(original)
	stegoDetected := stegoDensity >= normalize.ZalgoSuspiciousThreshold
	defer func() {
		out.SuppressedMatches = suppressedMatches
		out.ObservedCoreMatches = observedCoreMatches
		out.StegoDensity = stegoDensity
		out.StegoDetected = stegoDetected
	}()

	// Fail-closed: if context is already canceled, block immediately.
	if ctx != nil && ctx.Err() != nil {
		return ResponseScanResult{
			Clean:     false,
			ScanError: ctx.Err().Error(),
		}
	}

	// Core response patterns run FIRST - immutable safety floor.
	// These run regardless of response_scanning.enabled.
	if coreSet := s.scanCoreResponse(content, filterSuppressed, forceEncodedDecode); len(coreSet.matches) > 0 {
		result := ResponseScanResult{
			Clean:   false,
			Matches: coreSet.matches,
		}
		// Support strip/ask actions on core matches so callers that
		// configured strip still get TransformedContent.
		if s.responseAction == config.ActionStrip || s.responseAction == config.ActionAsk {
			transformed := normalize.ForMatching(content)
			transformed = redactResponsePatterns(transformed, s.core.responsePatterns)
			transformed = redactResponsePatterns(transformed, s.core.responseOptSpacePatterns)
			transformed = redactResponsePatterns(transformed, s.core.responseVowelFoldPatterns)
			if transformed != normalize.ForMatching(content) {
				result.TransformedContent = transformed
			}
		}
		return result
	}

	if !s.responseEnabled {
		return ResponseScanResult{Clean: true}
	}

	// Primary: drop invisible chars, then normalize. Catches mid-word ZW insertion
	// where the attacker splits a keyword: "igno\u200bre" → "ignore" (detected).
	// Capture the pre-strip (post-excise) content FIRST so the Secondary spaced
	// pass can reassemble word boundaries from text that still contains the
	// invisibles. Running ReplaceInvisibleWithSpace on the already-stripped
	// content below would be a no-op (nothing left to replace) and silently
	// disable the pass - see scanCoreResponse, which reassembles from `original`.
	preStripContent := content
	content = normalize.ForMatching(content)

	// Primary: run response patterns whose keywords appear in content.
	// Pre-filter checks are per-pass: each normalized variant gets its
	// own keyword check because normalization reveals new keywords
	// (e.g., leetspeak "1gnore" → "ignore" after normalization).
	// Defensive anti-solicitation matches are dropped per-pass (not after the
	// cascade) so an all-defensive early pass cannot mask an encoded
	// solicitation that only a later pass catches. See scanCoreResponse.
	var matches []ResponseMatch
	matches = filterSuppressed(withResponseSpans(filterDefensiveCredentialSolicitationMatches(content, s.matchResponsePatternsPreFiltered(content)), ViewForMatching))

	// Secondary: replace invisible chars with spaces, then normalize. Catches
	// word-boundary collapse where the attacker uses ZW instead of space:
	// "ignore\u200ball" → ForMatching drops ZW → "ignoreall" (bypass).
	// Replacing with space first → "ignore all" → regex `ignore\s+all` matches.
	// Reassemble from preStripContent (invisibles intact), NOT content (already
	// stripped): config patterns with literal inter-word spaces ("you are now")
	// have no other surviving defense because the opt-space pass only relaxes
	// trailing \s+, not literal spaces inside the alternation.
	if len(matches) == 0 {
		spaced := normalize.ForMatching(normalize.ReplaceInvisibleWithSpace(preStripContent))
		if spaced != content {
			matches = filterSuppressed(withResponseSpans(filterDefensiveCredentialSolicitationMatches(spaced, s.matchResponsePatternsPreFiltered(spaced)), ViewInvisibleSpaced))
			if len(matches) > 0 {
				content = spaced // use spaced version for strip action
			}
		}
	}

	// Tertiary: leetspeak normalization. Pre-filter runs on the LEETED
	// content, catching keywords that emerge after digit-to-letter conversion.
	if len(matches) == 0 {
		leeted := normalize.Leetspeak(content)
		if leeted != content {
			matches = filterSuppressed(withResponseSpans(filterDefensiveCredentialSolicitationMatches(leeted, s.matchResponsePatternsPreFiltered(leeted)), ViewLeetspeak))
		}
	}

	// Quaternary: optional-whitespace matching on ZW-stripped text. Catches the
	// combined attack where ZW chars split keywords AND replace word separators:
	// "i\u200bgnore\u200ball\u200bprevious" -> strip ZW -> "ignoreallprevious"
	// Standard \s+ patterns fail on zero whitespace; \s* variants match.
	if len(matches) == 0 && len(s.responseOptSpacePatterns) > 0 {
		matches = filterSuppressed(withResponseSpans(filterDefensiveCredentialSolicitationMatches(content, matchPatternsPreFiltered(s.responseOptSpacePreFilter, s.responseOptSpacePatterns, content)), ViewForMatching))
	}

	// Quinary: vowel-folded matching. Catches confusable-vowel attacks where
	// one character (e.g., ø→o) replaces multiple different vowels, producing
	// near-miss words like "instroctions" that don't match "instructions".
	// Folding all vowels to 'a' in both content and patterns makes them match.
	if len(matches) == 0 && len(s.responseVowelFoldPatterns) > 0 {
		folded := normalize.FoldVowels(content)
		if folded != content {
			matches = filterSuppressed(withResponseSpans(filterDefensiveCredentialSolicitationMatches(folded, matchPatternsPreFiltered(s.responseVowelFoldPreFilter, s.responseVowelFoldPatterns, folded)), ViewVowelFold))
		}
	}

	// Senary: base64/hex decode pass. Only runs when content contains a
	// contiguous run of base64/hex alphabet characters long enough to be
	// a meaningful encoded payload. Skips expensive decode attempts on
	// normal text content.
	if len(matches) == 0 && (forceEncodedDecode || hasEncodedRun(content)) {
		decodedSet := s.matchDecodedResponse(content)
		matches = filterSuppressed(decodedSet.matches)
	}

	// Post-scan context check: if context expired during scanning, fail closed.
	if ctx != nil && ctx.Err() != nil {
		return ResponseScanResult{
			Clean:     false,
			ScanError: ctx.Err().Error(),
		}
	}

	if len(matches) == 0 {
		return ResponseScanResult{Clean: true}
	}
	// Response content cannot prove that a matched directive is harmless by
	// describing itself as educational or placing the directive in quotes.
	// Apply only operator-configured suppression after matching.
	matches = filterSuppressed(matches)
	if len(matches) == 0 {
		return ResponseScanResult{Clean: true}
	}

	result := ResponseScanResult{
		Clean:   false,
		Matches: matches,
	}

	if s.responseAction == config.ActionStrip || s.responseAction == config.ActionAsk {
		transformed := content
		transformed = redactResponsePatterns(transformed, s.responsePatterns)
		transformed = redactResponsePatterns(transformed, s.responseOptSpacePatterns)
		transformed = redactResponsePatterns(transformed, s.responseVowelFoldPatterns)
		// If redaction had no effect (detection came from a transformed pass
		// like vowel-fold or decoded where patterns don't match the original
		// text form), leave TransformedContent empty. Callers treat empty
		// TransformedContent as "could not strip, fall back to block".
		if transformed != content {
			result.TransformedContent = transformed
		}
	}

	return result
}

func redactResponsePatterns(content string, patterns []*compiledPattern) string {
	for _, p := range patterns {
		replacement := fmt.Sprintf("[REDACTED: %s]", p.name)
		locs := responsePatternMatchLocations(p, content)
		sort.Slice(locs, func(i, j int) bool { return locs[i][0] > locs[j][0] })
		for _, loc := range locs {
			content = content[:loc[0]] + replacement + content[loc[1]:]
		}
	}
	return content
}

func responseMatchLogicalKey(match ResponseMatch) string {
	return strings.Join([]string{
		match.PatternName,
		match.Bundle,
		match.BundleVersion,
		fmt.Sprint(match.Position),
		fmt.Sprint(match.matchLength),
	}, "\x00")
}

func filterDefensiveCredentialSolicitationMatches(content string, matches []ResponseMatch) []ResponseMatch {
	if len(matches) == 0 {
		return matches
	}

	filtered := matches[:0]
	for _, match := range matches {
		if isSecretAskPattern(match.PatternName) && isDefensiveCredentialSolicitation(content, match) {
			continue
		}
		filtered = append(filtered, match)
	}
	return filtered
}

func isSecretAskPattern(name string) bool {
	return name == "Credential "+"Solicitation"
}

// foldedContains / foldedHasSuffix match a literal in both its raw form and its
// vowel-folded form. The defensive-context check runs on whichever normalization
// pass surfaced the match, and the vowel-fold pass turns keywords like "never"
// into "navar"; matching the folded literal too keeps defensive detection
// invariant across passes without re-indexing folded content positions.
func foldedContains(haystack, needle string) bool {
	return strings.Contains(haystack, needle) || strings.Contains(haystack, normalize.FoldVowels(needle))
}

func foldedHasSuffix(s, suffix string) bool {
	return strings.HasSuffix(s, suffix) || strings.HasSuffix(s, normalize.FoldVowels(suffix))
}

func isDefensiveCredentialSolicitation(content string, match ResponseMatch) bool {
	start := match.Position
	if start < 0 || start > len(content) {
		return false
	}
	end := start + match.matchLength
	if match.matchLength == 0 {
		end = start + len(match.MatchText)
	}
	if end < start || end > len(content) {
		end = len(content)
	}

	lower := strings.ToLower(content)
	if hasDefensiveSolicitationPivot(lower[start:end]) {
		return false
	}
	if hasSolicitationContinuation(lower[end:]) {
		return false
	}
	sentenceStart := strings.LastIndexAny(lower[:start], ".!?\n\r;:") + 1
	prefix := strings.TrimSpace(lower[sentenceStart:start])
	if prefix == "" {
		return false
	}

	for _, phrase := range []string{
		"do not",
		"don't",
		"never",
		"must not",
		"must never",
		"should not",
		"should never",
		"will not",
		"will never",
		"won't",
		"cannot",
		"can't",
		"never ask you to",
		"not ask you to",
		"do not ask you to",
		"don't ask you to",
		"won't ask you to",
	} {
		if foldedHasSuffix(prefix, phrase) {
			return true
		}
	}
	return false
}

func hasDefensiveSolicitationPivot(matchText string) bool {
	for _, pivot := range []string{
		"; instead",
		", instead",
		" instead ",
		"; rather",
		", rather",
		" rather ",
		"; actually",
		", actually",
		" actually ",
		"; but ",
		", but ",
		" but ",
		"; however",
		", however",
		" however ",
	} {
		if foldedContains(matchText, pivot) {
			return true
		}
	}
	return false
}

func hasSolicitationContinuation(suffix string) bool {
	sentenceEnd := strings.IndexAny(suffix, ".!?\n\r")
	if sentenceEnd >= 0 {
		suffix = suffix[:sentenceEnd]
	}
	for _, phrase := range []string{
		", send it ",
		"; send it ",
		", send them ",
		"; send them ",
		", provide it ",
		"; provide it ",
		", provide them ",
		"; provide them ",
		", paste it ",
		"; paste it ",
		", paste them ",
		"; paste them ",
		", email it ",
		"; email it ",
		", email them ",
		"; email them ",
		", forward it ",
		"; forward it ",
		", forward them ",
		"; forward them ",
	} {
		if foldedContains(suffix, phrase) {
			return true
		}
	}
	return false
}

// matchPatternsAgainst runs a pattern set against content and returns matches.
// Shared by standard response patterns and optional-whitespace variants.
func matchPatternsAgainst(patterns []*compiledPattern, content string) []ResponseMatch {
	var matches []ResponseMatch
	for _, p := range patterns {
		if !responsePatternCanMatch(p, content) {
			continue
		}
		locs := responsePatternMatchLocations(p, content)
		for _, loc := range locs {
			matchText := content[loc[0]:loc[1]]
			if runes := []rune(matchText); len(runes) > 100 {
				matchText = string(runes[:100])
			}
			matches = append(matches, ResponseMatch{
				PatternName:   p.name,
				MatchText:     matchText,
				Position:      loc[0],
				Bundle:        p.bundle,
				BundleVersion: p.bundleVersion,
				matchLength:   loc[1] - loc[0],
			})
		}
	}
	return matches
}

func responsePatternCanMatch(p *compiledPattern, content string) bool {
	if len(p.requiredLiteralsAny) == 0 {
		return true
	}
	for _, literal := range p.requiredLiteralsAny {
		for i := 0; i+len(literal) <= len(content); i++ {
			if asciiEqualFold(content[i:i+len(literal)], literal) {
				return true
			}
		}
	}
	return false
}

func responsePatternRequiredLiterals(regex string) []string {
	if regex == config.MarkdownLinkCredentialExfilRegex {
		return []string{"http://", "https://"}
	}
	return nil
}

func withResponseSpans(matches []ResponseMatch, viewLabel string) []ResponseMatch {
	for i := range matches {
		end := matches[i].Position + matches[i].matchLength
		matches[i].span = newMatchSpan(
			matches[i].Position,
			end,
			viewLabel,
			matches[i].PatternName,
			matches[i].Bundle,
			matches[i].BundleVersion,
		)
	}
	return matches
}

// matchResponsePatternsPreFiltered checks the primary response pre-filter
// for keyword candidates, then runs only matching patterns' regex.
func (s *Scanner) matchResponsePatternsPreFiltered(content string) []ResponseMatch {
	return matchPatternsPreFiltered(s.responsePreFilter, s.responsePatterns, content)
}

// matchPatternsPreFiltered checks a pre-filter for keyword candidates in
// content, then runs ONLY the matching patterns' regex. If no pre-filter
// is configured, falls back to running all patterns. On clean 10KB content,
// the pre-filter finds no candidates and zero regex patterns execute.
func matchPatternsPreFiltered(pf *responsePreFilter, patterns []*compiledPattern, content string) []ResponseMatch {
	if pf == nil {
		return matchPatternsAgainst(patterns, content)
	}
	indices := pf.patternsToCheck(content)
	if len(indices) == 0 {
		return nil
	}
	// Large bodies spend most of their time in independent regexp engines.
	// Keep each pattern's result in its original slot so match order, pass
	// precedence, and suppression behavior are identical to the serial path.
	workers := min(runtime.GOMAXPROCS(0), len(indices))
	if workers < 2 || len(content) < 4096 {
		return matchPatternsSequential(indices, patterns, content)
	}
	results := make([][]ResponseMatch, len(indices))
	var wg sync.WaitGroup
	for worker := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for slot := worker; slot < len(indices); slot += workers {
				idx := indices[slot]
				if idx >= 0 && idx < len(patterns) {
					results[slot] = matchResponsePattern(patterns[idx], content)
				}
			}
		}()
	}
	wg.Wait()
	var matches []ResponseMatch
	for _, group := range results {
		matches = append(matches, group...)
	}
	return matches
}

func matchPatternsSequential(indices []int, patterns []*compiledPattern, content string) []ResponseMatch {
	var matches []ResponseMatch
	for _, idx := range indices {
		if idx >= 0 && idx < len(patterns) {
			matches = append(matches, matchResponsePattern(patterns[idx], content)...)
		}
	}
	return matches
}

func matchResponsePattern(p *compiledPattern, content string) []ResponseMatch {
	if !responsePatternCanMatch(p, content) {
		return nil
	}
	locs := responsePatternMatchLocations(p, content)
	var matches []ResponseMatch
	for _, loc := range locs {
		matchText := content[loc[0]:loc[1]]
		if runes := []rune(matchText); len(runes) > 100 {
			matchText = string(runes[:100])
		}
		matches = append(matches, ResponseMatch{
			PatternName:   p.name,
			MatchText:     matchText,
			Position:      loc[0],
			Bundle:        p.bundle,
			BundleVersion: p.bundleVersion,
			matchLength:   loc[1] - loc[0],
		})
	}
	return matches
}

// minSegmentDecodeLen is the minimum length for an extracted base64/hex segment
// to attempt decoding. Short segments produce too many false decode attempts.
const minSegmentDecodeLen = 16

// responseDecodeMaxDepth bounds recursive decode to prevent CPU exhaustion.
// Set to 5 (vs text_dlp's 3) because the response path has no separate
// IterativeDecode pass for URL layers, so deeper nesting is plausible.
const responseDecodeMaxDepth = 5

// matchDecodedResponse tries base64/hex decoding content and checks the decoded
// result for injection patterns. Recurses up to responseDecodeMaxDepth to catch
// multi-layer chains (e.g., base64(hex(injection))). Two strategies per layer:
// whole-content decode and segment-level decode.
func (s *Scanner) matchDecodedResponse(content string) responseMatchSet {
	return markFragmentBoundaries(s.matchDecodedResponseRecursive(content, 0), content)
}

// matchDecodedResponseRecursive is the recursive implementation of matchDecodedResponse.
func (s *Scanner) matchDecodedResponseRecursive(content string, depth int) responseMatchSet {
	if depth >= responseDecodeMaxDepth {
		return responseMatchSet{}
	}

	// Strategy 1: whole-content decode.
	stripped, sourceOffsets := stripDecodeWhitespace(content, 0)

	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.RawURLEncoding,
	} {
		if decoded, err := enc.DecodeString(stripped); err == nil && len(decoded) > 0 {
			d := string(decoded)
			if decodedSet := s.matchDecodedNormalized(d, ViewBase64Decoded); len(decodedSet.matches) > 0 {
				return mapDecodedSources(decodedSet, d, sourceOffsets, false)
			}
			// Always recurse on successful decode. The depth limit is the
			// safety bound; gating on hasEncodedRun lets attackers bypass
			// by splitting or punctuating the inner encoded layer.
			if decodedSet := s.matchDecodedResponseRecursive(d, depth+1); len(decodedSet.matches) > 0 {
				return mapDecodedSources(decodedSet, d, sourceOffsets, false)
			}
		}
	}
	if decoded, err := hex.DecodeString(stripped); err == nil && len(decoded) > 0 {
		d := string(decoded)
		if decodedSet := s.matchDecodedNormalized(d, ViewHexDecoded); len(decodedSet.matches) > 0 {
			return mapDecodedSources(decodedSet, d, sourceOffsets, true)
		}
		if decodedSet := s.matchDecodedResponseRecursive(d, depth+1); len(decodedSet.matches) > 0 {
			return mapDecodedSources(decodedSet, d, sourceOffsets, true)
		}
	}

	// Strategy 2: segment-level decode with recursion.
	if decodedSet := s.matchDecodedSegmentsRecursive(content, depth); len(decodedSet.matches) > 0 {
		return decodedSet
	}

	return responseMatchSet{}
}

// matchDecodedSegmentsRecursive extracts contiguous base64-alphabet runs from
// content, decodes each individually, and checks for injection patterns.
// Recurses on decoded segments to catch multi-layer encoding.
func (s *Scanner) matchDecodedSegmentsRecursive(content string, depth int) responseMatchSet {
	if depth >= responseDecodeMaxDepth {
		return responseMatchSet{}
	}
	segments := extractEncodedRunSpans(content, minSegmentDecodeLen)
	for _, seg := range segments {
		_, sourceOffsets := stripDecodeWhitespace(seg.text, seg.start)
		for _, enc := range []*base64.Encoding{
			base64.StdEncoding, base64.URLEncoding,
			base64.RawStdEncoding, base64.RawURLEncoding,
		} {
			if decoded, err := enc.DecodeString(seg.text); err == nil && len(decoded) > 0 && isPrintableText(decoded) {
				d := string(decoded)
				if decodedSet := s.matchDecodedNormalized(d, ViewBase64Decoded); len(decodedSet.matches) > 0 {
					return mapDecodedSources(decodedSet, d, sourceOffsets, false)
				}
				if decodedSet := s.matchDecodedResponseRecursive(d, depth+1); len(decodedSet.matches) > 0 {
					return mapDecodedSources(decodedSet, d, sourceOffsets, false)
				}
			}
		}
		if decoded, err := hex.DecodeString(seg.text); err == nil && len(decoded) > 0 && isPrintableText(decoded) {
			d := string(decoded)
			if decodedSet := s.matchDecodedNormalized(d, ViewHexDecoded); len(decodedSet.matches) > 0 {
				return mapDecodedSources(decodedSet, d, sourceOffsets, true)
			}
			if decodedSet := s.matchDecodedResponseRecursive(d, depth+1); len(decodedSet.matches) > 0 {
				return mapDecodedSources(decodedSet, d, sourceOffsets, true)
			}
		}
	}
	return responseMatchSet{}
}

func markFragmentBoundaries(set responseMatchSet, source string) responseMatchSet {
	for i := range set.matches {
		match := &set.matches[i]
		if match.hasDecodedSource && match.decodedSourceStart >= 0 && match.decodedSourceEnd <= len(source) && match.decodedSourceStart < match.decodedSourceEnd {
			match.crossesFragmentBoundary = strings.ContainsRune(source[match.decodedSourceStart:match.decodedSourceEnd], '\n')
		}
	}
	return set
}

func stripDecodeWhitespace(content string, offset int) (string, []int) {
	var stripped strings.Builder
	stripped.Grow(len(content))
	offsets := make([]int, 0, len(content))
	for i := 0; i < len(content); i++ {
		switch content[i] {
		case ' ', '\n', '\r', '\t':
			continue
		default:
			stripped.WriteByte(content[i])
			offsets = append(offsets, offset+i)
		}
	}
	return stripped.String(), offsets
}

func mapDecodedSources(set responseMatchSet, decoded string, encodedOffsets []int, hexEncoded bool) responseMatchSet {
	for i := range set.matches {
		match := &set.matches[i]
		start, end := 0, len(decoded)
		if match.hasDecodedSource {
			start, end = match.decodedSourceStart, match.decodedSourceEnd
		} else if mappedStart, mappedEnd, ok := normalizedMatchSourceRange(decoded, *match); ok {
			start, end = mappedStart, mappedEnd
		}
		if start < 0 || end <= start || end > len(decoded) {
			continue
		}
		encodedStart, encodedEnd := decodedRangeToEncoded(start, end, hexEncoded)
		encodedEnd = min(encodedEnd, len(encodedOffsets))
		if encodedStart < 0 || encodedStart >= encodedEnd {
			continue
		}
		match.decodedSourceStart = encodedOffsets[encodedStart]
		match.decodedSourceEnd = encodedOffsets[encodedEnd-1] + 1
		match.hasDecodedSource = true
	}
	return set
}

func normalizedMatchSourceRange(decoded string, match ResponseMatch) (int, int, bool) {
	transform := func(value string) string {
		if strings.Contains(match.span.ViewLabel, "invisible_spaced") {
			value = normalize.ReplaceInvisibleWithSpace(value)
		}
		value = normalize.ForMatching(value)
		if strings.Contains(match.span.ViewLabel, "vowel_fold") {
			value = normalize.FoldVowels(value)
		}
		return value
	}

	view := transform(decoded)
	if match.span.ByteStart < 0 || match.span.ByteEnd > len(view) || match.span.ByteStart >= match.span.ByteEnd {
		return 0, 0, false
	}
	var rebuilt strings.Builder
	starts := make([]int, 0, len(view))
	ends := make([]int, 0, len(view))
	for start := 0; start < len(decoded); {
		_, size := utf8.DecodeRuneInString(decoded[start:])
		end := start + size
		piece := transform(decoded[start:end])
		rebuilt.WriteString(piece)
		for range len(piece) {
			starts = append(starts, start)
			ends = append(ends, end)
		}
		start = end
	}
	if rebuilt.String() != view || match.span.ByteEnd > len(starts) {
		return 0, 0, false
	}
	return starts[match.span.ByteStart], ends[match.span.ByteEnd-1], true
}

func decodedRangeToEncoded(start, end int, hexEncoded bool) (int, int) {
	if hexEncoded {
		return start * 2, end * 2
	}
	return (start / 3) * 4, ((end + 2) / 3) * 4
}

// extractEncodedRuns finds contiguous runs of base64/hex alphabet characters
// at least minLen long. Returns the segments without surrounding text.
//
// '=' is treated as a segment boundary (like key=value separators) rather than
// part of the alphabet. After each run is collected, up to 2 trailing '='
// characters are re-attached as base64 padding. This prevents "key=payload"
// from collapsing into one segment that decoders reject.
type encodedRunSpan struct {
	text       string
	start, end int
}

//pipelock:provenance-transform encoded_run
func extractEncodedRunSpans(content string, minLen int) []encodedRunSpan {
	var runs []encodedRunSpan
	start := -1
	for i := 0; i < len(content); i++ {
		c := content[i]
		inAlphabet := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '/' ||
			c == '-' || c == '_'
		if inAlphabet {
			if start < 0 {
				start = i
			}
		} else {
			if start >= 0 {
				end := i
				// Re-attach up to 2 trailing '=' for base64 padding.
				end = attachBase64Padding(content, end)
				if end-start >= minLen {
					runs = append(runs, encodedRunSpan{text: content[start:end], start: start, end: end})
				}
			}
			start = -1
		}
	}
	// Flush trailing run at end of content.
	if start >= 0 {
		end := len(content)
		if end-start >= minLen {
			runs = append(runs, encodedRunSpan{text: content[start:end], start: start, end: end})
		}
	}
	return runs
}

func extractEncodedRuns(content string, minLen int) []string {
	spans := extractEncodedRunSpans(content, minLen)
	runs := make([]string, 0, len(spans))
	for _, span := range spans {
		runs = append(runs, span.text)
	}
	return runs
}

// attachBase64Padding extends end past up to 2 consecutive '=' characters
// immediately following a base64 alphabet run.
func attachBase64Padding(content string, end int) int {
	for pad := 0; pad < 2 && end < len(content) && content[end] == '='; pad++ {
		end++
	}
	return end
}

// isPrintableText checks whether decoded bytes are mostly printable text.
// Accepts valid UTF-8 including non-ASCII letters and symbols (which the
// normalizer's confusable map handles), but rejects control characters and
// invalid byte sequences. Prevents false positives from random byte
// sequences that happen to base64-decode.
func isPrintableText(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	if !utf8.Valid(data) {
		return false
	}
	total := 0
	printable := 0
	for i := 0; i < len(data); {
		r, size := utf8.DecodeRune(data[i:])
		total++
		if unicode.IsPrint(r) || r == '\t' || r == '\n' || r == '\r' {
			printable++
		}
		i += size
	}
	// At least 80% printable runes to be considered text.
	return printable*5 >= total*4
}

// isTextualResponseBody classifies bytes by what they contain, not by the
// response's declared media type. Invalid UTF-8 and control bytes count against
// the body instead of causing an immediate binary verdict, so a small malformed
// prefix cannot hide an otherwise textual prompt injection. Opaque compressed
// data stays below the printable threshold and is not fed to prose regexes.
func isTextualResponseBody(ctx context.Context, data []byte) (bool, error) {
	if len(data) == 0 {
		return true, nil
	}
	var total uint64
	var printable uint64
	nextContextCheck := 0
	for i := 0; i < len(data); {
		if i >= nextContextCheck {
			if ctx != nil {
				if err := ctx.Err(); err != nil {
					return false, err
				}
			}
			nextContextCheck = i + responseBodyContextCheckBytes
		}
		r, size := utf8.DecodeRune(data[i:])
		total++
		if isPrintableResponseRune(r, size) {
			printable++
		}
		i += size
	}
	return printable*5 >= total*4, nil
}

// Sixteen bytes is long enough to represent a phrase-level instruction while
// excluding short token-like coincidences such as the three-byte ISO witness.
const binaryResponseTextRunMinBytes = 16

// Keep cancellation latency bounded without adding a context lookup per byte.
const responseBodyContextCheckBytes = 4096

type opaqueResponseTextViews struct {
	retained   string
	fragmented string
	encoded    string
	decoded    string
}

// opaqueResponseTextView produces bounded scanner views from an opaque body.
// Short spans of control or malformed bytes are semantic text boundaries and
// become a space, so split instructions remain visible. Longer binary spans end
// the group. Substantive groups retain hard-boundary sentinels, while a second
// prose-only view reconnects two or more fragments at phrase length so neither
// binary nor printable punctuation can make attacker-controlled words vanish.
// A single short accidental token is excluded from both views.
func opaqueResponseTextView(ctx context.Context, data []byte) (opaqueResponseTextViews, error) {
	var view strings.Builder
	var proseChain strings.Builder
	var encodedChain strings.Builder
	var encodedParts []string
	var group strings.Builder
	printableBytes := 0
	proseFragments := 0
	proseBytes := 0
	encodedFragments := 0
	encodedBytes := 0
	nextContextCheck := 0
	checkContext := func(offset int) error {
		if offset < nextContextCheck {
			return nil
		}
		nextContextCheck = offset + responseBodyContextCheckBytes
		if ctx == nil {
			return nil
		}
		return ctx.Err()
	}
	flush := func() {
		fragment := group.String()
		if printableBytes >= binaryResponseTextRunMinBytes {
			if view.Len() > 0 {
				view.WriteString("\n\ufffd\n")
			}
			view.WriteString(fragment)
		}
		if isOpaqueResponseProseFragment(fragment) {
			if proseFragments > 0 {
				proseChain.WriteByte('\n')
			}
			proseChain.WriteString(strings.Map(func(r rune) rune {
				if unicode.IsSpace(r) {
					return ' '
				}
				return r
			}, fragment))
			proseFragments++
			proseBytes += printableBytes
		}
		if isOpaqueResponseEncodedFragment(fragment) {
			if encodedFragments > 0 {
				encodedChain.WriteByte('\n')
			}
			encodedChain.WriteString(fragment)
			encodedFragments++
			encodedBytes += printableBytes
			encodedParts = append(encodedParts, fragment)
		}
		group.Reset()
		printableBytes = 0
	}

	for i := 0; i < len(data); {
		if err := checkContext(i); err != nil {
			return opaqueResponseTextViews{}, err
		}
		r, size := utf8.DecodeRune(data[i:])
		if isPrintableResponseRune(r, size) {
			group.Write(data[i : i+size])
			printableBytes += size
			i += size
			continue
		}

		separatorStart := i
		for i < len(data) {
			if err := checkContext(i); err != nil {
				return opaqueResponseTextViews{}, err
			}
			r, size = utf8.DecodeRune(data[i:])
			if isPrintableResponseRune(r, size) {
				break
			}
			i += size
		}
		if i-separatorStart <= 8 && group.Len() > 0 {
			group.WriteByte(' ')
			continue
		}
		flush()
	}
	flush()
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return opaqueResponseTextViews{}, err
		}
	}
	fragmented := ""
	if proseFragments >= 2 && proseBytes >= binaryResponseTextRunMinBytes {
		fragmented = proseChain.String()
	}
	encoded := ""
	if encodedFragments >= 2 && encodedBytes >= binaryResponseTextRunMinBytes {
		encoded = encodedChain.String()
	}
	decoded := decodeOpaqueResponseFragments(encodedParts)
	return opaqueResponseTextViews{retained: view.String(), fragmented: fragmented, encoded: encoded, decoded: decoded}, nil
}

func isOpaqueResponseProseFragment(fragment string) bool {
	hasLetterOrDigit := false
	for _, r := range fragment {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r):
			hasLetterOrDigit = true
		case unicode.IsSpace(r), strings.ContainsRune(".,;:!?'-()[]{}\"/", r):
		default:
			return false
		}
	}
	return hasLetterOrDigit
}

func isOpaqueResponseEncodedFragment(fragment string) bool {
	hasData := false
	for _, r := range fragment {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r), strings.ContainsRune("+/-_", r):
			hasData = true
		case r == '=':
		default:
			return false
		}
	}
	return hasData
}

func decodeOpaqueResponseFragments(fragments []string) string {
	if len(fragments) < 2 {
		return ""
	}
	var joined strings.Builder
	decodedBytes := 0
	decodedFragments := 0
	for _, fragment := range fragments {
		decoded, ok := decodeOpaqueResponseFragment(fragment)
		if !ok {
			continue
		}
		if decodedFragments > 0 {
			joined.WriteByte('\n')
		}
		joined.Write(decoded)
		decodedBytes += len(decoded)
		decodedFragments++
	}
	if decodedFragments < 2 || decodedBytes < binaryResponseTextRunMinBytes {
		return ""
	}
	return joined.String()
}

func decodeOpaqueResponseFragment(fragment string) ([]byte, bool) {
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.RawURLEncoding,
	} {
		if decoded, err := encoding.DecodeString(fragment); err == nil && len(decoded) > 0 && isPrintableText(decoded) {
			return decoded, true
		}
	}
	if decoded, err := hex.DecodeString(fragment); err == nil && len(decoded) > 0 && isPrintableText(decoded) {
		return decoded, true
	}
	return nil, false
}

func isPrintableResponseRune(r rune, size int) bool {
	return (r != utf8.RuneError || size != 1) && (unicode.IsPrint(r) || r == '\t' || r == '\n' || r == '\r')
}

// matchDecodedNormalized runs all response scanning passes (primary, opt-space,
// vowel-fold) against decoded content. Without this, encoded payloads carrying
// vowel-substituted or zero-width-separated injection would bypass detection.
func (s *Scanner) matchDecodedNormalized(decoded, decodedViewLabel string) responseMatchSet {
	normalized := normalize.ForMatching(decoded)
	if matches := filterDefensiveCredentialSolicitationMatches(normalized, matchPatternsPreFiltered(s.responsePreFilter, s.responsePatterns, normalized)); len(matches) > 0 {
		return responseMatchSet{matches: withResponseSpans(matches, decodedViewLabel), content: normalized}
	}
	spaced := normalize.ForMatching(normalize.ReplaceInvisibleWithSpace(decoded))
	if spaced != normalized {
		if matches := filterDefensiveCredentialSolicitationMatches(spaced, matchPatternsPreFiltered(s.responsePreFilter, s.responsePatterns, spaced)); len(matches) > 0 {
			return responseMatchSet{matches: withResponseSpans(matches, spanViewLabel("invisible_spaced", decodedViewLabel)), content: spaced}
		}
	}
	if len(s.responseOptSpacePatterns) > 0 {
		if matches := filterDefensiveCredentialSolicitationMatches(normalized, matchPatternsPreFiltered(s.responseOptSpacePreFilter, s.responseOptSpacePatterns, normalized)); len(matches) > 0 {
			return responseMatchSet{matches: withResponseSpans(matches, decodedViewLabel), content: normalized}
		}
	}
	if len(s.responseVowelFoldPatterns) > 0 {
		folded := normalize.FoldVowels(normalized)
		if folded != normalized {
			if matches := filterDefensiveCredentialSolicitationMatches(folded, matchPatternsPreFiltered(s.responseVowelFoldPreFilter, s.responseVowelFoldPatterns, folded)); len(matches) > 0 {
				return responseMatchSet{matches: withResponseSpans(matches, vowelFoldViewLabel(decodedViewLabel)), content: folded}
			}
		}
	}
	return responseMatchSet{}
}

// ResponseScanningEnabled returns whether response scanning is active.
// Always returns true when core response patterns exist, even if the
// user disabled response_scanning.enabled - core is the safety floor.
func (s *Scanner) ResponseScanningEnabled() bool {
	if s.core != nil && len(s.core.responsePatterns) > 0 {
		return true
	}
	return s.responseEnabled
}

// ResponseAction returns the configured response scanning action (strip, warn, block).
// When main response scanning is disabled but core patterns are active,
// defaults to "block" - core findings are non-negotiable.
func (s *Scanner) ResponseAction() string {
	if s.responseAction == "" && s.core != nil && len(s.core.responsePatterns) > 0 {
		return config.ActionBlock
	}
	return s.responseAction
}

// ObservedCoreMatch is one core-floor finding withheld from blocking by a
// declared operator exception, carried with the authorization that withheld it
// so the evidence names who accepted the risk and until when.
type ObservedCoreMatch struct {
	Match   ResponseMatch
	Host    string
	Reason  string
	Owner   string
	Expires string
}

// coreObserveHostFromTarget extracts the host a core-observe exception is
// matched against. Callers pass a full destination URL on every HTTP transport
// and a bare host on some MCP paths, so both are accepted. Anything that
// yields no host returns "", which means no exception can match and the floor
// keeps blocking.
func coreObserveHostFromTarget(target string) string {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return ""
	}
	if parsed, err := url.Parse(trimmed); err == nil && parsed.Hostname() != "" {
		return strings.ToLower(parsed.Hostname())
	}
	// A bare "host" or "host:port" never parses with a Hostname, so retry it
	// as an authority rather than treating it as unmatched.
	if parsed, err := url.Parse("//" + trimmed); err == nil && parsed.Hostname() != "" {
		return strings.ToLower(parsed.Hostname())
	}
	return ""
}
