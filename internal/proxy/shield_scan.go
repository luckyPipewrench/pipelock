// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"

	readability "github.com/go-shiori/go-readability"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/shield"
)

// fetchResponseSurface is the fetch representation shared by retention and
// delivery. Successful readability extraction excludes executable scripts and
// markup; only the existing extraction-failure fallback scans raw HTML.
type fetchResponseSurface struct {
	content, title, hidden string
	html, readabilityOK    bool
	extractionErr          error
}

func deriveFetchResponse(body []byte, contentType string, target *url.URL) fetchResponseSurface {
	surface := fetchResponseSurface{content: string(body)}
	mediaType, valid := shieldMediaTypeEssence(contentType)
	surface.html = valid && (mediaType == "text/html" || mediaType == "application/xhtml+xml") && !scanner.IsVerifiedImageResponseBody(body)
	if !surface.html {
		return surface
	}
	decoded, utf16, err := decodeShieldUTF16(body, contentType, shield.PipelineHTML)
	if err != nil {
		surface.html = false // Preserve the existing body-scanner fallback.
		return surface
	}
	if utf16 {
		surface.content = decoded
	}
	surface.hidden = extractHiddenContent(surface.content)
	article, err := readability.FromReader(strings.NewReader(surface.content), target)
	surface.extractionErr = err
	if err == nil && article.TextContent != "" {
		surface.content, surface.title = article.TextContent, article.Title
		surface.readabilityOK = true
	}
	return surface
}

type fetchResponseScan struct {
	result scanner.ResponseScanResult
	hidden *scanner.ResponseScanResult
}

func scanFetchResponse(ctx context.Context, sc *scanner.Scanner, cfg *config.Config, surface fetchResponseSurface, target string) fetchResponseScan {
	scanned := fetchResponseScan{}
	if surface.html {
		// Fetch delivers title and content separately. Scan them together once,
		// preserving cross-field matches; only content is a supported strip target.
		prefix := ""
		if surface.title != "" {
			prefix = surface.title + "\n"
		}
		scanned.result = sc.ScanResponseWithSuppress(ctx, prefix+surface.content, target, cfg.Suppress)
		if prefix != "" && scanned.result.TransformedContent != "" {
			// A changed title cannot be delivered through content's strip output.
			// An unchanged prefix maps the scanner's remaining output exactly to the
			// separately delivered content, without inventing or reusing offsets.
			candidate, unchangedTitle := strings.CutPrefix(scanned.result.TransformedContent, prefix)
			scanned.result.TransformedContent = ""
			if unchangedTitle {
				scanned.result.TransformedContent = candidate
			}
		}
	} else {
		scanned.result = sc.ScanResponseBodyWithSuppress(ctx, []byte(surface.content), target, cfg.Suppress)
	}

	if surface.hidden != "" {
		hidden := sc.ScanResponseWithSuppress(ctx, surface.hidden, target, cfg.Suppress)
		scanned.hidden = &hidden
		visibleSuppressed := scanned.result.SuppressedMatches
		scanned.result = retainShieldScan(&hidden, scanned.result, []byte(surface.content))
		// Distinct hidden and visible surfaces each retain suppression counts.
		scanned.result.SuppressedMatches = append(append([]scanner.ResponseMatch(nil), hidden.SuppressedMatches...), visibleSuppressed...)
	}
	return scanned
}

// scanBeforeShield retains classifications on the transport's scan surface.
// Callers invoke it lazily only when Shield actually changes the body.
func scanBeforeShield(ctx context.Context, sc *scanner.Scanner, cfg *config.Config, body []byte, headers http.Header, target, transport string) *scanner.ResponseScanResult {
	if !sc.ResponseScanningEnabled() || !cfg.BrowserShield.Enabled {
		return nil
	}
	contentType := responseContentType(headers)
	if shieldLeavesBodyUnchanged(detectShieldPipelineForResponse(contentType, body, headers)) {
		return nil
	}
	if transport == TransportFetch {
		parsed, err := url.Parse(target)
		if err != nil {
			return nil
		}
		scanned := scanFetchBeforeShield(ctx, sc, cfg, body, headers, parsed)
		return &scanned.result
	}
	result := sc.ScanResponseBodyWithSuppress(ctx, shieldScanSurface(cfg, contentType, body, headers, target), target, cfg.Suppress)
	result.TransformedContent = "" // Original bytes are classification-only.
	return &result
}

// scanFetchBeforeShield is the single fetch derivation of pre-Shield bytes. The
// fetch handler's lazy Shield callback calls it directly because it also keeps
// the hidden-fragment result for the readability-failure refusal.
func scanFetchBeforeShield(ctx context.Context, sc *scanner.Scanner, cfg *config.Config, original []byte, headers http.Header, target *url.URL) fetchResponseScan {
	contentType := responseContentType(headers)
	surface := shieldScanSurface(cfg, contentType, original, headers, target.String())
	scanned := scanFetchResponse(ctx, sc, cfg, deriveFetchResponse(surface, contentType, target), target.String())
	scanned.result.TransformedContent = "" // Original bytes are classification-only.
	return scanned
}

// shieldScanSurface returns the bytes the transport's own scan reads for this
// response. Media policy runs after Browser Shield on fetch, forward and
// CONNECT, so the pre-Shield bytes still hold image metadata and trailing bytes
// it removes before scanning, and hold metadata it leaves in place when the
// policy is off, skips metadata stripping, or exempts a challenge host. A
// refused verdict keeps the original bytes: the response is blocked before any
// scan result is consulted. SVG has no metadata to strip, so it passes as is.
func shieldScanSurface(cfg *config.Config, contentType string, body []byte, headers http.Header, target string) []byte {
	host := ""
	if parsed, err := url.Parse(target); err == nil {
		host = parsed.Hostname()
	}
	verdict := applyMediaPolicy(cfg, contentType, body, mediaPolicyOptions{svgShielded: true, headers: headers, host: host})
	if verdict.Blocked || verdict.StripResult == nil || !verdict.StripResult.Changed() {
		return body
	}
	return verdict.Body
}

// retainShieldScan combines findings, never transformations. Only the scan of
// the delivered representation may supply strip output; original offsets and
// transformed bytes do not address the rewritten body.
func retainShieldScan(original *scanner.ResponseScanResult, current scanner.ResponseScanResult, body []byte) scanner.ResponseScanResult {
	if original == nil {
		return current
	}
	if current.Clean && !current.Failed() && !original.Clean {
		current.TransformedContent = string(body)
	}
	current.Clean = original.Clean && current.Clean
	current.Matches = mergeJoinedInjectionMatches(append([]scanner.ResponseMatch(nil), original.Matches...), current.Matches)
	current.SuppressedMatches = mergeJoinedInjectionMatches(append([]scanner.ResponseMatch(nil), original.SuppressedMatches...), current.SuppressedMatches)
	for _, match := range original.ObservedCoreMatches {
		if !slices.Contains(current.ObservedCoreMatches, match) {
			current.ObservedCoreMatches = append(current.ObservedCoreMatches, match)
		}
	}
	current.StegoDetected = current.StegoDetected || original.StegoDetected
	current.StegoDensity = max(current.StegoDensity, original.StegoDensity)
	if original.Failed() {
		current.ScanError = original.ScanError
	}
	if current.Failed() {
		current.Clean = false
		current.TransformedContent = ""
	}
	return current
}

// Keep the retained classification in the existing signed pattern field. The
// rewrite admission remains separate from the terminal response policy verdict.
func shieldReceiptPattern(result *scanner.ResponseScanResult) string {
	if result == nil || len(result.Matches) == 0 {
		return browserShieldPattern
	}
	names := make([]string, 0, len(result.Matches))
	for _, match := range result.Matches {
		if !slices.Contains(names, match.PatternName) {
			names = append(names, match.PatternName)
		}
	}
	return browserShieldPattern + ": " + strings.Join(names, ", ")
}
