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
)

// scanBeforeShield preserves the transport's existing scan surface before a
// rewrite can remove it. Declared HTML on fetch scans only hidden fragments:
// executable scripts and markup remain outside its readability-based contract.
func scanBeforeShield(ctx context.Context, sc *scanner.Scanner, cfg *config.Config, body []byte, headers http.Header, target, transport string) *scanner.ResponseScanResult {
	if !sc.ResponseScanningEnabled() || !cfg.BrowserShield.Enabled {
		return nil
	}
	contentType := responseContentType(headers)
	pipeline := detectShieldPipelineForResponse(contentType, body, headers)
	if shieldLeavesBodyUnchanged(pipeline) {
		return nil
	}
	// Scan what the transport's own scan reads once media policy has run, so
	// image metadata the existing path removes is not retained and metadata it
	// keeps is not lost to a rewrite.
	surface := shieldScanSurface(cfg, contentType, body, headers, target)
	var result scanner.ResponseScanResult
	mediaType, validMediaType := shieldMediaTypeEssence(contentType)
	fetchHTML := transport == TransportFetch && validMediaType && (mediaType == "text/html" || mediaType == "application/xhtml+xml") && !scanner.IsVerifiedImageResponseBody(surface)
	if fetchHTML {
		content, utf16, err := decodeShieldUTF16(surface, contentType, pipeline)
		if err != nil {
			return nil // Shield and the body scanner retain their error handling.
		}
		if !utf16 {
			content = string(surface)
		}
		hidden := extractHiddenContent(content)
		if hidden == "" {
			return nil
		}
		result = sc.ScanResponseWithSuppress(ctx, hidden, target, cfg.Suppress)
	} else {
		result = sc.ScanResponseBodyWithSuppress(ctx, surface, target, cfg.Suppress)
	}
	return &result
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

// scanFetchReadableBeforeShield preserves fetch's original readability result,
// including its raw-content fallback only when readability is unavailable.
func scanFetchReadableBeforeShield(ctx context.Context, sc *scanner.Scanner, cfg *config.Config, body []byte, headers http.Header, target string) *scanner.ResponseScanResult {
	if !sc.ResponseScanningEnabled() || !cfg.BrowserShield.Enabled {
		return nil
	}
	contentType := responseContentType(headers)
	mediaType, valid := shieldMediaTypeEssence(contentType)
	pipeline := detectShieldPipelineForResponse(contentType, body, headers)
	if !valid || (mediaType != "text/html" && mediaType != "application/xhtml+xml") || shieldLeavesBodyUnchanged(pipeline) {
		return nil
	}
	surface := shieldScanSurface(cfg, contentType, body, headers, target)
	if scanner.IsVerifiedImageResponseBody(surface) {
		return nil // handleFetch scans a verified image's metadata, not readable text.
	}
	content, utf16, err := decodeShieldUTF16(surface, contentType, pipeline)
	if err != nil {
		return nil // Keep the existing Shield/body-scan failure path.
	}
	if !utf16 {
		content = string(surface)
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return nil
	}
	article, err := readability.FromReader(strings.NewReader(content), parsed)
	if err == nil && article.TextContent != "" {
		content = article.TextContent
	}
	// Match handleFetch: raw content is scanned only when extraction fails or
	// returns no text. Successful extraction still excludes markup and scripts.
	readable := sc.ScanResponseWithSuppress(ctx, content, target, cfg.Suppress)
	readable.TransformedContent = "" // Original bytes are classification-only.
	return &readable
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
