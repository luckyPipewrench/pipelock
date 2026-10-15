// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"net/http"
	"slices"
	"strings"

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
	var result scanner.ResponseScanResult
	mediaType, validMediaType := shieldMediaTypeEssence(contentType)
	fetchHTML := transport == TransportFetch && validMediaType && (mediaType == "text/html" || mediaType == "application/xhtml+xml")
	if fetchHTML {
		content, utf16, err := decodeShieldUTF16(body, contentType, pipeline)
		if err != nil {
			return nil // Shield and the body scanner retain their error handling.
		}
		if !utf16 {
			content = string(body)
		}
		hidden := extractHiddenContent(content)
		if hidden == "" {
			return nil
		}
		result = sc.ScanResponseWithSuppress(ctx, hidden, target, cfg.Suppress)
	} else {
		result = sc.ScanResponseBodyWithSuppress(ctx, body, target, cfg.Suppress)
	}
	return &result
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
