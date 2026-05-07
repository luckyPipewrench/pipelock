// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// reasonFromScanner maps a scanner.Scanner* layer label to the public
// blockreason.Reason code. This is the single source of truth used by every
// HTTP transport's block path so the same scanner finding produces the same
// header value on forward, intercept, fetch, reverse, MCP, and WebSocket.
//
// Returns blockreason.ParseError when the label is unrecognized so the helper
// is total: a missing mapping never leaves a block path emitting an empty
// header. New scanner labels MUST be added here when introduced.
func reasonFromScanner(label string) blockreason.Reason {
	switch label {
	case scanner.ScannerScheme:
		return blockreason.SchemeBlocked
	case scanner.ScannerBlocklist:
		return blockreason.DomainBlocklist
	case scanner.ScannerSSRFMetadata:
		return blockreason.SSRFMetadata
	case scanner.ScannerSSRF:
		return blockreason.SSRFPrivateIP
	case scanner.ScannerEntropy:
		return blockreason.PathEntropy
	case scanner.ScannerSubdomainEntropy:
		return blockreason.SubdomainEntropy
	case scanner.ScannerLength:
		return blockreason.URLLength
	case scanner.ScannerRateLimit:
		return blockreason.RateLimit
	case scanner.ScannerDataBudget:
		return blockreason.DataBudget
	case scanner.ScannerDLP, scannerLabelBodyDLP, scannerLabelAddressProtection:
		return blockreason.DLPMatch
	case scannerLabelRedaction:
		return blockreason.RedactionFailure
	case scannerLabelUnavailable:
		return blockreason.PatternUnavailable
	case scanner.ScannerParser:
		return blockreason.ParseError
	default:
		// Unknown layer: keep the block fail-closed but emit a generic
		// reason rather than an empty header. ParseError doubles as the
		// unknown-layer sentinel because both indicate "the proxy could
		// not parse the request shape into something it understood."
		return blockreason.ParseError
	}
}

// severityFromReason delegates to the canonical
// blockreason.SeverityFor table. The local wrapper used to maintain its own
// switch, which silently drifted from the canonical mapping (BlockReasonOverflow,
// for example, was returning SeverityCritical here while the canonical
// helper returned SeverityWarn). Delegating keeps blockheaders.go correct
// against any future vocabulary addition without a per-call-site update.
func severityFromReason(r blockreason.Reason) blockreason.Severity {
	return blockreason.SeverityFor(r)
}

// retryFromReason delegates to the canonical blockreason.RetryFor table for
// the same reason as severityFromReason: drift between local and canonical
// mappings was a latent bug class. The canonical helper is the single source
// of truth used by NewForReason, the spec doc, and the matrix tests.
func retryFromReason(r blockreason.Reason) blockreason.Retry {
	return blockreason.RetryFor(r)
}

// blockInfo builds a complete blockreason.Info from a scanner label.
// Used by transports whose block decision came from the URL/header pipeline.
//
// Uses the non-panicking blockreason.New so a missing reason-vocabulary
// update fails closed (returning a fallback ParseError Info) instead of
// panicking on the request hot path. Per CLAUDE.md: "Never panic on runtime
// input." WithLayer's validation is honored: a label that fails the
// layer-byte validator (a future scanner label with characters outside the
// alphabet) leaves the optional Layer slot unset.
func blockInfo(scannerLabel string) blockreason.Info {
	r := reasonFromScanner(scannerLabel)
	info, err := blockreason.New(r, severityFromReason(r), retryFromReason(r))
	if err != nil {
		info = parseErrorFallback()
	}
	out, layerErr := info.WithLayer(scannerLabel)
	if layerErr != nil {
		return info
	}
	return out
}

// blockInfoFor builds a blockreason.Info from an explicit reason code, e.g.
// for non-scanner block sources (envelope verify, kill switch, airlock,
// budget admission, MCP tool policy). Severity and retry are derived from
// the reason per the spec; layer is set when supplied and validates.
//
// Uses blockreason.New rather than MustNew so a missing reason-vocabulary
// update fails closed instead of panicking on the request path.
func blockInfoFor(reason blockreason.Reason, layer string) blockreason.Info {
	info, err := blockreason.New(reason, severityFromReason(reason), retryFromReason(reason))
	if err != nil {
		info = parseErrorFallback()
	}
	if layer == "" {
		return info
	}
	out, layerErr := info.WithLayer(layer)
	if layerErr != nil {
		return info
	}
	return out
}

// parseErrorFallback is the safe fail-closed Info returned when a reason
// triple cannot be constructed (would only happen on a future vocab gap).
// ParseError is the documented unknown-vocabulary sentinel; it preserves
// fail-closed semantics while still emitting a valid header set.
func parseErrorFallback() blockreason.Info {
	// blockreason.ParseError + SeverityWarn + RetryNone is in the v1
	// vocabulary, so MustNew here is provably safe and never reached on
	// the New() error path. This is package-internal init-time use, not
	// hot-path runtime input.
	return blockreason.MustNew(blockreason.ParseError, blockreason.SeverityWarn, blockreason.RetryNone)
}

// writeBlockedError is a drop-in replacement for http.Error that first sets
// the X-Pipelock-Block-Reason header set so agents can react intelligently.
// Headers must be set before WriteHeader; http.Error calls WriteHeader
// internally, so SetHeaders runs first.
//
// Existing call sites that pass a free-text reason string in the body
// continue to work; only the header set is added.
func writeBlockedError(w http.ResponseWriter, info blockreason.Info, body string, status int) {
	info.SetHeaders(w.Header())
	http.Error(w, body, status)
}

// writeBlockedJSON is the fetch-handler analogue of writeBlockedError. The
// fetch endpoint emits a JSON FetchResponse on every block via writeJSON;
// this helper sets the X-Pipelock-Block-Reason header set first so the
// JSON body and the response headers carry consistent block metadata.
//
// Status is parameterized for forward compatibility even though every
// current fetch block path passes 403. The unparam linter exception is
// tagged below; future block paths may want 5xx (e.g., service-unavailable
// for kill-switch active when fetch surface gains kill-switch parity).
//
//nolint:unparam // status arg kept for forward compat with non-403 block paths
func writeBlockedJSON(w http.ResponseWriter, info blockreason.Info, status int, resp FetchResponse) {
	info.SetHeaders(w.Header())
	writeJSON(w, status, resp)
}
