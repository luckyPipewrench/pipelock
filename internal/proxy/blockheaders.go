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
	case scanner.ScannerDLP:
		return blockreason.DLPMatch
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

// severityFromReason returns the canonical severity for a block-reason code.
// Severity is fixed per reason per docs/specs/block-reason-header.md so call
// sites do not need to track it manually.
func severityFromReason(r blockreason.Reason) blockreason.Severity {
	switch r {
	// info: malformed client request, feature gate.
	case blockreason.NotEnabled, blockreason.BadRequest:
		return blockreason.SeverityInfo
	// warn: scanner ceilings, parser fails, transient unavailability.
	case blockreason.SchemeBlocked,
		blockreason.PathEntropy,
		blockreason.SubdomainEntropy,
		blockreason.URLLength,
		blockreason.RateLimit,
		blockreason.DataBudget,
		blockreason.MediaPolicy,
		blockreason.ParseError,
		blockreason.Timeout,
		blockreason.PatternUnavailable:
		return blockreason.SeverityWarn
	// critical: real security events.
	default:
		return blockreason.SeverityCritical
	}
}

// retryFromReason returns the canonical retry hint for a block-reason code.
// See docs/specs/block-reason-header.md: none = permanent, transient =
// time-bound, policy = needs operator policy change.
func retryFromReason(r blockreason.Reason) blockreason.Retry {
	switch r {
	// transient: time-bound conditions.
	case blockreason.SSRFDNSRebind,
		blockreason.RateLimit,
		blockreason.AirlockActive,
		blockreason.KillSwitchActive,
		blockreason.EscalationLevel,
		blockreason.RedactionFailure,
		blockreason.Timeout,
		blockreason.PatternUnavailable:
		return blockreason.RetryTransient
	// policy: only retry after operator changes pipelock policy.
	case blockreason.DomainBlocklist,
		blockreason.PathEntropy,
		blockreason.SubdomainEntropy,
		blockreason.URLLength,
		blockreason.DataBudget,
		blockreason.MediaPolicy,
		blockreason.ToolPolicyDeny,
		blockreason.SessionBinding,
		blockreason.AuthorityMismatch,
		blockreason.NotEnabled:
		return blockreason.RetryPolicy
	// none: permanent for the request as-is.
	default:
		return blockreason.RetryNone
	}
}

// blockInfo builds a complete blockreason.Info from a scanner label.
// Used by transports whose block decision came from the URL/header pipeline.
func blockInfo(scannerLabel string) blockreason.Info {
	r := reasonFromScanner(scannerLabel)
	return blockreason.New(r, severityFromReason(r), retryFromReason(r)).
		WithLayer(scannerLabel)
}

// blockInfoFor builds a blockreason.Info from an explicit reason code, e.g.
// for non-scanner block sources (envelope verify, kill switch, airlock,
// budget admission, MCP tool policy). Severity and retry are derived from
// the reason per the spec; layer is set when known.
func blockInfoFor(reason blockreason.Reason, layer string) blockreason.Info {
	info := blockreason.New(reason, severityFromReason(reason), retryFromReason(reason))
	if layer != "" {
		info = info.WithLayer(layer)
	}
	return info
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
