// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"path"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

// submitProfileGateResult signals whether the request passed the submit
// profile's per-request checks and what to do next.
type submitProfileGateResult struct {
	// Allowed is true when the request may continue down the existing
	// reverse-proxy pipeline.
	Allowed bool
	// Status is the HTTP status to return when Allowed is false.
	Status int
	// Block carries the blockreason info (X-Pipelock-Block-Reason headers + body).
	Block blockreason.Info
	// Reason is the user-facing reason string for writeReverseProxyBlock.
	Reason string
}

func submitProfileAllow() submitProfileGateResult {
	return submitProfileGateResult{Allowed: true}
}

func submitProfileDeny(status int, info blockreason.Info, reason string) submitProfileGateResult {
	return submitProfileGateResult{
		Allowed: false,
		Status:  status,
		Block:   info,
		Reason:  reason,
	}
}

// evaluateSubmitProfileGate runs the per-request checks that the submit
// profile adds on top of the generic reverse proxy. It is a no-op when
// cfg.ReverseProxy.Profile is empty.
//
// Order of checks matches the threat model:
//
//  1. Method allowlist (cheapest, deterministic; rejects probe scans)
//  2. Raw-path canonicality (catches encoded-traversal evasions before
//     decoding shifts the path under us)
//  3. Path allowlist against the canonical decoded path
//  4. Body size against the listener cap (returns 413; never forwards)
//
// Body DLP, header DLP, and upstream URL scanning happen downstream in the
// existing reverse-proxy pipeline. Dial-time SSRF hardening is intentionally
// separate from this gate so the trust path can be audited independently.
func evaluateSubmitProfileGate(cfg *config.Config, r *http.Request) submitProfileGateResult {
	if cfg.ReverseProxy.Profile != config.ReverseProxyProfileSubmit {
		return submitProfileAllow()
	}

	// 1. Method allowlist. Empty defaults to POST-only.
	allowedMethods := cfg.ReverseProxy.AllowedMethods
	if len(allowedMethods) == 0 {
		allowedMethods = []string{http.MethodPost}
	}
	methodAllowed := false
	for _, m := range allowedMethods {
		if strings.EqualFold(m, r.Method) {
			methodAllowed = true
			break
		}
	}
	if !methodAllowed {
		return submitProfileDeny(
			http.StatusMethodNotAllowed,
			blockInfoFor(blockreason.BadRequest, scannerLabelSubmitProfile),
			"submit profile: method "+r.Method+" not in allowed_methods",
		)
	}

	// 2. Raw-path canonicality. The path string the client sent must not
	// contain encoded traversal or encoded path separators; those would let
	// a request match a different allowed_paths entry after decoding.
	// We compare against r.URL.EscapedPath() (the literal path bytes as
	// received) rather than r.URL.Path (already decoded).
	if reason, ok := submitProfileRawPathRejection(r.URL.EscapedPath()); !ok {
		return submitProfileDeny(
			http.StatusBadRequest,
			blockInfoFor(blockreason.BadRequest, scannerLabelSubmitProfile),
			"submit profile: raw path rejected: "+reason,
		)
	}

	// 3. Path allowlist against canonical decoded path. r.URL.Path is the
	// already-decoded form; path.Clean drops any stray dot segments. The
	// allowed_paths entries are validated at config load to be canonical
	// and start with /, so this is an exact byte comparison.
	canonicalPath := path.Clean(r.URL.Path)
	if canonicalPath != r.URL.Path {
		// Canonicalization changed the path, meaning the request contained
		// `/.`, `//`, or `/..` segments. Reject before allowlist comparison.
		return submitProfileDeny(
			http.StatusBadRequest,
			blockInfoFor(blockreason.BadRequest, scannerLabelSubmitProfile),
			"submit profile: decoded path is not canonical",
		)
	}
	pathAllowed := false
	for _, p := range cfg.ReverseProxy.AllowedPaths {
		if p.Exact == canonicalPath {
			pathAllowed = true
			break
		}
	}
	if !pathAllowed {
		return submitProfileDeny(
			http.StatusNotFound,
			blockInfoFor(blockreason.BadRequest, scannerLabelSubmitProfile),
			"submit profile: path "+canonicalPath+" not in allowed_paths",
		)
	}

	// 4. Body size cap. Effective cap = min(reverse_proxy.max_body_bytes,
	// request_body_scanning.max_body_bytes). Compare r.ContentLength;
	// chunked requests (ContentLength == -1) get a 411 because the cap
	// cannot be enforced before reading.
	bodyCap := effectiveSubmitBodyCap(cfg)
	if bodyCap <= 0 {
		// Should not happen — validateReverseProxySubmit requires positive.
		// Defense in depth: fail closed if the operator's config slipped past.
		return submitProfileDeny(
			http.StatusInternalServerError,
			blockInfoFor(blockreason.PatternUnavailable, scannerLabelSubmitProfile),
			"submit profile: effective body cap is not configured",
		)
	}
	if r.ContentLength < 0 {
		return submitProfileDeny(
			http.StatusLengthRequired,
			blockInfoFor(blockreason.PatternUnavailable, scannerLabelSubmitProfile),
			"submit profile: requests must declare Content-Length",
		)
	}
	if r.ContentLength > bodyCap {
		return submitProfileDeny(
			http.StatusRequestEntityTooLarge,
			blockInfoFor(blockreason.DataBudget, scannerLabelSubmitProfile),
			"submit profile: body exceeds effective cap",
		)
	}

	return submitProfileAllow()
}

// effectiveSubmitBodyCap returns min(reverse_proxy.max_body_bytes,
// request_body_scanning.max_body_bytes), preferring whichever is positive
// when only one is set. Returns 0 only when both are non-positive (an
// invalid post-validation state). The scanner field is int; widen to int64
// for the comparison.
func effectiveSubmitBodyCap(cfg *config.Config) int64 {
	listenerCap := cfg.ReverseProxy.MaxBodyBytes
	scannerCap := int64(cfg.RequestBodyScanning.MaxBodyBytes)
	switch {
	case listenerCap > 0 && scannerCap > 0:
		if listenerCap < scannerCap {
			return listenerCap
		}
		return scannerCap
	case listenerCap > 0:
		return listenerCap
	case scannerCap > 0:
		return scannerCap
	}
	return 0
}

// submitProfileRawPathRejection inspects the request's raw (still-encoded)
// path for evasion patterns that would let a request match a different
// allowed_paths entry after decoding. Returns (reason, false) when the
// raw path contains a forbidden pattern, ("", true) otherwise.
//
// Patterns rejected:
//
//   - %2e or %2E (encoded dot — would let "/%2e%2e/foo" canonicalize to "/foo")
//   - %2f or %2F (encoded slash — would let "/api%2fsecret" appear as one segment)
//   - %5c or %5C (encoded backslash — Windows path traversal in some parsers)
//   - %25 (encoded percent — blocks double-encoded traversal like %252e%252e)
//   - ; (semicolon path parameter — RFC 3986 leftover that some routers strip)
//   - %3b or %3B (encoded semicolon — would decode to ; after the gate
//     runs, defeating the literal-semicolon rejection above)
func submitProfileRawPathRejection(rawPath string) (string, bool) {
	upper := strings.ToUpper(rawPath)
	switch {
	case strings.Contains(upper, "%25"):
		return "encoded percent (%25)", false
	case strings.Contains(upper, "%2E"):
		return "encoded dot (%2e)", false
	case strings.Contains(upper, "%2F"):
		return "encoded slash (%2f)", false
	case strings.Contains(upper, "%5C"):
		return "encoded backslash (%5c)", false
	case strings.Contains(upper, "%3B"):
		return "encoded semicolon (%3b)", false
	case strings.Contains(rawPath, ";"):
		return "semicolon path parameter", false
	}
	return "", true
}

// scannerLabelSubmitProfile is the scanner-layer label used in receipts
// and block headers for submit-profile-originated denials.
const scannerLabelSubmitProfile = "reverse_proxy_submit"
