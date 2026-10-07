// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"github.com/luckyPipewrench/pipelock/internal/destination"
	scannerpkg "github.com/luckyPipewrench/pipelock/internal/scanner"
)

type contentFieldMode int

const (
	contentFieldModeRedacted contentFieldMode = iota
	contentFieldModeDestination
	contentFieldModePathDiagnostic
)

// scannerContentFieldMode classifies URL/target/resource fields for audit
// output. The default is redaction: future or misspelled scanner labels may be
// content-bearing, so they must not silently echo paths, queries, or resources
// into logs and external sinks.
//
// No mode emits a query string or fragment. Scanner order decides which
// detector reports a request first, and a destination-class scanner routinely
// fires ahead of DLP: the core SSRF floor runs several stages before the core
// DLP floor, so a request to a metadata address carrying a credential in its
// query is attributed to SSRF and never reaches the detector that would have
// recognised the credential. Classifying by scanner identity therefore cannot
// decide whether a URL is safe to log; only the URL component can. Query and
// fragment are operand-carrying by construction and are always dropped.
func scannerContentFieldMode(scanner string) contentFieldMode {
	switch scanner {
	case scannerpkg.ScannerPathTraversal,
		scannerpkg.ScannerCRLF:
		// The path is the finding itself; a block is not diagnosable without it.
		return contentFieldModePathDiagnostic
	case scannerpkg.ScannerSSRF,
		scannerpkg.ScannerSSRFMetadata,
		scannerpkg.ScannerCoreSSRF,
		scannerpkg.ScannerAllowlist,
		scannerpkg.ScannerBlocklist,
		scannerpkg.ScannerRateLimit,
		scannerpkg.ScannerDataBudget,
		scannerpkg.ScannerContext,
		scannerpkg.ScannerMCPToolScanning,
		scannerpkg.AuditMCPSessionBinding,
		scannerpkg.AuditFrozenTool:
		// The destination, not the request line, is the diagnostic object.
		return contentFieldModeDestination
	default:
		return contentFieldModeRedacted
	}
}

// IsContentScanner reports whether blocks attributed to the given scanner
// name imply the URL/target contains the secret-shaped bytes that fired
// the match. Callers constructing client-facing block responses (fetch,
// reverse proxy, forward proxy) should redact the URL/target before
// echoing it back so the credential is not returned to the caller.
func IsContentScanner(name string) bool {
	return scannerContentFieldMode(name) == contentFieldModeRedacted
}

func redactedContentFields(ctx LogContext, scanner string) (loggedURL, loggedTarget, loggedResource string) {
	loggedResource = ctx.resource
	switch scannerContentFieldMode(scanner) {
	case contentFieldModeDestination:
		return dropURLContentSegments(ctx.url, false),
			dropURLContentSegments(ctx.target, false),
			loggedResource
	case contentFieldModePathDiagnostic:
		return dropURLContentSegments(ctx.url, true),
			dropURLContentSegments(ctx.target, true),
			loggedResource
	default:
		loggedURL = redactContentBearingURL(ctx.url)
		loggedTarget = redactContentBearingURL(ctx.target)
		if loggedResource != "" {
			loggedResource = "[redacted]"
		}
		return loggedURL, loggedTarget, loggedResource
	}
}

// dropURLContentSegments removes the query and fragment from raw, and removes
// the path as well unless keepPath is set. A value that does not parse as an
// absolute URL is parsed as a schemeless authority, so CONNECT destinations
// survive while opaque payloads and malformed destinations are redacted.
func dropURLContentSegments(raw string, keepPath bool) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		u, err = url.Parse("//" + raw)
	}
	if err != nil || !validAuditAuthority(u) {
		return "[redacted-url]"
	}
	out := u.Host
	if u.Scheme != "" {
		out = u.Scheme + "://" + u.Host
	}
	if keepPath {
		out += u.EscapedPath()
	}
	return out
}

// validAuditAuthority accepts DNS names and IP literals with an optional
// numeric port. URL parsing alone also accepts opaque scheme-shaped inputs
// and malformed DNS labels, which must not become destination diagnostics.
func validAuditAuthority(u *url.URL) bool {
	host := u.Hostname()
	if host == "" || strings.HasSuffix(u.Host, ":") {
		return false
	}
	if port := u.Port(); port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return false
		}
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Zone() == ""
	}
	if strings.ContainsAny(host, "[]:") || strings.HasPrefix(u.Host, "[") {
		return false
	}
	ascii, err := destination.LookupASCII(host)
	if err != nil {
		return false
	}
	ascii = strings.TrimSuffix(ascii, ".")
	if ascii == "" || len(ascii) > 253 {
		return false
	}
	for label := range strings.SplitSeq(ascii, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' {
				continue
			}
			return false
		}
	}
	return true
}

// RedactContentBearingURL returns a URL safe to echo when a
// content-matching scanner fired. Keeps scheme + host; drops path,
// query, and fragment. Falls back to a generic placeholder when parsing
// fails rather than passing the raw string through. Exported for use
// from the proxy package in client-facing block responses.
func RedactContentBearingURL(raw string) string {
	return redactContentBearingURL(raw)
}

// redactContentBearingURL is the internal implementation. Kept separate
// from the exported wrapper so in-package callers (LogBlocked) and
// out-of-package callers (proxy FetchResponse / reverse-proxy block
// bodies) share a single source of truth.
func redactContentBearingURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "[redacted-url]"
	}
	return u.Scheme + "://" + u.Host + "/[redacted]"
}

// sanitizeString strips control characters and ANSI escape sequences from a
// string before logging. Prevents terminal escape injection via crafted URLs
// (e.g., \x1b[2J to clear screen when tailing audit logs).
func sanitizeString(s string) string {
	// Fast path: most strings have no control characters.
	clean := true
	for _, r := range s {
		if r != '\t' && r != '\n' && (unicode.IsControl(r) || r == '\x1b') {
			clean = false
			break
		}
	}
	if clean {
		return s
	}

	var b strings.Builder
	b.Grow(len(s))
	inEscape := false
	for _, r := range s {
		if inEscape {
			// ANSI escape sequences end with a letter (A-Z, a-z).
			if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
				inEscape = false
			}
			continue
		}
		if r == '\x1b' {
			inEscape = true
			continue
		}
		// Allow tabs and newlines but strip other control chars.
		if r != '\t' && r != '\n' && unicode.IsControl(r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
