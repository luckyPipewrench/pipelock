// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"net/url"
	"strings"
)

// Placeholders substituted into a target when sanitizing secret-bearing
// components before signing. They share one consistent, self-describing
// [redacted-<scope>] format and are deliberately distinct from the recorder's
// own "[REDACTED]" field marker (recorder.go). That distinction matters in an
// audit trail: a receipt carrying these markers was sanitized normally pre-sign
// and still verifies, whereas a receipt carrying the recorder's "[REDACTED]"
// means the fail-closed post-sign redaction fired (an unexpected secret-bearing
// field) and that receipt no longer verifies. None of them match a DLP pattern.
const (
	// redactedTarget fully replaces a target whose secret cannot be isolated
	// to userinfo, a query value, the path, or fragment.
	redactedTarget = "[redacted-target]"
	// redactedValue replaces an individual secret-bearing query parameter value
	// while preserving its key and the URL's overall shape.
	redactedValue = "[redacted-value]"
	// redactedSegment replaces a secret-bearing URL path while keeping the
	// scheme and host meaningful for forensics.
	redactedSegment = "[redacted-path]"
)

// dlpClean reports whether text is free of DLP matches. It wraps the same
// redaction function the recorder uses so the emitter's pre-sign sanitization
// is guaranteed consistent with the recorder's post-sign scan.
type dlpClean func(string) bool

// sanitizeTarget removes secret-bearing components from a target while
// preserving as much structure as possible, returning a value that is
// guaranteed DLP-clean under clean. This lets the recorder's receipt redaction
// be a no-op, so a signed receipt survives the recorder's redaction pass and
// verifies from the evidence file alone.
//
// For URL targets it strips userinfo (user:pass@) unconditionally, replaces
// secret-bearing query values with a placeholder (keys and order preserved),
// and then coarsens progressively (drop query+fragment, then path, then to a
// bare marker) only as far as needed to reach a clean result. Non-URL targets
// (CONNECT host:port authorities, MCP tool names) pass through unless they are
// themselves dirty, in which case they collapse to the marker.
//
// clean must be non-nil; callers gate on redaction being enabled.
func sanitizeTarget(target string, clean dlpClean) string {
	if target == "" || clean == nil {
		return target
	}

	// CONNECT authorities (host:port) and opaque targets (tool names) have no
	// userinfo or query to strip; url.Parse would also misread "host:443" as a
	// scheme. Only structurally rewrite when a real scheme is present.
	if !strings.Contains(target, "://") {
		return cleanOrRedacted(target, clean)
	}

	u, err := url.Parse(target)
	if err != nil {
		return cleanOrRedacted(target, clean)
	}

	// Userinfo is credentials by definition - always strip it.
	u.User = nil

	// Redact secret-bearing query values, preserving keys and order so the
	// receipt stays meaningful for non-secret parameters.
	if u.RawQuery != "" {
		u.RawQuery = redactQueryValues(u.RawQuery, clean)
	}

	return coarsenUntilClean(u, clean)
}

// cleanOrRedacted returns s unchanged when DLP-clean, else the coarse marker.
func cleanOrRedacted(s string, clean dlpClean) string {
	if clean(s) {
		return s
	}
	return redactedTarget
}

// redactQueryValues replaces each secret-bearing query parameter value with a
// placeholder, preserving parameter keys and their original order. It operates
// on the raw query string (not url.Values) so order is stable and the per-value
// scan sees exactly what the agent sent (including percent-encoding, which the
// DLP function decodes internally).
func redactQueryValues(rawQuery string, clean dlpClean) string {
	parts := strings.Split(rawQuery, "&")
	for i, p := range parts {
		key, val, hasEq := strings.Cut(p, "=")
		if !hasEq || val == "" {
			continue
		}
		if !clean(val) {
			parts[i] = key + "=" + redactedValue
		}
	}
	return strings.Join(parts, "&")
}

// coarsenUntilClean returns the least-redacted form of u that is DLP-clean.
// It tries, in order: the URL as-is (after per-value query redaction); with the
// query and fragment dropped; with the path replaced; and finally a bare
// marker. Each step is a strict superset removal of the previous, so the loop
// terminates with a guaranteed-clean result.
func coarsenUntilClean(u *url.URL, clean dlpClean) string {
	if s := u.String(); clean(s) {
		return s
	}

	// Secret survived in the query (e.g. split across params) or fragment.
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	u.RawFragment = ""
	if s := u.String(); clean(s) {
		return s
	}

	// Secret in the path. Keep scheme and host; replace the path with a literal
	// marker. Built by string concatenation rather than u.Path assignment so
	// the bracketed marker is not percent-encoded by url.String().
	if u.Host != "" {
		hostForm := u.Scheme + "://" + u.Host + "/" + redactedSegment
		if clean(hostForm) {
			return hostForm
		}
	}

	// Secret in the host/authority (e.g. encoded subdomain exfiltration).
	// Nothing structural is safe to keep.
	return redactedTarget
}

// SanitizeTarget exposes the v1 emitter's pre-sign target sanitization to the
// v2 proxy_decision emitter (internal/contract/proxydecision). The v2 receipt
// stamps the same secret-bearing target field into a SIGNED payload, so it MUST
// apply byte-identical sanitization (#676) rather than duplicate this
// security-critical logic. clean is gated on flight-recorder redaction being
// enabled; pass nil (or build it from recorder.ReceiptRedactor) to leave
// targets unchanged when redaction is off.
func SanitizeTarget(target string, clean func(string) bool) string {
	if clean == nil {
		return sanitizeTarget(target, nil)
	}
	return sanitizeTarget(target, dlpClean(clean))
}

// CleanOrRedacted exposes the v1 emitter's pre-sign field sanitization for
// non-URL secret-bearing fields (e.g. a scanner pattern/rule label that may
// echo matched bytes). Same rationale as SanitizeTarget: the v2 emitter signs
// these fields, so it reuses this function instead of duplicating it.
func CleanOrRedacted(s string, clean func(string) bool) string {
	if clean == nil {
		return s
	}
	return cleanOrRedacted(s, dlpClean(clean))
}
