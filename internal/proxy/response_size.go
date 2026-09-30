// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// shieldMaxBytesForResponse returns the whole-body Browser Shield ceiling for
// a response that has already been buffered. Forward, CONNECT, and reverse
// responses are bounded by the normal scan cap; when a size-exempt response
// crosses that cap, its larger memory reservation stays held until the shield
// finishes. Both cases can safely reuse the response-scanning ceiling. Fetch
// has no size-exempt bounded-buffer path and keeps the ordinary shield ceiling.
func shieldMaxBytesForResponse(cfg *config.Config, hostname, transport string) int {
	limit := cfg.BrowserShield.MaxShieldBytes
	if limit <= 0 || transport == TransportFetch ||
		!isResponseSizeExempt(hostname, cfg.ResponseScanning.SizeExemptDomains) {
		return limit
	}

	switch transport {
	case TransportForward, TransportConnect, TransportReverse:
		if cfg.ResponseScanning.SizeExemptScanMaxBytes > limit {
			return cfg.ResponseScanning.SizeExemptScanMaxBytes
		}
	}
	return limit
}

// sizeRemedies names the above-cap escape hatches the blocking path really
// consults. A remediation hint must only name knobs the path reads: an inert
// hint teaches the operator that policy changed when nothing did.
type sizeRemedies struct {
	// SizeExempt: response_scanning.size_exempt_domains lifts the block into a
	// bounded whole-buffer scan.
	SizeExempt bool
	// Exempt: response_scanning.exempt_domains streams the host unscanned with
	// no size cap on this transport.
	Exempt bool
	// Passthrough: tls_interception.passthrough_domains skips interception.
	// Only the TLS-intercept path can honor it.
	Passthrough bool
	// ExemptUnavailable explains why the response cannot take the streaming valve.
	ExemptUnavailable string
}

// responseStreamingSizeRemedies mirrors the eligibility of the full-trust
// streaming branches in forward and intercept. Declared SVG remains buffered.
func responseStreamingSizeRemedies(cfg *config.Config, header http.Header, passthrough bool) sizeRemedies {
	rem := sizeRemedies{Exempt: true, Passthrough: passthrough}
	if !cfg.ResponseScanning.Enabled {
		rem.Exempt = false
		rem.ExemptUnavailable = "response_scanning.exempt_domains does not remove this cap while response_scanning.enabled is false"
	} else if responseHeadersDeclareSVG(header) {
		rem.Exempt = false
		rem.ExemptUnavailable = "response_scanning.exempt_domains does not remove this cap for declared SVG content"
	}
	return rem
}

const (
	sizeRemedyExemptText      = "response_scanning.exempt_domains (that host's responses are then not scanned)"
	sizeRemedyPassthroughText = "tls_interception.passthrough_domains (not intercepted or body-scanned; requires an accepted configuration change and a new CONNECT)"
)

// responseSizeBlockReason renders the operator-facing reason for a response
// blocked on size. sizeExemptHonored reports whether the blocking path actually
// consults response_scanning.size_exempt_domains: the forward path gates this
// very block on it, but the fetch path never reads it, so naming it there would
// send an operator to a knob that cannot lift their block. A remediation hint
// must only name knobs the blocking path consults.
func responseSizeBlockReason(host string, size, limit int64, knob string, sizeExemptHonored bool) string {
	return responseSizeObservedBlockReason(host, size, limit, knob, sizeExemptHonored, true)
}

// responseSizeObservedBlockReason distinguishes a complete size from the lower
// bound produced by a limited read of a streamed response.
func responseSizeObservedBlockReason(host string, size, limit int64, knob string, sizeExemptHonored, exact bool) string {
	return responseSizeRemedyBlockReason(host, size, limit, knob, exact, sizeRemedies{SizeExempt: sizeExemptHonored})
}

// responseSizeRemedyBlockReason renders the over-cap block reason, listing the
// narrowest remedy first and the unscanned valves last with an explicit
// warning.
func responseSizeRemedyBlockReason(host string, size, limit int64, knob string, exact bool, rem sizeRemedies) string {
	if host == "" {
		host = "unknown-host"
	}
	sizeText := fmt.Sprintf("%d bytes", size)
	if !exact {
		sizeText = fmt.Sprintf("at least %d bytes", size)
	}
	// An empty knob means this transport's ceiling is a compile-time constant
	// with nothing to raise. Lead with the remedy that does exist, and say the
	// ceiling is fixed, rather than naming a setting the operator would go
	// looking for and never find.
	if knob == "" {
		const fixed = "this transport's scan ceiling is fixed and cannot be raised by configuration"
		if rem.SizeExempt {
			return fmt.Sprintf(
				"response from %s is %s, exceeding scan ceiling %d bytes; add the trusted host to response_scanning.size_exempt_domains (%s)",
				host, sizeText, limit, fixed,
			)
		}
		return fmt.Sprintf(
			"response from %s is %s, exceeding scan ceiling %d bytes; %s and this path has no per-host size exemption",
			host, sizeText, limit, fixed,
		)
	}
	remedy := fmt.Sprintf("raise %s", knob)
	if rem.SizeExempt {
		remedy += " or add the trusted host to response_scanning.size_exempt_domains"
		if rem.Exempt || rem.Passthrough || rem.ExemptUnavailable != "" {
			remedy += " (bounded scan up to response_scanning.size_exempt_scan_max_bytes)"
			remedy += unscannedRemedies(rem, ", or for a trusted artifact host whose downloads exceed that bound use ")
		}
	} else {
		// Say the exemption is unavailable rather than staying silent about it.
		// An operator who knows size_exempt_domains from the forward path would
		// otherwise assume it applies here and quietly get no effect.
		remedy += " (this path has no per-host size exemption)"
		remedy += unscannedRemedies(rem, ", or for a trusted artifact host use ")
	}
	return fmt.Sprintf("response from %s is %s, exceeding scan ceiling %d bytes; %s", host, sizeText, limit, remedy)
}

// unscannedRemedies joins the enabled full-trust remedies behind lead, or
// appends an explanation when response streaming is unavailable.
func unscannedRemedies(rem sizeRemedies, lead string) string {
	var parts []string
	if rem.Exempt {
		parts = append(parts, sizeRemedyExemptText)
	}
	if rem.Passthrough {
		parts = append(parts, sizeRemedyPassthroughText)
	}
	text := ""
	if len(parts) != 0 {
		text = lead + strings.Join(parts, " or ")
	}
	if rem.ExemptUnavailable != "" {
		text += "; " + rem.ExemptUnavailable
	}
	return text
}

func responseSizeExemptScanBlockReason(host string, size, limit int64) string {
	return responseSizeExemptObservedScanBlockReason(host, size, limit, true, sizeRemedies{})
}

func responseSizeExemptObservedScanBlockReason(host string, size, limit int64, exact bool, rem sizeRemedies) string {
	if host == "" {
		host = "unknown-host"
	}
	sizeText := fmt.Sprintf("%d bytes", size)
	if !exact {
		sizeText = fmt.Sprintf("at least %d bytes", size)
	}
	return fmt.Sprintf("size-exempt response from %s is %s, exceeding bounded scan ceiling %d bytes; raise response_scanning.size_exempt_scan_max_bytes or configure response_scanning.unscannable_passthrough for deliberately unscannable opaque content%s", host, sizeText, limit, unscannedRemedies(rem, ", or for a trusted artifact host whose downloads exceed that bound use "))
}

// shieldOversizeBlockReason explains a browser-shield oversize block the way
// responseSizeBlockReason explains a scan-ceiling block: the host, the size,
// the cap that fired, and every knob that changes the outcome. A bare "exceeds
// browser shield size limit" sent operators hunting through the config for a
// knob the message never named; legal texts and long specs trip this cap
// routinely, so the block page has to carry its own remediation.
func shieldOversizeBlockReason(host string, size, limit int) string {
	return shieldOversizeObservedReason(host, size, limit, true)
}

// shieldOversizeObservedReason keeps streamed oversize evidence honest. A
// limit reader proves only that an unknown-length body is larger than the
// configured cap; it does not know the final byte count.
func shieldOversizeObservedReason(host string, size, limit int, exact bool) string {
	if host == "" {
		host = "unknown-host"
	}
	sizeText := fmt.Sprintf("%d bytes", size)
	if !exact {
		sizeText = fmt.Sprintf("at least %d bytes", size)
	}
	return fmt.Sprintf(
		"response from %s is %s, exceeding browser_shield.max_shield_bytes %d; "+
			"raise browser_shield.max_shield_bytes, set browser_shield.oversize_action to scan_head "+
			"(shields the first max_shield_bytes and passes the rest unshielded), "+
			"or add the trusted host to browser_shield.exempt_domains",
		host, sizeText, limit,
	)
}
