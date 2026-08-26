// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import "fmt"

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
		if sizeExemptHonored {
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
	if sizeExemptHonored {
		remedy += " or add the trusted host to response_scanning.size_exempt_domains"
	} else {
		// Say the exemption is unavailable rather than staying silent about it.
		// An operator who knows size_exempt_domains from the forward path would
		// otherwise assume it applies here and quietly get no effect.
		remedy += " (this path has no per-host size exemption)"
	}
	return fmt.Sprintf("response from %s is %s, exceeding scan ceiling %d bytes; %s", host, sizeText, limit, remedy)
}

func responseSizeExemptScanBlockReason(host string, size, limit int64) string {
	return responseSizeExemptObservedScanBlockReason(host, size, limit, true)
}

func responseSizeExemptObservedScanBlockReason(host string, size, limit int64, exact bool) string {
	if host == "" {
		host = "unknown-host"
	}
	sizeText := fmt.Sprintf("%d bytes", size)
	if !exact {
		sizeText = fmt.Sprintf("at least %d bytes", size)
	}
	return fmt.Sprintf("size-exempt response from %s is %s, exceeding bounded scan ceiling %d bytes; raise response_scanning.size_exempt_scan_max_bytes or configure response_scanning.unscannable_passthrough for deliberately unscannable opaque content", host, sizeText, limit)
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
