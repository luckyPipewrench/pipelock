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
	if host == "" {
		host = "unknown-host"
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
	return fmt.Sprintf("response from %s is %d bytes, exceeding scan ceiling %d bytes; %s", host, size, limit, remedy)
}

func responseSizeExemptScanBlockReason(host string, size, limit int64) string {
	if host == "" {
		host = "unknown-host"
	}
	return fmt.Sprintf("size-exempt response from %s is %d bytes, exceeding bounded scan ceiling %d bytes; raise response_scanning.size_exempt_scan_max_bytes or configure response_scanning.unscannable_passthrough for deliberately unscannable opaque content", host, size, limit)
}
