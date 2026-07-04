// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import "fmt"

func responseSizeBlockReason(host string, size, limit int64, knob string) string {
	if host == "" {
		host = "unknown-host"
	}
	return fmt.Sprintf("response from %s is %d bytes, exceeding scan ceiling %d bytes; raise %s or add the trusted host to response_scanning.size_exempt_domains", host, size, limit, knob)
}

func responseSizeExemptScanBlockReason(host string, size, limit int64) string {
	if host == "" {
		host = "unknown-host"
	}
	return fmt.Sprintf("size-exempt response from %s is %d bytes, exceeding bounded scan ceiling %d bytes; raise response_scanning.size_exempt_scan_max_bytes or configure response_scanning.unscannable_passthrough for deliberately unscannable opaque content", host, size, limit)
}
