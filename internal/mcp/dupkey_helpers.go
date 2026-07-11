// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import "strings"

// hasNonIdentityEncoding reports whether the Content-Encoding header carries
// any encoding other than "identity" (which means no encoding). Mirrors the
// helper in internal/proxy/bodyscan.go; duplicated here to avoid pulling the
// proxy package into mcp callers.
func hasNonIdentityEncoding(ce string) bool {
	if ce == "" {
		return false
	}
	for _, enc := range strings.Split(ce, ",") {
		enc = strings.TrimSpace(strings.ToLower(enc))
		if enc != "" && enc != "identity" {
			return true
		}
	}
	return false
}
