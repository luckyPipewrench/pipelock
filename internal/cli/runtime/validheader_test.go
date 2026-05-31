// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import "testing"

// TestValidHeaderName pins the RFC 7230 §3.2.6 token rules for the MCP
// extra-header allowlist. The function iterates by byte so any non-ASCII
// (multi-byte UTF-8) header name is rejected — a header name is an ASCII
// token and never carries high bytes.
func TestValidHeaderName(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want bool
	}{
		{"simple", "Authorization", true},
		{"with-dash", "X-Pipelock-Session", true},
		{"all token specials", "!#$%&'*+-.^_`|~", true},
		{"digits", "X-Trace-123", true},
		{"empty", "", false},
		{"space", "X Bad", false},
		{"colon", "X:Bad", false},
		{"control char", "X\tBad", false},
		{"newline", "X\nBad", false},
		{"non-ascii accent", "X-Café", false}, // 'é' multi-byte UTF-8
		{"non-ascii euro", "X-€uro", false},   // '€' 3-byte UTF-8
		{"raw high byte", "X-\xffBad", false}, // invalid UTF-8 high byte
		{"cyrillic homoglyph", "Аuth", false}, // leading Cyrillic А (U+0410)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validHeaderName(tt.key); got != tt.want {
				t.Errorf("validHeaderName(%q) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
}
