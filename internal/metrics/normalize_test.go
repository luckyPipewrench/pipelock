// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import "testing"

func TestNormalizeHTTPMethod(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method string
		want   string
	}{
		{"GET", "GET", "GET"},
		{"POST", "POST", "POST"},
		{"PUT", "PUT", "PUT"},
		{"DELETE", "DELETE", "DELETE"},
		{"PATCH", "PATCH", "PATCH"},
		{"HEAD", "HEAD", "HEAD"},
		{"OPTIONS", "OPTIONS", "OPTIONS"},
		{"unknown TRACE", "TRACE", "OTHER"},
		{"unknown CONNECT", "CONNECT", "OTHER"},
		{"empty string", "", "OTHER"},
		{"lowercase get", "get", "OTHER"},
		{"mixed case Get", "Get", "OTHER"},
		{"nonsense", "FOOBAR", "OTHER"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := normalizeHTTPMethod(tt.method)
			if got != tt.want {
				t.Errorf("normalizeHTTPMethod(%q) = %q, want %q", tt.method, got, tt.want)
			}
		})
	}
}
