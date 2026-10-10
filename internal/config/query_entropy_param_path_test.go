// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

// A framework with trailing-slash routing serves its image endpoint at
// /_next/image/. The scanner matches the escaped request path exactly, so the
// validator must be able to name that spelling without becoming a way
// to name a non-canonical path.
func TestValidateQueryEntropyParamExclusions_TrailingSlash(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"single trailing slash", "/_next/image/", false},
		{"no trailing slash", "/_next/image", false},
		{"nested trailing slash", "/a/b/", false},
		{"double trailing slash", "/a//", true},
		{"only two slashes", "//", true},
		{"bare root", "/", true},
		{"traversal before slash", "/a/../", true},
		{"dot segment before slash", "/a/./", true},
		{"dot dot without slash", "/a/..", true},
		{"empty segment inside", "/a//b/", true},
		{"encoded slash before trailing slash", "/a%2Fb/", true},
		{"decoded query character", "/a%3Fb/", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateQueryEntropyParamExclusions([]QueryEntropyParamExclusion{{
				Host: "www.vendor.example", Path: tt.path, Param: "url",
			}})
			if (err != nil) != tt.wantErr {
				t.Fatalf("path %q: err = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}
