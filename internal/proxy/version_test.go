// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

func TestVersionInitializesWithoutCLIRoot(t *testing.T) {
	if Version != cliutil.Version {
		t.Fatalf("Version = %q, want cliutil.Version %q", Version, cliutil.Version)
	}
}

func TestResolvedVersionForStandaloneProxyUse(t *testing.T) {
	const sourceBuildVersion = "0.0.0-dev.20260912.gabcdef123456"

	tests := []struct {
		name       string
		version    string
		cliVersion string
		want       string
	}{
		{
			name:       "source build uses CLI build info fallback",
			version:    defaultVersion,
			cliVersion: sourceBuildVersion,
			want:       sourceBuildVersion,
		},
		{
			name:       "missing build info stays honestly unknown",
			version:    defaultVersion,
			cliVersion: defaultVersion,
			want:       defaultVersion,
		},
		{
			name:       "proxy ldflags stamp wins",
			version:    "3.5.0",
			cliVersion: sourceBuildVersion,
			want:       "3.5.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolvedVersion(tt.version, tt.cliVersion); got != tt.want {
				t.Fatalf("resolvedVersion(%q, %q) = %q, want %q", tt.version, tt.cliVersion, got, tt.want)
			}
		})
	}
}
