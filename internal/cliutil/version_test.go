// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cliutil

import (
	"strings"
	"testing"
)

func TestDisplayVersionForStartupBanner(t *testing.T) {
	old := Version
	t.Cleanup(func() { Version = old })

	tests := []struct {
		name    string
		version string
		want    string
	}{
		{name: "prefixed release", version: "v2.5.0", want: "Pipelock v2.5.0"},
		{name: "bare release", version: "2.5.0", want: "Pipelock v2.5.0"},
		{name: "prefixed rc", version: "v2.5.0-rc1", want: "Pipelock v2.5.0-rc1"},
		{name: "dev empty", version: "", want: "Pipelock dev"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Version = tt.version
			banner := "Pipelock " + DisplayVersion() + " starting"
			if !strings.Contains(banner, tt.want) {
				t.Fatalf("banner %q does not contain %q", banner, tt.want)
			}
			if strings.Contains(banner, "Pipelock vv") {
				t.Fatalf("double-v banner: %q", banner)
			}
			if strings.Contains(banner, "Pipelock v starting") {
				t.Fatalf("empty version banner: %q", banner)
			}
		})
	}
}
