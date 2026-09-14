// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import "testing"

func TestClassifyMCPToolForAuthorityPreservesRawNames(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		want ActionType
	}{
		{"read_file", ActionRead},
		{"write_file", ActionWrite},
		{"run_command", ActionDelegate},
		{"terminal", ActionUnclassified},
		{"mcp__filesystem__read_file", ActionUnclassified},
		{"mcp__filesystem__write_file", ActionUnclassified},
		{"mcp__console__terminal", ActionUnclassified},
		{"filesystem.read_file", ActionUnclassified},
		{"filesystem:write_file", ActionUnclassified},
		{"read_namespace:write_file", ActionRead},
		{"write_config.read_file", ActionWrite},
		{"mcpevilreadfile", ActionUnclassified},
		{"evil.readfile", ActionUnclassified},
		{"", ActionUnclassified},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyMCPToolForAuthority(tc.name, "tools/call"); got != tc.want {
				t.Fatalf("authority action for %q = %q, want %q", tc.name, got, tc.want)
			}
		})
	}
}
