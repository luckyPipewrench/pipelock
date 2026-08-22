// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// TestIsWrapped_ForgedMarkerIsNotTrusted covers the forged-marker mediation
// bypass. isWrapped decided "already wrapped" from the mere presence of the
// _pipelock key, so an attacker-authored project config could carry a bare
// marker beside a raw stdio command. The installer then reported the server as
// already wrapped and skipped it, leaving its traffic unmediated: the exact
// outcome wrapping exists to prevent.
//
// The marker is something we write, so it cannot be the evidence. The question
// isWrapped must answer is whether the invocation actually goes through the
// pipelock proxy.
func TestIsWrapped_ForgedMarkerIsNotTrusted(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	genuine, _, err := wrapMCPServer(map[string]interface{}{
		mcpFieldCommand: testEchoCmd,
	}, self, "", false, "")
	if err != nil {
		t.Fatalf("wrapMCPServer: %v", err)
	}
	genuine[mcpFieldPipelock] = map[string]interface{}{"original_type": "stdio"}

	for _, tc := range []struct {
		name   string
		server map[string]interface{}
		want   bool
	}{
		{
			name:   "genuine_wrap",
			server: genuine,
			want:   true,
		},
		{
			name: "bare_forged_marker",
			server: map[string]interface{}{
				mcpFieldPipelock: map[string]interface{}{},
				mcpFieldCommand:  "/usr/bin/attacker-server",
			},
			want: false,
		},
		{
			name: "forged_marker_with_plausible_metadata",
			server: map[string]interface{}{
				mcpFieldPipelock: map[string]interface{}{
					"original_type":    "stdio",
					"original_command": "echo",
				},
				mcpFieldCommand: "/usr/bin/attacker-server",
				mcpFieldArgs:    []interface{}{"--serve"},
			},
			want: false,
		},
		{
			// The bypass that args-only checking allows: the attacker supplies
			// the proxy subcommand in front of their OWN binary, so the
			// invocation reads as mediated while nothing is mediated. This is
			// why the command must be checked as well as the arguments.
			name: "binary_merely_named_pipelock_is_not_mediated",
			server: map[string]interface{}{
				mcpFieldCommand: "/usr/local/bin/pipelock",
				mcpFieldArgs:    []interface{}{"mcp", "proxy", "--", "echo"},
			},
			want: false,
		},
		{
			name: "attacker_binary_with_proxy_args",
			server: map[string]interface{}{
				mcpFieldPipelock: map[string]interface{}{"original_type": "stdio"},
				mcpFieldCommand:  "/usr/bin/attacker-server",
				mcpFieldArgs:     []interface{}{"mcp", "proxy", "--", "echo"},
			},
			want: false,
		},
		{
			// Same shape in OpenCode's single command array, where the binary is
			// element zero rather than a separate field.
			name: "attacker_binary_with_proxy_args_array_form",
			server: map[string]interface{}{
				mcpFieldPipelock: map[string]interface{}{"original_type": "stdio"},
				mcpFieldCommand:  []interface{}{"/usr/bin/attacker-server", "mcp", "proxy", "--", "echo"},
			},
			want: false,
		},
		{
			// The array form of a genuine wrap must still be recognised, or a
			// rerun would wrap the wrapper.
			name: "genuine_wrap_array_form",
			server: map[string]interface{}{
				mcpFieldCommand: []interface{}{self, "mcp", "proxy", "--", "echo"},
			},
			want: true,
		},
		{
			name: "marker_beside_unrelated_args",
			server: map[string]interface{}{
				mcpFieldPipelock: map[string]interface{}{"original_type": "stdio"},
				mcpFieldCommand:  self,
				mcpFieldArgs:     []interface{}{"serve", "--port", "9999"},
			},
			want: false,
		},
		{
			// An entry with a marker and no command at all makes a claim it cannot
			// back. It must not read as wrapped, or the installer would skip an
			// entry it never examined.
			name: "marker_with_empty_command",
			server: map[string]interface{}{
				mcpFieldPipelock: map[string]interface{}{"original_type": "stdio"},
				mcpFieldCommand:  "",
				mcpFieldArgs:     []interface{}{"mcp", "proxy"},
			},
			want: false,
		},
		{
			name:   "no_marker_at_all",
			server: map[string]interface{}{mcpFieldCommand: testEchoCmd},
			want:   false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isWrappedBySelf(tc.server); got != tc.want {
				t.Fatalf("isWrapped = %v, want %v (server=%+v)", got, tc.want, tc.server)
			}
		})
	}
}

// TestIsWrapped_GenuineWrapStaysIdempotent guards the availability direction.
// A real wrap must keep reporting as wrapped so a rerun skips it instead of
// wrapping the wrapper, which would nest one proxy inside another.
func TestIsWrapped_GenuineWrapStaysIdempotent(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	for _, server := range []map[string]interface{}{
		{mcpFieldCommand: testEchoCmd},
		{mcpFieldType: "http", mcpFieldURL: "https://mcp.vendor.example/sse"},
	} {
		wrapped, meta, wrapErr := wrapMCPServer(server, self, "", false, "")
		if wrapErr != nil {
			t.Fatalf("wrapMCPServer(%+v): %v", server, wrapErr)
		}
		wrapped[mcpFieldPipelock] = map[string]interface{}{"original_type": meta.OriginalType}
		if !isWrappedBySelf(wrapped) {
			t.Fatalf("genuine wrap reported unwrapped, a rerun would double-wrap it: %+v", wrapped)
		}
	}
}

// TestWarnForeignWrapper covers what the installer tells the operator. Both cases
// are wrapped regardless, so the traffic ends up mediated; the warning exists so a
// claim of coverage this binary cannot confirm is visible rather than silently
// corrected.
func TestWarnForeignWrapper(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	for _, tc := range []struct {
		name   string
		server map[string]interface{}
		want   string
	}{
		{
			name: "foreign binary running proxy arguments",
			server: map[string]interface{}{
				mcpFieldCommand: "/usr/bin/attacker-server",
				mcpFieldArgs:    []interface{}{"mcp", "proxy", "--", testEchoCmd},
			},
			want: "is not this pipelock binary",
		},
		{
			name: "marker beside a command that does not run the proxy",
			server: map[string]interface{}{
				mcpFieldPipelock: map[string]interface{}{"original_type": "stdio"},
				mcpFieldCommand:  testEchoCmd,
			},
			want: "carries pipelock metadata but does not run through the proxy",
		},
		{
			name: "genuinely mediated entry says nothing",
			server: map[string]interface{}{
				mcpFieldCommand: self,
				mcpFieldArgs:    []interface{}{"mcp", "proxy", "--", testEchoCmd},
			},
			want: "",
		},
		{
			name:   "ordinary unwrapped entry says nothing",
			server: map[string]interface{}{mcpFieldCommand: testEchoCmd},
			want:   "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			warnForeignWrapper(&buf, "srv", tc.server)
			got := buf.String()
			if tc.want == "" {
				if got != "" {
					t.Fatalf("expected silence, got %q", got)
				}
				return
			}
			if !strings.Contains(got, tc.want) {
				t.Fatalf("warning = %q, want it to mention %q", got, tc.want)
			}
		})
	}
}
