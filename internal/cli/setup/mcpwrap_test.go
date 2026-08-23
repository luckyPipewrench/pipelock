// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"os"
	"path/filepath"
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

// TestIsRestorableWrapper_RefusesEntryWithoutRestorationMetadata pins the pairing
// between the predicate that SELECTS entries for removal and the function that
// restores them. Restoration is driven entirely by the _pipelock metadata, so a
// proxy-shaped entry without it cannot be put back.
//
// Selecting one anyway produced a false success rather than a visible failure:
// unwrapMCPServer returns such an entry unchanged, so remove incremented its
// count, rewrote the config and the backup, and told the operator it had
// unwrapped a server that was still routed through someone else's proxy. The
// assertion is on the PAIRING, not on either half, because each half is correct
// alone and only the combination lies.
func TestIsRestorableWrapper_RefusesEntryWithoutRestorationMetadata(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	for _, tc := range []struct {
		name    string
		command string
	}{
		{name: "wrapped by this binary", command: self},
		{name: "wrapped by a pipelock at another path", command: "/other/bin/pipelock"},
		{name: "wrapped by an attacker binary in the project", command: "./tools/pipelock"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := map[string]interface{}{
				mcpFieldCommand: tc.command,
				mcpFieldArgs:    []interface{}{"mcp", "proxy", "--", "node", "x.js"},
			}
			if classifyWrapper(server) == stateNotWrapper {
				t.Fatalf("fixture is not proxy-shaped, so it does not exercise the case")
			}
			if isRestorableWrapper(server) {
				t.Fatalf("selected for restore with no metadata to restore from")
			}

			// The other half of the pairing: had it been selected, the restore
			// would have been a no-op reported as a success.
			restored, err := unwrapMCPServer(server)
			if err != nil {
				t.Fatalf("unwrapMCPServer: %v", err)
			}
			if restored[mcpFieldCommand] != tc.command {
				t.Fatalf("unwrapMCPServer restored something; this test no longer describes the code")
			}
		})
	}
}

// TestWarnUnrestorableWrapper_TellsOperatorWhyNothingHappened covers the
// availability direction of the refusal above. Refusing silently would read as
// "nothing was wrapped" when the truth is "this is wrapped and I cannot put it
// back", which leaves the operator with no way to act.
func TestWarnUnrestorableWrapper_TellsOperatorWhyNothingHappened(t *testing.T) {
	var buf bytes.Buffer
	warnUnrestorableWrapper(&buf, "orphaned", map[string]interface{}{
		mcpFieldCommand: "/other/bin/pipelock",
		mcpFieldArgs:    []interface{}{"mcp", "proxy", "--", "node", "x.js"},
	})
	got := buf.String()
	for _, want := range []string{"orphaned", "/other/bin/pipelock", "no pipelock metadata", "by hand"} {
		if !strings.Contains(got, want) {
			t.Fatalf("warning omitted %q: %s", want, got)
		}
	}

	// A forged marker on a command that never reaches the proxy is the OTHER
	// unrestorable cause, and it was silent: it shares "cannot restore" with the
	// case above but for the opposite reason, so one condition could not cover
	// both. Staying quiet here reintroduced on the removal path exactly the
	// forged-marker trust this change removed from the install path.
	buf.Reset()
	warnUnrestorableWrapper(&buf, "forged", map[string]interface{}{
		mcpFieldCommand:  "node",
		mcpFieldArgs:     []interface{}{"x.js"},
		mcpFieldPipelock: map[string]interface{}{"original_type": "stdio", "original_command": "node"},
	})
	got = buf.String()
	for _, want := range []string{"forged", "without the proxy", "nothing needs removing"} {
		if !strings.Contains(got, want) {
			t.Fatalf("forged-marker warning omitted %q: %s", want, got)
		}
	}

	// A genuine wrapper and an ordinary server both stay silent, so the warning
	// does not become noise on every remove.
	buf.Reset()
	warnUnrestorableWrapper(&buf, "genuine", map[string]interface{}{
		mcpFieldCommand:  "/other/bin/pipelock",
		mcpFieldArgs:     []interface{}{"mcp", "proxy", "--", "node", "x.js"},
		mcpFieldPipelock: map[string]interface{}{"original_type": "stdio", "original_command": "node"},
	})
	warnUnrestorableWrapper(&buf, "ordinary", map[string]interface{}{
		mcpFieldCommand: "node",
		mcpFieldArgs:    []interface{}{"x.js"},
	})
	if buf.Len() != 0 {
		t.Fatalf("warned about an entry that needs no warning: %s", buf.String())
	}
}

// TestInstallersWarnOnForeignWrapper_AllSurfaces pins the warning to every
// installer rather than to the shared helper. The helper being correct is not the
// property that matters; every install path CALLING it is, and the original marker
// bypass survived in five integrations at once precisely because each surface was
// wired separately. A structural check is used because a behavioural test per
// installer would still silently pass for a surface nobody thought to add.
func TestInstallersWarnOnForeignWrapper_AllSurfaces(t *testing.T) {
	// Every map-based installer skips with isWrappedBySelf and must warn.
	for _, fn := range []string{"cline.go", "jetbrains.go", "opencode.go", "vscode.go", "zed.go"} {
		src, err := os.ReadFile(filepath.Clean(fn))
		if err != nil {
			t.Fatalf("reading %s: %v", fn, err)
		}
		text := string(src)
		if !strings.Contains(text, "isWrappedBySelf(server)") {
			t.Fatalf("%s no longer gates install on isWrappedBySelf; this test needs updating", fn)
		}
		if !strings.Contains(text, "warnForeignWrapper(cmd.ErrOrStderr()") {
			t.Fatalf("%s skips a foreign wrapper without warning, so a false mediation claim is invisible there", fn)
		}
		if !strings.Contains(text, "warnUnrestorableWrapper(cmd.ErrOrStderr()") {
			t.Fatalf("%s removes without reporting an entry it cannot restore", fn)
		}
	}

	// Codex builds a plan rather than writing directly, so it carries the note on
	// the plan and prints it in the execution loop.
	src, err := os.ReadFile(filepath.Clean("codex.go"))
	if err != nil {
		t.Fatalf("reading codex.go: %v", err)
	}
	if !strings.Contains(string(src), "foreignCodexWrapperReason(s)") {
		t.Fatalf("codex install no longer records the foreign-wrapper note")
	}
}

// TestForeignCodexWrapperReason covers the note itself in both directions: it
// fires for a wrapper this binary cannot confirm and stays quiet otherwise, so it
// does not become noise on every codex install.
func TestForeignCodexWrapperReason(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	foreign := codexMCPServer{Transport: codexMCPTransport{
		Type: "stdio", Command: "/other/bin/pipelock",
		Args: []string{"mcp", "proxy", "--", "node", "x.js"},
	}}
	reason := foreignCodexWrapperReason(foreign)
	if !strings.Contains(reason, "/other/bin/pipelock") || !strings.Contains(reason, "not this pipelock binary") {
		t.Fatalf("note does not name the binary or the problem: %q", reason)
	}

	for _, quiet := range []struct {
		name   string
		server codexMCPServer
	}{
		{name: "mediated by this binary", server: codexMCPServer{Transport: codexMCPTransport{
			Type: "stdio", Command: self, Args: []string{"mcp", "proxy", "--", "node", "x.js"},
		}}},
		{name: "an ordinary server", server: codexMCPServer{Transport: codexMCPTransport{
			Type: "stdio", Command: "node", Args: []string{"x.js"},
		}}},
	} {
		t.Run(quiet.name, func(t *testing.T) {
			if got := foreignCodexWrapperReason(quiet.server); got != "" {
				t.Fatalf("warned where nothing is wrong: %q", got)
			}
		})
	}
}
