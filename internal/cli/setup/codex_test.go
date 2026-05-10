// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

const (
	pipelockBin    = "/usr/local/bin/pipelock"
	pipelockBinAlt = "/opt/pipelock/bin/pipelock"
	cfgPath        = "/etc/pipelock/cfg.yaml"
	osWindows      = "windows"
)

// writeShellScript writes a shell-script fixture to t.TempDir(). G306 wants
// ≤0o600, but a shell script needs the owner-execute bit. Helper localizes
// the suppression.
func writeShellScript(t *testing.T, path, content string) {
	t.Helper()
	//nolint:gosec // G306: test fixture under t.TempDir(); exec bit needed for fork+exec
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

func codexBoolPtr(v bool) *bool {
	return &v
}

func TestParseCodexMCPList(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []codexMCPServer
		wantErr bool
	}{
		{
			name:  "empty input is empty list",
			input: "",
			want:  nil,
		},
		{
			name:  "whitespace-only input is empty list",
			input: "   \n\t  ",
			want:  nil,
		},
		{
			name: "single stdio server with env",
			input: `[{
				"name": "claude-peers",
				"enabled": true,
				"transport": {
					"type": "stdio",
					"command": "/usr/local/bin/pipelock",
					"args": ["mcp", "proxy", "--env", "TOKEN", "--", "/usr/bin/bun", "server.ts"],
					"env": {"TOKEN": "abc"}
				}
			}]`,
			want: []codexMCPServer{{
				Name:    "claude-peers",
				Enabled: codexBoolPtr(true),
				Transport: codexMCPTransport{
					Type:    "stdio",
					Command: "/usr/local/bin/pipelock",
					Args:    []string{"mcp", "proxy", "--env", "TOKEN", "--", "/usr/bin/bun", "server.ts"},
					Env:     map[string]string{"TOKEN": "abc"},
				},
			}},
		},
		{
			name:    "malformed JSON returns error",
			input:   `[{"name":`,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCodexMCPList([]byte(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestIsCodexWrapped(t *testing.T) {
	tests := []struct {
		name        string
		server      codexMCPServer
		pipelockBin string
		want        bool
	}{
		{
			name: "stdio with pipelock + mcp proxy prefix is wrapped",
			server: codexMCPServer{
				Transport: codexMCPTransport{
					Type:    "stdio",
					Command: pipelockBin,
					Args:    []string{"mcp", "proxy", "--", "node", "x.js"},
				},
			},
			pipelockBin: pipelockBin,
			want:        true,
		},
		{
			name: "stdio with pipelock but wrong subcommand is NOT wrapped",
			server: codexMCPServer{
				Transport: codexMCPTransport{
					Type:    "stdio",
					Command: pipelockBin,
					Args:    []string{"run", "--config", "x.yaml"},
				},
			},
			pipelockBin: pipelockBin,
			want:        false,
		},
		{
			name: "stdio with different binary is NOT wrapped",
			server: codexMCPServer{
				Transport: codexMCPTransport{
					Type:    "stdio",
					Command: "/usr/bin/node",
					Args:    []string{"mcp", "proxy"},
				},
			},
			pipelockBin: pipelockBin,
			want:        false,
		},
		{
			name: "stdio command containing 'pipelock' substring is NOT wrapped",
			server: codexMCPServer{
				Transport: codexMCPTransport{
					Type:    "stdio",
					Command: "/some/path/with-pipelock-in-name/run.sh",
					Args:    []string{"mcp", "proxy"},
				},
			},
			pipelockBin: pipelockBin,
			want:        false,
		},
		{
			name: "URL transport is NOT wrapped",
			server: codexMCPServer{
				Transport: codexMCPTransport{
					Type: "streamable_http",
					URL:  "https://api.example.com/mcp",
				},
			},
			pipelockBin: pipelockBin,
			want:        false,
		},
		{
			name: "stdio with too-short args is NOT wrapped",
			server: codexMCPServer{
				Transport: codexMCPTransport{
					Type:    "stdio",
					Command: pipelockBin,
					Args:    []string{"mcp"},
				},
			},
			pipelockBin: pipelockBin,
			want:        false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isCodexWrapped(tt.server, tt.pipelockBin); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWrapCodexArgs(t *testing.T) {
	tests := []struct {
		name       string
		origCmd    string
		origArgs   []string
		env        map[string]string
		configFile string
		want       []string
	}{
		{
			name:     "no env, no config",
			origCmd:  "node",
			origArgs: []string{"server.js"},
			want:     []string{"mcp", "proxy", "--", "node", "server.js"},
		},
		{
			name:       "with config",
			origCmd:    "node",
			origArgs:   []string{"server.js"},
			configFile: cfgPath,
			want:       []string{"mcp", "proxy", "--config", cfgPath, "--", "node", "server.js"},
		},
		{
			name:     "with env keys, sorted deterministically",
			origCmd:  "node",
			origArgs: []string{"server.js"},
			env:      map[string]string{"BANANA": "y", "APPLE": "x"},
			want:     []string{"mcp", "proxy", "--env", "APPLE", "--env", "BANANA", "--", "node", "server.js"},
		},
		{
			name:       "config + env + args together",
			origCmd:    "/usr/bin/bun",
			origArgs:   []string{"--quiet", "server.ts"},
			env:        map[string]string{"TOKEN": "x"},
			configFile: cfgPath,
			want:       []string{"mcp", "proxy", "--config", cfgPath, "--env", "TOKEN", "--", "/usr/bin/bun", "--quiet", "server.ts"},
		},
		{
			name:    "no orig args, just command",
			origCmd: "/bin/foo",
			want:    []string{"mcp", "proxy", "--", "/bin/foo"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := wrapCodexArgs(tt.origCmd, tt.origArgs, tt.env, tt.configFile)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWrapCodexURL(t *testing.T) {
	got := wrapCodexURL("https://example.com/mcp", "")
	want := []string{"mcp", "proxy", "--upstream", "https://example.com/mcp"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}

	gotCfg := wrapCodexURL("https://example.com/mcp", cfgPath)
	wantCfg := []string{"mcp", "proxy", "--config", cfgPath, "--upstream", "https://example.com/mcp"}
	if !reflect.DeepEqual(gotCfg, wantCfg) {
		t.Errorf("got %v, want %v", gotCfg, wantCfg)
	}
}

func TestUnwrapCodexArgs(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantCmd     string
		wantArgs    []string
		wantURL     string
		wantErr     bool
		errContains string
	}{
		{
			name:     "stdio: just command after separator",
			args:     []string{"mcp", "proxy", "--", "/bin/foo"},
			wantCmd:  "/bin/foo",
			wantArgs: []string{},
		},
		{
			name:     "stdio: command + args",
			args:     []string{"mcp", "proxy", "--", "node", "server.js", "--quiet"},
			wantCmd:  "node",
			wantArgs: []string{"server.js", "--quiet"},
		},
		{
			name:     "stdio: with --config and --env preceding separator",
			args:     []string{"mcp", "proxy", "--config", cfgPath, "--env", "TOKEN", "--env", "OTHER", "--", "/bin/bun", "x.ts"},
			wantCmd:  "/bin/bun",
			wantArgs: []string{"x.ts"},
		},
		{
			name:    "url: --upstream URL",
			args:    []string{"mcp", "proxy", "--upstream", "https://example.com/mcp"},
			wantURL: "https://example.com/mcp",
		},
		{
			name:    "url: --config + --upstream",
			args:    []string{"mcp", "proxy", "--config", cfgPath, "--upstream", "https://example.com/mcp"},
			wantURL: "https://example.com/mcp",
		},
		{
			name:        "not wrapped: missing prefix",
			args:        []string{"run", "--config", "x.yaml"},
			wantErr:     true,
			errContains: "not a pipelock-wrapped",
		},
		{
			name:        "malformed: trailing --config",
			args:        []string{"mcp", "proxy", "--config"},
			wantErr:     true,
			errContains: "trailing --config",
		},
		{
			name:        "malformed: trailing --upstream",
			args:        []string{"mcp", "proxy", "--upstream"},
			wantErr:     true,
			errContains: "trailing --upstream",
		},
		{
			name:        "malformed: separator with no command",
			args:        []string{"mcp", "proxy", "--"},
			wantErr:     true,
			errContains: "no command",
		},
		{
			name:        "malformed: unknown token before separator",
			args:        []string{"mcp", "proxy", "--bogus", "x"},
			wantErr:     true,
			errContains: "unexpected token",
		},
		{
			name:        "malformed: no command or upstream found",
			args:        []string{"mcp", "proxy", "--config", cfgPath},
			wantErr:     true,
			errContains: "no command or upstream",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, args, url, err := unwrapCodexArgs(tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cmd != tt.wantCmd {
				t.Errorf("cmd: got %q, want %q", cmd, tt.wantCmd)
			}
			// Treat nil and empty as equivalent for args.
			if len(args) != len(tt.wantArgs) {
				t.Errorf("args: got %v, want %v", args, tt.wantArgs)
			} else {
				for i := range args {
					if args[i] != tt.wantArgs[i] {
						t.Errorf("args[%d]: got %q, want %q", i, args[i], tt.wantArgs[i])
					}
				}
			}
			if url != tt.wantURL {
				t.Errorf("url: got %q, want %q", url, tt.wantURL)
			}
		})
	}
}

func TestPlanCodexInstall(t *testing.T) {
	servers := []codexMCPServer{
		{
			Name: "already-wrapped",
			Transport: codexMCPTransport{
				Type:    "stdio",
				Command: pipelockBin,
				Args:    []string{"mcp", "proxy", "--", "node", "x.js"},
			},
		},
		{
			Name: "fresh-stdio",
			Transport: codexMCPTransport{
				Type:    "stdio",
				Command: "/usr/bin/node",
				Args:    []string{"server.js"},
				Env:     map[string]string{"PORT": "3000"},
			},
		},
		{
			Name: "fresh-url",
			Transport: codexMCPTransport{
				Type: "streamable_http",
				URL:  "https://example.com/mcp",
			},
		},
		{
			Name: "weird-no-command",
			Transport: codexMCPTransport{
				Type: "stdio",
				// Command empty: skip-unsupported.
			},
		},
	}
	plans := planCodexInstall(servers, pipelockBin, cfgPath)
	if len(plans) != 4 {
		t.Fatalf("expected 4 plans, got %d", len(plans))
	}

	if plans[0].Server != "already-wrapped" || plans[0].Action != "skip-already-wrapped" {
		t.Errorf("plan[0]: got %+v", plans[0])
	}
	if plans[1].Server != "fresh-stdio" || plans[1].Action != codexActionWrapStdio {
		t.Errorf("plan[1]: got %+v", plans[1])
	}
	if plans[1].NewCmd != pipelockBin {
		t.Errorf("plan[1] NewCmd: got %q, want %q", plans[1].NewCmd, pipelockBin)
	}
	wantArgs := []string{"mcp", "proxy", "--config", cfgPath, "--env", "PORT", "--", "/usr/bin/node", "server.js"}
	if !reflect.DeepEqual(plans[1].NewArgs, wantArgs) {
		t.Errorf("plan[1] NewArgs: got %v, want %v", plans[1].NewArgs, wantArgs)
	}
	if plans[1].Env["PORT"] != "3000" {
		t.Errorf("plan[1] Env: lost PORT, got %v", plans[1].Env)
	}

	if plans[2].Server != "fresh-url" || plans[2].Action != "wrap-url" {
		t.Errorf("plan[2]: got %+v", plans[2])
	}
	wantURLArgs := []string{"mcp", "proxy", "--config", cfgPath, "--upstream", "https://example.com/mcp"}
	if !reflect.DeepEqual(plans[2].NewArgs, wantURLArgs) {
		t.Errorf("plan[2] NewArgs: got %v, want %v", plans[2].NewArgs, wantURLArgs)
	}

	if plans[3].Server != "weird-no-command" || plans[3].Action != "skip-unsupported" {
		t.Errorf("plan[3]: got %+v", plans[3])
	}
}

func TestPlanCodexInstall_DifferentPipelockBinIsSkipped(t *testing.T) {
	// Server is wrapped with an OLDER pipelock binary path (e.g.,
	// /tmp/pipelock-dev or a previous install location). A fresh install from
	// a different pipelock binary must NOT re-wrap it — that would produce
	// nested `pipelock proxy -- pipelock proxy -- node x.js` and break unwrap.
	// Detection keys on basename "pipelock" + canonical args prefix, not on
	// exact-match against the running pipelock path.
	servers := []codexMCPServer{{
		Name: "old-wrap",
		Transport: codexMCPTransport{
			Type:    "stdio",
			Command: pipelockBinAlt,
			Args:    []string{"mcp", "proxy", "--", "node", "x.js"},
		},
	}}
	plans := planCodexInstall(servers, pipelockBin, "")
	if len(plans) != 1 {
		t.Fatalf("expected 1 plan, got %d", len(plans))
	}
	if plans[0].Action != codexActionSkipWrapped {
		t.Errorf("expected skip-already-wrapped (idempotent across pipelock paths), got %q", plans[0].Action)
	}
}

func TestPlanCodexInstall_SkipsUnsupportedCodexState(t *testing.T) {
	servers := []codexMCPServer{
		{
			Name:    "disabled",
			Enabled: codexBoolPtr(false),
			Transport: codexMCPTransport{
				Type:    "stdio",
				Command: "/usr/bin/node",
				Args:    []string{"server.js"},
			},
		},
		{
			Name: "with-cwd",
			Transport: codexMCPTransport{
				Type:    "stdio",
				Command: "/usr/bin/node",
				Args:    []string{"server.js"},
				CWD:     "/srv/mcp",
			},
		},
		{
			Name: "with-env-vars",
			Transport: codexMCPTransport{
				Type:    "stdio",
				Command: "/usr/bin/node",
				Args:    []string{"server.js"},
				EnvVars: []string{"TOKEN"},
			},
		},
		{
			Name: "with-timeout",
			Transport: codexMCPTransport{
				Type:    "stdio",
				Command: "/usr/bin/node",
				Args:    []string{"server.js"},
			},
			StartupTimeoutSec: json.RawMessage(`15`),
		},
		{
			Name: "with-unsafe-env",
			Transport: codexMCPTransport{
				Type:    "stdio",
				Command: "/usr/bin/node",
				Args:    []string{"server.js"},
				Env:     map[string]string{"--config": "evil"},
			},
		},
		{
			Name: "url-with-bearer",
			Transport: codexMCPTransport{
				Type:              "streamable_http",
				URL:               "https://api.example.com/mcp",
				BearerTokenEnvVar: "MCP_TOKEN",
			},
		},
		{
			Name: "url-with-headers",
			Transport: codexMCPTransport{
				Type:           "streamable_http",
				URL:            "https://api.example.com/mcp",
				EnvHTTPHeaders: json.RawMessage(`{"Authorization":"MCP_TOKEN"}`),
			},
		},
	}

	plans := planCodexInstall(servers, pipelockBin, "")
	if len(plans) != len(servers) {
		t.Fatalf("expected %d plans, got %d", len(servers), len(plans))
	}
	for _, plan := range plans {
		if plan.Action != codexActionSkipUnsupported {
			t.Errorf("%s action = %q, want %q", plan.Server, plan.Action, codexActionSkipUnsupported)
		}
		if plan.Reason == "" {
			t.Errorf("%s missing skip reason", plan.Server)
		}
	}
}

func TestLooksLikePipelockBinary(t *testing.T) {
	tests := []struct {
		command string
		want    bool
	}{
		{"/usr/local/bin/pipelock", true},
		{"/tmp/pipelock-dev", true},
		{"/opt/build/pipelock-rc1", true},
		{"./pipelock.exe", true},
		{"pipelock", true},
		{"/usr/bin/node", false},
		{"/some/path/with-pipelock-in-name/run.sh", false},
		{"", false},
		{"/usr/bin/pipelocker", false},
	}
	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			if got := looksLikePipelockBinary(tt.command); got != tt.want {
				t.Errorf("looksLikePipelockBinary(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

func TestPlanCodexRemove(t *testing.T) {
	servers := []codexMCPServer{
		{
			Name: "wrapped-stdio",
			Transport: codexMCPTransport{
				Type:    "stdio",
				Command: pipelockBin,
				Args:    []string{"mcp", "proxy", "--config", cfgPath, "--env", "TOKEN", "--", "/usr/bin/bun", "x.ts"},
				Env:     map[string]string{"TOKEN": "secret"},
			},
		},
		{
			Name: "wrapped-url",
			Transport: codexMCPTransport{
				Type:    "stdio",
				Command: pipelockBin,
				Args:    []string{"mcp", "proxy", "--upstream", "https://example.com/mcp"},
			},
		},
		{
			Name: "not-wrapped",
			Transport: codexMCPTransport{
				Type:    "stdio",
				Command: "/usr/bin/node",
				Args:    []string{"server.js"},
			},
		},
	}
	plans, err := planCodexRemove(servers, pipelockBin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(plans) != 3 {
		t.Fatalf("expected 3 plans, got %d", len(plans))
	}

	if plans[0].Action != "unwrap-stdio" {
		t.Errorf("plan[0]: got %+v", plans[0])
	}
	if plans[0].NewCmd != "/usr/bin/bun" {
		t.Errorf("plan[0] NewCmd: got %q", plans[0].NewCmd)
	}
	if !reflect.DeepEqual(plans[0].NewArgs, []string{"x.ts"}) {
		t.Errorf("plan[0] NewArgs: got %v", plans[0].NewArgs)
	}
	if plans[0].Env["TOKEN"] != "secret" {
		t.Errorf("plan[0] env preservation: got %v", plans[0].Env)
	}

	if plans[1].Action != "unwrap-url" || plans[1].NewURL != "https://example.com/mcp" {
		t.Errorf("plan[1]: got %+v", plans[1])
	}

	if plans[2].Action != "skip-not-wrapped" {
		t.Errorf("plan[2]: got %+v", plans[2])
	}
}

func TestPlanCodexRemove_MalformedWrapErrors(t *testing.T) {
	// Wrapped command pointing at pipelock but with malformed args after the
	// prefix should propagate the unwrap error rather than silently skipping.
	servers := []codexMCPServer{{
		Name: "bad",
		Transport: codexMCPTransport{
			Type:    "stdio",
			Command: pipelockBin,
			Args:    []string{"mcp", "proxy", "--config"}, // trailing flag
		},
	}}
	_, err := planCodexRemove(servers, pipelockBin)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), `"bad"`) {
		t.Errorf("error should reference server name: %v", err)
	}
}

func TestPlanCodexRemove_UnsupportedCodexStateErrors(t *testing.T) {
	wrappedArgs := []string{"mcp", "proxy", "--", "node", "x.js"}
	tests := []struct {
		name       string
		transport  codexMCPTransport
		startupRaw json.RawMessage
		toolRaw    json.RawMessage
		errMatch   string
	}{
		{
			name: "cwd",
			transport: codexMCPTransport{
				Type: "stdio", Command: pipelockBin, Args: wrappedArgs,
				CWD: "/srv/mcp",
			},
			errMatch: "cwd cannot be preserved",
		},
		{
			name: "env_vars passthrough",
			transport: codexMCPTransport{
				Type: "stdio", Command: pipelockBin, Args: wrappedArgs,
				EnvVars: []string{"HOME"},
			},
			errMatch: "env_vars passthrough",
		},
		{
			name: "unsafe env key",
			transport: codexMCPTransport{
				Type: "stdio", Command: pipelockBin, Args: wrappedArgs,
				Env: map[string]string{"--config": "evil"},
			},
			errMatch: "unsafe env key",
		},
		{
			name: "startup timeout",
			transport: codexMCPTransport{
				Type: "stdio", Command: pipelockBin, Args: wrappedArgs,
			},
			startupRaw: json.RawMessage(`30`),
			errMatch:   "custom timeout",
		},
		{
			name: "tool timeout",
			transport: codexMCPTransport{
				Type: "stdio", Command: pipelockBin, Args: wrappedArgs,
			},
			toolRaw:  json.RawMessage(`5`),
			errMatch: "custom timeout",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			servers := []codexMCPServer{{
				Name:              "x",
				Transport:         tt.transport,
				StartupTimeoutSec: tt.startupRaw,
				ToolTimeoutSec:    tt.toolRaw,
			}}
			_, err := planCodexRemove(servers, pipelockBin)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.errMatch) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.errMatch)
			}
		})
	}
}

func TestPlanCodexRemove_DisabledServerErrors(t *testing.T) {
	// A wrapped server flagged disabled in Codex's config must NOT be unwrapped
	// blindly: codex mcp add re-adds as enabled, silently mutating state. The
	// remove path errors with a clear reason rather than re-enabling.
	servers := []codexMCPServer{{
		Name:    "wrapped-disabled",
		Enabled: codexBoolPtr(false),
		Transport: codexMCPTransport{
			Type:    "stdio",
			Command: pipelockBin,
			Args:    []string{"mcp", "proxy", "--", "node", "x.js"},
		},
	}}
	_, err := planCodexRemove(servers, pipelockBin)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "server disabled") {
		t.Errorf("error should explain disabled state: %v", err)
	}
}

func TestRawJSONHasValue(t *testing.T) {
	tests := []struct {
		raw  string
		want bool
	}{
		{"", false},
		{"null", false},
		{"{}", false},
		{"[]", false},
		{`""`, false},
		{"  null  ", false},
		{"42", true},
		{`"hello"`, true},
		{`{"k":1}`, true},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			if got := rawJSONHasValue(json.RawMessage(tt.raw)); got != tt.want {
				t.Errorf("rawJSONHasValue(%q) = %v, want %v", tt.raw, got, tt.want)
			}
		})
	}
}

func TestResolveCodexBinary(t *testing.T) {
	// Override path that exists.
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "codex")
	writeShellScript(t, bin, "#!/bin/sh\nexit 0\n")
	got, err := resolveCodexBinary(bin)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if got != bin {
		t.Errorf("got %q, want %q", got, bin)
	}

	// Override path that doesn't exist.
	if _, err := resolveCodexBinary(filepath.Join(tmp, "nope")); err == nil {
		t.Errorf("expected error for missing override, got nil")
	}

	// PATH lookup: ensure the function compiles in this code path. We don't
	// assert success because the test environment may or may not have codex
	// installed; we only assert that "no override + not on PATH" produces a
	// clear error.
	t.Setenv("PATH", tmp) // tmp has 'codex' from above, so this should succeed
	if _, err := resolveCodexBinary(""); err != nil {
		t.Errorf("expected PATH lookup to find tmp/codex: %v", err)
	}
	t.Setenv("PATH", filepath.Join(tmp, "definitely-not-here"))
	if _, err := resolveCodexBinary(""); err == nil {
		t.Errorf("expected PATH lookup to fail with no codex on PATH")
	}
}

// fakeCodex is a small helper that synthesizes a `codex` binary in a tempdir
// for end-to-end tests of runCodexInstall / runCodexRemove. It writes a shell
// script that:
//   - For `mcp list --json`, prints the canned JSON from listJSON.
//   - For `mcp add` and `mcp remove`, appends the full argv to invokeLog.
//   - Returns `0` always (success).
//
// The script is portable to the test machines we care about (Linux/macOS).
// On Windows we skip the helper.
func fakeCodex(t *testing.T, listJSON string) (binPath, invokeLog string) {
	t.Helper()
	if runtime.GOOS == osWindows {
		t.Skip("fakeCodex shell helper not supported on Windows")
	}
	dir := t.TempDir()
	binPath = filepath.Join(dir, "codex")
	invokeLog = filepath.Join(dir, "invocations.log")
	listFile := filepath.Join(dir, "list.json")
	if err := os.WriteFile(listFile, []byte(listJSON), 0o600); err != nil {
		t.Fatalf("writing list.json: %v", err)
	}
	script := fmt.Sprintf(`#!/bin/sh
case "$1 $2" in
"mcp list")
  cat %q
  exit 0
  ;;
esac
echo "$@" >> %q
exit 0
`, listFile, invokeLog)
	writeShellScript(t, binPath, script)
	return binPath, invokeLog
}

func TestRunCodexInstall_DryRun(t *testing.T) {
	listJSON := `[{
		"name": "demo",
		"enabled": true,
		"transport": {
			"type": "stdio",
			"command": "/usr/bin/node",
			"args": ["server.js"],
			"env": {"PORT": "3000"}
		}
	}]`
	codexBin, invokeLog := fakeCodex(t, listJSON)

	root := newCodexTestRoot()
	root.SetArgs([]string{"codex", "install", "--dry-run", "--codex-path", codexBin})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)

	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if !strings.Contains(out.String(), "would wrap demo") {
		t.Errorf("expected dry-run plan in output, got: %s", out.String())
	}
	if !strings.Contains(out.String(), "Plan: 1 to wrap") {
		t.Errorf("expected summary in output, got: %s", out.String())
	}
	if strings.Contains(out.String(), "3000") {
		t.Errorf("dry-run output leaked env value: %s", out.String())
	}
	if !strings.Contains(out.String(), "--env PORT=<redacted>") {
		t.Errorf("expected redacted env preview, got: %s", out.String())
	}

	// Dry-run must NOT have called codex mcp add or remove.
	if data, err := os.ReadFile(filepath.Clean(invokeLog)); err == nil && len(bytes.TrimSpace(data)) > 0 {
		t.Errorf("dry-run invoked codex: %s", data)
	}
}

func TestRunCodexInstall_RealInstall(t *testing.T) {
	listJSON := `[{
		"name": "demo",
		"enabled": true,
		"transport": {
			"type": "stdio",
			"command": "/usr/bin/node",
			"args": ["server.js"],
			"env": {"PORT": "3000"}
		}
	}]`
	codexBin, invokeLog := fakeCodex(t, listJSON)

	root := newCodexTestRoot()
	root.SetArgs([]string{"codex", "install", "--codex-path", codexBin, "--config", cfgPath})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)

	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if !strings.Contains(out.String(), "wrapped demo") {
		t.Errorf("expected 'wrapped demo' in output, got: %s", out.String())
	}

	logData, err := os.ReadFile(filepath.Clean(invokeLog))
	if err != nil {
		t.Fatalf("reading invoke log: %v", err)
	}
	logStr := string(logData)
	if !strings.Contains(logStr, "mcp remove demo") {
		t.Errorf("expected codex mcp remove in log, got: %s", logStr)
	}
	if !strings.Contains(logStr, "mcp add") {
		t.Errorf("expected codex mcp add in log, got: %s", logStr)
	}
	if !strings.Contains(logStr, "--env PORT=3000") {
		t.Errorf("expected env to be passed to codex mcp add, got: %s", logStr)
	}
	if !strings.Contains(logStr, cfgPath) {
		t.Errorf("expected --config %s passthrough in log, got: %s", cfgPath, logStr)
	}
}

func TestRunCodexInstall_AlreadyWrappedSkipped(t *testing.T) {
	// Wrapped server's command is a "pipelock" basename at any path —
	// detection is location-independent so a server wrapped by an earlier
	// pipelock binary at a different path is still treated as already-wrapped.
	listJSON := `[{
		"name": "preWrapped",
		"enabled": true,
		"transport": {
			"type": "stdio",
			"command": "/some/prior/install/pipelock",
			"args": ["mcp", "proxy", "--", "node", "x.js"]
		}
	}]`
	codexBin, invokeLog := fakeCodex(t, listJSON)

	root := newCodexTestRoot()
	root.SetArgs([]string{"codex", "install", "--codex-path", codexBin})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if !strings.Contains(out.String(), "skip preWrapped") {
		t.Errorf("expected skip line in output: %s", out.String())
	}
	if data, err := os.ReadFile(filepath.Clean(invokeLog)); err == nil && len(bytes.TrimSpace(data)) > 0 {
		t.Errorf("idempotent install should not have called codex add/remove: %s", data)
	}
}

func TestRunCodexInstall_URLServer(t *testing.T) {
	listJSON := `[{
		"name": "remote",
		"enabled": true,
		"transport": {
			"type": "streamable_http",
			"url": "https://api.example.com/mcp"
		}
	}]`
	codexBin, invokeLog := fakeCodex(t, listJSON)

	root := newCodexTestRoot()
	root.SetArgs([]string{"codex", "install", "--codex-path", codexBin})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(out.String(), "wrapped remote") {
		t.Errorf("expected 'wrapped remote' in output: %s", out.String())
	}
	logData, err := os.ReadFile(filepath.Clean(invokeLog))
	if err != nil {
		t.Fatalf("reading invoke log: %v", err)
	}
	logStr := string(logData)
	if !strings.Contains(logStr, "mcp remove remote") {
		t.Errorf("expected mcp remove for URL server: %s", logStr)
	}
	if !strings.Contains(logStr, "--upstream https://api.example.com/mcp") {
		t.Errorf("expected --upstream in wrap args: %s", logStr)
	}
}

func TestRunCodexInstall_UnsupportedTransport(t *testing.T) {
	// Stdio transport with empty command — falls through to skip-unsupported.
	listJSON := `[{
		"name": "weird",
		"enabled": true,
		"transport": {
			"type": "stdio",
			"command": ""
		}
	}]`
	codexBin, invokeLog := fakeCodex(t, listJSON)

	root := newCodexTestRoot()
	root.SetArgs([]string{"codex", "install", "--codex-path", codexBin})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(out.String(), "skip weird") {
		t.Errorf("expected skip line for unsupported transport: %s", out.String())
	}
	if data, err := os.ReadFile(filepath.Clean(invokeLog)); err == nil && len(bytes.TrimSpace(data)) > 0 {
		t.Errorf("unsupported server should not have triggered codex calls: %s", data)
	}
}

func TestRunCodexRemove_DryRun(t *testing.T) {
	listJSON := `[{
		"name": "wrapped",
		"enabled": true,
		"transport": {
			"type": "stdio",
			"command": "/usr/local/bin/pipelock",
			"args": ["mcp", "proxy", "--", "/bin/foo"]
		}
	}]`
	codexBin, invokeLog := fakeCodex(t, listJSON)

	root := newCodexTestRoot()
	root.SetArgs([]string{"codex", "remove", "--dry-run", "--codex-path", codexBin})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(out.String(), "would unwrap wrapped") {
		t.Errorf("expected dry-run preview line: %s", out.String())
	}
	if !strings.Contains(out.String(), "Plan: 1 to unwrap") {
		t.Errorf("expected plan summary: %s", out.String())
	}
	if data, err := os.ReadFile(filepath.Clean(invokeLog)); err == nil && len(bytes.TrimSpace(data)) > 0 {
		t.Errorf("dry-run should not invoke codex: %s", data)
	}
}

func TestRunCodexRemove_URLServer(t *testing.T) {
	listJSON := `[{
		"name": "wrappedURL",
		"enabled": true,
		"transport": {
			"type": "stdio",
			"command": "/usr/local/bin/pipelock",
			"args": ["mcp", "proxy", "--upstream", "https://api.example.com/mcp"]
		}
	}]`
	codexBin, invokeLog := fakeCodex(t, listJSON)

	root := newCodexTestRoot()
	root.SetArgs([]string{"codex", "remove", "--codex-path", codexBin})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(out.String(), "unwrapped wrappedURL") {
		t.Errorf("expected unwrap line: %s", out.String())
	}
	logData, err := os.ReadFile(filepath.Clean(invokeLog))
	if err != nil {
		t.Fatalf("reading invoke log: %v", err)
	}
	logStr := string(logData)
	if !strings.Contains(logStr, "mcp add wrappedURL --url https://api.example.com/mcp") {
		t.Errorf("expected URL re-add: %s", logStr)
	}
}

func TestRunCodexRemove_NotWrapped(t *testing.T) {
	listJSON := `[{
		"name": "plain",
		"enabled": true,
		"transport": {
			"type": "stdio",
			"command": "/usr/bin/node",
			"args": ["server.js"]
		}
	}]`
	codexBin, invokeLog := fakeCodex(t, listJSON)

	root := newCodexTestRoot()
	root.SetArgs([]string{"codex", "remove", "--codex-path", codexBin})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(out.String(), "skip plain") {
		t.Errorf("expected skip line: %s", out.String())
	}
	if data, err := os.ReadFile(filepath.Clean(invokeLog)); err == nil && len(bytes.TrimSpace(data)) > 0 {
		t.Errorf("non-wrapped server should not invoke codex: %s", data)
	}
}

func TestRunCodexRemove_CodexBinaryMissing(t *testing.T) {
	root := newCodexTestRoot()
	root.SetArgs([]string{"codex", "remove", "--codex-path", "/definitely/not/here/codex"})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	if err := root.ExecuteContext(context.Background()); err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func TestRunCodexInstall_CodexBinaryMissing(t *testing.T) {
	root := newCodexTestRoot()
	root.SetArgs([]string{"codex", "install", "--codex-path", "/definitely/not/here/codex"})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	err := root.ExecuteContext(context.Background())
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "/definitely/not/here/codex") {
		t.Errorf("error should reference path: %v", err)
	}
}

func TestRunCodexRemove_RoundTrip(t *testing.T) {
	listJSON := `[{
		"name": "wrapped",
		"enabled": true,
		"transport": {
			"type": "stdio",
			"command": "/usr/local/bin/pipelock",
			"args": ["mcp", "proxy", "--env", "TOKEN", "--", "/usr/bin/bun", "x.ts"],
			"env": {"TOKEN": "abc"}
		}
	}]`
	codexBin, invokeLog := fakeCodex(t, listJSON)

	root := newCodexTestRoot()
	root.SetArgs([]string{"codex", "remove", "--codex-path", codexBin})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(out.String(), "unwrapped wrapped") {
		t.Errorf("expected unwrap line in output: %s", out.String())
	}

	logData, err := os.ReadFile(filepath.Clean(invokeLog))
	if err != nil {
		t.Fatalf("reading invoke log: %v", err)
	}
	logStr := string(logData)
	if !strings.Contains(logStr, "mcp remove wrapped") {
		t.Errorf("expected mcp remove in log: %s", logStr)
	}
	if !strings.Contains(logStr, "mcp add") || !strings.Contains(logStr, "/usr/bin/bun") {
		t.Errorf("expected mcp add with original command: %s", logStr)
	}
	if !strings.Contains(logStr, "x.ts") {
		t.Errorf("expected original args preserved: %s", logStr)
	}
	if !strings.Contains(logStr, "--env TOKEN=abc") {
		t.Errorf("expected env preserved: %s", logStr)
	}
}

// rollbackFakeCodex returns a codex binary that simulates a failed wrap-add
// followed by a succeeding rollback-add. It detects the wrap by checking
// whether the add line contains "pipelock" (i.e. is wrapping a server
// through pipelock) and rejects only that. Other adds (the rollback) succeed.
// Each invocation is appended to invokeLog for assertion.
func rollbackFakeCodex(t *testing.T, listJSON string) (binPath, invokeLog string) {
	t.Helper()
	if runtime.GOOS == osWindows {
		t.Skip("rollbackFakeCodex shell helper not supported on Windows")
	}
	dir := t.TempDir()
	binPath = filepath.Join(dir, "codex")
	invokeLog = filepath.Join(dir, "invocations.log")
	listFile := filepath.Join(dir, "list.json")
	if err := os.WriteFile(listFile, []byte(listJSON), 0o600); err != nil {
		t.Fatalf("writing list.json: %v", err)
	}
	script := fmt.Sprintf(`#!/bin/sh
echo "$@" >> %q
case "$1 $2" in
"mcp list")
  cat %q
  exit 0
  ;;
"mcp remove")
  exit 0
  ;;
"mcp add")
  # Reject only the wrap-add (args contain "mcp proxy" after the "--"
  # separator, the canonical pipelock wrap shape). Accept the rollback-add
  # which re-registers the original command.
  if echo "$@" | grep -q "mcp proxy"; then
    echo "Error: synthetic wrap-add failure" >&2
    exit 1
  fi
  exit 0
  ;;
esac
exit 0
`, invokeLog, listFile)
	writeShellScript(t, binPath, script)
	return binPath, invokeLog
}

// failingFakeCodex returns a codex binary that succeeds on `mcp list --json`
// but fails on every other call (used to exercise add/remove error paths).
func failingFakeCodex(t *testing.T, listJSON string) string {
	t.Helper()
	if runtime.GOOS == osWindows {
		t.Skip("failingFakeCodex shell helper not supported on Windows")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "codex")
	listFile := filepath.Join(dir, "list.json")
	if err := os.WriteFile(listFile, []byte(listJSON), 0o600); err != nil {
		t.Fatalf("writing list.json: %v", err)
	}
	// mcp remove returns "not found" (which codexMCPRemoveBestEffort treats as
	// success), so the install/remove path proceeds to mcp add. mcp add fails
	// with a generic synthetic failure, which then triggers the rollback path
	// which ALSO fails (same script). Tests use this to exercise the
	// "rollback also failed" branch.
	script := fmt.Sprintf(`#!/bin/sh
case "$1 $2" in
"mcp list")
  cat %q
  exit 0
  ;;
"mcp remove")
  echo "Error: server not found" >&2
  exit 1
  ;;
esac
echo "Error: synthetic failure" >&2
exit 1
`, listFile)
	writeShellScript(t, bin, script)
	return bin
}

// alwaysFailingCodex fails on every call (used to exercise `codex mcp list`
// error path).
func alwaysFailingCodex(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == osWindows {
		t.Skip("alwaysFailingCodex shell helper not supported on Windows")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "codex")
	writeShellScript(t, bin, `#!/bin/sh
echo "Error: codex broken" >&2
exit 1
`)
	return bin
}

func TestRunCodexInstall_MCPListFails(t *testing.T) {
	codexBin := alwaysFailingCodex(t)
	root := newCodexTestRoot()
	root.SetArgs([]string{"codex", "install", "--codex-path", codexBin})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	if err := root.ExecuteContext(context.Background()); err == nil {
		t.Fatalf("expected error from failing mcp list, got nil")
	} else if !strings.Contains(err.Error(), "codex mcp list") {
		t.Errorf("error should reference mcp list, got: %v", err)
	}
}

func TestRunCodexRemove_MCPListFails(t *testing.T) {
	codexBin := alwaysFailingCodex(t)
	root := newCodexTestRoot()
	root.SetArgs([]string{"codex", "remove", "--codex-path", codexBin})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	if err := root.ExecuteContext(context.Background()); err == nil {
		t.Fatalf("expected error from failing mcp list, got nil")
	}
}

func TestRunCodexInstall_AddFailsRollsBackToOriginal(t *testing.T) {
	// Wrap-add fails; rollback re-adds the original stdio server. The user
	// should see the failure but be told the rollback succeeded so they know
	// the server is still functional in its original (unwrapped) form.
	listJSON := `[{
		"name": "demo",
		"enabled": true,
		"transport": {"type": "stdio", "command": "/usr/bin/node", "args": ["server.js"], "env": {"PORT": "3000"}}
	}]`
	codexBin, invokeLog := rollbackFakeCodex(t, listJSON)

	root := newCodexTestRoot()
	root.SetArgs([]string{"codex", "install", "--codex-path", codexBin})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	err := root.ExecuteContext(context.Background())
	if err == nil {
		t.Fatalf("expected error from failed wrap-add, got nil")
	}
	if !strings.Contains(err.Error(), "rolled back") {
		t.Errorf("error should mention successful rollback, got: %v", err)
	}

	logData, readErr := os.ReadFile(filepath.Clean(invokeLog))
	if readErr != nil {
		t.Fatalf("reading invoke log: %v", readErr)
	}
	logStr := string(logData)
	// Expect: 1 list, 1 remove, 1 wrap-add (fails), 1 rollback-add (succeeds with original cmd).
	if strings.Count(logStr, "mcp add") != 2 {
		t.Errorf("expected exactly 2 mcp add invocations (wrap + rollback), got log: %s", logStr)
	}
	if !strings.Contains(logStr, "/usr/bin/node") {
		t.Errorf("rollback should re-add original /usr/bin/node command, got: %s", logStr)
	}
	if !strings.Contains(logStr, "--env PORT=3000") {
		t.Errorf("rollback should preserve original env, got: %s", logStr)
	}
}

func TestRunCodexInstall_AddFailsAndRollbackFails(t *testing.T) {
	// failingFakeCodex fails on every non-list call, so both the wrap-add AND
	// the rollback-add will fail. The error should explicitly tell the user
	// the rollback failed and to verify with `codex mcp list`.
	listJSON := `[{
		"name": "demo",
		"enabled": true,
		"transport": {"type": "stdio", "command": "/usr/bin/node", "args": ["x.js"]}
	}]`
	codexBin := failingFakeCodex(t, listJSON)
	root := newCodexTestRoot()
	root.SetArgs([]string{"codex", "install", "--codex-path", codexBin})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	err := root.ExecuteContext(context.Background())
	if err == nil {
		t.Fatalf("expected error from failing mcp add, got nil")
	}
	if !strings.Contains(err.Error(), "wrapping") || !strings.Contains(err.Error(), "demo") {
		t.Errorf("error should reference wrap target: %v", err)
	}
	if !strings.Contains(err.Error(), "rollback also failed") {
		t.Errorf("error should report rollback failure, got: %v", err)
	}
	if !strings.Contains(err.Error(), "codex mcp list") {
		t.Errorf("error should tell operator to verify with codex mcp list, got: %v", err)
	}
}

func TestRunCodexRemove_AddFailsRollsBackToWrapped(t *testing.T) {
	// Unwrap-add fails; rollback re-adds the wrapped (original input) server.
	// rollbackFakeCodex succeeds on rollback because the rollback-add args
	// contain "pipelock" (the wrap), which our fake script accepts since it
	// only fails when "pipelock" is in args. We invert: use a fake that
	// fails when "pipelock" is NOT in args (i.e. fails the unwrap).
	if runtime.GOOS == osWindows {
		t.Skip("shell helper not supported on Windows")
	}
	listJSON := `[{
		"name": "wrapped",
		"enabled": true,
		"transport": {
			"type": "stdio",
			"command": "/usr/local/bin/pipelock",
			"args": ["mcp", "proxy", "--", "/usr/bin/node", "server.js"],
			"env": {"PORT": "3000"}
		}
	}]`
	dir := t.TempDir()
	codexBin := filepath.Join(dir, "codex")
	invokeLog := filepath.Join(dir, "invocations.log")
	listFile := filepath.Join(dir, "list.json")
	if err := os.WriteFile(listFile, []byte(listJSON), 0o600); err != nil {
		t.Fatalf("writing list.json: %v", err)
	}
	// Script: list/remove succeed, mcp add SUCCEEDS only when args contain
	// "pipelock" (the rollback re-adds the wrapped form, which contains
	// "pipelock" in its command). Unwrap-add (no "pipelock") fails.
	script := fmt.Sprintf(`#!/bin/sh
echo "$@" >> %q
case "$1 $2" in
"mcp list") cat %q; exit 0 ;;
"mcp remove") exit 0 ;;
"mcp add")
  if echo "$@" | grep -q "pipelock"; then exit 0; fi
  echo "Error: synthetic unwrap-add failure" >&2
  exit 1
  ;;
esac
exit 0
`, invokeLog, listFile)
	writeShellScript(t, codexBin, script)

	root := newCodexTestRoot()
	root.SetArgs([]string{"codex", "remove", "--codex-path", codexBin})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	err := root.ExecuteContext(context.Background())
	if err == nil {
		t.Fatalf("expected error from failed unwrap-add, got nil")
	}
	if !strings.Contains(err.Error(), "rolled back") {
		t.Errorf("error should mention successful rollback, got: %v", err)
	}
	logData, readErr := os.ReadFile(filepath.Clean(invokeLog))
	if readErr != nil {
		t.Fatalf("reading invoke log: %v", readErr)
	}
	logStr := string(logData)
	if strings.Count(logStr, "mcp add") != 2 {
		t.Errorf("expected exactly 2 mcp add invocations (unwrap + rollback), got log: %s", logStr)
	}
}

func TestRunCodexRemove_AddFails(t *testing.T) {
	listJSON := `[{
		"name": "wrappedURL",
		"enabled": true,
		"transport": {
			"type": "stdio",
			"command": "/usr/local/bin/pipelock",
			"args": ["mcp", "proxy", "--upstream", "https://api.example.com/mcp"]
		}
	}]`
	codexBin := failingFakeCodex(t, listJSON)

	root := newCodexTestRoot()
	root.SetArgs([]string{"codex", "remove", "--codex-path", codexBin})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	if err := root.ExecuteContext(context.Background()); err == nil {
		t.Fatalf("expected error from failing mcp add (URL), got nil")
	}
}

func TestCodexMCPRemoveBestEffort(t *testing.T) {
	t.Run("not found is success", func(t *testing.T) {
		tmp := t.TempDir()
		bin := filepath.Join(tmp, "codex")
		writeShellScript(t, bin, `#!/bin/sh
echo "Error: server 'foo' not found" >&2
exit 1
`)
		if err := codexMCPRemoveBestEffort(context.Background(), bin, "foo"); err != nil {
			t.Errorf("expected 'not found' to be treated as success, got: %v", err)
		}
	})

	t.Run("other error propagates", func(t *testing.T) {
		tmp := t.TempDir()
		bin := filepath.Join(tmp, "codex")
		writeShellScript(t, bin, `#!/bin/sh
echo "Error: permission denied" >&2
exit 1
`)
		err := codexMCPRemoveBestEffort(context.Background(), bin, "foo")
		if err == nil {
			t.Errorf("expected error, got nil")
		}
	})
}

func TestCopyStringMap(t *testing.T) {
	if got := copyStringMap(nil); got != nil {
		t.Errorf("nil input should return nil, got %v", got)
	}
	in := map[string]string{"a": "1", "b": "2"}
	got := copyStringMap(in)
	if !reflect.DeepEqual(got, in) {
		t.Errorf("copy mismatch: got %v, want %v", got, in)
	}
	got["a"] = "mutated"
	if in["a"] == "mutated" {
		t.Errorf("copy is not deep — mutating result mutated source")
	}
}

func TestFormatEnvFlagsRedactsValues(t *testing.T) {
	got := formatEnvFlags(map[string]string{
		"TOKEN": "secret value",
	})
	if strings.Contains(got, "secret value") {
		t.Fatalf("formatEnvFlags leaked env value: %s", got)
	}
	if got != " --env TOKEN=<redacted>" {
		t.Fatalf("got %q, want redacted env flag", got)
	}
}

func TestJoinArgsQuotesTokenBoundaries(t *testing.T) {
	got := joinArgs([]string{"mcp", "proxy", "--", "node", "server with spaces.js"})
	want := `"mcp" "proxy" "--" "node" "server with spaces.js"`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestUnwrapCodexArgs_NilArgsErrors(t *testing.T) {
	_, _, _, err := unwrapCodexArgs(nil)
	if err == nil {
		t.Fatalf("expected error for nil args, got nil")
	}
}

// newCodexTestRoot constructs a minimal cobra root with the codex command
// attached, so end-to-end tests don't pull in the full pipelock root command
// graph.
func newCodexTestRoot() *cobra.Command {
	root := &cobra.Command{Use: "pipelock"}
	root.AddCommand(CodexCmd())
	return root
}
