// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/mcpwrap"
)

func TestCodexInstallForeignUpgradeAndRefusal(t *testing.T) {
	for _, tc := range []struct {
		name   string
		args   []string
		want   []string
		refuse bool
	}{
		{"stdio", []string{"mcp", "proxy", "--", "node", "server.js"}, []string{"--env", "EXAMPLE_MODE", "--", "node", "server.js"}, false},
		{"upstream", []string{"mcp", "proxy", "--upstream", "https://api.vendor.example/mcp"}, []string{"--upstream", "https://api.vendor.example/mcp"}, false},
		{"sidecar", []string{"mcp", "proxy", "--header-file", "credentials.headers", "--upstream", "https://api.vendor.example/mcp"}, nil, true},
		{"missing upstream URL", []string{"mcp", "proxy", "--upstream", "--header-file"}, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exe, err := resolvePipelockBinary()
			if err != nil {
				t.Fatal(err)
			}
			servers := []codexMCPServer{
				{Name: "fresh", Transport: codexMCPTransport{Type: codexTransportStdio, Command: exe, Args: []string{"mcp", "proxy", "--", "node", "fresh.js"}}},
				{Name: "upgrading", Transport: codexMCPTransport{Type: codexTransportStdio, Command: foreignBinary, Args: tc.args, Env: map[string]string{"EXAMPLE_MODE": "local"}}},
			}
			list, err := json.Marshal(servers)
			if err != nil {
				t.Fatal(err)
			}
			bin, logPath := fakeCodex(t, string(list))
			// Preserve argv boundaries and separate invocations, including empty args.
			script := fmt.Sprintf(`#!/bin/sh
case "$1 $2" in
"mcp list") cat %q; exit 0 ;;
esac
printf '%%s\000' "$@" >> %q
printf '\000' >> %q
`, filepath.Join(filepath.Dir(bin), "list.json"), logPath, logPath)
			writeShellScript(t, bin, script)

			cfgPath := filepath.Join(t.TempDir(), "pipelock.yaml")
			if err := os.WriteFile(cfgPath, []byte("version: 1\nmode: balanced\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := newCodexTestRoot()
			cmd.SetArgs([]string{"codex", "install", "--codex-path", bin, "--config", cfgPath})
			var output bytes.Buffer
			cmd.SetOut(&output)
			cmd.SetErr(&output)
			installErr := cmd.Execute()
			logData, err := os.ReadFile(filepath.Clean(logPath))
			if err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if tc.refuse {
				if !errors.Is(installErr, mcpwrap.ErrCannotNormalize) {
					t.Fatalf("install error = %v, want refusal; output: %s", installErr, output.String())
				}
				if len(bytes.TrimSpace(logData)) != 0 {
					t.Fatalf("refusal modified a server: %s", logData)
				}
				return
			}
			if installErr != nil {
				t.Fatal(installErr)
			}
			wantAdd := []string{"mcp", "add", "--env", "EXAMPLE_MODE=local", "upgrading", "--", exe, "mcp", "proxy", "--config", cfgPath}
			wantAdd = append(wantAdd, tc.want...)
			wantLog := strings.Join([]string{"mcp", "remove", "upgrading"}, "\x00") + "\x00\x00" + strings.Join(wantAdd, "\x00") + "\x00\x00"
			if !slices.Equal(logData, []byte(wantLog)) {
				t.Fatalf("upgrade invocations = %q, want %q (fresh server must remain untouched)", logData, wantLog)
			}
		})
	}
}

func TestPlanCodexForeignAuthRefused(t *testing.T) {
	for _, transport := range []codexMCPTransport{
		{HTTPHeaders: json.RawMessage(`{"X-Example-Auth":"test-only-value"}`)},
		{EnvHTTPHeaders: json.RawMessage(`{"X-Example-Auth":"EXAMPLE_AUTH"}`)},
		{BearerTokenEnvVar: "EXAMPLE_AUTH"},
	} {
		transport.Type = codexTransportStdio
		transport.Command = foreignBinary
		transport.Args = []string{"mcp", "proxy", "--upstream", "https://api.vendor.example/mcp"}
		plans, err := planCodexInstall([]codexMCPServer{{Name: "example", Transport: transport}}, "/current/proxy", "config.yaml")
		if !errors.Is(err, mcpwrap.ErrCannotNormalize) || plans != nil {
			t.Fatalf("ambiguous authentication produced a replacement plan: %v %v", plans, err)
		}
	}
}
