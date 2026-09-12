// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/mcpwrap"
)

func TestCodexInstallForeignUpgradeAndRefusal(t *testing.T) {
	for _, tc := range []struct {
		name   string
		args   []string
		want   string
		refuse bool
	}{
		{"stdio", []string{"mcp", "proxy", "--", "node", "server.js"}, "--env EXAMPLE_MODE -- node server.js", false},
		{"upstream", []string{"mcp", "proxy", "--upstream", "https://api.vendor.example/mcp"}, "--upstream https://api.vendor.example/mcp", false},
		{"sidecar", []string{"mcp", "proxy", "--header-file", "credentials.headers", "--upstream", "https://api.vendor.example/mcp"}, "", true},
		{"missing upstream URL", []string{"mcp", "proxy", "--upstream", "--header-file"}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			servers := []codexMCPServer{
				{Name: "fresh", Transport: codexMCPTransport{Type: codexTransportStdio, Command: "node", Args: []string{"fresh.js"}}},
				{Name: "upgrading", Transport: codexMCPTransport{Type: codexTransportStdio, Command: foreignBinary, Args: tc.args, Env: map[string]string{"EXAMPLE_MODE": "local"}}},
			}
			list, err := json.Marshal(servers)
			if err != nil {
				t.Fatal(err)
			}
			bin, logPath := fakeCodex(t, string(list))
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
			if strings.Contains(string(logData), foreignBinary) || !strings.Contains(string(logData), tc.want) {
				t.Fatalf("upgrade did not replace the foreign wrapper: %s", logData)
			}
		})
	}
}
