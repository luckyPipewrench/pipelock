// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/mcpwrap"
	"github.com/spf13/cobra"
)

func TestInstallerForeignRefusalPreservesConfig(t *testing.T) {
	for _, tc := range []struct {
		name    string
		newCmd  func() *cobra.Command
		path    string
		key     string
		project bool
		array   bool
	}{
		{"vscode", VscodeCmd, ".vscode/mcp.json", "servers", true, false},
		{"jetbrains", JetbrainsCmd, ".junie/mcp/mcp.json", "mcpServers", true, false},
		{"cline", ClineCmd, "mcp.json", "mcpServers", false, false},
		{"opencode", OpenCodeCmd, "opencode.json", "mcp", false, true},
		{"zed", ZedCmd, "settings.json", "context_servers", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Chdir(dir)
			configPath := filepath.Join(dir, "pipelock.yaml")
			if err := os.WriteFile(configPath, []byte("version: 1\nmode: balanced\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			args := []string{"mcp", "proxy", "--header-file", "credentials.headers", "--upstream", "https://api.vendor.example/mcp"}
			server := map[string]interface{}{"command": foreignBinary, "args": args}
			if tc.array {
				server = map[string]interface{}{"type": "local", "command": append([]string{foreignBinary}, args...)}
			}
			data, err := json.Marshal(map[string]interface{}{tc.key: map[string]interface{}{"example": server}})
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, tc.path)
			if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadDir(filepath.Dir(path))
			if err != nil {
				t.Fatal(err)
			}
			cmd := tc.newCmd()
			var output bytes.Buffer
			cmd.SetOut(&output)
			cmd.SetErr(&output)
			cmdArgs := []string{"install", "--config", configPath}
			if tc.project {
				cmdArgs = append(cmdArgs, "--project")
			} else {
				cmdArgs = append(cmdArgs, "--path", path)
			}
			cmd.SetArgs(cmdArgs)
			if err := cmd.Execute(); !errors.Is(err, mcpwrap.ErrCannotNormalize) {
				t.Fatalf("install error = %v, want refusal; output: %s", err, output.String())
			}
			after, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(after, data) {
				t.Fatal("refused install changed the configuration")
			}
			entries, err := os.ReadDir(filepath.Dir(path))
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != len(before) {
				t.Fatal("refused install created a backup or sidecar")
			}
		})
	}
}
