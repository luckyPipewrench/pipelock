// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package hermes

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/mcpwrap"
)

func TestMCPOnlyInstallReplacesForeignWrapper(t *testing.T) {
	dir := t.TempDir()
	opts := fullOpts(dir)
	opts.Mode = ModeMCPOnly
	opts.PipelockConfig = filepath.Join(dir, "pipelock.yaml")
	seed := "mcp_servers:\n  example:\n    command: /nonexistent/older-proxy\n    args: [mcp, proxy, --config, old.yaml, --env, EXAMPLE_MODE, --, node, server.js]\n    env:\n      EXAMPLE_MODE: local\n    _pipelock:\n      original_command: wrong-command\n"
	if err := os.WriteFile(opts.HermesConfig, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := installCmd()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	if err := runInstall(cmd, opts); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadHermesConfig(opts.HermesConfig)
	if err != nil {
		t.Fatal(err)
	}
	server, ok := cfg.mcpServers()["example"].(map[string]interface{})
	if !ok {
		t.Fatal("missing server")
	}
	args := mcpwrap.InterfaceSliceToStrings(server["args"])
	joined := strings.Join(args, " ")
	if !mcpwrap.IsWrappedBySelf(server) || !strings.Contains(joined, "-- node server.js") || strings.Contains(joined, "older-proxy") || strings.Contains(joined, "old.yaml") {
		t.Fatalf("upgrade did not produce one current wrapper: %v", server)
	}
	if !strings.Contains(joined, "--env EXAMPLE_MODE") {
		t.Fatalf("env passthrough lost: %v", args)
	}
	first, err := os.ReadFile(opts.HermesConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := runInstall(cmd, opts); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(opts.HermesConfig)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("second install changed the current wrapper")
	}
}

func TestMCPOnlyForeignRefusalPreservesConfig(t *testing.T) {
	for _, seed := range []string{
		"mcp_servers:\n  example:\n    command: /nonexistent/older-proxy\n    args: [mcp, proxy, --header-file, credentials.headers, --upstream, 'https://api.vendor.example/mcp']\n",
		"mcp_servers:\n  example:\n    command: /nonexistent/older-proxy\n    args: [mcp, proxy, --upstream, 'https://api.vendor.example/mcp']\n    headers:\n      X-Example-Auth: test-only-value\n",
	} {
		dir := t.TempDir()
		opts := fullOpts(dir)
		opts.Mode = ModeMCPOnly
		opts.PipelockConfig = filepath.Join(dir, "pipelock.yaml")
		if err := os.WriteFile(opts.HermesConfig, []byte(seed), 0o600); err != nil {
			t.Fatal(err)
		}
		before, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		cmd := installCmd()
		var output bytes.Buffer
		cmd.SetOut(&output)
		cmd.SetErr(&output)
		if err := runInstall(cmd, opts); err == nil {
			t.Fatal("refused wrapper reported successful install")
		}
		if !strings.Contains(output.String(), "cannot normalize wrapper") {
			t.Fatalf("refusal warning missing: %s", output.String())
		}
		after, err := os.ReadFile(opts.HermesConfig)
		if err != nil || !bytes.Equal(after, []byte(seed)) {
			t.Fatalf("refusal changed config: %v", err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != len(before) {
			t.Fatalf("refusal created a backup or sidecar: %v", err)
		}
	}
}
