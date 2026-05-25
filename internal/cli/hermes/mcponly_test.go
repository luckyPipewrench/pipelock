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

// runMCPOnlyInstall installs in mcp-only mode against opts and returns combined
// stdout. HOME is redirected by the caller (header sidecars live under HOME).
func runMCPOnlyInstall(t *testing.T, opts *installOptions) string {
	t.Helper()
	opts.Mode = ModeMCPOnly
	cmd := installCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := runInstall(cmd, opts); err != nil {
		t.Fatalf("mcp-only install: %v", err)
	}
	return out.String()
}

func TestMCPOnly_HTTPHeadersSidecar(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // header sidecar dir lives under HOME

	tmp := t.TempDir()
	opts := fullOpts(tmp)
	seed := "mcp_servers:\n" +
		"  remote:\n" +
		"    url: https://up.example/mcp\n" +
		"    headers:\n" +
		"      Authorization: \"Bearer sk-secret-xyz\"\n"
	if err := os.WriteFile(opts.HermesConfig, []byte(seed), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	out := runMCPOnlyInstall(t, opts)
	if !strings.Contains(out, "auth-header sidecar") {
		t.Errorf("output missing sidecar note: %q", out)
	}

	cfg, err := loadHermesConfig(opts.HermesConfig)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	remote := cfg.mcpServers()["remote"].(map[string]interface{})
	if !mcpwrap.IsWrapped(remote) {
		t.Fatal("remote server not wrapped")
	}
	args := strings.Join(mcpwrap.InterfaceSliceToStrings(remote["args"]), " ")
	// The credential value must NOT appear in the wrapped argv (that is the
	// exposure the sidecar closes: /proc/<pid>/cmdline is world-visible). The
	// argv carries only the --header-file path reference.
	if strings.Contains(args, "sk-secret-xyz") || strings.Contains(args, "Bearer") {
		t.Fatalf("credential leaked into wrapped argv: %q", args)
	}
	if !strings.Contains(args, "--header-file") || !strings.Contains(args, "--upstream https://up.example/mcp") {
		t.Fatalf("wrapped args missing header-file/upstream: %q", args)
	}
	// The sidecar file the args point at must exist at 0600 with the header.
	sidecar := sidecarPathFromArgs(t, mcpwrap.InterfaceSliceToStrings(remote["args"]))
	info, err := os.Stat(sidecar)
	if err != nil {
		t.Fatalf("sidecar missing: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("sidecar perms = %o, want 600", info.Mode().Perm())
	}
	body, _ := os.ReadFile(filepath.Clean(sidecar))
	if !strings.Contains(string(body), "Authorization: Bearer sk-secret-xyz") {
		t.Errorf("sidecar body missing header: %q", body)
	}
}

func TestMCPOnly_NoServers(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	opts := fullOpts(tmp)
	if err := os.WriteFile(opts.HermesConfig, []byte("terminal:\n  backend: local\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	opts.Mode = ModeMCPOnly
	cmd := installCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := runInstall(cmd, opts); err != nil {
		t.Fatalf("install: %v", err)
	}
	if !strings.Contains(out.String(), "nothing to wrap") || !strings.Contains(out.String(), "coverage = none") {
		t.Fatalf("unexpected no-servers output: %q", out.String())
	}
}

func TestMCPOnly_RollbackRoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	tmp := t.TempDir()
	opts := fullOpts(tmp)
	seed := "mcp_servers:\n" +
		"  local:\n" +
		"    command: mytool\n" +
		"    args: [\"--flag\"]\n" +
		"  remote:\n" +
		"    url: https://up/mcp\n" +
		"    headers:\n" +
		"      Authorization: \"Bearer tok\"\n"
	if err := os.WriteFile(opts.HermesConfig, []byte(seed), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	runMCPOnlyInstall(t, opts)

	// Capture the sidecar path before rollback so we can assert it is deleted.
	cfg, err := loadHermesConfig(opts.HermesConfig)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	remote := cfg.mcpServers()["remote"].(map[string]interface{})
	sidecar := sidecarPathFromArgs(t, mcpwrap.InterfaceSliceToStrings(remote["args"]))
	if _, err := os.Stat(sidecar); err != nil {
		t.Fatalf("sidecar should exist after install: %v", err)
	}

	// Rollback (surgical).
	rb := &rollbackOptions{PluginRoot: opts.PluginRoot, HermesConfig: opts.HermesConfig}
	rcmd := rollbackCmd()
	var rout bytes.Buffer
	rcmd.SetOut(&rout)
	rcmd.SetErr(&rout)
	if err := runRollback(rcmd, rb); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if !strings.Contains(rout.String(), "unwrapped 2 mcp server(s)") {
		t.Fatalf("rollback output: %q", rout.String())
	}

	// Original entries restored, no pipelock metadata, sidecar deleted.
	restored, err := loadHermesConfig(opts.HermesConfig)
	if err != nil {
		t.Fatalf("reload after rollback: %v", err)
	}
	local := restored.mcpServers()["local"].(map[string]interface{})
	if mcpwrap.IsWrapped(local) || local["command"] != "mytool" {
		t.Fatalf("local server not restored: %#v", local)
	}
	rem := restored.mcpServers()["remote"].(map[string]interface{})
	if mcpwrap.IsWrapped(rem) || rem["url"] != "https://up/mcp" {
		t.Fatalf("remote server not restored: %#v", rem)
	}
	hdrs, ok := rem["headers"].(map[string]interface{})
	if !ok || hdrs["Authorization"] != "Bearer tok" {
		t.Fatalf("remote headers not restored: %#v", rem["headers"])
	}
	if _, err := os.Stat(sidecar); !os.IsNotExist(err) {
		t.Errorf("sidecar not deleted on rollback: %v", err)
	}
}

func TestMCPOnly_VerifyReportsPartialCoverage(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	tmp := t.TempDir()
	opts := fullOpts(tmp)
	if err := os.WriteFile(opts.HermesConfig, []byte("mcp_servers:\n  s:\n    command: x\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	runMCPOnlyInstall(t, opts)

	report := buildVerifyReport(&installOptions{PluginRoot: opts.PluginRoot, HermesConfig: opts.HermesConfig})
	if report.MCPServersWrapped != 1 {
		t.Errorf("MCPServersWrapped = %d, want 1", report.MCPServersWrapped)
	}
	if report.Coverage != coveragePartial {
		t.Errorf("coverage = %q, want %q", report.Coverage, coveragePartial)
	}
}

func TestMCPOnly_FailsClosedOnUnwrappableServer(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	tmp := t.TempDir()
	opts := fullOpts(tmp)
	seed := "mcp_servers:\n" +
		"  good:\n" +
		"    command: x\n" +
		"  ambiguous:\n" +
		"    command: y\n" +
		"    url: https://up/mcp\n"
	if err := os.WriteFile(opts.HermesConfig, []byte(seed), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	opts.Mode = ModeMCPOnly
	cmd := installCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := runInstall(cmd, opts)
	if err == nil || !strings.Contains(err.Error(), "could not be wrapped") {
		t.Fatalf("install err = %v, want could-not-wrap failure", err)
	}
	if !strings.Contains(out.String(), "both command and url") {
		t.Fatalf("install output missing ambiguous-server warning: %q", out.String())
	}

	cfg, err := loadHermesConfig(opts.HermesConfig)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	good := cfg.mcpServers()["good"].(map[string]interface{})
	if mcpwrap.IsWrapped(good) {
		t.Fatalf("install saved partial wrap despite failure: %#v", good)
	}
}

func TestMCPOnly_DiscoversPipelockConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "pipelock.yaml")
	if err := os.WriteFile(configPath, []byte("mode: monitor\n"), 0o600); err != nil {
		t.Fatalf("seed pipelock config: %v", err)
	}
	t.Setenv("PIPELOCK_CONFIG", configPath)

	opts := fullOpts(tmp)
	opts.PipelockConfig = ""
	if err := os.WriteFile(opts.HermesConfig, []byte("mcp_servers:\n  s:\n    command: x\n"), 0o600); err != nil {
		t.Fatalf("seed hermes config: %v", err)
	}

	out := runMCPOnlyInstall(t, opts)
	if !strings.Contains(out, "using config "+configPath) {
		t.Fatalf("install did not report discovered config: %q", out)
	}

	cfg, err := loadHermesConfig(opts.HermesConfig)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	server := cfg.mcpServers()["s"].(map[string]interface{})
	args := strings.Join(mcpwrap.InterfaceSliceToStrings(server["args"]), " ")
	if !strings.Contains(args, "--config "+configPath) {
		t.Fatalf("wrapped args did not include discovered config %q: %q", configPath, args)
	}
}

func TestMCPOnly_WarnsWhenPluginAlreadyInstalled(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PIPELOCK_CONFIG", "")

	tmp := t.TempDir()
	opts := fullOpts(tmp)
	if err := os.WriteFile(opts.HermesConfig, []byte("mcp_servers:\n  s:\n    command: x\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Install the full-mode plugin first (it already scans MCP tool calls).
	full := *opts
	full.Mode = ModeFull
	fcmd := installCmd()
	fcmd.SetOut(&bytes.Buffer{})
	if err := runInstall(fcmd, &full); err != nil {
		t.Fatalf("full install: %v", err)
	}

	// mcp-only on top must warn that MCP traffic would be scanned twice.
	opts.Mode = ModeMCPOnly
	opts.PipelockConfig = filepath.Join(tmp, "pipelock.yaml")
	cmd := installCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := runInstall(cmd, opts); err != nil {
		t.Fatalf("mcp-only install: %v", err)
	}
	if !strings.Contains(out.String(), "scan MCP traffic twice") {
		t.Fatalf("missing double-scan warning: %q", out.String())
	}
}

// sidecarPathFromArgs extracts the --header-file value from a wrapped arg list.
func sidecarPathFromArgs(t *testing.T, args []string) string {
	t.Helper()
	for i, a := range args {
		if a == "--header-file" && i+1 < len(args) {
			return args[i+1]
		}
	}
	t.Fatalf("no --header-file in args: %v", args)
	return ""
}
