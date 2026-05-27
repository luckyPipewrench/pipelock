// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package hermes

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stubPipelock points lookPipelock at a fake executable for the test duration.
func stubPipelock(t *testing.T, executable bool) {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "pipelock")
	mode := os.FileMode(0o600)
	if executable {
		mode = 0o700
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), mode); err != nil {
		t.Fatalf("seed fake bin: %v", err)
	}
	prev := lookPipelock
	lookPipelock = func() (string, bool) { return bin, executable }
	t.Cleanup(func() { lookPipelock = prev })
}

func TestClassifyCoverage(t *testing.T) {
	t.Parallel()

	cases := []struct {
		plugin, env, mcpWrapped bool
		want                    string
	}{
		{true, true, false, coverageFull},
		{true, true, true, coverageFull},
		{true, false, false, coveragePartial},
		{false, true, false, coveragePartial},
		{false, false, true, coveragePartial}, // mcp-only path
		{true, false, true, coveragePartial},
		{false, false, false, coverageNone},
	}
	for _, tc := range cases {
		if got := classifyCoverage(tc.plugin, tc.env, tc.mcpWrapped); got != tc.want {
			t.Fatalf("classifyCoverage(%v,%v,%v) = %q, want %q", tc.plugin, tc.env, tc.mcpWrapped, got, tc.want)
		}
	}
}

func TestIsBroadNoProxy(t *testing.T) {
	t.Parallel()

	cases := map[string]bool{
		"":                    false,
		"api.openai.com":      false,
		"*":                   true,
		".internal":           true,
		"localhost,.corp.net": true,
		"a.com,b.com":         false,
	}
	for value, want := range cases {
		if got := isBroadNoProxy(value); got != want {
			t.Fatalf("isBroadNoProxy(%q) = %v, want %v", value, got, want)
		}
	}
}

func TestBuildVerifyReport_FullCoverage(t *testing.T) {
	// No t.Parallel(): stubs the package-level lookPipelock seam.
	stubPipelock(t, true)
	tmp := t.TempDir()
	opts := fullOpts(tmp)
	configPath := filepath.Join(tmp, "pipelock.yaml")
	if err := os.WriteFile(configPath, []byte("mode: monitor\n"), 0o600); err != nil {
		t.Fatalf("seed pipelock config: %v", err)
	}
	opts.PipelockConfig = configPath
	cmd := installCmd()
	cmd.SetOut(&bytes.Buffer{})
	if err := runInstall(cmd, opts); err != nil {
		t.Fatalf("install: %v", err)
	}

	report := buildVerifyReport(&installOptions{PluginRoot: opts.PluginRoot, HermesConfig: opts.HermesConfig})
	if !report.PluginPresent {
		t.Fatal("plugin not detected as present")
	}
	if report.Coverage != coverageFull {
		t.Fatalf("coverage = %q, want full", report.Coverage)
	}
	if len(report.ProxyEnvMissing) != 0 {
		t.Fatalf("missing env names after full install: %v", report.ProxyEnvMissing)
	}
	if report.ConfigSidecar == "" {
		t.Fatal("config sidecar not detected")
	}
	if report.PipelockConfig != configPath {
		t.Fatalf("pipelock config = %q, want %q", report.PipelockConfig, configPath)
	}
	if report.ConfigReadable == nil || !*report.ConfigReadable {
		t.Fatalf("config readable = %v, want true", report.ConfigReadable)
	}
}

func TestBuildVerifyReport_None(t *testing.T) {
	// No t.Parallel(): stubs the package-level lookPipelock seam.
	stubPipelock(t, true)
	tmp := t.TempDir()
	report := buildVerifyReport(&installOptions{
		PluginRoot:   filepath.Join(tmp, "plugins", "pipelock"),
		HermesConfig: filepath.Join(tmp, "config.yaml"),
	})
	if report.Coverage != coverageNone {
		t.Fatalf("coverage = %q, want none", report.Coverage)
	}
	if report.PluginPresent {
		t.Fatal("plugin falsely reported present")
	}
	if len(report.ProxyEnvMissing) != len(proxyEnvNames) {
		t.Fatalf("expected all env names missing, got %d", len(report.ProxyEnvMissing))
	}
}

// seedEnabledPluginConfig writes a Hermes config that enables the pipelock
// plugin (and nothing else) at path, using the canonical registry name.
func seedEnabledPluginConfig(t *testing.T, path string) {
	t.Helper()
	body := "plugins:\n  enabled:\n    - " + pluginRegistryName + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("seed enabled-plugin config: %v", err)
	}
}

func TestBuildVerifyReport_PartialPluginOnly(t *testing.T) {
	// No t.Parallel(): stubs the package-level lookPipelock seam.
	stubPipelock(t, true)
	tmp := t.TempDir()
	pluginRoot := filepath.Join(tmp, "plugins", "pipelock")
	if _, err := Install(PluginTarget{Root: pluginRoot}); err != nil {
		t.Fatalf("plugin install: %v", err)
	}
	// Plugin enabled (so it is genuinely ready) but no terminal env injected
	// -> partial: a ready plugin path with no env, not full.
	hermesCfg := filepath.Join(tmp, "config.yaml")
	seedEnabledPluginConfig(t, hermesCfg)
	report := buildVerifyReport(&installOptions{
		PluginRoot:   pluginRoot,
		HermesConfig: hermesCfg,
	})
	if report.Coverage != coveragePartial {
		t.Fatalf("coverage = %q, want partial", report.Coverage)
	}
}

// TestBuildVerifyReport_PresentButDisabledIsNotReady proves the core honesty
// fix: a plugin whose files (and manifest) are on disk but which is NOT in
// plugins.enabled never loads under Hermes, so it must not count as coverage.
// Before the fix, verify reported this state as protective; that was false
// protection on the default path.
func TestBuildVerifyReport_PresentButDisabledIsNotReady(t *testing.T) {
	// No t.Parallel(): stubs the package-level lookPipelock seam.
	stubPipelock(t, true)
	tmp := t.TempDir()
	pluginRoot := filepath.Join(tmp, "plugins", "pipelock")
	if _, err := Install(PluginTarget{Root: pluginRoot}); err != nil {
		t.Fatalf("plugin install: %v", err)
	}
	// Config present but plugin NOT enabled, and no env injected.
	hermesCfg := filepath.Join(tmp, "config.yaml")
	if err := os.WriteFile(hermesCfg, []byte("model: gpt-4\n"), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	report := buildVerifyReport(&installOptions{PluginRoot: pluginRoot, HermesConfig: hermesCfg})
	if !report.PluginPresent || !report.ManifestPresent {
		t.Fatalf("expected files+manifest present: present=%v manifest=%v", report.PluginPresent, report.ManifestPresent)
	}
	if report.PluginEnabled {
		t.Fatal("plugin falsely reported enabled with no plugins.enabled entry")
	}
	if report.Coverage != coverageNone {
		t.Fatalf("coverage = %q, want none for a present-but-disabled plugin with no env", report.Coverage)
	}
}

// TestBuildVerifyReport_EnabledButManifestMissingIsNotReady proves the manifest
// gate: even an enabled, file-present plugin is inert if plugin.yaml is gone,
// because Hermes skips manifest-less plugin directories at discovery.
func TestBuildVerifyReport_EnabledButManifestMissingIsNotReady(t *testing.T) {
	// No t.Parallel(): stubs the package-level lookPipelock seam.
	stubPipelock(t, true)
	tmp := t.TempDir()
	pluginRoot := filepath.Join(tmp, "plugins", "pipelock")
	if _, err := Install(PluginTarget{Root: pluginRoot}); err != nil {
		t.Fatalf("plugin install: %v", err)
	}
	// Remove the manifest Hermes requires for discovery.
	if err := os.Remove(filepath.Join(pluginRoot, manifestName)); err != nil {
		t.Fatalf("remove manifest: %v", err)
	}
	hermesCfg := filepath.Join(tmp, "config.yaml")
	seedEnabledPluginConfig(t, hermesCfg)
	report := buildVerifyReport(&installOptions{PluginRoot: pluginRoot, HermesConfig: hermesCfg})
	if report.ManifestPresent {
		t.Fatal("manifest reported present after removal")
	}
	if report.Coverage != coverageNone {
		t.Fatalf("coverage = %q, want none when the manifest is missing", report.Coverage)
	}
}

func TestBuildVerifyReport_DockerMissingForwardEnvIsPartial(t *testing.T) {
	// No t.Parallel(): stubs the package-level lookPipelock seam.
	stubPipelock(t, true)
	tmp := t.TempDir()
	pluginRoot := filepath.Join(tmp, "plugins", "pipelock")
	if _, err := Install(PluginTarget{Root: pluginRoot}); err != nil {
		t.Fatalf("plugin install: %v", err)
	}

	cfg := &hermesConfig{path: filepath.Join(tmp, "config.yaml"), root: map[string]interface{}{
		terminalKey: map[string]interface{}{backendKey: backendDocker},
	}}
	term := cfg.root[terminalKey].(map[string]interface{})
	mergeStringList(term, envPassthroughKey, proxyEnvNames)
	// Enable the plugin so it is ready; the missing docker_forward_env (not a
	// disabled plugin) is what makes the env ineffective and the result partial.
	if _, err := cfg.enablePlugin(); err != nil {
		t.Fatalf("enable plugin: %v", err)
	}
	if _, err := cfg.save(false); err != nil {
		t.Fatalf("save seed config: %v", err)
	}

	report := buildVerifyReport(&installOptions{PluginRoot: pluginRoot, HermesConfig: cfg.path})
	if report.Coverage != coveragePartial {
		t.Fatalf("coverage = %q, want partial when docker_forward_env is missing", report.Coverage)
	}
	if len(report.ProxyEnvPresent) != 0 {
		t.Fatalf("effective proxy env present = %v, want none without docker_forward_env", report.ProxyEnvPresent)
	}
}

func TestBuildVerifyReport_MissingSidecarConfigIsPartial(t *testing.T) {
	// No t.Parallel(): stubs the package-level lookPipelock seam.
	stubPipelock(t, true)
	tmp := t.TempDir()
	opts := fullOpts(tmp)
	opts.PipelockConfig = filepath.Join(tmp, "missing-pipelock.yaml")
	cmd := installCmd()
	cmd.SetOut(&bytes.Buffer{})
	if err := runInstall(cmd, opts); err != nil {
		t.Fatalf("install: %v", err)
	}

	report := buildVerifyReport(&installOptions{PluginRoot: opts.PluginRoot, HermesConfig: opts.HermesConfig})
	if report.Coverage != coveragePartial {
		t.Fatalf("coverage = %q, want partial when sidecar config is missing", report.Coverage)
	}
	if report.ConfigReadable == nil || *report.ConfigReadable {
		t.Fatalf("config readable = %v, want false", report.ConfigReadable)
	}
	if report.ConfigWarning == "" {
		t.Fatal("missing sidecar config did not produce a warning")
	}
}

func TestBuildVerifyReport_RelativeSidecarConfigIsNotReady(t *testing.T) {
	// No t.Parallel(): stubs the package-level lookPipelock seam.
	stubPipelock(t, true)
	tmp := t.TempDir()
	pluginRoot := filepath.Join(tmp, "plugins", "pipelock")
	if _, err := Install(PluginTarget{Root: pluginRoot}); err != nil {
		t.Fatalf("plugin install: %v", err)
	}
	if err := writeConfigSidecar(pluginRoot, "pipelock.yaml"); err != nil {
		t.Fatalf("write sidecar: %v", err)
	}

	report := buildVerifyReport(&installOptions{
		PluginRoot:   pluginRoot,
		HermesConfig: filepath.Join(tmp, "config.yaml"),
	})
	if report.Coverage != coverageNone {
		t.Fatalf("coverage = %q, want none when plugin config path is relative and env is absent", report.Coverage)
	}
	if !strings.Contains(report.ConfigWarning, "relative path") {
		t.Fatalf("warning = %q, want relative path warning", report.ConfigWarning)
	}
}

func TestVerifyCmd_JSONOutput(t *testing.T) {
	// No t.Parallel(): stubs the package-level lookPipelock seam.
	stubPipelock(t, true)
	tmp := t.TempDir()
	opts := fullOpts(tmp)
	icmd := installCmd()
	icmd.SetOut(&bytes.Buffer{})
	if err := runInstall(icmd, opts); err != nil {
		t.Fatalf("install: %v", err)
	}

	cmd := verifyCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--json", "--plugin-root", opts.PluginRoot, "--hermes-config", opts.HermesConfig})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("verify --json: %v", err)
	}

	var report verifyReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("verify JSON parse: %v (%q)", err, out.String())
	}
	if report.Coverage != coverageFull {
		t.Fatalf("json coverage = %q, want full", report.Coverage)
	}
	if !report.HookExecutable {
		t.Fatal("json hook_executable false for stubbed executable binary")
	}
}

func TestVerifyCmd_TextOutput(t *testing.T) {
	// No t.Parallel(): stubs the package-level lookPipelock seam.
	stubPipelock(t, false)
	tmp := t.TempDir()
	cmd := verifyCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{
		"--plugin-root", filepath.Join(tmp, "plugins", "pipelock"),
		"--hermes-config", filepath.Join(tmp, "config.yaml"),
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !strings.Contains(out.String(), "Coverage:") {
		t.Fatalf("text output missing Coverage line: %q", out.String())
	}
}

func TestVerifyCmd_TextFullCoverageIsHonest(t *testing.T) {
	// No t.Parallel(): stubs the package-level lookPipelock seam.
	stubPipelock(t, true)
	tmp := t.TempDir()
	opts := fullOpts(tmp)
	configPath := filepath.Join(tmp, "pipelock.yaml")
	if err := os.WriteFile(configPath, []byte("mode: monitor\n"), 0o600); err != nil {
		t.Fatalf("seed pipelock config: %v", err)
	}
	opts.PipelockConfig = configPath
	icmd := installCmd()
	icmd.SetOut(&bytes.Buffer{})
	if err := runInstall(icmd, opts); err != nil {
		t.Fatalf("install: %v", err)
	}

	cmd := verifyCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--plugin-root", opts.PluginRoot, "--hermes-config", opts.HermesConfig})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("verify: %v", err)
	}
	s := out.String()
	// Full coverage must surface manifest + enabled state AND stay honest that
	// terminal egress is cooperative — never a bare "full" that reads as
	// enforced network isolation.
	for _, want := range []string{"Manifest present: true", "Plugin enabled:   true", "Coverage:", "full", "cooperative"} {
		if !strings.Contains(s, want) {
			t.Fatalf("verify text missing %q:\n%s", want, s)
		}
	}
}

func TestVerifyCmd_TextWithMCPServersAndWarning(t *testing.T) {
	// No t.Parallel(): mutates env NO_PROXY and stubs lookPipelock.
	t.Setenv("NO_PROXY", "*")
	stubPipelock(t, true)

	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("mcp_servers:\n  scrapling:\n    url: http://x\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	cmd := verifyCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{
		"--plugin-root", filepath.Join(tmp, "plugins", "pipelock"),
		"--hermes-config", cfgPath,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("verify: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "MCP servers:") {
		t.Fatalf("text output missing MCP servers line: %q", s)
	}
	if !strings.Contains(s, "WARNING:") {
		t.Fatalf("text output missing NO_PROXY warning: %q", s)
	}
}

func TestVerifyReport_NoProxyWarning(t *testing.T) {
	// No t.Parallel(): mutates process env NO_PROXY.
	t.Setenv("NO_PROXY", "*")
	stubPipelock(t, true)

	tmp := t.TempDir()
	report := buildVerifyReport(&installOptions{
		PluginRoot:   filepath.Join(tmp, "plugins", "pipelock"),
		HermesConfig: filepath.Join(tmp, "config.yaml"),
	})
	if report.NoProxyWarning == "" {
		t.Fatal("broad NO_PROXY did not produce a warning")
	}
}
