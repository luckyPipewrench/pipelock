// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package hermes

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/mcpwrap"
)

// fullOpts builds installOptions wired entirely under tmp so tests never touch
// the operator's real ~/.hermes.
func fullOpts(tmp string) *installOptions {
	return &installOptions{
		Mode:         ModeFull,
		PluginRoot:   filepath.Join(tmp, "plugins", "pipelock"),
		HermesConfig: filepath.Join(tmp, "config.yaml"),
	}
}

func TestInstallOptionsValidate(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		mode    string
		wantErr bool
	}{
		{"full", ModeFull, false},
		{"mcp-only", ModeMCPOnly, false},
		{"empty", "", true},
		{"unknown", "experimental", true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := &installOptions{Mode: tc.mode}
			err := opts.validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("validate(%q) err = %v, wantErr = %v", tc.mode, err, tc.wantErr)
			}
		})
	}
}

func TestInstallCmd_FlagsAndUsage(t *testing.T) {
	t.Parallel()

	cmd := installCmd()
	if cmd.Use != "install" {
		t.Fatalf("Use = %q, want install", cmd.Use)
	}
	for _, flag := range []string{"mode", "plugin-root", "hermes-config", "pipelock-config"} {
		if cmd.Flags().Lookup(flag) == nil {
			t.Fatalf("missing --%s flag", flag)
		}
	}
	// Default is full (max coverage); mcp-only is the lighter opt-in.
	if cmd.Flags().Lookup("mode").DefValue != ModeFull {
		t.Fatalf("--mode default = %q, want %q", cmd.Flags().Lookup("mode").DefValue, ModeFull)
	}
}

func TestCmd_RegistersAllSubcommands(t *testing.T) {
	t.Parallel()

	parent := Cmd()
	want := map[string]bool{"install": false, "verify": false, "rollback": false, "hook": false}
	for _, sub := range parent.Commands() {
		if _, ok := want[sub.Name()]; ok {
			want[sub.Name()] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Fatalf("Cmd() did not register %q subcommand", name)
		}
	}
}

func TestRunInstall_FullModeWritesPluginAndEnv(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	opts := fullOpts(tmp)
	opts.PipelockConfig = "/etc/pipelock/pipelock.yaml"

	cmd := installCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)

	if err := runInstall(cmd, opts); err != nil {
		t.Fatalf("runInstall: %v", err)
	}

	if !strings.Contains(out.String(), "hermes plugin installed") {
		t.Fatalf("output missing install message: %q", out.String())
	}
	if _, err := os.Stat(filepath.Join(opts.PluginRoot, "plugin.py")); err != nil {
		t.Fatalf("plugin.py missing after install: %v", err)
	}
	// Config sidecar written.
	sidecar := filepath.Join(opts.PluginRoot, configSidecarName)
	data, err := os.ReadFile(sidecar) //nolint:gosec // path under t.TempDir()
	if err != nil {
		t.Fatalf("sidecar missing: %v", err)
	}
	if strings.TrimSpace(string(data)) != "/etc/pipelock/pipelock.yaml" {
		t.Fatalf("sidecar content = %q, want the pipelock-config path", string(data))
	}
	// Env injected into config.yaml.
	cfg, err := loadHermesConfig(opts.HermesConfig)
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if got := len(cfg.terminalEnvPresent()); got != len(proxyEnvNames) {
		t.Fatalf("env_passthrough has %d proxy names, want %d", got, len(proxyEnvNames))
	}
}

func TestRunInstall_FullModeEnablesPluginAndWritesManifest(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	opts := fullOpts(tmp)

	cmd := installCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := runInstall(cmd, opts); err != nil {
		t.Fatalf("runInstall: %v", err)
	}

	// The plugin is opt-in: without this entry Hermes discovers it disabled and
	// it never fires. Prove the install writes it.
	cfg, err := loadHermesConfig(opts.HermesConfig)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !cfg.pluginEnabled() {
		t.Fatal("full install did not enable the plugin in plugins.enabled")
	}
	if !strings.Contains(out.String(), "enabled plugin") {
		t.Fatalf("output missing enable line: %q", out.String())
	}
	// The manifest Hermes requires for discovery must be extracted too.
	if !pluginManifestPresent(opts.PluginRoot) {
		t.Fatal("plugin.yaml manifest missing after full install")
	}
	// Full coverage is honest about the one cooperative arm (terminal egress)
	// without overclaiming enforced network isolation.
	if !strings.Contains(out.String(), "coverage = full") || !strings.Contains(out.String(), "cooperative terminal") {
		t.Fatalf("full install output missing honest coverage line: %q", out.String())
	}
}

func TestRunInstall_FullModePreservesOtherEnabledPlugins(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	opts := fullOpts(tmp)
	// Operator already enabled another plugin; full install must add pipelock
	// without dropping it.
	if err := os.WriteFile(opts.HermesConfig,
		[]byte("plugins:\n  enabled:\n    - disk-cleanup\n"), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	cmd := installCmd()
	cmd.SetOut(&bytes.Buffer{})
	if err := runInstall(cmd, opts); err != nil {
		t.Fatalf("runInstall: %v", err)
	}

	cfg, err := loadHermesConfig(opts.HermesConfig)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !cfg.pluginEnabled() {
		t.Fatal("pipelock not enabled after full install")
	}
	plugins := cfg.root[pluginsKey].(map[string]interface{})
	if !toStringSet(plugins[enabledKey])["disk-cleanup"] {
		t.Fatal("full install dropped the operator's pre-enabled plugin")
	}
}

func TestRunInstall_FullModeMalformedPluginsSectionErrors(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	opts := fullOpts(tmp)
	// A non-mapping plugins section must abort the install before touching the
	// plugin tree or clobbering operator config we cannot parse.
	if err := os.WriteFile(opts.HermesConfig,
		[]byte("plugins:\n  - not-a-mapping\n"), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	cmd := installCmd()
	cmd.SetOut(&bytes.Buffer{})
	err := runInstall(cmd, opts)
	if err == nil {
		t.Fatal("full install did not error on a malformed plugins section")
	}
	if !strings.Contains(err.Error(), pluginsKey) {
		t.Fatalf("error %q does not mention the plugins section", err.Error())
	}
	// The malformed config must be left exactly as the operator wrote it.
	data, readErr := os.ReadFile(opts.HermesConfig) //nolint:gosec // under t.TempDir()
	if readErr != nil {
		t.Fatalf("read config: %v", readErr)
	}
	if !strings.Contains(string(data), "not-a-mapping") {
		t.Fatalf("install mutated a config it could not parse: %q", string(data))
	}
	if pluginInstalled(opts.PluginRoot) {
		t.Fatal("install wrote plugin files after rejecting malformed plugin config")
	}
}

func TestRunInstall_FullModeMalformedPluginsEnabledErrors(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	opts := fullOpts(tmp)
	// A malformed plugins.enabled value must not be replaced, because doing so
	// could disable operator-managed plugin config that we cannot preserve.
	if err := os.WriteFile(opts.HermesConfig,
		[]byte("plugins:\n  enabled: disk-cleanup\n"), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	cmd := installCmd()
	cmd.SetOut(&bytes.Buffer{})
	err := runInstall(cmd, opts)
	if err == nil {
		t.Fatal("full install did not error on malformed plugins.enabled")
	}
	if !strings.Contains(err.Error(), "plugins.enabled") {
		t.Fatalf("error %q does not mention plugins.enabled", err.Error())
	}
	data, readErr := os.ReadFile(opts.HermesConfig) //nolint:gosec // under t.TempDir()
	if readErr != nil {
		t.Fatalf("read config: %v", readErr)
	}
	if !strings.Contains(string(data), "enabled: disk-cleanup") {
		t.Fatalf("install mutated malformed plugins.enabled: %q", string(data))
	}
	if pluginInstalled(opts.PluginRoot) {
		t.Fatal("install wrote plugin files after rejecting malformed plugins.enabled")
	}
}

func TestRunInstall_RecordsAbsolutePipelockConfig(t *testing.T) {
	tmp := t.TempDir()
	t.Chdir(tmp)

	opts := fullOpts(tmp)
	opts.PipelockConfig = "pipelock.yaml"

	cmd := installCmd()
	cmd.SetOut(&bytes.Buffer{})
	if err := runInstall(cmd, opts); err != nil {
		t.Fatalf("runInstall: %v", err)
	}

	sidecar := filepath.Join(opts.PluginRoot, configSidecarName)
	data, err := os.ReadFile(sidecar) //nolint:gosec // path under t.TempDir()
	if err != nil {
		t.Fatalf("sidecar missing: %v", err)
	}
	want := filepath.Join(tmp, "pipelock.yaml")
	if strings.TrimSpace(string(data)) != want {
		t.Fatalf("sidecar config path = %q, want %q", strings.TrimSpace(string(data)), want)
	}
}

func TestRunInstall_MCPOnlyWrapsStdioServer(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	opts := fullOpts(tmp)
	opts.Mode = ModeMCPOnly
	// Pin the config explicitly so the wrap does not fall back to
	// cliutil.DiscoverConfigPath() and pick up machine state (keeps this
	// parallel test hermetic; t.Setenv is unavailable under t.Parallel).
	opts.PipelockConfig = filepath.Join(tmp, "pipelock.yaml")
	seed := "mcp_servers:\n" +
		"  github:\n" +
		"    command: npx\n" +
		"    args: [\"-y\", \"server-github\"]\n" +
		"    env:\n" +
		"      TOKEN: secret\n"
	if err := os.WriteFile(opts.HermesConfig, []byte(seed), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	cmd := installCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := runInstall(cmd, opts); err != nil {
		t.Fatalf("mcp-only install: %v", err)
	}

	cfg, err := loadHermesConfig(opts.HermesConfig)
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	gh, ok := cfg.mcpServers()["github"].(map[string]interface{})
	if !ok {
		t.Fatalf("github server missing or wrong type: %T", cfg.mcpServers()["github"])
	}
	if !mcpwrap.IsWrapped(gh) {
		t.Fatal("github server not wrapped (no _pipelock metadata)")
	}
	// Hermes omits the type field; the wrapped (still type-less) entry must not
	// gain one, since Hermes infers stdio from the command key.
	if _, hasType := gh["type"]; hasType {
		t.Errorf("wrapped type-less entry gained a type field: %v", gh["type"])
	}
	joined := strings.Join(mcpwrap.InterfaceSliceToStrings(gh["args"]), " ")
	for _, want := range []string{"mcp proxy", "--env TOKEN", "-- npx -y server-github"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("wrapped args %q missing %q", joined, want)
		}
	}

	// Idempotent: a second run wraps nothing new.
	out.Reset()
	cmd2 := installCmd()
	cmd2.SetOut(&out)
	if err := runInstall(cmd2, opts); err != nil {
		t.Fatalf("second mcp-only install: %v", err)
	}
	if !strings.Contains(out.String(), "already wrapped") {
		t.Fatalf("re-run not idempotent: %q", out.String())
	}
}

func TestRunInstall_RejectsBadMode(t *testing.T) {
	t.Parallel()

	cmd := installCmd()
	cmd.SetOut(&bytes.Buffer{})

	err := runInstall(cmd, &installOptions{Mode: "garbage", PluginRoot: t.TempDir()})
	if err == nil {
		t.Fatal("runInstall accepted invalid mode")
	}
	if !strings.Contains(err.Error(), "garbage") {
		t.Fatalf("error message does not include offending mode: %v", err)
	}
}

func TestRunInstall_UsesHomeDirOverride(t *testing.T) {
	t.Parallel()

	tmpHome := t.TempDir()
	opts := &installOptions{Mode: ModeFull, HomeDir: tmpHome}

	cmd := installCmd()
	cmd.SetOut(&bytes.Buffer{})

	if err := runInstall(cmd, opts); err != nil {
		t.Fatalf("runInstall: %v", err)
	}

	if _, err := os.Stat(filepath.Join(tmpHome, DefaultPluginSubpath, "plugin.py")); err != nil {
		t.Fatalf("plugin.py missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmpHome, DefaultHermesConfigSubpath)); err != nil {
		t.Fatalf("config.yaml missing under home: %v", err)
	}
}

func TestRunInstall_IdempotentReruns(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	opts := fullOpts(tmp)

	cmd := installCmd()
	cmd.SetOut(&bytes.Buffer{})
	if err := runInstall(cmd, opts); err != nil {
		t.Fatalf("first install: %v", err)
	}

	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := runInstall(cmd, opts); err != nil {
		t.Fatalf("second install: %v", err)
	}
	if !strings.Contains(out.String(), "already present") {
		t.Fatalf("rerun did not report env names already present: %q", out.String())
	}

	// No duplicate proxy names after the rerun.
	cfg, err := loadHermesConfig(opts.HermesConfig)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := len(cfg.terminalEnvPresent()); got != len(proxyEnvNames) {
		t.Fatalf("env_passthrough drifted to %d proxy names after rerun, want %d", got, len(proxyEnvNames))
	}
	matches, err := filepath.Glob(opts.HermesConfig + ".bak.*")
	if err != nil {
		t.Fatalf("glob backups: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("no-op rerun should not rotate config backups, got %v", matches)
	}
}

func TestRunInstall_PropagatesInstallError(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	conflict := filepath.Join(tmp, "blocker")
	if err := os.WriteFile(conflict, []byte("x"), pluginFilePerm); err != nil {
		t.Fatalf("seed conflict file: %v", err)
	}
	opts := &installOptions{
		Mode:         ModeFull,
		PluginRoot:   filepath.Join(conflict, "child"),
		HermesConfig: filepath.Join(tmp, "config.yaml"),
	}

	cmd := installCmd()
	cmd.SetOut(&bytes.Buffer{})
	if err := runInstall(cmd, opts); err == nil {
		t.Fatal("runInstall did not surface Install failure")
	}
}

func TestInstallCmd_ExecuteWiresRunE(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	cmd := installCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--plugin-root", filepath.Join(tmp, "plugins", "pipelock"),
		"--hermes-config", filepath.Join(tmp, "config.yaml"),
		"--mode", ModeFull,
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("installCmd execute: %v", err)
	}
	if !strings.Contains(out.String(), "hermes plugin installed") {
		t.Fatalf("installCmd output missing success line: %q", out.String())
	}
}

func TestRunInstall_PropagatesUserHomeDirError(t *testing.T) {
	// No t.Parallel(): reassigns the package-level userHomeDir seam.
	prev := userHomeDir
	userHomeDir = func() (string, error) { return "", errors.New("no home for you") }
	t.Cleanup(func() { userHomeDir = prev })

	cmd := installCmd()
	cmd.SetOut(&bytes.Buffer{})

	err := runInstall(cmd, &installOptions{Mode: ModeFull})
	if err == nil {
		t.Fatal("runInstall did not surface UserHomeDir failure")
	}
	if !strings.Contains(err.Error(), "no home for you") {
		t.Fatalf("error %q does not propagate UserHomeDir failure", err.Error())
	}
}
