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

func TestRunInstall_MCPOnlyFailsHonestly(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	opts := fullOpts(tmp)
	opts.Mode = ModeMCPOnly

	cmd := installCmd()
	cmd.SetOut(&bytes.Buffer{})

	err := runInstall(cmd, opts)
	if err == nil {
		t.Fatal("mcp-only install did not return an error")
	}
	if !strings.Contains(err.Error(), "not yet available") {
		t.Fatalf("error does not explain mcp-only deferral: %v", err)
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
