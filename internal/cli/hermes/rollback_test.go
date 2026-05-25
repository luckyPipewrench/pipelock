// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package hermes

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// installForRollback runs a full install under tmp and returns the options.
func installForRollback(t *testing.T, tmp string) *installOptions {
	t.Helper()
	opts := fullOpts(tmp)
	cmd := installCmd()
	cmd.SetOut(&bytes.Buffer{})
	if err := runInstall(cmd, opts); err != nil {
		t.Fatalf("install: %v", err)
	}
	return opts
}

func TestRollback_SurgicalRemovesPipelockState(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	// Seed an operator key + entry that must survive rollback.
	cfgPath := filepath.Join(tmp, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("model: gpt-4\nterminal:\n  env_passthrough:\n    - GITHUB_TOKEN\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	iopts := fullOpts(tmp)
	icmd := installCmd()
	icmd.SetOut(&bytes.Buffer{})
	if err := runInstall(icmd, iopts); err != nil {
		t.Fatalf("install: %v", err)
	}

	cmd := rollbackCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	ropts := &rollbackOptions{PluginRoot: iopts.PluginRoot, HermesConfig: iopts.HermesConfig}
	if err := runRollback(cmd, ropts); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	cfg, err := loadHermesConfig(cfgPath)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if cfg.root["model"] != "gpt-4" {
		t.Fatal("rollback dropped operator's model key")
	}
	term := cfg.root[terminalKey].(map[string]interface{})
	got := toStringSet(term[envPassthroughKey])
	if !got["GITHUB_TOKEN"] {
		t.Fatal("rollback dropped operator's GITHUB_TOKEN")
	}
	if got["HTTPS_PROXY"] {
		t.Fatal("rollback left pipelock's HTTPS_PROXY")
	}
	if pluginInstalled(iopts.PluginRoot) {
		t.Fatal("rollback left the plugin directory")
	}
}

func TestRollback_KeepPlugin(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	iopts := installForRollback(t, tmp)

	cmd := rollbackCmd()
	cmd.SetOut(&bytes.Buffer{})
	ropts := &rollbackOptions{PluginRoot: iopts.PluginRoot, HermesConfig: iopts.HermesConfig, KeepPlugin: true}
	if err := runRollback(cmd, ropts); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if !pluginInstalled(iopts.PluginRoot) {
		t.Fatal("--keep-plugin removed the plugin directory")
	}
}

func TestRollback_NoStateIsClean(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	cmd := rollbackCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	ropts := &rollbackOptions{
		PluginRoot:   filepath.Join(tmp, "plugins", "pipelock"),
		HermesConfig: filepath.Join(tmp, "config.yaml"),
	}
	if err := runRollback(cmd, ropts); err != nil {
		t.Fatalf("rollback on clean state: %v", err)
	}
	if !strings.Contains(out.String(), "no pipelock proxy env names found") {
		t.Fatalf("clean rollback output unexpected: %q", out.String())
	}
}

func TestRollback_RestoreBackup(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "config.yaml")
	original := "model: original\n"
	if err := os.WriteFile(cfgPath, []byte(original), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	backupPath := filepath.Join(tmp, "config.yaml.bak.123")
	if err := os.WriteFile(backupPath, []byte("model: from-backup\n"), 0o600); err != nil {
		t.Fatalf("seed backup: %v", err)
	}

	cmd := rollbackCmd()
	cmd.SetOut(&bytes.Buffer{})
	ropts := &rollbackOptions{HermesConfig: cfgPath, RestoreBackup: backupPath}
	if err := runRollback(cmd, ropts); err != nil {
		t.Fatalf("restore: %v", err)
	}

	data, err := os.ReadFile(cfgPath) //nolint:gosec // under t.TempDir()
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if !strings.Contains(string(data), "from-backup") {
		t.Fatalf("restore did not apply backup content: %q", string(data))
	}
}

func TestRollback_RestoreBackupMissingFile(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	cmd := rollbackCmd()
	cmd.SetOut(&bytes.Buffer{})
	ropts := &rollbackOptions{
		HermesConfig:  filepath.Join(tmp, "config.yaml"),
		RestoreBackup: filepath.Join(tmp, "does-not-exist.bak"),
	}
	if err := runRollback(cmd, ropts); err == nil {
		t.Fatal("restore from missing backup did not error")
	}
}

func TestRollbackCmd_Flags(t *testing.T) {
	t.Parallel()

	cmd := rollbackCmd()
	for _, flag := range []string{"plugin-root", "hermes-config", "restore-backup", "keep-plugin"} {
		if cmd.Flags().Lookup(flag) == nil {
			t.Fatalf("missing --%s flag", flag)
		}
	}
}

func TestRemovePluginTreeRejectsUnsafeRoot(t *testing.T) {
	t.Parallel()

	for _, bad := range []string{"", "/", "."} {
		if err := removePluginTree(bad); err == nil {
			t.Fatalf("removePluginTree(%q) did not reject unsafe root", bad)
		}
	}
}
