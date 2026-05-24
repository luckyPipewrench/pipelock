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
	mode := cmd.Flags().Lookup("mode")
	if mode == nil {
		t.Fatal("missing --mode flag")
	}
	if mode.DefValue != ModeFull {
		t.Fatalf("--mode default = %q, want %q", mode.DefValue, ModeFull)
	}
	if cmd.Flags().Lookup("plugin-root") == nil {
		t.Fatal("missing --plugin-root flag")
	}
}

func TestCmd_RegistersInstallSubcommand(t *testing.T) {
	t.Parallel()

	parent := Cmd()
	var found bool
	for _, sub := range parent.Commands() {
		if sub.Name() == "install" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("Cmd() did not register install subcommand")
	}
}

func TestRunInstall_FullModeWritesPlugin(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	opts := &installOptions{Mode: ModeFull, PluginRoot: filepath.Join(tmp, "plugin")}

	cmd := installCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)

	if err := runInstall(cmd, opts); err != nil {
		t.Fatalf("runInstall: %v", err)
	}

	if !strings.Contains(out.String(), "hermes plugin installed") {
		t.Fatalf("output missing install message: %q", out.String())
	}
	if _, err := os.Stat(filepath.Join(tmp, "plugin", "plugin.py")); err != nil {
		t.Fatalf("plugin.py missing after install: %v", err)
	}
}

func TestRunInstall_MCPOnlyModePrintsDeferralNote(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	opts := &installOptions{Mode: ModeMCPOnly, PluginRoot: tmp}

	cmd := installCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)

	if err := runInstall(cmd, opts); err != nil {
		t.Fatalf("runInstall: %v", err)
	}
	if !strings.Contains(out.String(), "mcp-only") {
		t.Fatalf("expected deferral note for mcp-only, got %q", out.String())
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

	expected := filepath.Join(tmpHome, DefaultPluginSubpath, "plugin.py")
	if _, err := os.Stat(expected); err != nil {
		t.Fatalf("plugin.py at %s missing: %v", expected, err)
	}
}

func TestRunInstall_PrintsBackupPathsOnRerun(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	opts := &installOptions{Mode: ModeFull, PluginRoot: tmp}

	cmd := installCmd()
	cmd.SetOut(&bytes.Buffer{})
	if err := runInstall(cmd, opts); err != nil {
		t.Fatalf("runInstall first pass: %v", err)
	}

	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := runInstall(cmd, opts); err != nil {
		t.Fatalf("runInstall second pass: %v", err)
	}
	if !strings.Contains(out.String(), "rotated existing file") {
		t.Fatalf("rerun output missing rotation messages: %q", out.String())
	}
}

func TestRunInstall_PropagatesInstallError(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	// Make the install root a path under a regular file. MkdirAll will
	// fail at the inner Install call.
	conflict := filepath.Join(tmp, "blocker")
	if err := os.WriteFile(conflict, []byte("x"), pluginFilePerm); err != nil {
		t.Fatalf("seed conflict file: %v", err)
	}
	opts := &installOptions{Mode: ModeFull, PluginRoot: filepath.Join(conflict, "child")}

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
	cmd.SetArgs([]string{"--plugin-root", tmp, "--mode", ModeFull})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("installCmd execute: %v", err)
	}
	if !strings.Contains(out.String(), "hermes plugin installed") {
		t.Fatalf("installCmd output missing success line: %q", out.String())
	}
}

func TestRunInstall_PropagatesUserHomeDirError(t *testing.T) {
	// No t.Parallel(): this test reassigns the package-level userHomeDir
	// seam, which other tests read via runInstall. Running it serially
	// avoids a data race on the shared global.
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
