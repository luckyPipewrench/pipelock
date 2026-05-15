// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testPEMCA is a minimal PEM-shaped string for stubbing pipelock tls
// show-ca output. Tests don't validate the certificate, only that the
// pipeline accepts a PEM and rejects non-PEM.
const testPEMCA = "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKvHM6vHM6vHMA0GCSqGSIb3DQEBCwUAMA0xCzAJBgNVBAYTAlVT\n-----END CERTIFICATE-----\n"

func TestRunCARefresh_FullSuccessPath(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	// show-ca emits PEM to stdout. Go captures it and writes
	// env.caExportPath; the fake just supplies the bytes.
	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name == testSudoCmd && containsArg(args, "show-ca") {
			return testPEMCA, 0, nil
		}
		return "", 0, nil
	}
	if err := os.MkdirAll(filepath.Dir(env.caExportPath), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	systemBundle := filepath.Join(t.TempDir(), "system.pem")
	if err := os.WriteFile(systemBundle, []byte("SYS\n"), 0o600); err != nil {
		t.Fatalf("plant system: %v", err)
	}
	err := runCARefresh(context.Background(), env, caRefreshOpts{systemBundle: systemBundle})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	got, _ := os.ReadFile(env.caBundlePath) //nolint:gosec // tmpdir-scoped test path
	if !strings.Contains(string(got), "BEGIN CERTIFICATE") || !strings.Contains(string(got), "SYS") {
		t.Errorf("bundle: %q", got)
	}
}

func TestRebuildCombinedBundle_ConcatenatesSourceAndPipelock(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	system := filepath.Join(t.TempDir(), "system.pem")
	if err := os.WriteFile(system, []byte("SYSTEM_BUNDLE_DATA"), 0o600); err != nil {
		t.Fatalf("write system: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(env.caExportPath), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(env.caExportPath, []byte("PIPELOCK_CA_DATA\n"), 0o600); err != nil {
		t.Fatalf("write pipelock ca: %v", err)
	}
	if err := rebuildCombinedBundle(env, system); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	got, err := os.ReadFile(env.caBundlePath)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	// The system bundle has no trailing newline; we inject one before
	// appending the pipelock CA.
	want := "SYSTEM_BUNDLE_DATA\nPIPELOCK_CA_DATA\n"
	if string(got) != want {
		t.Errorf("bundle: got %q, want %q", got, want)
	}
}

func TestRebuildCombinedBundle_HonorsExistingTrailingNewline(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	system := filepath.Join(t.TempDir(), "system.pem")
	if err := os.WriteFile(system, []byte("SYSTEM\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(env.caExportPath), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(env.caExportPath, []byte("PIPELOCK\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := rebuildCombinedBundle(env, system); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	got, _ := os.ReadFile(env.caBundlePath)
	// Don't add a SECOND newline when source already ends with one.
	if string(got) != "SYSTEM\nPIPELOCK\n" {
		t.Errorf("bundle: %q", got)
	}
}

func TestExportPipelockCA_RemovesStaleBeforeExport(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	// Stub show-ca: return a PEM on stdout. exportPipelockCA captures it
	// and writes env.caExportPath.
	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		runner.mu.Lock()
		runner.calls = append(runner.calls, fakeCall{name: name, args: append([]string(nil), args...)})
		runner.mu.Unlock()
		if name == testSudoCmd && containsArg(args, "show-ca") {
			return testPEMCA, 0, nil
		}
		return "", 0, nil
	}
	// Plant a stale export with content distinct from testPEMCA.
	if err := os.MkdirAll(filepath.Dir(env.caExportPath), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(env.caExportPath, []byte("OLD STALE CONTENT"), 0o600); err != nil {
		t.Fatalf("write old: %v", err)
	}
	if err := exportPipelockCA(context.Background(), env); err != nil {
		t.Fatalf("export: %v", err)
	}
	// After: file must exist with the new PEM, not the stale bytes.
	got, err := os.ReadFile(env.caExportPath) //nolint:gosec // tmpdir-scoped test path
	if err != nil {
		t.Fatalf("read after export: %v", err)
	}
	if string(got) != testPEMCA {
		t.Errorf("export wrote wrong content: %q", got)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("expected 1 shell-out, got %v", runner.calls)
	}
	call := runner.calls[0]
	if call.name != testSudoCmd {
		t.Errorf("expected sudo, got %s", call.name)
	}
	if !containsArg(call.args, env.proxyUserName) {
		t.Errorf("sudo args missing proxy user: %v", call.args)
	}
	if !containsArg(call.args, "tls") || !containsArg(call.args, "show-ca") {
		t.Errorf("sudo args missing tls show-ca: %v", call.args)
	}
}

func TestRunCARefresh_DryRunIsNonMutating(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	systemBundle := filepath.Join(t.TempDir(), "system.pem")
	if err := os.WriteFile(systemBundle, []byte("SYS"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	var buf bytes.Buffer
	env.out = &buf
	opts := caRefreshOpts{dryRun: true, systemBundle: systemBundle}
	if err := runCARefresh(context.Background(), env, opts); err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "ca-refresh") || !strings.Contains(out, "planned") {
		t.Errorf("dry-run output: %q", out)
	}
}

func TestCARefreshCmd_Wiring(t *testing.T) {
	cmd := caRefreshCmd()
	if cmd.Use != "ca-refresh" {
		t.Errorf("Use: %q", cmd.Use)
	}
	for _, f := range []string{"dry-run", "ca-output", "bundle-output", "system-bundle"} {
		if cmd.Flag(f) == nil {
			t.Errorf("missing flag %s", f)
		}
	}
}
