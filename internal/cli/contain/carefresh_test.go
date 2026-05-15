// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testPEMCA(t *testing.T) string {
	return testPEMCert(t, true)
}

func testPEMCert(t *testing.T, isCA bool) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Pipelock Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestRunCARefresh_FullSuccessPath(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	// show-ca emits PEM to stdout. Go captures it and writes
	// env.caExportPath; the fake just supplies the bytes.
	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name == testSudoCmd && containsArg(args, "show-ca") {
			return testPEMCA(t), 0, nil
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
			return testPEMCA(t), 0, nil
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
	if !strings.Contains(string(got), "BEGIN CERTIFICATE") {
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

func TestExportPipelockCAInitializesMissingCAThenRetries(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	var showCalls int
	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		runner.mu.Lock()
		runner.calls = append(runner.calls, fakeCall{name: name, args: append([]string(nil), args...)})
		runner.mu.Unlock()
		if name == testSudoCmd && containsArg(args, "show-ca") {
			showCalls++
			if showCalls == 1 {
				return "missing ca", 1, nil
			}
			return testPEMCA(t), 0, nil
		}
		if name == testSudoCmd && containsArg(args, "init") {
			return "initialized", 0, nil
		}
		return "", 0, nil
	}
	if err := os.MkdirAll(filepath.Dir(env.caExportPath), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := exportPipelockCA(context.Background(), env); err != nil {
		t.Fatalf("export: %v", err)
	}
	got, err := os.ReadFile(env.caExportPath)
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	if !strings.Contains(string(got), "BEGIN CERTIFICATE") {
		t.Fatalf("exported CA: %q", got)
	}
	if showCalls != 2 {
		t.Fatalf("show-ca calls: got %d want 2", showCalls)
	}
	var sawInit bool
	for _, c := range runner.calls {
		if containsArg(c.args, "init") {
			sawInit = true
		}
	}
	if !sawInit {
		t.Fatalf("tls init not called, calls=%v", runner.calls)
	}
}

func TestExportPipelockCARejectsNonPEMOutput(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name == testSudoCmd && containsArg(args, "show-ca") {
			return "not a certificate", 0, nil
		}
		return "", 0, nil
	}
	if err := os.MkdirAll(filepath.Dir(env.caExportPath), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	err := exportPipelockCA(context.Background(), env)
	if err == nil {
		t.Fatal("expected non-PEM rejection")
	}
	if !strings.Contains(err.Error(), "invalid CA PEM") {
		t.Fatalf("err: %v", err)
	}
}

func TestRunShowCAPropagatesExecError(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.runCmd = func(_ context.Context, _ string, _ ...string) (string, int, error) {
		return "boom", 0, stringError("sudo unavailable")
	}
	_, _, err := runShowCA(context.Background(), env)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "sudo unavailable") {
		t.Fatalf("err: %v", err)
	}
}

func TestRebuildCombinedBundleReportsMissingInputs(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	system := filepath.Join(t.TempDir(), "system.pem")
	if err := rebuildCombinedBundle(env, system); err == nil || !strings.Contains(err.Error(), "read system CA bundle") {
		t.Fatalf("missing system err: %v", err)
	}
	if err := os.WriteFile(system, []byte("SYSTEM\n"), 0o600); err != nil {
		t.Fatalf("write system: %v", err)
	}
	if err := rebuildCombinedBundle(env, system); err == nil || !strings.Contains(err.Error(), "read pipelock CA") {
		t.Fatalf("missing pipelock err: %v", err)
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

func TestRunCARefresh_DryRunValidatesPaths(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	systemBundle := filepath.Join(t.TempDir(), "system.pem")
	if err := os.WriteFile(systemBundle, []byte("system"), 0o600); err != nil {
		t.Fatalf("write system: %v", err)
	}
	env.caExportPath = filepath.Join(t.TempDir(), "outside-ca.pem")
	err := runCARefresh(context.Background(), env, caRefreshOpts{dryRun: true, systemBundle: systemBundle})
	if err == nil {
		t.Fatal("expected output path rejection")
	}
	if !strings.Contains(err.Error(), "must stay under") {
		t.Fatalf("err: %v", err)
	}
}

func TestValidateCARefreshPathsRejectsUnsafeInputs(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if err := validateCARefreshPaths(env, "relative.pem"); err == nil || !strings.Contains(err.Error(), "must be absolute") {
		t.Fatalf("relative bundle err: %v", err)
	}
	systemBundle := filepath.Join(t.TempDir(), "system.pem")
	if err := os.WriteFile(systemBundle, []byte("system"), 0o600); err != nil {
		t.Fatalf("write system: %v", err)
	}
	env.caBundlePath = filepath.Join(t.TempDir(), "combined-ca.pem")
	if err := validateCARefreshPaths(env, systemBundle); err == nil || !strings.Contains(err.Error(), "must stay under") {
		t.Fatalf("outside output err: %v", err)
	}
	env.caBundlePath = filepath.Join(env.configDir, "combined-ca.pem")
	link := filepath.Join(env.configDir, "ca-link.pem")
	if err := os.Symlink(filepath.Join(t.TempDir(), "target.pem"), link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	env.caExportPath = link
	if err := validateCARefreshPaths(env, systemBundle); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink output err: %v", err)
	}
	env.caExportPath = filepath.Join(env.configDir, "ca.pem")
	bundleLink := filepath.Join(t.TempDir(), "bundle-link.pem")
	if err := os.Symlink(systemBundle, bundleLink); err != nil {
		t.Fatalf("bundle symlink: %v", err)
	}
	if err := validateCARefreshPaths(env, bundleLink); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink bundle err: %v", err)
	}
}

func TestValidateSingleCAPEMRejectsExtraDataAndNonCA(t *testing.T) {
	if err := validateSingleCAPEM([]byte(testPEMCA(t) + "junk")); err == nil || !strings.Contains(err.Error(), "extra data") {
		t.Fatalf("extra data err: %v", err)
	}
	if err := validateSingleCAPEM([]byte(testPEMCert(t, false))); err == nil || !strings.Contains(err.Error(), "not a CA") {
		t.Fatalf("non-CA err: %v", err)
	}
	if err := validateSingleCAPEM([]byte("-----BEGIN PIPELOCK TEST BLOCK-----\nAA==\n-----END PIPELOCK TEST BLOCK-----\n")); err == nil || !strings.Contains(err.Error(), "unexpected PEM") {
		t.Fatalf("wrong block err: %v", err)
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
