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
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testCARegeneratedOutput = "regenerated"
	testCAInitDeniedOutput  = "denied"
	testCAInitializedOutput = "initialized"
	testCAMissingOutput     = "missing"
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

func plantManagedTLSCA(t *testing.T, env *installEnv) (certPath, keyPath string) {
	t.Helper()
	certPath = filepath.Join(env.configDir, "tls", "ca.pem")
	keyPath = filepath.Join(env.configDir, "tls", "ca-key.pem")
	if err := os.MkdirAll(filepath.Dir(certPath), 0o750); err != nil {
		t.Fatalf("mkdir tls: %v", err)
	}
	if err := os.WriteFile(certPath, []byte(testPEMCA(t)), 0o600); err != nil {
		t.Fatalf("write managed cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("test private key"), 0o600); err != nil {
		t.Fatalf("write managed key: %v", err)
	}
	return certPath, keyPath
}

func plantSystemBundle(t *testing.T) string {
	t.Helper()
	systemBundle := filepath.Join(t.TempDir(), "system.pem")
	if err := os.WriteFile(systemBundle, []byte("SYS\n"), 0o600); err != nil {
		t.Fatalf("write system bundle: %v", err)
	}
	return systemBundle
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

func TestRunCARefresh_RegenerateOnSnapshotRestore(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	certPath, keyPath := plantManagedTLSCA(t, env)
	var warn bytes.Buffer
	env.errOut = &warn
	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		runner.mu.Lock()
		runner.calls = append(runner.calls, fakeCall{name: name, args: append([]string(nil), args...)})
		runner.mu.Unlock()
		if name == testSudoCmd && containsArg(args, "init") && containsArg(args, "--force") {
			return testCARegeneratedOutput, 0, nil
		}
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
	err := runCARefresh(context.Background(), env, caRefreshOpts{
		regenerateOnSnapshotRestore: true,
		systemBundle:                systemBundle,
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("calls: got %d want 2: %v", len(runner.calls), runner.calls)
	}
	if !containsArg(runner.calls[0].args, "init") || !containsArg(runner.calls[0].args, "--force") {
		t.Fatalf("first call should force-regenerate CA: %v", runner.calls[0])
	}
	if !containsArg(runner.calls[1].args, "show-ca") {
		t.Fatalf("second call should export CA: %v", runner.calls[1])
	}
	got, err := os.ReadFile(env.caBundlePath)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	if !strings.Contains(string(got), "SYS") || !strings.Contains(string(got), "BEGIN CERTIFICATE") {
		t.Errorf("bundle: %q", got)
	}
	if !strings.Contains(warn.String(), "SSL_CERT_FILE") || !strings.Contains(warn.String(), "Kubernetes sidecars") {
		t.Errorf("warning: %q", warn.String())
	}
	for _, path := range []string{certPath, keyPath} {
		matches, err := filepath.Glob(path + ".prerotate.*")
		if err != nil {
			t.Fatalf("glob backups: %v", err)
		}
		if len(matches) != 1 {
			t.Fatalf("backups for %s: got %d want 1 (%v)", path, len(matches), matches)
		}
		info, err := os.Stat(matches[0])
		if err != nil {
			t.Fatalf("stat backup %s: %v", matches[0], err)
		}
		wantMode := modeCAReadable
		if path == keyPath {
			wantMode = modePinSecret
		}
		if got := info.Mode().Perm(); got != wantMode {
			t.Fatalf("backup mode for %s = %s, want %s", path, got, wantMode)
		}
	}
	marker, err := os.ReadFile(snapshotRefreshMarkerPath(env))
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	if _, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(marker))); err != nil {
		t.Fatalf("marker timestamp: %q: %v", marker, err)
	}
}

func TestRunCARefresh_UsesContainManagedTLSCA(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	managedCert, _ := plantManagedTLSCA(t, env)
	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		runner.mu.Lock()
		runner.calls = append(runner.calls, fakeCall{name: name, args: append([]string(nil), args...)})
		runner.mu.Unlock()
		if name == testSudoCmd && containsArg(args, "init") && containsArg(args, "--force") {
			return testCARegeneratedOutput, 0, nil
		}
		if name == testSudoCmd && containsArg(args, "show-ca") && containsArg(args, "--cert") && containsArg(args, managedCert) {
			return testPEMCA(t), 0, nil
		}
		return "", 0, nil
	}
	systemBundle := filepath.Join(t.TempDir(), "system.pem")
	if err := os.WriteFile(systemBundle, []byte("SYS\n"), 0o600); err != nil {
		t.Fatalf("plant system: %v", err)
	}
	if err := runCARefresh(context.Background(), env, caRefreshOpts{
		regenerateOnSnapshotRestore: true,
		systemBundle:                systemBundle,
	}); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("calls: got %d want 2: %v", len(runner.calls), runner.calls)
	}
	if !containsArg(runner.calls[0].args, "--out") || !containsArg(runner.calls[0].args, filepath.Dir(managedCert)) {
		t.Fatalf("regenerate should target managed TLS dir: %v", runner.calls[0])
	}
	if !containsArg(runner.calls[1].args, "--cert") || !containsArg(runner.calls[1].args, managedCert) {
		t.Fatalf("show-ca should read managed cert: %v", runner.calls[1])
	}
}

func TestRunCARefresh_RegenerateOnSnapshotRestoreRequiresContainTLSMaterial(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	systemBundle := filepath.Join(t.TempDir(), "system.pem")
	if err := os.WriteFile(systemBundle, []byte("SYS\n"), 0o600); err != nil {
		t.Fatalf("plant system: %v", err)
	}
	err := runCARefresh(context.Background(), env, caRefreshOpts{
		regenerateOnSnapshotRestore: true,
		systemBundle:                systemBundle,
	})
	if err == nil {
		t.Fatal("expected missing contain TLS material error")
	}
	if !strings.Contains(err.Error(), "contain-managed TLS CA certificate") {
		t.Fatalf("err: %v", err)
	}
}

func TestRunCARefresh_RegenerateOnSnapshotRestoreRefusesImmediateRepeat(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	plantManagedTLSCA(t, env)
	if err := writeSnapshotRefreshMarker(env, time.Now().UTC()); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	systemBundle := filepath.Join(t.TempDir(), "system.pem")
	if err := os.WriteFile(systemBundle, []byte("SYS\n"), 0o600); err != nil {
		t.Fatalf("plant system: %v", err)
	}
	err := runCARefresh(context.Background(), env, caRefreshOpts{
		regenerateOnSnapshotRestore: true,
		systemBundle:                systemBundle,
	})
	if err == nil {
		t.Fatal("expected repeat guard error")
	}
	if !strings.Contains(err.Error(), "use --force") {
		t.Fatalf("err: %v", err)
	}
}

func TestRunCARefresh_RegenerateOnSnapshotRestoreForceAllowsImmediateRepeat(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	plantManagedTLSCA(t, env)
	var warn bytes.Buffer
	env.errOut = &warn
	if err := writeSnapshotRefreshMarker(env, time.Now().UTC()); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		runner.mu.Lock()
		runner.calls = append(runner.calls, fakeCall{name: name, args: append([]string(nil), args...)})
		runner.mu.Unlock()
		if name == testSudoCmd && containsArg(args, "init") && containsArg(args, "--force") {
			return testCARegeneratedOutput, 0, nil
		}
		if name == testSudoCmd && containsArg(args, "show-ca") {
			return testPEMCA(t), 0, nil
		}
		return "", 0, nil
	}
	systemBundle := filepath.Join(t.TempDir(), "system.pem")
	if err := os.WriteFile(systemBundle, []byte("SYS\n"), 0o600); err != nil {
		t.Fatalf("plant system: %v", err)
	}
	if err := runCARefresh(context.Background(), env, caRefreshOpts{
		force:                       true,
		regenerateOnSnapshotRestore: true,
		systemBundle:                systemBundle,
	}); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("calls: got %d want 2: %v", len(runner.calls), runner.calls)
	}
	if !strings.Contains(warn.String(), "WARN: --force bypassed the snapshot CA repeat guard") {
		t.Fatalf("force warning: %q", warn.String())
	}
}

func TestRunCARefresh_ReportsMutationFailures(t *testing.T) {
	t.Run("regenerate", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		plantManagedTLSCA(t, env)
		env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
			if name == testSudoCmd && containsArg(args, "init") && containsArg(args, "--force") {
				return testCAInitDeniedOutput, 9, nil
			}
			return "", 0, nil
		}
		err := runCARefresh(context.Background(), env, caRefreshOpts{
			regenerateOnSnapshotRestore: true,
			systemBundle:                plantSystemBundle(t),
		})
		if err == nil || !strings.Contains(err.Error(), "tls init --force exited 9") {
			t.Fatalf("regenerate err: %v", err)
		}
	})

	t.Run("marker", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		plantManagedTLSCA(t, env)
		origWriteFile := env.writeFile
		env.writeFile = func(path string, contents []byte, mode os.FileMode) error {
			if path == snapshotRefreshMarkerPath(env) {
				return stringError("marker denied")
			}
			return origWriteFile(path, contents, mode)
		}
		env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
			if name == testSudoCmd && containsArg(args, "init") && containsArg(args, "--force") {
				return testCARegeneratedOutput, 0, nil
			}
			return "", 0, nil
		}
		err := runCARefresh(context.Background(), env, caRefreshOpts{
			regenerateOnSnapshotRestore: true,
			systemBundle:                plantSystemBundle(t),
		})
		if err == nil || !strings.Contains(err.Error(), "marker denied") {
			t.Fatalf("marker err: %v", err)
		}
	})

	t.Run("export", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.runCmd = func(_ context.Context, _ string, _ ...string) (string, int, error) {
			return "show failed", -1, stringError("sudo unavailable")
		}
		err := runCARefresh(context.Background(), env, caRefreshOpts{systemBundle: plantSystemBundle(t)})
		if err == nil || !strings.Contains(err.Error(), "sudo unavailable") {
			t.Fatalf("export err: %v", err)
		}
	})

	t.Run("rebuild", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
			if name == testSudoCmd && containsArg(args, "show-ca") {
				return testPEMCA(t), 0, nil
			}
			return "", 0, nil
		}
		origReadFile := env.readFile
		env.readFile = func(path string) ([]byte, error) {
			if path == env.caExportPath {
				return nil, stringError("export vanished")
			}
			return origReadFile(path)
		}
		err := runCARefresh(context.Background(), env, caRefreshOpts{systemBundle: plantSystemBundle(t)})
		if err == nil || !strings.Contains(err.Error(), "export vanished") {
			t.Fatalf("rebuild err: %v", err)
		}
	})
}

func TestRegeneratePipelockCAReportsFailure(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	plantManagedTLSCA(t, env)
	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name == testSudoCmd && containsArg(args, "init") && containsArg(args, "--force") {
			return testCAInitDeniedOutput, 7, nil
		}
		return "", 0, nil
	}
	err := regeneratePipelockCA(context.Background(), env, time.Now().UTC())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "tls init --force exited 7") {
		t.Fatalf("err: %v", err)
	}
}

func TestRegeneratePipelockCAReportsExecError(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	plantManagedTLSCA(t, env)
	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name == testSudoCmd && containsArg(args, "init") && containsArg(args, "--force") {
			return "sudo unavailable", -1, stringError("exec denied")
		}
		return "", 0, nil
	}
	err := regeneratePipelockCA(context.Background(), env, time.Now().UTC())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "exec denied") {
		t.Fatalf("err: %v", err)
	}
}

func TestValidateSnapshotRegenerationPreconditionsEdges(t *testing.T) {
	t.Run("symlink certificate", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		certPath, keyPath := plantManagedTLSCA(t, env)
		if err := os.Remove(certPath); err != nil {
			t.Fatalf("remove cert: %v", err)
		}
		if err := os.Symlink(keyPath, certPath); err != nil {
			t.Fatalf("symlink cert: %v", err)
		}
		err := validateSnapshotRegenerationPreconditions(env, caRefreshOpts{}, time.Now().UTC())
		if err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("symlink err: %v", err)
		}
	})

	t.Run("directory private key", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		_, keyPath := plantManagedTLSCA(t, env)
		if err := os.Remove(keyPath); err != nil {
			t.Fatalf("remove key: %v", err)
		}
		if err := os.Mkdir(keyPath, 0o700); err != nil {
			t.Fatalf("mkdir key path: %v", err)
		}
		err := validateSnapshotRegenerationPreconditions(env, caRefreshOpts{}, time.Now().UTC())
		if err == nil || !strings.Contains(err.Error(), "directory") {
			t.Fatalf("directory err: %v", err)
		}
	})

	t.Run("invalid marker", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		plantManagedTLSCA(t, env)
		if err := os.MkdirAll(filepath.Dir(snapshotRefreshMarkerPath(env)), 0o750); err != nil {
			t.Fatalf("mkdir marker dir: %v", err)
		}
		if err := os.WriteFile(snapshotRefreshMarkerPath(env), []byte("not-a-time"), 0o600); err != nil {
			t.Fatalf("write marker: %v", err)
		}
		err := validateSnapshotRegenerationPreconditions(env, caRefreshOpts{}, time.Now().UTC())
		if err == nil || !strings.Contains(err.Error(), "parse snapshot CA regeneration marker") {
			t.Fatalf("parse err: %v", err)
		}
	})

	t.Run("old marker allowed", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		plantManagedTLSCA(t, env)
		now := time.Now().UTC()
		if err := writeSnapshotRefreshMarker(env, now.Add(-snapshotCARepeatGuard-time.Second)); err != nil {
			t.Fatalf("write marker: %v", err)
		}
		if err := validateSnapshotRegenerationPreconditions(env, caRefreshOpts{}, now); err != nil {
			t.Fatalf("old marker should pass: %v", err)
		}
	})
}

func TestWriteSnapshotWarningsHandleNilWriters(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.out = nil
	env.errOut = nil
	writeSnapshotCAWarning(env)
	writeSnapshotForceWarning(env, time.Now().UTC())
}

func TestBackupSnapshotCAFileEdges(t *testing.T) {
	t.Run("read failure", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		err := backupSnapshotCAFile(env, filepath.Join(env.configDir, "tls", "missing.pem"), modeCAReadable, time.Now().UTC())
		if err == nil || !strings.Contains(err.Error(), "read CA material") {
			t.Fatalf("read err: %v", err)
		}
	})

	t.Run("existing backup", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		certPath, _ := plantManagedTLSCA(t, env)
		now := time.Date(2026, 5, 16, 18, 0, 0, 0, time.UTC)
		backup := fmt.Sprintf("%s.prerotate.%s", certPath, now.Format("20060102T150405.000000000Z"))
		if err := os.WriteFile(backup, []byte("old backup"), 0o600); err != nil {
			t.Fatalf("write backup: %v", err)
		}
		err := backupSnapshotCAFile(env, certPath, modeCAReadable, now)
		if err == nil || !strings.Contains(err.Error(), "refusing to overwrite existing CA backup") {
			t.Fatalf("existing backup err: %v", err)
		}
	})

	t.Run("write failure", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		certPath, _ := plantManagedTLSCA(t, env)
		env.writeFile = func(string, []byte, os.FileMode) error {
			return stringError("write denied")
		}
		err := backupSnapshotCAFile(env, certPath, modeCAReadable, time.Now().UTC())
		if err == nil || !strings.Contains(err.Error(), "write denied") {
			t.Fatalf("write err: %v", err)
		}
	})
}

func TestWriteSnapshotRefreshMarkerReportsHookErrors(t *testing.T) {
	t.Run("mkdir", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.mkdirAll = func(string, os.FileMode) error {
			return stringError("mkdir denied")
		}
		err := writeSnapshotRefreshMarker(env, time.Now().UTC())
		if err == nil || !strings.Contains(err.Error(), "mkdir denied") {
			t.Fatalf("mkdir err: %v", err)
		}
	})

	t.Run("chmod", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.chmod = func(string, os.FileMode) error {
			return stringError("chmod denied")
		}
		err := writeSnapshotRefreshMarker(env, time.Now().UTC())
		if err == nil || !strings.Contains(err.Error(), "chmod denied") {
			t.Fatalf("chmod err: %v", err)
		}
	})

	t.Run("write", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.writeFile = func(string, []byte, os.FileMode) error {
			return stringError("write denied")
		}
		err := writeSnapshotRefreshMarker(env, time.Now().UTC())
		if err == nil || !strings.Contains(err.Error(), "write denied") {
			t.Fatalf("write err: %v", err)
		}
	})
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
			return testCAInitializedOutput, 0, nil
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

func TestExportPipelockCAInitializesManagedCAMaterial(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	managedCert, _ := plantManagedTLSCA(t, env)
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
			return testCAInitializedOutput, 0, nil
		}
		return "", 0, nil
	}
	if err := exportPipelockCA(context.Background(), env); err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("calls: got %d want 3: %v", len(runner.calls), runner.calls)
	}
	if !containsArg(runner.calls[1].args, "--out") || !containsArg(runner.calls[1].args, filepath.Dir(managedCert)) {
		t.Fatalf("managed init should target managed TLS dir: %v", runner.calls[1])
	}
}

func TestExportPipelockCAReportsRetryFailures(t *testing.T) {
	t.Run("init exec", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
			if name == testSudoCmd && containsArg(args, "show-ca") {
				return testCAMissingOutput, 1, nil
			}
			if name == testSudoCmd && containsArg(args, "init") {
				return testCAInitDeniedOutput, -1, stringError("exec denied")
			}
			return "", 0, nil
		}
		err := exportPipelockCA(context.Background(), env)
		if err == nil || !strings.Contains(err.Error(), "exec denied") {
			t.Fatalf("init exec err: %v", err)
		}
	})

	t.Run("init exit", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
			if name == testSudoCmd && containsArg(args, "show-ca") {
				return testCAMissingOutput, 1, nil
			}
			if name == testSudoCmd && containsArg(args, "init") {
				return testCAInitDeniedOutput, 5, nil
			}
			return "", 0, nil
		}
		err := exportPipelockCA(context.Background(), env)
		if err == nil || !strings.Contains(err.Error(), "tls init exited 5") {
			t.Fatalf("init exit err: %v", err)
		}
	})

	t.Run("retry exec", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		var showCalls int
		env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
			if name == testSudoCmd && containsArg(args, "show-ca") {
				showCalls++
				if showCalls == 1 {
					return testCAMissingOutput, 1, nil
				}
				return "boom", -1, stringError("retry denied")
			}
			if name == testSudoCmd && containsArg(args, "init") {
				return testCAInitializedOutput, 0, nil
			}
			return "", 0, nil
		}
		err := exportPipelockCA(context.Background(), env)
		if err == nil || !strings.Contains(err.Error(), "retry denied") {
			t.Fatalf("retry exec err: %v", err)
		}
	})

	t.Run("retry exit", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		var showCalls int
		env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
			if name == testSudoCmd && containsArg(args, "show-ca") {
				showCalls++
				if showCalls == 1 {
					return testCAMissingOutput, 1, nil
				}
				return "still missing", 2, nil
			}
			if name == testSudoCmd && containsArg(args, "init") {
				return testCAInitializedOutput, 0, nil
			}
			return "", 0, nil
		}
		err := exportPipelockCA(context.Background(), env)
		if err == nil || !strings.Contains(err.Error(), "show-ca after init exited 2") {
			t.Fatalf("retry exit err: %v", err)
		}
	})
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
	_, _, err := runShowCA(context.Background(), env, "")
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

func TestRunCARefresh_DryRunShowsSnapshotRegeneration(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	plantManagedTLSCA(t, env)
	systemBundle := filepath.Join(t.TempDir(), "system.pem")
	if err := os.WriteFile(systemBundle, []byte("SYS"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	var buf bytes.Buffer
	env.out = &buf
	env.errOut = &buf
	opts := caRefreshOpts{
		dryRun:                      true,
		regenerateOnSnapshotRestore: true,
		systemBundle:                systemBundle,
	}
	if err := runCARefresh(context.Background(), env, opts); err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "regenerate contain-managed CA") || !strings.Contains(out, "snapshot restore") || !strings.Contains(out, "SSL_CERT_FILE") {
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

func TestRunCARefresh_ResolvesSystemBundleSymlink(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	target := filepath.Join(t.TempDir(), "system.pem")
	if err := os.WriteFile(target, []byte("SYS"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(t.TempDir(), "system-link.pem")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	var buf bytes.Buffer
	env.out = &buf
	if err := runCARefresh(context.Background(), env, caRefreshOpts{dryRun: true, systemBundle: link}); err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if !strings.Contains(buf.String(), "planned") {
		t.Fatalf("dry-run output: %q", buf.String())
	}
}

func TestResolveSystemBundlePathEdges(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if got, err := resolveSystemBundlePath(env, "relative.pem"); err != nil || got != "relative.pem" {
		t.Fatalf("relative: got %q err %v", got, err)
	}
	missing := filepath.Join(t.TempDir(), "missing.pem")
	if got, err := resolveSystemBundlePath(env, missing); err != nil || got != missing {
		t.Fatalf("missing: got %q err %v", got, err)
	}
	link := filepath.Join(t.TempDir(), "broken-link.pem")
	if err := os.Symlink(filepath.Join(t.TempDir(), "missing-target.pem"), link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := resolveSystemBundlePath(env, link); err == nil || !strings.Contains(err.Error(), "resolve --system-bundle") {
		t.Fatalf("broken symlink err: %v", err)
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

func TestValidateCARefreshPathsRejectsMoreUnsafeInputs(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	missing := filepath.Join(t.TempDir(), "missing.pem")
	if err := validateCARefreshPaths(env, missing); err == nil || !strings.Contains(err.Error(), "--system-bundle") {
		t.Fatalf("missing bundle err: %v", err)
	}
	dir := t.TempDir()
	if err := validateCARefreshPaths(env, dir); err == nil || !strings.Contains(err.Error(), "directory") {
		t.Fatalf("directory bundle err: %v", err)
	}
	systemBundle := plantSystemBundle(t)
	env.caExportPath = "relative-ca.pem"
	if err := validateCARefreshPaths(env, systemBundle); err == nil || !strings.Contains(err.Error(), "must be absolute") {
		t.Fatalf("relative output err: %v", err)
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
	for _, f := range []string{"dry-run", "force", "regenerate-on-snapshot-restore", "ca-output", "bundle-output", "system-bundle"} {
		if cmd.Flag(f) == nil {
			t.Errorf("missing flag %s", f)
		}
	}
}
