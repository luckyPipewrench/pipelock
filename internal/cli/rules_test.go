// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/rules"
)

// Test-scoped constants for repeated string literals.
const (
	testBundlePath    = "/test-bundle/bundle.yaml"
	testBundleSigPath = "/test-bundle/bundle.yaml.sig"
	testBundleName    = "test-bundle"
)

// validBundleYAML is minimal valid bundle YAML for testing.
const validBundleYAML = `format_version: 1
name: test-bundle
version: "2026.03.1"
author: Test Author
description: A test bundle
min_pipelock: "0.1.0"
license: Apache-2.0
rules:
  - id: test-rule-one
    type: dlp
    status: stable
    name: Test Rule
    description: Detects test patterns
    severity: high
    confidence: high
    pattern:
      regex: "test-secret-[a-z]+"
`

// secondVersionBundleYAML is a newer version of the test bundle.
const secondVersionBundleYAML = `format_version: 1
name: test-bundle
version: "2026.04.1"
author: Test Author
description: A test bundle
min_pipelock: "0.1.0"
license: Apache-2.0
rules:
  - id: test-rule-one
    type: dlp
    status: stable
    name: Test Rule
    description: Detects test patterns
    severity: high
    confidence: high
    pattern:
      regex: "test-secret-[a-z]+"
  - id: test-rule-two
    type: dlp
    status: stable
    name: Another Test Rule
    description: Detects more patterns
    severity: medium
    confidence: medium
    pattern:
      regex: "another-pattern-[0-9]+"
`

// setupUnsignedBundle creates a bundle directory with an unsigned bundle.yaml
// and bundle.lock.
func setupUnsignedBundle(t *testing.T, rulesDir, bundleName string, bundleData []byte) {
	t.Helper()

	bundleDir := filepath.Join(rulesDir, bundleName)
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatalf("creating bundle dir: %v", err)
	}

	bundlePath := filepath.Join(bundleDir, "bundle.yaml")
	if err := os.WriteFile(bundlePath, bundleData, 0o600); err != nil {
		t.Fatalf("writing bundle: %v", err)
	}

	hash := sha256.Sum256(bundleData)
	digest := hex.EncodeToString(hash[:])

	lf := &rules.LockFile{
		InstalledVersion: "2026.03.1",
		InstalledAt:      "2026-03-15T10:00:00Z",
		Source:           "local:/tmp/my-rules",
		LastCheck:        "2026-03-15T10:00:00Z",
		BundleSHA256:     digest,
		Unsigned:         true,
	}
	lockPath := filepath.Join(bundleDir, "bundle.lock")
	if err := rules.WriteLockFile(lockPath, lf); err != nil {
		t.Fatalf("writing lock file: %v", err)
	}
}

// Tests in this file that call rootCmd() are intentionally NOT parallel
// because rootCmd() writes to the package-level pipelockHome variable.
// Tests that mutate rules.KeyringHex or http.DefaultClient are also
// sequential to avoid data races.

// ---------- rules list tests ----------

func TestRulesList_Empty(t *testing.T) {
	rulesDir := t.TempDir()
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"rules", "list", "--rules-dir", rulesDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(buf.String(), "No bundles installed.") {
		t.Errorf("expected 'No bundles installed.', got %q", buf.String())
	}
}

func TestRulesList_NonExistentDir(t *testing.T) {
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"rules", "list", "--rules-dir", "/tmp/nonexistent-rules-dir-" + t.Name()})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(buf.String(), "No bundles installed.") {
		t.Errorf("expected 'No bundles installed.', got %q", buf.String())
	}
}

func TestRulesList_WithBundle(t *testing.T) {
	rulesDir := t.TempDir()
	setupUnsignedBundle(t, rulesDir, testBundleName, []byte(validBundleYAML))

	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"rules", "list", "--rules-dir", rulesDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, testBundleName) {
		t.Errorf("expected bundle name in output, got %q", output)
	}
	if !strings.Contains(output, "2026.03.1") {
		t.Errorf("expected version in output, got %q", output)
	}
	if !strings.Contains(output, "unsigned") {
		t.Errorf("expected 'unsigned' in output, got %q", output)
	}
}

func TestRulesList_JSON(t *testing.T) {
	rulesDir := t.TempDir()
	setupUnsignedBundle(t, rulesDir, testBundleName, []byte(validBundleYAML))

	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"rules", "list", "--rules-dir", rulesDir, "--json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var entries []bundleListEntry
	if err := json.Unmarshal([]byte(buf.String()), &entries); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	if entries[0].Name != testBundleName {
		t.Errorf("Name = %q, want %q", entries[0].Name, testBundleName)
	}
	if entries[0].Signed {
		t.Error("expected Signed = false for unsigned bundle")
	}
}

// ---------- rules install tests ----------

func TestRulesInstall_LocalUnsigned(t *testing.T) {
	rulesDir := t.TempDir()

	// Create a local bundle source directory.
	srcDir := filepath.Join(t.TempDir(), "my-rules")
	if err := os.MkdirAll(srcDir, 0o750); err != nil {
		t.Fatalf("creating source dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "bundle.yaml"), []byte(validBundleYAML), 0o600); err != nil {
		t.Fatalf("writing bundle: %v", err)
	}

	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"rules", "install", "--path", srcDir, "--allow-unsigned", "--rules-dir", rulesDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Installed test-bundle") {
		t.Errorf("expected install confirmation, got %q", output)
	}
	if !strings.Contains(output, "unsigned") {
		t.Errorf("expected 'unsigned' in output, got %q", output)
	}

	// Verify bundle.lock was written.
	lockPath := filepath.Join(rulesDir, testBundleName, "bundle.lock")
	lf, err := rules.ReadLockFile(lockPath)
	if err != nil {
		t.Fatalf("reading lock file: %v", err)
	}
	if !lf.Unsigned {
		t.Error("expected lock file to be unsigned")
	}
	if lf.InstalledVersion != "2026.03.1" {
		t.Errorf("InstalledVersion = %q, want %q", lf.InstalledVersion, "2026.03.1")
	}
}

func TestRulesInstall_LocalWithoutFlag(t *testing.T) {
	rulesDir := t.TempDir()
	srcDir := filepath.Join(t.TempDir(), "my-rules")
	if err := os.MkdirAll(srcDir, 0o750); err != nil {
		t.Fatalf("creating source dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "bundle.yaml"), []byte(validBundleYAML), 0o600); err != nil {
		t.Fatalf("writing bundle: %v", err)
	}

	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"rules", "install", "--path", srcDir, "--rules-dir", rulesDir})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for --path without --allow-unsigned")
	}
	if !strings.Contains(err.Error(), "allow-unsigned") {
		t.Errorf("error should mention --allow-unsigned, got: %v", err)
	}
}

func TestRulesInstall_PipelockPrefix_NonOfficial(t *testing.T) {
	rulesDir := t.TempDir()

	// Bundle YAML with pipelock- prefix.
	pipelockPrefixYAML := strings.Replace(validBundleYAML, "name: test-bundle", "name: pipelock-community", 1)

	srcDir := filepath.Join(t.TempDir(), "my-rules")
	if err := os.MkdirAll(srcDir, 0o750); err != nil {
		t.Fatalf("creating source dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "bundle.yaml"), []byte(pipelockPrefixYAML), 0o600); err != nil {
		t.Fatalf("writing bundle: %v", err)
	}

	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"rules", "install", "--path", srcDir, "--allow-unsigned", "--rules-dir", rulesDir})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for pipelock- prefix in unsigned bundle")
	}
	if !strings.Contains(err.Error(), "reserved prefix") {
		t.Errorf("error should mention reserved prefix, got: %v", err)
	}
}

func TestRulesInstall_AlreadyInstalled(t *testing.T) {
	rulesDir := t.TempDir()

	// Create a local bundle source directory.
	srcDir := filepath.Join(t.TempDir(), "my-rules")
	if err := os.MkdirAll(srcDir, 0o750); err != nil {
		t.Fatalf("creating source dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "bundle.yaml"), []byte(validBundleYAML), 0o600); err != nil {
		t.Fatalf("writing bundle: %v", err)
	}

	// Install first time.
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"rules", "install", "--path", srcDir, "--allow-unsigned", "--rules-dir", rulesDir})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("first install error: %v", err)
	}

	// Install again (same version, same content).
	cmd2 := rootCmd()
	buf2 := &strings.Builder{}
	cmd2.SetOut(buf2)
	cmd2.SetArgs([]string{"rules", "install", "--path", srcDir, "--allow-unsigned", "--rules-dir", rulesDir})
	err := cmd2.Execute()
	if err == nil {
		t.Fatal("expected error for duplicate install")
	}
	if !strings.Contains(err.Error(), "already installed") {
		t.Errorf("error should mention already installed, got: %v", err)
	}
}

func TestRulesInstall_RemoteSigned(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	bundleData := []byte(validBundleYAML)
	sig := ed25519.Sign(priv, bundleData)
	sigEncoded := base64.StdEncoding.EncodeToString(sig) + "\n"

	// Set up embedded keyring.
	orig := rules.KeyringHex
	rules.KeyringHex = hex.EncodeToString(pub)
	t.Cleanup(func() { rules.KeyringHex = orig })

	// HTTP test server serving bundle.yaml and bundle.yaml.sig.
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case testBundlePath:
			_, _ = w.Write(bundleData)
		case testBundleSigPath:
			_, _ = w.Write([]byte(sigEncoded))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	// Override http.DefaultClient for TLS test server.
	origClient := http.DefaultClient
	http.DefaultClient = ts.Client()
	t.Cleanup(func() { http.DefaultClient = origClient })

	rulesDir := t.TempDir()
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"rules", "install", "--source", ts.URL + testBundlePath, "--rules-dir", rulesDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Installed test-bundle") {
		t.Errorf("expected install confirmation, got %q", output)
	}
	if !strings.Contains(output, "official") {
		t.Errorf("expected 'official' tier in output, got %q", output)
	}
}

func TestRulesInstall_NoArgs(t *testing.T) {
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"rules", "install"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for no args")
	}
}

// ---------- rules remove tests ----------

func TestRulesRemove_Exists(t *testing.T) {
	rulesDir := t.TempDir()
	setupUnsignedBundle(t, rulesDir, testBundleName, []byte(validBundleYAML))

	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"rules", "remove", testBundleName, "--rules-dir", rulesDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(buf.String(), "Removed test-bundle") {
		t.Errorf("expected removal confirmation, got %q", buf.String())
	}

	// Verify directory was removed.
	bundleDir := filepath.Join(rulesDir, testBundleName)
	if _, err := os.Stat(bundleDir); !os.IsNotExist(err) {
		t.Error("expected bundle directory to be removed")
	}
}

func TestRulesRemove_NotInstalled(t *testing.T) {
	rulesDir := t.TempDir()
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"rules", "remove", "nonexistent", "--rules-dir", rulesDir})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for non-existent bundle")
	}
	if !strings.Contains(err.Error(), "not installed") {
		t.Errorf("error should mention 'not installed', got: %v", err)
	}
}

// ---------- rules verify tests ----------

func TestRulesVerify_Valid(t *testing.T) {
	rulesDir := t.TempDir()
	bundleData := []byte(validBundleYAML)

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	// Set embedded keyring.
	orig := rules.KeyringHex
	rules.KeyringHex = hex.EncodeToString(pub)
	t.Cleanup(func() { rules.KeyringHex = orig })

	bundleDir := filepath.Join(rulesDir, testBundleName)
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatalf("creating bundle dir: %v", err)
	}

	bundlePath := filepath.Join(bundleDir, "bundle.yaml")
	if err := os.WriteFile(bundlePath, bundleData, 0o600); err != nil {
		t.Fatalf("writing bundle: %v", err)
	}

	sig := ed25519.Sign(priv, bundleData)
	sigEncoded := base64.StdEncoding.EncodeToString(sig) + "\n"
	sigPath := filepath.Join(bundleDir, "bundle.yaml.sig")
	if err := os.WriteFile(sigPath, []byte(sigEncoded), 0o600); err != nil {
		t.Fatalf("writing sig: %v", err)
	}

	fingerprint := hex.EncodeToString(pub)
	hash := sha256.Sum256(bundleData)
	digest := hex.EncodeToString(hash[:])

	lf := &rules.LockFile{
		InstalledVersion:  "2026.03.1",
		InstalledAt:       "2026-03-15T10:00:00Z",
		Source:            "https://rules.pipelock.dev/test-bundle/bundle.yaml",
		LastCheck:         "2026-03-15T10:00:00Z",
		BundleSHA256:      digest,
		SignerFingerprint: fingerprint,
	}
	lockPath := filepath.Join(bundleDir, "bundle.lock")
	if err := rules.WriteLockFile(lockPath, lf); err != nil {
		t.Fatalf("writing lock file: %v", err)
	}

	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"rules", "verify", "--rules-dir", rulesDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "OK") {
		t.Errorf("expected 'OK' in output, got %q", output)
	}
	if !strings.Contains(output, "signature OK") {
		t.Errorf("expected 'signature OK' in output, got %q", output)
	}
}

func TestRulesVerify_Tampered(t *testing.T) {
	rulesDir := t.TempDir()
	bundleData := []byte(validBundleYAML)

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	// Set embedded keyring.
	orig := rules.KeyringHex
	rules.KeyringHex = hex.EncodeToString(pub)
	t.Cleanup(func() { rules.KeyringHex = orig })

	bundleDir := filepath.Join(rulesDir, testBundleName)
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatalf("creating bundle dir: %v", err)
	}

	bundlePath := filepath.Join(bundleDir, "bundle.yaml")
	if err := os.WriteFile(bundlePath, bundleData, 0o600); err != nil {
		t.Fatalf("writing bundle: %v", err)
	}

	sig := ed25519.Sign(priv, bundleData)
	sigEncoded := base64.StdEncoding.EncodeToString(sig) + "\n"
	sigPath := filepath.Join(bundleDir, "bundle.yaml.sig")
	if err := os.WriteFile(sigPath, []byte(sigEncoded), 0o600); err != nil {
		t.Fatalf("writing sig: %v", err)
	}

	fingerprint := hex.EncodeToString(pub)
	hash := sha256.Sum256(bundleData)
	digest := hex.EncodeToString(hash[:])

	lf := &rules.LockFile{
		InstalledVersion:  "2026.03.1",
		InstalledAt:       "2026-03-15T10:00:00Z",
		Source:            "https://rules.pipelock.dev/test-bundle/bundle.yaml",
		LastCheck:         "2026-03-15T10:00:00Z",
		BundleSHA256:      digest,
		SignerFingerprint: fingerprint,
	}
	lockPath := filepath.Join(bundleDir, "bundle.lock")
	if err := rules.WriteLockFile(lockPath, lf); err != nil {
		t.Fatalf("writing lock file: %v", err)
	}

	// Tamper with bundle after writing lock.
	tamperedData := []byte(strings.Replace(validBundleYAML, "Test Rule", "TAMPERED", 1))
	if err := os.WriteFile(bundlePath, tamperedData, 0o600); err != nil {
		t.Fatalf("writing tampered bundle: %v", err)
	}

	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"rules", "verify", "--rules-dir", rulesDir})

	err = cmd.Execute()
	if err == nil {
		t.Fatal("expected error for tampered bundle")
	}

	output := buf.String()
	if !strings.Contains(output, "FAIL") {
		t.Errorf("expected 'FAIL' in output, got %q", output)
	}
}

func TestRulesVerify_UnsignedValid(t *testing.T) {
	rulesDir := t.TempDir()
	setupUnsignedBundle(t, rulesDir, testBundleName, []byte(validBundleYAML))

	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"rules", "verify", "--rules-dir", rulesDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "OK") {
		t.Errorf("expected 'OK' in output, got %q", output)
	}
	if !strings.Contains(output, "SHA-256 OK") {
		t.Errorf("expected 'SHA-256 OK' in output, got %q", output)
	}
}

// ---------- rules update tests ----------

func TestRulesUpdate_LocalPathSkipped(t *testing.T) {
	rulesDir := t.TempDir()
	setupUnsignedBundle(t, rulesDir, testBundleName, []byte(validBundleYAML))

	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"rules", "update", testBundleName, "--rules-dir", rulesDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "skipping test-bundle") {
		t.Errorf("expected skip message, got %q", output)
	}
	if !strings.Contains(output, "local path") {
		t.Errorf("expected 'local path' in skip message, got %q", output)
	}
}

func TestRulesUpdate_NotInstalled(t *testing.T) {
	rulesDir := t.TempDir()
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"rules", "update", "nonexistent", "--rules-dir", rulesDir})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for non-existent bundle")
	}
	if !strings.Contains(err.Error(), "not installed") {
		t.Errorf("error should mention 'not installed', got: %v", err)
	}
}

func TestRulesUpdate_RemoteUpToDate(t *testing.T) {
	bundleData := []byte(validBundleYAML)

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	sig := ed25519.Sign(priv, bundleData)
	sigEncoded := base64.StdEncoding.EncodeToString(sig) + "\n"

	orig := rules.KeyringHex
	rules.KeyringHex = hex.EncodeToString(pub)
	t.Cleanup(func() { rules.KeyringHex = orig })

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case testBundlePath:
			_, _ = w.Write(bundleData)
		case testBundleSigPath:
			_, _ = w.Write([]byte(sigEncoded))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	origClient := http.DefaultClient
	http.DefaultClient = ts.Client()
	t.Cleanup(func() { http.DefaultClient = origClient })

	// Set up installed bundle with matching version and digest.
	rulesDir := t.TempDir()
	bundleDir := filepath.Join(rulesDir, testBundleName)
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatalf("creating bundle dir: %v", err)
	}
	bundlePath := filepath.Join(bundleDir, "bundle.yaml")
	if err := os.WriteFile(bundlePath, bundleData, 0o600); err != nil {
		t.Fatalf("writing bundle: %v", err)
	}
	sigPath := filepath.Join(bundleDir, "bundle.yaml.sig")
	if err := os.WriteFile(sigPath, []byte(sigEncoded), 0o600); err != nil {
		t.Fatalf("writing sig: %v", err)
	}

	fingerprint := hex.EncodeToString(pub)
	hash := sha256.Sum256(bundleData)
	digest := hex.EncodeToString(hash[:])

	lf := &rules.LockFile{
		InstalledVersion:  "2026.03.1",
		InstalledAt:       "2026-03-15T10:00:00Z",
		Source:            ts.URL + testBundlePath,
		LastCheck:         "2026-03-15T10:00:00Z",
		BundleSHA256:      digest,
		SignerFingerprint: fingerprint,
	}
	lockPath := filepath.Join(bundleDir, "bundle.lock")
	if err := rules.WriteLockFile(lockPath, lf); err != nil {
		t.Fatalf("writing lock file: %v", err)
	}

	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"rules", "update", testBundleName, "--rules-dir", rulesDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "already up to date") {
		t.Errorf("expected 'already up to date', got %q", output)
	}

	// Verify last_check was updated.
	updatedLF, err := rules.ReadLockFile(lockPath)
	if err != nil {
		t.Fatalf("reading lock file: %v", err)
	}
	if updatedLF.LastCheck == lf.LastCheck {
		t.Error("expected last_check to be updated")
	}
}

func TestRulesUpdate_NewerVersion(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	oldData := []byte(validBundleYAML)
	newData := []byte(secondVersionBundleYAML)
	newSig := ed25519.Sign(priv, newData)
	newSigEncoded := base64.StdEncoding.EncodeToString(newSig) + "\n"

	orig := rules.KeyringHex
	rules.KeyringHex = hex.EncodeToString(pub)
	t.Cleanup(func() { rules.KeyringHex = orig })

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case testBundlePath:
			_, _ = w.Write(newData)
		case testBundleSigPath:
			_, _ = w.Write([]byte(newSigEncoded))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	origClient := http.DefaultClient
	http.DefaultClient = ts.Client()
	t.Cleanup(func() { http.DefaultClient = origClient })

	// Set up installed bundle with old version.
	rulesDir := t.TempDir()
	bundleDir := filepath.Join(rulesDir, testBundleName)
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatalf("creating bundle dir: %v", err)
	}
	bundlePath := filepath.Join(bundleDir, "bundle.yaml")
	if err := os.WriteFile(bundlePath, oldData, 0o600); err != nil {
		t.Fatalf("writing bundle: %v", err)
	}

	// Sign old data too for the initial install.
	oldSig := ed25519.Sign(priv, oldData)
	oldSigEncoded := base64.StdEncoding.EncodeToString(oldSig) + "\n"
	sigPath := filepath.Join(bundleDir, "bundle.yaml.sig")
	if err := os.WriteFile(sigPath, []byte(oldSigEncoded), 0o600); err != nil {
		t.Fatalf("writing sig: %v", err)
	}

	fingerprint := hex.EncodeToString(pub)
	oldHash := sha256.Sum256(oldData)
	oldDigest := hex.EncodeToString(oldHash[:])

	lf := &rules.LockFile{
		InstalledVersion:  "2026.03.1",
		InstalledAt:       "2026-03-15T10:00:00Z",
		Source:            ts.URL + testBundlePath,
		LastCheck:         "2026-03-15T10:00:00Z",
		BundleSHA256:      oldDigest,
		SignerFingerprint: fingerprint,
	}
	lockPath := filepath.Join(bundleDir, "bundle.lock")
	if err := rules.WriteLockFile(lockPath, lf); err != nil {
		t.Fatalf("writing lock file: %v", err)
	}

	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"rules", "update", testBundleName, "--rules-dir", rulesDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Updated test-bundle") {
		t.Errorf("expected update confirmation, got %q", output)
	}
	if !strings.Contains(output, "2026.04.1") {
		t.Errorf("expected new version in output, got %q", output)
	}

	// Verify lock file was updated.
	updatedLF, err := rules.ReadLockFile(lockPath)
	if err != nil {
		t.Fatalf("reading lock file: %v", err)
	}
	if updatedLF.InstalledVersion != "2026.04.1" {
		t.Errorf("InstalledVersion = %q, want %q", updatedLF.InstalledVersion, "2026.04.1")
	}
}

// ---------- rules diff tests ----------

func TestRulesDiff_NoDifferences(t *testing.T) {
	bundleData := []byte(validBundleYAML)

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == testBundlePath {
			_, _ = w.Write(bundleData)
			return
		}
		// Diff also fetches the sig file as part of fetchRemoteBundle.
		if r.URL.Path == testBundleSigPath {
			_, _ = w.Write([]byte("placeholder"))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	origClient := http.DefaultClient
	http.DefaultClient = ts.Client()
	t.Cleanup(func() { http.DefaultClient = origClient })

	rulesDir := t.TempDir()
	bundleDir := filepath.Join(rulesDir, testBundleName)
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatalf("creating bundle dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, "bundle.yaml"), bundleData, 0o600); err != nil {
		t.Fatalf("writing bundle: %v", err)
	}

	hash := sha256.Sum256(bundleData)
	lf := &rules.LockFile{
		InstalledVersion: "2026.03.1",
		InstalledAt:      "2026-03-15T10:00:00Z",
		Source:           ts.URL + testBundlePath,
		LastCheck:        "2026-03-15T10:00:00Z",
		BundleSHA256:     hex.EncodeToString(hash[:]),
	}
	lockPath := filepath.Join(bundleDir, "bundle.lock")
	if err := rules.WriteLockFile(lockPath, lf); err != nil {
		t.Fatalf("writing lock file: %v", err)
	}

	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"rules", "diff", testBundleName, "--rules-dir", rulesDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(buf.String(), "No differences found") {
		t.Errorf("expected 'No differences found', got %q", buf.String())
	}
}

func TestRulesDiff_WithChanges(t *testing.T) {
	oldData := []byte(validBundleYAML)
	newData := []byte(secondVersionBundleYAML)

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == testBundlePath {
			_, _ = w.Write(newData)
			return
		}
		if r.URL.Path == testBundleSigPath {
			_, _ = w.Write([]byte("placeholder"))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	origClient := http.DefaultClient
	http.DefaultClient = ts.Client()
	t.Cleanup(func() { http.DefaultClient = origClient })

	rulesDir := t.TempDir()
	bundleDir := filepath.Join(rulesDir, testBundleName)
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatalf("creating bundle dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, "bundle.yaml"), oldData, 0o600); err != nil {
		t.Fatalf("writing bundle: %v", err)
	}

	hash := sha256.Sum256(oldData)
	lf := &rules.LockFile{
		InstalledVersion: "2026.03.1",
		InstalledAt:      "2026-03-15T10:00:00Z",
		Source:           ts.URL + testBundlePath,
		LastCheck:        "2026-03-15T10:00:00Z",
		BundleSHA256:     hex.EncodeToString(hash[:]),
	}
	lockPath := filepath.Join(bundleDir, "bundle.lock")
	if err := rules.WriteLockFile(lockPath, lf); err != nil {
		t.Fatalf("writing lock file: %v", err)
	}

	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"rules", "diff", testBundleName, "--rules-dir", rulesDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	// New version adds test-rule-two.
	if !strings.Contains(output, "+ test-bundle:test-rule-two") {
		t.Errorf("expected added rule in output, got %q", output)
	}
	if !strings.Contains(output, "1 added") {
		t.Errorf("expected '1 added' in summary, got %q", output)
	}
}

func TestRulesDiff_LocalBundle(t *testing.T) {
	rulesDir := t.TempDir()
	localBundleName := "local-only-bundle"
	// Use a different bundle name (with matching YAML) to exercise the bundleName parameter.
	localYAML := strings.Replace(validBundleYAML, "name: test-bundle", "name: "+localBundleName, 1)
	setupUnsignedBundle(t, rulesDir, localBundleName, []byte(localYAML))

	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"rules", "diff", localBundleName, "--rules-dir", rulesDir})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for local bundle diff")
	}
	if !strings.Contains(err.Error(), "cannot diff local bundles") {
		t.Errorf("error should mention local bundles, got: %v", err)
	}
}

// ---------- helper tests (no globals, safe for parallel) ----------

func TestDecodeSignatureBytes_Valid(t *testing.T) {
	t.Parallel()

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	data := []byte("test data")
	sig := ed25519.Sign(priv, data)
	encoded := base64.StdEncoding.EncodeToString(sig) + "\n"

	decoded, err := decodeSignatureBytes([]byte(encoded))
	if err != nil {
		t.Fatalf("decodeSignatureBytes() error: %v", err)
	}

	if len(decoded) != ed25519.SignatureSize {
		t.Errorf("signature length = %d, want %d", len(decoded), ed25519.SignatureSize)
	}
}

func TestDecodeSignatureBytes_Invalid(t *testing.T) {
	t.Parallel()

	_, err := decodeSignatureBytes([]byte("not-valid-base64!!!"))
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

// ---------- loadRulesConfig tests ----------

func TestLoadRulesConfig_ExplicitPathError(t *testing.T) {
	// Explicit --config with nonexistent file must return error.
	_, err := loadRulesConfig("/nonexistent/pipelock.yaml")
	if err == nil {
		t.Error("expected error for nonexistent explicit config path")
	}
}

func TestLoadRulesConfig_EmptyFallback(t *testing.T) {
	// Empty configFile + no env + no cwd config → nil, nil (not an error).
	t.Setenv("PIPELOCK_CONFIG", "")
	cfg, err := loadRulesConfig("")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	// cfg may be nil (no config found) or non-nil (if pipelock.yaml exists in cwd).
	// Either is OK — the key invariant is no error.
	_ = cfg
}

// ---------- helper tests (no globals, safe for parallel) ----------

func TestRuleChanged(t *testing.T) {
	t.Parallel()

	a := &rules.Rule{
		ID:          "test-rule",
		Type:        "dlp",
		Status:      "stable",
		Severity:    "high",
		Description: "desc",
		Pattern:     rules.RulePattern{Regex: "abc"},
	}
	b := &rules.Rule{
		ID:          "test-rule",
		Type:        "dlp",
		Status:      "stable",
		Severity:    "high",
		Description: "desc",
		Pattern:     rules.RulePattern{Regex: "abc"},
	}

	if ruleChanged(a, b) {
		t.Error("identical rules should not be marked as changed")
	}

	b.Pattern.Regex = "xyz"
	if !ruleChanged(a, b) {
		t.Error("rules with different regex should be marked as changed")
	}
}

// ---------- coverage gap tests ----------

func TestVerifyRemoteSignature_TrustedKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	bundleData := []byte("test bundle data")
	sig := ed25519.Sign(priv, bundleData)
	sigEncoded := base64.StdEncoding.EncodeToString(sig) + "\n"

	// Not in embedded keyring — use trusted keys instead.
	trustedKeys := []config.TrustedKey{
		{Name: "test-signer", PublicKey: hex.EncodeToString(pub)},
	}

	result, err := verifyRemoteSignature(bundleData, []byte(sigEncoded), trustedKeys)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Tier != rules.TrustTierThirdParty {
		t.Errorf("Tier = %q, want %q", result.Tier, rules.TrustTierThirdParty)
	}
	if result.SignerFingerprint == "" {
		t.Error("expected non-empty signer fingerprint")
	}
}

func TestVerifyRemoteSignature_NoMatchingSigner(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	bundleData := []byte("test bundle data")
	sig := ed25519.Sign(priv, bundleData)
	sigEncoded := base64.StdEncoding.EncodeToString(sig) + "\n"

	// Empty embedded keyring, no trusted keys.
	orig := rules.KeyringHex
	rules.KeyringHex = ""
	t.Cleanup(func() { rules.KeyringHex = orig })

	_, err = verifyRemoteSignature(bundleData, []byte(sigEncoded), nil)
	if err == nil {
		t.Fatal("expected error for no matching signer")
	}
	if !strings.Contains(err.Error(), "no matching signer") {
		t.Errorf("error should mention no matching signer, got: %v", err)
	}
}

func TestVerifyRemoteSignature_TrustedKeyBadHex(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	bundleData := []byte("test bundle data")
	sig := ed25519.Sign(priv, bundleData)
	sigEncoded := base64.StdEncoding.EncodeToString(sig) + "\n"

	orig := rules.KeyringHex
	rules.KeyringHex = ""
	t.Cleanup(func() { rules.KeyringHex = orig })

	// Invalid hex and wrong-size key — both should be skipped, not panic.
	trustedKeys := []config.TrustedKey{
		{Name: "bad-hex", PublicKey: "not-hex!!!"},
		{Name: "wrong-size", PublicKey: "aabbccdd"},
	}

	_, err = verifyRemoteSignature(bundleData, []byte(sigEncoded), trustedKeys)
	if err == nil {
		t.Fatal("expected error for no matching signer")
	}
}

func TestRuleChanged_AllFields(t *testing.T) {
	t.Parallel()

	base := rules.Rule{
		ID: "r1", Type: "dlp", Status: "stable",
		Severity: "high", Description: "desc",
		Pattern: rules.RulePattern{Regex: "abc"},
	}

	tests := []struct {
		name   string
		modify func(r *rules.Rule)
	}{
		{"type differs", func(r *rules.Rule) { r.Type = "response" }},
		{"status differs", func(r *rules.Rule) { r.Status = "experimental" }},
		{"severity differs", func(r *rules.Rule) { r.Severity = "critical" }},
		{"description differs", func(r *rules.Rule) { r.Description = "different" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a := base
			b := base
			tt.modify(&b)
			if !ruleChanged(&a, &b) {
				t.Errorf("expected rules to differ when %s", tt.name)
			}
		})
	}
}

func TestLoadRulesConfig_ExplicitPathSuccess(t *testing.T) {
	// Create a minimal valid config file.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "test-pipelock.yaml")
	if err := os.WriteFile(cfgPath, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	cfg, err := loadRulesConfig(cfgPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
}

func TestLoadRulesConfig_EnvVarFallback(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "env-pipelock.yaml")
	if err := os.WriteFile(cfgPath, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	t.Setenv("PIPELOCK_CONFIG", cfgPath)

	cfg, err := loadRulesConfig("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config from env var fallback")
	}
}

func TestFetchRemoteBundle_NonHTTPS(t *testing.T) {
	t.Parallel()

	_, _, err := fetchRemoteBundle(t.Context(), "http://evil.com/bundle.yaml")
	if err == nil {
		t.Fatal("expected error for non-HTTPS URL")
	}
	if !strings.Contains(err.Error(), "HTTPS") {
		t.Errorf("error should mention HTTPS, got: %v", err)
	}
}

func TestHttpGet_Non200(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	origClient := http.DefaultClient
	http.DefaultClient = ts.Client()
	t.Cleanup(func() { http.DefaultClient = origClient })

	_, err := httpGet(t.Context(), ts.URL+"/missing")
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
	if !strings.Contains(err.Error(), "status 404") {
		t.Errorf("error should mention status 404, got: %v", err)
	}
}

func TestHttpGet_ServerError(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	origClient := http.DefaultClient
	http.DefaultClient = ts.Client()
	t.Cleanup(func() { http.DefaultClient = origClient })

	_, err := httpGet(t.Context(), ts.URL+"/fail")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	if !strings.Contains(err.Error(), "status 500") {
		t.Errorf("error should mention status 500, got: %v", err)
	}
}

func TestDecodeSignatureBytes_WrongLength(t *testing.T) {
	t.Parallel()

	// Valid base64 but decodes to wrong length (not 64 bytes).
	shortSig := base64.StdEncoding.EncodeToString([]byte("too-short"))
	_, err := decodeSignatureBytes([]byte(shortSig))
	if err == nil {
		t.Fatal("expected error for wrong signature length")
	}
	if !strings.Contains(err.Error(), "invalid signature length") {
		t.Errorf("error should mention invalid signature length, got: %v", err)
	}
}

func TestCheckExistingInstall_DifferentDigest(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleDir := filepath.Join(dir, testBundleName)
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatalf("creating dir: %v", err)
	}

	lf := &rules.LockFile{
		InstalledVersion: "2026.03.1",
		InstalledAt:      "2026-03-15T10:00:00Z",
		Source:           "https://example.com/bundle.yaml",
		BundleSHA256:     "aaaa",
	}
	if err := rules.WriteLockFile(filepath.Join(bundleDir, "bundle.lock"), lf); err != nil {
		t.Fatalf("writing lock: %v", err)
	}

	err := checkExistingInstall(bundleDir, "2026.03.1", "bbbb")
	if err == nil {
		t.Fatal("expected error for same version different digest")
	}
	if !strings.Contains(err.Error(), "republish") {
		t.Errorf("error should mention republish, got: %v", err)
	}
}

func TestCheckExistingInstall_NotInstalled(t *testing.T) {
	t.Parallel()

	err := checkExistingInstall(filepath.Join(t.TempDir(), "nonexistent"), "2026.03.1", "abc")
	if err != nil {
		t.Errorf("expected nil error for not-installed bundle, got: %v", err)
	}
}

func TestRulesVerify_NoBundles(t *testing.T) {
	rulesDir := t.TempDir()

	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"rules", "verify", "--rules-dir", rulesDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(buf.String(), "No bundles installed") {
		t.Errorf("expected 'No bundles installed', got %q", buf.String())
	}
}

func TestRulesVerify_MissingLockFile(t *testing.T) {
	rulesDir := t.TempDir()
	// Create a bundle dir without a lock file.
	bundleDir := filepath.Join(rulesDir, testBundleName)
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatalf("creating dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, "bundle.yaml"), []byte(validBundleYAML), 0o600); err != nil {
		t.Fatalf("writing bundle: %v", err)
	}

	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"rules", "verify", "--rules-dir", rulesDir})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for failed verification")
	}
	if !strings.Contains(buf.String(), "FAIL") {
		t.Errorf("expected FAIL in output, got %q", buf.String())
	}
	if !strings.Contains(buf.String(), "missing lock file") {
		t.Errorf("expected 'missing lock file' in output, got %q", buf.String())
	}
}

func TestRulesUpdate_UpdateAll(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	newData := []byte(secondVersionBundleYAML)
	sig := ed25519.Sign(priv, newData)
	sigEncoded := base64.StdEncoding.EncodeToString(sig) + "\n"

	orig := rules.KeyringHex
	rules.KeyringHex = hex.EncodeToString(pub)
	t.Cleanup(func() { rules.KeyringHex = orig })

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sig") {
			_, _ = w.Write([]byte(sigEncoded))
			return
		}
		_, _ = w.Write(newData)
	}))
	defer ts.Close()

	origClient := http.DefaultClient
	http.DefaultClient = ts.Client()
	t.Cleanup(func() { http.DefaultClient = origClient })

	rulesDir := t.TempDir()

	// Set up an installed signed bundle.
	oldData := []byte(validBundleYAML)
	bundleDir := filepath.Join(rulesDir, testBundleName)
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatalf("creating dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, "bundle.yaml"), oldData, 0o600); err != nil {
		t.Fatalf("writing bundle: %v", err)
	}

	hash := sha256.Sum256(oldData)
	lf := &rules.LockFile{
		InstalledVersion:  "2026.03.1",
		InstalledAt:       "2026-03-15T10:00:00Z",
		Source:            ts.URL + testBundlePath,
		LastCheck:         "2026-03-15T10:00:00Z",
		BundleSHA256:      hex.EncodeToString(hash[:]),
		SignerFingerprint: hex.EncodeToString(pub),
	}
	if err := rules.WriteLockFile(filepath.Join(bundleDir, "bundle.lock"), lf); err != nil {
		t.Fatalf("writing lock: %v", err)
	}

	// Run update with no name arg (update all).
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"rules", "update", "--rules-dir", rulesDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Updated test-bundle") {
		t.Errorf("expected update confirmation, got %q", output)
	}
}

func TestRulesUpdate_RepublishAttack(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	// Same version but modified content (different digest).
	modifiedYAML := strings.Replace(validBundleYAML, "Detects test patterns", "Modified description", 1)
	newData := []byte(modifiedYAML)
	sig := ed25519.Sign(priv, newData)
	sigEncoded := base64.StdEncoding.EncodeToString(sig) + "\n"

	orig := rules.KeyringHex
	rules.KeyringHex = hex.EncodeToString(pub)
	t.Cleanup(func() { rules.KeyringHex = orig })

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sig") {
			_, _ = w.Write([]byte(sigEncoded))
			return
		}
		_, _ = w.Write(newData)
	}))
	defer ts.Close()

	origClient := http.DefaultClient
	http.DefaultClient = ts.Client()
	t.Cleanup(func() { http.DefaultClient = origClient })

	rulesDir := t.TempDir()
	oldData := []byte(validBundleYAML)
	bundleDir := filepath.Join(rulesDir, testBundleName)
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatalf("creating dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, "bundle.yaml"), oldData, 0o600); err != nil {
		t.Fatalf("writing bundle: %v", err)
	}

	hash := sha256.Sum256(oldData)
	lf := &rules.LockFile{
		InstalledVersion:  "2026.03.1",
		InstalledAt:       "2026-03-15T10:00:00Z",
		Source:            ts.URL + testBundlePath,
		LastCheck:         "2026-03-15T10:00:00Z",
		BundleSHA256:      hex.EncodeToString(hash[:]),
		SignerFingerprint: hex.EncodeToString(pub),
	}
	if err := rules.WriteLockFile(filepath.Join(bundleDir, "bundle.lock"), lf); err != nil {
		t.Fatalf("writing lock: %v", err)
	}

	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"rules", "update", testBundleName, "--rules-dir", rulesDir})

	err = cmd.Execute()
	if err == nil {
		t.Fatal("expected error for republish attack")
	}
	if !strings.Contains(err.Error(), "republish") {
		t.Errorf("error should mention republish, got: %v", err)
	}
}

func TestRulesUpdate_DowngradeRejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	// Serve an OLDER version than what's installed.
	olderYAML := strings.Replace(validBundleYAML, `version: "2026.03.1"`, `version: "2025.12.1"`, 1)
	newData := []byte(olderYAML)
	sig := ed25519.Sign(priv, newData)
	sigEncoded := base64.StdEncoding.EncodeToString(sig) + "\n"

	orig := rules.KeyringHex
	rules.KeyringHex = hex.EncodeToString(pub)
	t.Cleanup(func() { rules.KeyringHex = orig })

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sig") {
			_, _ = w.Write([]byte(sigEncoded))
			return
		}
		_, _ = w.Write(newData)
	}))
	defer ts.Close()

	origClient := http.DefaultClient
	http.DefaultClient = ts.Client()
	t.Cleanup(func() { http.DefaultClient = origClient })

	rulesDir := t.TempDir()
	oldData := []byte(validBundleYAML)
	bundleDir := filepath.Join(rulesDir, testBundleName)
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatalf("creating dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, "bundle.yaml"), oldData, 0o600); err != nil {
		t.Fatalf("writing bundle: %v", err)
	}

	hash := sha256.Sum256(oldData)
	lf := &rules.LockFile{
		InstalledVersion:  "2026.03.1",
		InstalledAt:       "2026-03-15T10:00:00Z",
		Source:            ts.URL + testBundlePath,
		LastCheck:         "2026-03-15T10:00:00Z",
		BundleSHA256:      hex.EncodeToString(hash[:]),
		SignerFingerprint: hex.EncodeToString(pub),
	}
	if err := rules.WriteLockFile(filepath.Join(bundleDir, "bundle.lock"), lf); err != nil {
		t.Fatalf("writing lock: %v", err)
	}

	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"rules", "update", testBundleName, "--rules-dir", rulesDir})

	err = cmd.Execute()
	if err == nil {
		t.Fatal("expected error for downgrade")
	}
	if !strings.Contains(err.Error(), "older") {
		t.Errorf("error should mention older version, got: %v", err)
	}
}

func TestRulesInstall_RemoteNameMismatch(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	bundleData := []byte(validBundleYAML) // name: test-bundle
	sig := ed25519.Sign(priv, bundleData)
	sigEncoded := base64.StdEncoding.EncodeToString(sig) + "\n"

	orig := rules.KeyringHex
	rules.KeyringHex = hex.EncodeToString(pub)
	t.Cleanup(func() { rules.KeyringHex = orig })

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sig") {
			_, _ = w.Write([]byte(sigEncoded))
			return
		}
		_, _ = w.Write(bundleData)
	}))
	defer ts.Close()

	origClient := http.DefaultClient
	http.DefaultClient = ts.Client()
	t.Cleanup(func() { http.DefaultClient = origClient })

	rulesDir := t.TempDir()
	buf := &strings.Builder{}

	// Call installRemote directly with an expectedName that doesn't match the bundle.
	err = installRemote(buf, rulesDir, ts.URL+testBundlePath, "", "wrong-name")
	if err == nil {
		t.Fatal("expected error for name mismatch")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Errorf("error should mention name mismatch, got: %v", err)
	}
}

func TestRulesInstall_RemoteSignatureFailure(t *testing.T) {
	// Bundle signed with key A, but only key B in keyring → signature verification fails.
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	bundleData := []byte(validBundleYAML)
	sig := ed25519.Sign(priv, bundleData)
	sigEncoded := base64.StdEncoding.EncodeToString(sig) + "\n"

	// Generate a DIFFERENT key for the keyring (won't match).
	otherPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating other key: %v", err)
	}
	orig := rules.KeyringHex
	rules.KeyringHex = hex.EncodeToString(otherPub)
	t.Cleanup(func() { rules.KeyringHex = orig })

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sig") {
			_, _ = w.Write([]byte(sigEncoded))
			return
		}
		_, _ = w.Write(bundleData)
	}))
	defer ts.Close()

	origClient := http.DefaultClient
	http.DefaultClient = ts.Client()
	t.Cleanup(func() { http.DefaultClient = origClient })

	rulesDir := t.TempDir()
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"rules", "install", "--source", ts.URL + testBundlePath, "--rules-dir", rulesDir})

	err = cmd.Execute()
	if err == nil {
		t.Fatal("expected error for signature verification failure")
	}
	if !strings.Contains(err.Error(), "signature verification") {
		t.Errorf("error should mention signature verification, got: %v", err)
	}
}
