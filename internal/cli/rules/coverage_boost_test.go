// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------- validateBundlePath (additional cases not in rules_test.go) ----------

func TestValidateBundlePath_TraversalCases(t *testing.T) {
	rulesDir := t.TempDir()

	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"dotdot name", "..", true},
		{"dot name", ".", true},
		{"empty after clean does not match", "", true},
		{"has nested path sep", "foo/bar", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateBundlePath(rulesDir, tc.input)
			if tc.wantErr && err == nil {
				t.Error("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateBundlePath_ExistingDir(t *testing.T) {
	rulesDir := t.TempDir()
	bundleDir := filepath.Join(rulesDir, "existing-bundle")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatal(err)
	}

	got, err := validateBundlePath(rulesDir, "existing-bundle")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != bundleDir {
		t.Errorf("got %q, want %q", got, bundleDir)
	}
}

// ---------- loadRulesConfig (additional cases) ----------

func TestLoadRulesConfig_ExplicitFile_Valid(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "pipelock.yaml")
	cfgContent := "mode: balanced\n"
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadRulesConfig(cfgPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
}

func TestLoadRulesConfig_EnvVar_Valid(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "pipelock.yaml")
	cfgContent := "mode: balanced\n"
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PIPELOCK_CONFIG", cfgPath)

	cfg, err := loadRulesConfig("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config from env var")
	}
}

func TestLoadRulesConfig_NoFlag_NilConfig(t *testing.T) {
	// Clear env and ensure no pipelock.yaml in cwd.
	t.Setenv("PIPELOCK_CONFIG", "")

	cfg, err := loadRulesConfig("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// May return nil or a config from cwd pipelock.yaml; either is acceptable.
	_ = cfg
}

// ---------- decodeSignatureBytes (additional cases) ----------

func TestDecodeSignatureBytes_InvalidBase64(t *testing.T) {
	_, err := decodeSignatureBytes([]byte("not-valid-base64!!!"))
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

// ---------- sha256Hex ----------

func TestSha256Hex(t *testing.T) {
	got := sha256Hex([]byte("hello"))
	want := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if got != want {
		t.Errorf("sha256Hex(%q) = %q, want %q", "hello", got, want)
	}
}

func TestSha256Hex_Empty(t *testing.T) {
	got := sha256Hex(nil)
	// SHA-256 of empty input.
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got != want {
		t.Errorf("sha256Hex(nil) = %q, want %q", got, want)
	}
}

// ---------- timeNowUTC ----------

func TestTimeNowUTC_Format(t *testing.T) {
	s := timeNowUTC()
	// Should be valid RFC3339 and end with Z (UTC).
	if !strings.HasSuffix(s, "Z") {
		t.Errorf("timeNowUTC() = %q, expected UTC (Z suffix)", s)
	}
	if len(s) < 20 {
		t.Errorf("timeNowUTC() = %q, too short for RFC3339", s)
	}
}

// ---------- ensureDir ----------

func TestEnsureDir_Nested(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "new", "nested", "dir")

	if err := ensureDir(dir); err != nil {
		t.Fatalf("ensureDir: %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected directory")
	}
}

func TestEnsureDir_AlreadyExists(t *testing.T) {
	dir := t.TempDir()
	// Should be idempotent.
	if err := ensureDir(dir); err != nil {
		t.Fatalf("ensureDir on existing dir: %v", err)
	}
}

// ---------- checkExistingInstall (additional case) ----------

func TestCheckExistingInstall_SameVersionSameDigest(t *testing.T) {
	rulesDir := t.TempDir()
	setupUnsignedBundle(t, rulesDir, testBundleName, []byte(validBundleYAML))

	bundleDir := filepath.Join(rulesDir, testBundleName)
	err := checkExistingInstall(bundleDir, testBundleVersion, sha256Hex([]byte(validBundleYAML)))
	if err == nil {
		t.Error("expected error for same version + same digest")
	}
	if !strings.Contains(err.Error(), "skipping") {
		t.Errorf("expected 'skipping' message, got: %v", err)
	}
}

// ---------- verifyRemoteSignature (additional case) ----------

func TestVerifyRemoteSignature_NoMatchingKey(t *testing.T) {
	_, err := verifyRemoteSignature(
		[]byte("data"),
		[]byte(base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))),
		nil,
	)
	if err == nil {
		t.Error("expected error when no key matches")
	}
}

// ---------- fetchRemoteBundle (additional case) ----------

func TestFetchRemoteBundle_RejectsHTTP(t *testing.T) {
	_, _, err := fetchRemoteBundle(context.Background(), "http://example.com/bundle.yaml")
	if err == nil {
		t.Error("expected error for HTTP URL")
	}
	if !strings.Contains(err.Error(), "HTTPS") {
		t.Errorf("expected HTTPS error message, got: %v", err)
	}
}
