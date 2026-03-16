// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/signing"

	"gopkg.in/yaml.v3"
)

// testPipelockVersion is used for tests that need a current pipelock version.
const testPipelockVersion = "1.3.0"

// testBundle is a minimal valid bundle for test helpers.
func testBundle(name string, rules []Rule) *Bundle {
	return &Bundle{
		FormatVersion: MaxFormatVersion,
		Name:          name,
		Version:       "2026.03.0",
		Author:        "Test Author",
		Description:   "Test bundle for loader tests",
		Rules:         rules,
	}
}

// testDLPRule creates a valid DLP rule with the given id, confidence, and status.
func testDLPRule(id, confidence, status string) Rule {
	return Rule{
		ID:          id,
		Type:        RuleTypeDLP,
		Status:      status,
		Name:        "Test DLP Rule " + id,
		Description: "Detects test pattern " + id,
		Severity:    severityHigh,
		Confidence:  confidence,
		Pattern:     RulePattern{Regex: `test-secret-\d+`},
	}
}

// testInjectionRule creates a valid injection rule.
func testInjectionRule(id, confidence, status string) Rule {
	return Rule{
		ID:          id,
		Type:        RuleTypeInjection,
		Status:      status,
		Name:        "Test Injection Rule " + id,
		Description: "Detects injection pattern " + id,
		Severity:    severityMedium,
		Confidence:  confidence,
		Pattern:     RulePattern{Regex: `(?i)ignore previous`},
	}
}

// testToolPoisonRule creates a valid tool-poison rule.
func testToolPoisonRule(id, confidence, status, scanField string) Rule {
	return Rule{
		ID:          id,
		Type:        RuleTypeToolPoison,
		Status:      status,
		Name:        "Test Tool Poison Rule " + id,
		Description: "Detects poisoned tool " + id,
		Severity:    severityCritical,
		Confidence:  confidence,
		Pattern:     RulePattern{Regex: `exec\s+curl`, ScanField: scanField},
	}
}

// writeUnsignedBundle writes a bundle.yaml and bundle.lock for an unsigned bundle.
func writeUnsignedBundle(t *testing.T, dir string, b *Bundle) {
	t.Helper()

	data, err := yaml.Marshal(b)
	if err != nil {
		t.Fatalf("marshaling bundle: %v", err)
	}

	bundlePath := filepath.Join(dir, bundleFilename)
	if err := os.WriteFile(bundlePath, data, 0o600); err != nil {
		t.Fatalf("writing bundle.yaml: %v", err)
	}

	hash := sha256.Sum256(data)
	lock := &LockFile{
		InstalledVersion: b.Version,
		Source:           "test",
		BundleSHA256:     hex.EncodeToString(hash[:]),
		Unsigned:         true,
	}

	lockPath := filepath.Join(dir, lockFilename)
	if err := WriteLockFile(lockPath, lock); err != nil {
		t.Fatalf("writing bundle.lock: %v", err)
	}
}

// writeSignedBundle writes a bundle.yaml, signs it, and writes bundle.lock.
// Returns the public key used for signing.
func writeSignedBundle(t *testing.T, dir string, b *Bundle, pub ed25519.PublicKey, priv ed25519.PrivateKey) {
	t.Helper()

	data, err := yaml.Marshal(b)
	if err != nil {
		t.Fatalf("marshaling bundle: %v", err)
	}

	bundlePath := filepath.Join(dir, bundleFilename)
	if err := os.WriteFile(bundlePath, data, 0o600); err != nil {
		t.Fatalf("writing bundle.yaml: %v", err)
	}

	sig, err := signing.SignFile(bundlePath, priv)
	if err != nil {
		t.Fatalf("signing bundle: %v", err)
	}
	if err := signing.SaveSignature(sig, bundlePath+signing.SigExtension); err != nil {
		t.Fatalf("saving signature: %v", err)
	}

	hash := sha256.Sum256(data)
	lock := &LockFile{
		InstalledVersion:  b.Version,
		Source:            "test-signed",
		BundleSHA256:      hex.EncodeToString(hash[:]),
		SignerFingerprint: KeyFingerprint(pub),
		Unsigned:          false,
	}

	lockPath := filepath.Join(dir, lockFilename)
	if err := WriteLockFile(lockPath, lock); err != nil {
		t.Fatalf("writing bundle.lock: %v", err)
	}
}

// setupKeyring sets KeyringHex to the given public key and returns a cleanup function.
// Must NOT be used in parallel tests.
func setupKeyring(t *testing.T, pub ed25519.PublicKey) {
	t.Helper()
	orig := KeyringHex
	KeyringHex = hex.EncodeToString(pub)
	t.Cleanup(func() { KeyringHex = orig })
}

func TestLoadBundles_NonExistentDir(t *testing.T) {
	t.Parallel()

	result := LoadBundles("/nonexistent/path/to/rules", LoadOptions{
		MinConfidence:   confidenceLow,
		PipelockVersion: testPipelockVersion,
	})

	if len(result.DLP) != 0 {
		t.Errorf("expected 0 DLP rules, got %d", len(result.DLP))
	}
	if len(result.Injection) != 0 {
		t.Errorf("expected 0 Injection rules, got %d", len(result.Injection))
	}
	if len(result.ToolPoison) != 0 {
		t.Errorf("expected 0 ToolPoison rules, got %d", len(result.ToolPoison))
	}
	if len(result.Errors) != 0 {
		t.Errorf("expected 0 errors, got %d: %v", len(result.Errors), result.Errors)
	}
	if len(result.Loaded) != 0 {
		t.Errorf("expected 0 loaded bundles, got %d", len(result.Loaded))
	}
}

func TestLoadBundles_EmptyDir(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	result := LoadBundles(dir, LoadOptions{
		MinConfidence:   confidenceLow,
		PipelockVersion: testPipelockVersion,
	})

	if len(result.DLP) != 0 {
		t.Errorf("expected 0 DLP rules, got %d", len(result.DLP))
	}
	if len(result.Errors) != 0 {
		t.Errorf("expected 0 errors, got %d", len(result.Errors))
	}
	if len(result.Loaded) != 0 {
		t.Errorf("expected 0 loaded bundles, got %d", len(result.Loaded))
	}
}

func TestLoadBundles_ValidUnsignedBundle(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleDir := filepath.Join(dir, "test-bundle")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatal(err)
	}

	b := testBundle("test-bundle", []Rule{
		testDLPRule("dlp-rule-001", confidenceHigh, StatusStable),
		testInjectionRule("inj-rule-001", confidenceMedium, StatusStable),
		testToolPoisonRule("tp-rule-001", confidenceHigh, StatusStable, scanFieldDescription),
	})
	writeUnsignedBundle(t, bundleDir, b)

	result := LoadBundles(dir, LoadOptions{
		MinConfidence:   confidenceLow,
		PipelockVersion: testPipelockVersion,
	})

	if len(result.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", result.Errors)
	}
	if len(result.Loaded) != 1 {
		t.Fatalf("expected 1 loaded bundle, got %d", len(result.Loaded))
	}

	// Check DLP rule.
	if len(result.DLP) != 1 {
		t.Fatalf("expected 1 DLP rule, got %d", len(result.DLP))
	}
	if result.DLP[0].Name != "test-bundle:dlp-rule-001" {
		t.Errorf("DLP name = %q, want %q", result.DLP[0].Name, "test-bundle:dlp-rule-001")
	}
	if result.DLP[0].Regex != `test-secret-\d+` {
		t.Errorf("DLP regex = %q, want %q", result.DLP[0].Regex, `test-secret-\d+`)
	}
	if result.DLP[0].Severity != severityHigh {
		t.Errorf("DLP severity = %q, want %q", result.DLP[0].Severity, severityHigh)
	}

	// Check injection rule.
	if len(result.Injection) != 1 {
		t.Fatalf("expected 1 injection rule, got %d", len(result.Injection))
	}
	if result.Injection[0].Name != "test-bundle:inj-rule-001" {
		t.Errorf("Injection name = %q, want %q", result.Injection[0].Name, "test-bundle:inj-rule-001")
	}

	// Check tool-poison rule.
	if len(result.ToolPoison) != 1 {
		t.Fatalf("expected 1 tool-poison rule, got %d", len(result.ToolPoison))
	}
	tp := result.ToolPoison[0]
	if tp.Name != "test-bundle:tp-rule-001" {
		t.Errorf("ToolPoison name = %q, want %q", tp.Name, "test-bundle:tp-rule-001")
	}
	if tp.RuleID != "test-bundle:tp-rule-001" {
		t.Errorf("ToolPoison RuleID = %q, want %q", tp.RuleID, "test-bundle:tp-rule-001")
	}
	if tp.ScanField != scanFieldDescription {
		t.Errorf("ToolPoison ScanField = %q, want %q", tp.ScanField, scanFieldDescription)
	}
	if tp.Bundle != "test-bundle" {
		t.Errorf("ToolPoison Bundle = %q, want %q", tp.Bundle, "test-bundle")
	}
	if tp.BundleVersion != "2026.03.0" {
		t.Errorf("ToolPoison BundleVersion = %q, want %q", tp.BundleVersion, "2026.03.0")
	}
	// Verify case-insensitive regex compilation.
	if !tp.Re.MatchString("EXEC CURL") {
		t.Error("expected case-insensitive regex to match 'EXEC CURL'")
	}

	// Check loaded bundle diagnostics.
	lb := result.Loaded[0]
	if lb.Name != "test-bundle" {
		t.Errorf("Loaded.Name = %q, want %q", lb.Name, "test-bundle")
	}
	if lb.Rules != 3 {
		t.Errorf("Loaded.Rules = %d, want 3", lb.Rules)
	}
	if lb.DLP != 1 {
		t.Errorf("Loaded.DLP = %d, want 1", lb.DLP)
	}
	if lb.Injection != 1 {
		t.Errorf("Loaded.Injection = %d, want 1", lb.Injection)
	}
	if lb.ToolPoison != 1 {
		t.Errorf("Loaded.ToolPoison = %d, want 1", lb.ToolPoison)
	}
	if !lb.Unsigned {
		t.Error("expected Loaded.Unsigned to be true")
	}
}

func TestLoadBundles_ValidSignedBundle(t *testing.T) {
	// Non-parallel: mutates KeyringHex.
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	setupKeyring(t, pub)

	dir := t.TempDir()
	bundleDir := filepath.Join(dir, "signed-bundle")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatal(err)
	}

	b := testBundle("signed-bundle", []Rule{
		testDLPRule("dlp-signed-001", confidenceHigh, StatusStable),
	})
	writeSignedBundle(t, bundleDir, b, pub, priv)

	result := LoadBundles(dir, LoadOptions{
		MinConfidence:   confidenceLow,
		PipelockVersion: testPipelockVersion,
	})

	if len(result.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", result.Errors)
	}
	if len(result.DLP) != 1 {
		t.Fatalf("expected 1 DLP rule, got %d", len(result.DLP))
	}
	if result.Loaded[0].Unsigned {
		t.Error("expected Loaded.Unsigned to be false for signed bundle")
	}
}

func TestLoadBundles_SignedBundleThirdPartyKey(t *testing.T) {
	// Non-parallel: mutates KeyringHex.

	// Official key in keyring (not the signer).
	officialPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating official key: %v", err)
	}
	setupKeyring(t, officialPub)

	// Third-party key signs the bundle.
	thirdPub, thirdPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating third-party key: %v", err)
	}

	dir := t.TempDir()
	bundleDir := filepath.Join(dir, "third-party-bundle")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatal(err)
	}

	b := testBundle("third-party-bundle", []Rule{
		testDLPRule("dlp-tp-001", confidenceHigh, StatusStable),
	})
	writeSignedBundle(t, bundleDir, b, thirdPub, thirdPriv)

	trustedKeys := []config.TrustedKey{
		{Name: "test-third-party", PublicKey: hex.EncodeToString(thirdPub)},
	}

	result := LoadBundles(dir, LoadOptions{
		MinConfidence:   confidenceLow,
		PipelockVersion: testPipelockVersion,
		TrustedKeys:     trustedKeys,
	})

	if len(result.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", result.Errors)
	}
	if len(result.DLP) != 1 {
		t.Fatalf("expected 1 DLP rule, got %d", len(result.DLP))
	}
}

func TestLoadBundles_InvalidBundleYAML(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleDir := filepath.Join(dir, "bad-yaml-bundle")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatal(err)
	}

	// Write invalid YAML for bundle.yaml.
	badYAML := []byte("{{{{invalid yaml")
	bundlePath := filepath.Join(bundleDir, bundleFilename)
	if err := os.WriteFile(bundlePath, badYAML, 0o600); err != nil {
		t.Fatal(err)
	}

	// Write lock file with matching SHA.
	hash := sha256.Sum256(badYAML)
	lock := &LockFile{
		InstalledVersion: "2026.03.0",
		Source:           "test",
		BundleSHA256:     hex.EncodeToString(hash[:]),
		Unsigned:         true,
	}
	lockPath := filepath.Join(bundleDir, lockFilename)
	if err := WriteLockFile(lockPath, lock); err != nil {
		t.Fatal(err)
	}

	result := LoadBundles(dir, LoadOptions{
		MinConfidence:   confidenceLow,
		PipelockVersion: testPipelockVersion,
	})

	if len(result.Errors) != 1 {
		t.Fatalf("expected 1 error, got %d: %v", len(result.Errors), result.Errors)
	}
	if result.Errors[0].Name != "bad-yaml-bundle" {
		t.Errorf("error Name = %q, want %q", result.Errors[0].Name, "bad-yaml-bundle")
	}
	if len(result.DLP) != 0 {
		t.Errorf("expected 0 DLP rules, got %d", len(result.DLP))
	}
}

func TestLoadBundles_InvalidBundleContinuesOthers(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Bundle "aaa-bad" has invalid YAML (sorted first).
	badDir := filepath.Join(dir, "aaa-bad")
	if err := os.MkdirAll(badDir, 0o750); err != nil {
		t.Fatal(err)
	}
	badYAML := []byte("{{{{invalid yaml")
	if err := os.WriteFile(filepath.Join(badDir, bundleFilename), badYAML, 0o600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(badYAML)
	lock := &LockFile{BundleSHA256: hex.EncodeToString(hash[:]), Unsigned: true}
	if err := WriteLockFile(filepath.Join(badDir, lockFilename), lock); err != nil {
		t.Fatal(err)
	}

	// Bundle "zzz-good" is valid (sorted second).
	goodDir := filepath.Join(dir, "zzz-good")
	if err := os.MkdirAll(goodDir, 0o750); err != nil {
		t.Fatal(err)
	}
	b := testBundle("zzz-good", []Rule{
		testDLPRule("dlp-good-001", confidenceHigh, StatusStable),
	})
	writeUnsignedBundle(t, goodDir, b)

	result := LoadBundles(dir, LoadOptions{
		MinConfidence:   confidenceLow,
		PipelockVersion: testPipelockVersion,
	})

	// Bad bundle produces error but doesn't prevent good bundle from loading.
	if len(result.Errors) != 1 {
		t.Fatalf("expected 1 error, got %d", len(result.Errors))
	}
	if len(result.DLP) != 1 {
		t.Fatalf("expected 1 DLP rule from good bundle, got %d", len(result.DLP))
	}
	if len(result.Loaded) != 1 {
		t.Fatalf("expected 1 loaded bundle, got %d", len(result.Loaded))
	}
	if result.Loaded[0].Name != "zzz-good" {
		t.Errorf("loaded bundle name = %q, want %q", result.Loaded[0].Name, "zzz-good")
	}
}

func TestLoadBundles_MinPipelockTooHigh(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleDir := filepath.Join(dir, "needs-future")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatal(err)
	}

	b := testBundle("needs-future", []Rule{
		testDLPRule("dlp-future-001", confidenceHigh, StatusStable),
	})
	b.MinPipelock = "99.0.0"
	writeUnsignedBundle(t, bundleDir, b)

	result := LoadBundles(dir, LoadOptions{
		MinConfidence:   confidenceLow,
		PipelockVersion: testPipelockVersion,
	})

	if len(result.Errors) != 1 {
		t.Fatalf("expected 1 error for min_pipelock, got %d", len(result.Errors))
	}
	if len(result.DLP) != 0 {
		t.Errorf("expected 0 DLP rules, got %d", len(result.DLP))
	}
}

func TestLoadBundles_ConfidenceFilterHigh(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleDir := filepath.Join(dir, "multi-conf")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatal(err)
	}

	b := testBundle("multi-conf", []Rule{
		testDLPRule("dlp-high-001", confidenceHigh, StatusStable),
		testDLPRule("dlp-med-001", confidenceMedium, StatusStable),
		testDLPRule("dlp-low-001", confidenceLow, StatusStable),
	})
	writeUnsignedBundle(t, bundleDir, b)

	result := LoadBundles(dir, LoadOptions{
		MinConfidence:   confidenceHigh,
		PipelockVersion: testPipelockVersion,
	})

	if len(result.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", result.Errors)
	}
	// Only high confidence should pass.
	if len(result.DLP) != 1 {
		t.Fatalf("expected 1 DLP rule (high only), got %d", len(result.DLP))
	}
	if result.DLP[0].Name != "multi-conf:dlp-high-001" {
		t.Errorf("DLP name = %q, want %q", result.DLP[0].Name, "multi-conf:dlp-high-001")
	}
}

func TestLoadBundles_ConfidenceFilterMedium(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleDir := filepath.Join(dir, "multi-conf")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatal(err)
	}

	b := testBundle("multi-conf", []Rule{
		testDLPRule("dlp-high-001", confidenceHigh, StatusStable),
		testDLPRule("dlp-med-001", confidenceMedium, StatusStable),
		testDLPRule("dlp-low-001", confidenceLow, StatusStable),
	})
	writeUnsignedBundle(t, bundleDir, b)

	result := LoadBundles(dir, LoadOptions{
		MinConfidence:   confidenceMedium,
		PipelockVersion: testPipelockVersion,
	})

	// High + medium should pass, low skipped.
	if len(result.DLP) != 2 {
		t.Fatalf("expected 2 DLP rules (high + medium), got %d", len(result.DLP))
	}
}

func TestLoadBundles_DeprecatedAlwaysSkipped(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleDir := filepath.Join(dir, "deprecated-test")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatal(err)
	}

	b := testBundle("deprecated-test", []Rule{
		testDLPRule("dlp-stable-001", confidenceHigh, StatusStable),
		testDLPRule("dlp-deprecated-001", confidenceHigh, StatusDeprecated),
	})
	writeUnsignedBundle(t, bundleDir, b)

	result := LoadBundles(dir, LoadOptions{
		MinConfidence:       confidenceLow,
		IncludeExperimental: true,
		PipelockVersion:     testPipelockVersion,
	})

	if len(result.DLP) != 1 {
		t.Fatalf("expected 1 DLP rule (deprecated skipped), got %d", len(result.DLP))
	}
	if result.DLP[0].Name != "deprecated-test:dlp-stable-001" {
		t.Errorf("DLP name = %q, want %q", result.DLP[0].Name, "deprecated-test:dlp-stable-001")
	}
}

func TestLoadBundles_ExperimentalSkippedByDefault(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleDir := filepath.Join(dir, "experimental-test")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatal(err)
	}

	b := testBundle("experimental-test", []Rule{
		testDLPRule("dlp-stable-001", confidenceHigh, StatusStable),
		testDLPRule("dlp-experimental-001", confidenceHigh, StatusExperimental),
	})
	writeUnsignedBundle(t, bundleDir, b)

	// Default: experimental not included.
	result := LoadBundles(dir, LoadOptions{
		MinConfidence:   confidenceLow,
		PipelockVersion: testPipelockVersion,
	})

	if len(result.DLP) != 1 {
		t.Fatalf("expected 1 DLP rule (experimental skipped), got %d", len(result.DLP))
	}
	if result.DLP[0].Name != "experimental-test:dlp-stable-001" {
		t.Errorf("DLP name = %q, want %q", result.DLP[0].Name, "experimental-test:dlp-stable-001")
	}
}

func TestLoadBundles_ExperimentalLoadedWithFlag(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleDir := filepath.Join(dir, "experimental-test")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatal(err)
	}

	b := testBundle("experimental-test", []Rule{
		testDLPRule("dlp-stable-001", confidenceHigh, StatusStable),
		testDLPRule("dlp-experimental-001", confidenceHigh, StatusExperimental),
	})
	writeUnsignedBundle(t, bundleDir, b)

	// Include experimental.
	result := LoadBundles(dir, LoadOptions{
		MinConfidence:       confidenceLow,
		IncludeExperimental: true,
		PipelockVersion:     testPipelockVersion,
	})

	if len(result.DLP) != 2 {
		t.Fatalf("expected 2 DLP rules (experimental included), got %d", len(result.DLP))
	}
}

func TestLoadBundles_DisabledByExactID(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleDir := filepath.Join(dir, "disable-test")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatal(err)
	}

	b := testBundle("disable-test", []Rule{
		testDLPRule("dlp-keep-001", confidenceHigh, StatusStable),
		testDLPRule("dlp-skip-001", confidenceHigh, StatusStable),
	})
	writeUnsignedBundle(t, bundleDir, b)

	result := LoadBundles(dir, LoadOptions{
		MinConfidence:   confidenceLow,
		Disabled:        []string{"disable-test:dlp-skip-001"},
		PipelockVersion: testPipelockVersion,
	})

	if len(result.DLP) != 1 {
		t.Fatalf("expected 1 DLP rule (1 disabled), got %d", len(result.DLP))
	}
	if result.DLP[0].Name != "disable-test:dlp-keep-001" {
		t.Errorf("DLP name = %q, want %q", result.DLP[0].Name, "disable-test:dlp-keep-001")
	}
}

func TestLoadBundles_DisabledByGlobPattern(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleDir := filepath.Join(dir, "glob-test")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatal(err)
	}

	b := testBundle("glob-test", []Rule{
		testDLPRule("dlp-rule-001", confidenceHigh, StatusStable),
		testDLPRule("dlp-rule-002", confidenceHigh, StatusStable),
		testInjectionRule("inj-rule-001", confidenceHigh, StatusStable),
	})
	writeUnsignedBundle(t, bundleDir, b)

	// Glob disables all DLP rules from this bundle.
	result := LoadBundles(dir, LoadOptions{
		MinConfidence:   confidenceLow,
		Disabled:        []string{"glob-test:dlp-*"},
		PipelockVersion: testPipelockVersion,
	})

	if len(result.DLP) != 0 {
		t.Fatalf("expected 0 DLP rules (all disabled by glob), got %d", len(result.DLP))
	}
	if len(result.Injection) != 1 {
		t.Fatalf("expected 1 injection rule (not disabled), got %d", len(result.Injection))
	}
}

func TestLoadBundles_MultipleBundlesAlphabetical(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Create bundles with names that sort alphabetically.
	for _, name := range []string{"beta-rules", "alpha-rules", "gamma-rules"} {
		bundleDir := filepath.Join(dir, name)
		if err := os.MkdirAll(bundleDir, 0o750); err != nil {
			t.Fatal(err)
		}
		b := testBundle(name, []Rule{
			testDLPRule("dlp-001", confidenceHigh, StatusStable),
		})
		writeUnsignedBundle(t, bundleDir, b)
	}

	result := LoadBundles(dir, LoadOptions{
		MinConfidence:   confidenceLow,
		PipelockVersion: testPipelockVersion,
	})

	if len(result.Loaded) != 3 {
		t.Fatalf("expected 3 loaded bundles, got %d", len(result.Loaded))
	}

	// Verify alphabetical ordering.
	expectedOrder := []string{"alpha-rules", "beta-rules", "gamma-rules"}
	for i, want := range expectedOrder {
		if result.Loaded[i].Name != want {
			t.Errorf("Loaded[%d].Name = %q, want %q", i, result.Loaded[i].Name, want)
		}
	}

	// Total DLP rules from all bundles.
	if len(result.DLP) != 3 {
		t.Errorf("expected 3 DLP rules total, got %d", len(result.DLP))
	}
}

func TestLoadBundles_PipelockPrefixNonOfficialSigner(t *testing.T) {
	// Non-parallel: mutates KeyringHex.

	// Official key in keyring.
	officialPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating official key: %v", err)
	}
	setupKeyring(t, officialPub)

	// Third-party key signs a bundle with pipelock- prefix.
	thirdPub, thirdPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating third-party key: %v", err)
	}

	dir := t.TempDir()
	bundleDir := filepath.Join(dir, "pipelock-core")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatal(err)
	}

	b := testBundle("pipelock-core", []Rule{
		testDLPRule("dlp-core-001", confidenceHigh, StatusStable),
	})
	writeSignedBundle(t, bundleDir, b, thirdPub, thirdPriv)

	result := LoadBundles(dir, LoadOptions{
		MinConfidence:   confidenceLow,
		PipelockVersion: testPipelockVersion,
		TrustedKeys: []config.TrustedKey{
			{Name: "impersonator", PublicKey: hex.EncodeToString(thirdPub)},
		},
	})

	if len(result.Errors) != 1 {
		t.Fatalf("expected 1 error for reserved prefix, got %d: %v", len(result.Errors), result.Errors)
	}
	if len(result.DLP) != 0 {
		t.Errorf("expected 0 DLP rules (reserved prefix violation), got %d", len(result.DLP))
	}
}

func TestLoadBundles_PipelockPrefixOfficialSigner(t *testing.T) {
	// Non-parallel: mutates KeyringHex.

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	setupKeyring(t, pub)

	dir := t.TempDir()
	bundleDir := filepath.Join(dir, "pipelock-core")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatal(err)
	}

	b := testBundle("pipelock-core", []Rule{
		testDLPRule("dlp-core-001", confidenceHigh, StatusStable),
	})
	writeSignedBundle(t, bundleDir, b, pub, priv)

	result := LoadBundles(dir, LoadOptions{
		MinConfidence:   confidenceLow,
		PipelockVersion: testPipelockVersion,
	})

	if len(result.Errors) != 0 {
		t.Fatalf("unexpected errors for official pipelock- bundle: %v", result.Errors)
	}
	if len(result.DLP) != 1 {
		t.Fatalf("expected 1 DLP rule, got %d", len(result.DLP))
	}
}

func TestLoadBundles_BundleExceedsMaxFileSize(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleDir := filepath.Join(dir, "oversized-bundle")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatal(err)
	}

	// Write an oversized bundle.yaml (MaxBundleFileSize + 1).
	oversize := make([]byte, MaxBundleFileSize+1)
	for i := range oversize {
		oversize[i] = 'x'
	}
	bundlePath := filepath.Join(bundleDir, bundleFilename)
	if err := os.WriteFile(bundlePath, oversize, 0o600); err != nil {
		t.Fatal(err)
	}

	// Write a lock file (SHA won't matter, we fail before integrity check).
	hash := sha256.Sum256(oversize)
	lock := &LockFile{BundleSHA256: hex.EncodeToString(hash[:]), Unsigned: true}
	if err := WriteLockFile(filepath.Join(bundleDir, lockFilename), lock); err != nil {
		t.Fatal(err)
	}

	result := LoadBundles(dir, LoadOptions{
		MinConfidence:   confidenceLow,
		PipelockVersion: testPipelockVersion,
	})

	if len(result.Errors) != 1 {
		t.Fatalf("expected 1 error for oversized bundle, got %d", len(result.Errors))
	}
}

func TestLoadBundles_RuleTypeRouting(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleDir := filepath.Join(dir, "routing-test")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatal(err)
	}

	b := testBundle("routing-test", []Rule{
		testDLPRule("dlp-001", confidenceHigh, StatusStable),
		testDLPRule("dlp-002", confidenceHigh, StatusStable),
		testInjectionRule("inj-001", confidenceHigh, StatusStable),
		testToolPoisonRule("tp-001", confidenceHigh, StatusStable, scanFieldName),
	})
	writeUnsignedBundle(t, bundleDir, b)

	result := LoadBundles(dir, LoadOptions{
		MinConfidence:   confidenceLow,
		PipelockVersion: testPipelockVersion,
	})

	if len(result.DLP) != 2 {
		t.Errorf("expected 2 DLP rules, got %d", len(result.DLP))
	}
	if len(result.Injection) != 1 {
		t.Errorf("expected 1 Injection rule, got %d", len(result.Injection))
	}
	if len(result.ToolPoison) != 1 {
		t.Errorf("expected 1 ToolPoison rule, got %d", len(result.ToolPoison))
	}
	// Verify scan_field is preserved for tool-poison.
	if result.ToolPoison[0].ScanField != scanFieldName {
		t.Errorf("ToolPoison ScanField = %q, want %q", result.ToolPoison[0].ScanField, scanFieldName)
	}
}

func TestLoadBundles_MissingLockFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleDir := filepath.Join(dir, "no-lock")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatal(err)
	}

	// Only write bundle.yaml, no lock file.
	b := testBundle("no-lock", []Rule{
		testDLPRule("dlp-001", confidenceHigh, StatusStable),
	})
	data, err := yaml.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, bundleFilename), data, 0o600); err != nil {
		t.Fatal(err)
	}

	result := LoadBundles(dir, LoadOptions{
		MinConfidence:   confidenceLow,
		PipelockVersion: testPipelockVersion,
	})

	if len(result.Errors) != 1 {
		t.Fatalf("expected 1 error for missing lock file, got %d: %v", len(result.Errors), result.Errors)
	}
}

func TestLoadBundles_IntegrityFailure(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleDir := filepath.Join(dir, "tampered")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatal(err)
	}

	b := testBundle("tampered", []Rule{
		testDLPRule("dlp-001", confidenceHigh, StatusStable),
	})
	data, err := yaml.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, bundleFilename), data, 0o600); err != nil {
		t.Fatal(err)
	}

	// Write lock file with wrong SHA.
	wrongSHA := "0000000000000000000000000000000000000000000000000000000000000000"
	lock := &LockFile{BundleSHA256: wrongSHA, Unsigned: true}
	if err := WriteLockFile(filepath.Join(bundleDir, lockFilename), lock); err != nil {
		t.Fatal(err)
	}

	result := LoadBundles(dir, LoadOptions{
		MinConfidence:   confidenceLow,
		PipelockVersion: testPipelockVersion,
	})

	if len(result.Errors) != 1 {
		t.Fatalf("expected 1 error for integrity failure, got %d", len(result.Errors))
	}
}

func TestLoadBundles_DLPExemptDomains(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleDir := filepath.Join(dir, "exempt-test")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatal(err)
	}

	rule := testDLPRule("dlp-exempt-001", confidenceHigh, StatusStable)
	rule.Pattern.ExemptDomains = []string{"example.com", "test.org"}
	b := testBundle("exempt-test", []Rule{rule})
	writeUnsignedBundle(t, bundleDir, b)

	result := LoadBundles(dir, LoadOptions{
		MinConfidence:   confidenceLow,
		PipelockVersion: testPipelockVersion,
	})

	if len(result.DLP) != 1 {
		t.Fatalf("expected 1 DLP rule, got %d", len(result.DLP))
	}
	if len(result.DLP[0].ExemptDomains) != 2 {
		t.Errorf("expected 2 exempt domains, got %d", len(result.DLP[0].ExemptDomains))
	}
}

func TestLoadBundles_SkipsNonDirectoryEntries(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Create a regular file (not a directory) in the rules dir.
	if err := os.WriteFile(filepath.Join(dir, "not-a-dir.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Create a valid bundle directory alongside it.
	bundleDir := filepath.Join(dir, "valid-bundle")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatal(err)
	}
	b := testBundle("valid-bundle", []Rule{
		testDLPRule("dlp-001", confidenceHigh, StatusStable),
	})
	writeUnsignedBundle(t, bundleDir, b)

	result := LoadBundles(dir, LoadOptions{
		MinConfidence:   confidenceLow,
		PipelockVersion: testPipelockVersion,
	})

	// Only the directory should be processed.
	if len(result.Errors) != 0 {
		t.Errorf("unexpected errors: %v", result.Errors)
	}
	if len(result.DLP) != 1 {
		t.Errorf("expected 1 DLP rule, got %d", len(result.DLP))
	}
}

func TestLoadBundles_LoadedBundleSource(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleDir := filepath.Join(dir, "source-test")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatal(err)
	}

	b := testBundle("source-test", []Rule{
		testDLPRule("dlp-001", confidenceHigh, StatusStable),
	})
	writeUnsignedBundle(t, bundleDir, b)

	result := LoadBundles(dir, LoadOptions{
		MinConfidence:   confidenceLow,
		PipelockVersion: testPipelockVersion,
	})

	if len(result.Loaded) != 1 {
		t.Fatalf("expected 1 loaded bundle, got %d", len(result.Loaded))
	}
	if result.Loaded[0].Source != "test" {
		t.Errorf("Loaded.Source = %q, want %q", result.Loaded[0].Source, "test")
	}
	if result.Loaded[0].Version != "2026.03.0" {
		t.Errorf("Loaded.Version = %q, want %q", result.Loaded[0].Version, "2026.03.0")
	}
}

func TestIsDisabled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		nsID     string
		disabled []string
		want     bool
	}{
		{
			name:     "exact match",
			nsID:     "bundle:rule-001",
			disabled: []string{"bundle:rule-001"},
			want:     true,
		},
		{
			name:     "no match",
			nsID:     "bundle:rule-001",
			disabled: []string{"bundle:rule-002"},
			want:     false,
		},
		{
			name:     "glob all rules in bundle",
			nsID:     "bundle:rule-001",
			disabled: []string{"bundle:*"},
			want:     true,
		},
		{
			name:     "glob prefix match",
			nsID:     "bundle:dlp-rule-001",
			disabled: []string{"bundle:dlp-*"},
			want:     true,
		},
		{
			name:     "glob no match",
			nsID:     "bundle:inj-rule-001",
			disabled: []string{"bundle:dlp-*"},
			want:     false,
		},
		{
			name:     "empty disabled list",
			nsID:     "bundle:rule-001",
			disabled: nil,
			want:     false,
		},
		{
			name:     "multiple patterns first matches",
			nsID:     "bundle:rule-001",
			disabled: []string{"bundle:rule-001", "other:*"},
			want:     true,
		},
		{
			name:     "glob question mark",
			nsID:     "bundle:rule-001",
			disabled: []string{"bundle:rule-00?"},
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := isDisabled(tt.nsID, tt.disabled)
			if got != tt.want {
				t.Errorf("isDisabled(%q, %v) = %v, want %v", tt.nsID, tt.disabled, got, tt.want)
			}
		})
	}
}

func TestIsOfficialFingerprint(t *testing.T) {
	// Non-parallel: mutates KeyringHex.
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	setupKeyring(t, pub)

	fp := KeyFingerprint(pub)
	if !isOfficialFingerprint(fp) {
		t.Error("expected official fingerprint to return true")
	}

	if isOfficialFingerprint("0000000000000000000000000000000000000000000000000000000000000000") {
		t.Error("expected non-official fingerprint to return false")
	}
}

func TestLoadBundles_MissingBundleYAML(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleDir := filepath.Join(dir, "no-bundle-yaml")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatal(err)
	}

	// Only write lock file, no bundle.yaml.
	lock := &LockFile{BundleSHA256: "deadbeef", Unsigned: true}
	if err := WriteLockFile(filepath.Join(bundleDir, lockFilename), lock); err != nil {
		t.Fatal(err)
	}

	result := LoadBundles(dir, LoadOptions{
		MinConfidence:   confidenceLow,
		PipelockVersion: testPipelockVersion,
	})

	if len(result.Errors) != 1 {
		t.Fatalf("expected 1 error for missing bundle.yaml, got %d", len(result.Errors))
	}
}

func TestLoadBundles_AllRulesDisabled(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleDir := filepath.Join(dir, "all-disabled")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatal(err)
	}

	b := testBundle("all-disabled", []Rule{
		testDLPRule("dlp-001", confidenceHigh, StatusStable),
		testDLPRule("dlp-002", confidenceHigh, StatusStable),
	})
	writeUnsignedBundle(t, bundleDir, b)

	result := LoadBundles(dir, LoadOptions{
		MinConfidence:   confidenceLow,
		Disabled:        []string{"all-disabled:*"},
		PipelockVersion: testPipelockVersion,
	})

	// Bundle still loads successfully, just with 0 rules.
	if len(result.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", result.Errors)
	}
	if len(result.DLP) != 0 {
		t.Errorf("expected 0 DLP rules, got %d", len(result.DLP))
	}
	if len(result.Loaded) != 1 {
		t.Fatalf("expected 1 loaded bundle, got %d", len(result.Loaded))
	}
	if result.Loaded[0].Rules != 0 {
		t.Errorf("Loaded.Rules = %d, want 0", result.Loaded[0].Rules)
	}
}

func TestLoadBundles_ConfidenceFilterLow(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundleDir := filepath.Join(dir, "conf-low-test")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatal(err)
	}

	b := testBundle("conf-low-test", []Rule{
		testDLPRule("dlp-high-001", confidenceHigh, StatusStable),
		testDLPRule("dlp-med-001", confidenceMedium, StatusStable),
		testDLPRule("dlp-low-001", confidenceLow, StatusStable),
	})
	writeUnsignedBundle(t, bundleDir, b)

	result := LoadBundles(dir, LoadOptions{
		MinConfidence:   confidenceLow,
		PipelockVersion: testPipelockVersion,
	})

	// All three should pass with low minimum.
	if len(result.DLP) != 3 {
		t.Fatalf("expected 3 DLP rules with low confidence filter, got %d", len(result.DLP))
	}
}
