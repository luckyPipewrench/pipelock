//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package entcli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const testOSWindows = "windows"

// setTestHome overrides both HOME (Unix) and USERPROFILE (Windows) so
// os.UserHomeDir() returns the temp directory on all platforms.
func setTestHome(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
}

func TestLicenseCmd(t *testing.T) {
	cmd := LicenseCmd()
	if cmd.Use != "license" {
		t.Errorf("Use = %q, want license", cmd.Use)
	}
	got := make(map[string]bool, len(cmd.Commands()))
	for _, sub := range cmd.Commands() {
		got[strings.Fields(sub.Use)[0]] = true
	}
	for _, want := range []string{"keygen", "issue", "inspect", "install"} {
		if !got[want] {
			t.Errorf("missing %q subcommand", want)
		}
	}
}

func TestLicenseKeygen(t *testing.T) {
	dir := t.TempDir()

	cmd := licenseKeygenCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--out", dir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("keygen: %v", err)
	}

	// Verify files were created.
	privPath := filepath.Join(dir, licensePrivKeyFile)
	pubPath := filepath.Join(dir, licensePubKeyFile)

	if _, err := os.Stat(privPath); err != nil {
		t.Errorf("private key not created: %v", err)
	}
	if _, err := os.Stat(pubPath); err != nil {
		t.Errorf("public key not created: %v", err)
	}

	if !strings.Contains(buf.String(), "Keypair generated") {
		t.Error("expected 'Keypair generated' in output")
	}
}

func TestLicenseKeygen_ExistingKey(t *testing.T) {
	dir := t.TempDir()

	// Create a dummy key file.
	privPath := filepath.Join(dir, licensePrivKeyFile)
	if err := os.WriteFile(privPath, []byte("dummy"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := licenseKeygenCmd()
	cmd.SetArgs([]string{"--out", dir})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when key already exists")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected 'already exists' error, got: %v", err)
	}
}

func TestLicenseIssue(t *testing.T) {
	dir := t.TempDir()

	// Generate keypair first.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privPath := filepath.Join(dir, licensePrivKeyFile)
	if err := signing.SavePrivateKey(priv, privPath); err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(dir, licensePubKeyFile)
	if err := signing.SavePublicKey(pub, pubPath); err != nil {
		t.Fatal(err)
	}

	ledgerPath := filepath.Join(dir, licenseLedgerFile)

	cmd := licenseIssueCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--key", privPath,
		"--email", "test@example.com",
		"--org", "Test Org",
		"--expires", time.Now().Add(365 * 24 * time.Hour).Format(time.DateOnly),
		"--ledger", ledgerPath,
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("issue: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "License issued") {
		t.Error("expected 'License issued' in output")
	}
	if !strings.Contains(output, "test@example.com") {
		t.Error("expected email in output")
	}
	if !strings.Contains(output, "Test Org") {
		t.Error("expected org in output")
	}

	// Verify ledger was created.
	if _, err := os.Stat(ledgerPath); err != nil {
		t.Errorf("ledger not created: %v", err)
	}
}

func TestLicenseIssue_WithTierAndSubscription(t *testing.T) {
	dir := t.TempDir()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privPath := filepath.Join(dir, licensePrivKeyFile)
	if err := signing.SavePrivateKey(priv, privPath); err != nil {
		t.Fatal(err)
	}

	ledgerPath := filepath.Join(dir, licenseLedgerFile)

	cmd := licenseIssueCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--key", privPath,
		"--email", "pro@example.com",
		"--tier", "founding_pro",
		"--subscription-id", "sub_polar_test123",
		"--expires", time.Now().Add(45 * 24 * time.Hour).Format(time.DateOnly),
		"--ledger", ledgerPath,
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("issue with tier: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "founding_pro") {
		t.Error("expected tier in output")
	}
	if !strings.Contains(output, "sub_polar_test123") {
		t.Error("expected subscription ID in output")
	}

	// Verify ledger contains the new fields.
	data, err := os.ReadFile(filepath.Clean(ledgerPath))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "founding_pro") {
		t.Error("expected tier in ledger")
	}
	if !strings.Contains(string(data), "sub_polar_test123") {
		t.Error("expected subscription_id in ledger")
	}
}

func TestLicenseIssue_NoEmail(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	privPath := filepath.Join(dir, licensePrivKeyFile)
	_ = signing.SavePrivateKey(priv, privPath)
	_ = signing.SavePublicKey(pub, filepath.Join(dir, licensePubKeyFile))

	cmd := licenseIssueCmd()
	cmd.SetArgs([]string{"--key", privPath})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when email missing")
	}
	if !strings.Contains(err.Error(), "email") {
		t.Errorf("expected email error, got: %v", err)
	}
}

func TestLicenseIssue_NoExpiry(t *testing.T) {
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	privPath := filepath.Join(dir, licensePrivKeyFile)
	_ = signing.SavePrivateKey(priv, privPath)

	cmd := licenseIssueCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--key", privPath,
		"--email", "test@example.com",
		"--ledger", filepath.Join(dir, licenseLedgerFile),
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("issue without expiry: %v", err)
	}
	if !strings.Contains(buf.String(), "never") {
		t.Error("expected 'never' for no-expiry license")
	}
}

func TestLicenseInspect(t *testing.T) {
	// Generate a token to inspect.
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	lic := license.License{
		ID:        "lic_test",
		Email:     "test@example.com",
		Org:       "Test Org",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		Features:  []string{license.FeatureAgents},
	}
	token, err := license.Issue(lic, priv)
	if err != nil {
		t.Fatal(err)
	}

	cmd := licenseInspectCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{token})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("inspect: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "lic_test") {
		t.Error("expected license ID in output")
	}
	if !strings.Contains(output, "test@example.com") {
		t.Error("expected email in output")
	}
	if !strings.Contains(output, "not expired") {
		t.Error("expected 'not expired' status")
	}
}

func TestLicenseInspect_WithTierFields(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	lic := license.License{
		ID:             "lic_tier",
		Email:          "pro@example.com",
		IssuedAt:       time.Now().Unix(),
		ExpiresAt:      time.Now().Add(24 * time.Hour).Unix(),
		Features:       []string{license.FeatureAgents},
		Tier:           "pro",
		SubscriptionID: "sub_abc",
	}
	token, err := license.Issue(lic, priv)
	if err != nil {
		t.Fatal(err)
	}

	cmd := licenseInspectCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{token})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("inspect: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "pro") {
		t.Error("expected tier in inspect output")
	}
	if !strings.Contains(output, "sub_abc") {
		t.Error("expected subscription ID in inspect output")
	}
}

func TestLicenseInspect_ExpiredToken(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	lic := license.License{
		ID:        "lic_expired",
		Email:     "test@example.com",
		IssuedAt:  time.Now().Add(-48 * time.Hour).Unix(),
		ExpiresAt: time.Now().Add(-24 * time.Hour).Unix(),
		Features:  []string{license.FeatureAgents},
	}
	token, err := license.Issue(lic, priv)
	if err != nil {
		t.Fatal(err)
	}

	cmd := licenseInspectCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{token})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if !strings.Contains(buf.String(), "EXPIRED") {
		t.Error("expected 'EXPIRED' status for expired token")
	}
}

func TestLicenseInspect_NoExpiry(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	lic := license.License{
		ID:       "lic_perpetual",
		Email:    "test@example.com",
		IssuedAt: time.Now().Unix(),
		Features: []string{license.FeatureAgents},
	}
	token, err := license.Issue(lic, priv)
	if err != nil {
		t.Fatal(err)
	}

	cmd := licenseInspectCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{token})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if !strings.Contains(buf.String(), "never") {
		t.Error("expected 'never' for perpetual license")
	}
}

func TestLicenseInspect_InvalidToken(t *testing.T) {
	cmd := licenseInspectCmd()
	cmd.SetArgs([]string{"not-a-valid-token"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestAppendLedger(t *testing.T) {
	dir := t.TempDir()
	ledgerPath := filepath.Join(dir, "test-ledger.jsonl")

	lic := license.License{
		ID:        "lic_test",
		Email:     "test@example.com",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		Features:  []string{license.FeatureAgents},
	}

	if err := appendLedger(ledgerPath, lic, "fake-token"); err != nil {
		t.Fatalf("appendLedger: %v", err)
	}

	// Verify file was created and contains the entry.
	data, err := os.ReadFile(filepath.Clean(ledgerPath))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "lic_test") {
		t.Error("expected license ID in ledger")
	}

	// Append a second entry.
	lic2 := license.License{
		ID:       "lic_test2",
		Email:    "test2@example.com",
		IssuedAt: time.Now().Unix(),
		Features: []string{license.FeatureAgents},
	}
	if err := appendLedger(ledgerPath, lic2, "fake-token-2"); err != nil {
		t.Fatalf("appendLedger second: %v", err)
	}

	data, err = os.ReadFile(filepath.Clean(ledgerPath))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Errorf("expected 2 ledger lines, got %d", len(lines))
	}
}

func TestLicenseInstall(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	lic := license.License{
		ID:        "lic_install",
		Email:     "install@example.com",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(45 * 24 * time.Hour).Unix(),
		Features:  []string{license.FeatureAgents},
	}
	token, err := license.Issue(lic, priv)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "license.token")

	cmd := licenseInstallCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--path", tokenPath, token})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("install: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "License installed") {
		t.Error("expected 'License installed' in output")
	}
	if !strings.Contains(output, "lic_install") {
		t.Error("expected license ID in output")
	}
	if !strings.Contains(output, "license_file:") {
		t.Error("expected config hint in output")
	}

	// Verify file was written with correct content and permissions.
	data, err := os.ReadFile(filepath.Clean(tokenPath))
	if err != nil {
		t.Fatalf("read token file: %v", err)
	}
	if strings.TrimSpace(string(data)) != token {
		t.Error("token file content doesn't match")
	}
	info, err := os.Stat(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != testOSWindows && info.Mode().Perm() != 0o600 {
		t.Errorf("token file mode = %04o, want 0600", info.Mode().Perm())
	}
}

func TestLicenseInstall_InvalidToken(t *testing.T) {
	cmd := licenseInstallCmd()
	cmd.SetArgs([]string{"not-a-valid-token"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
	if !strings.Contains(err.Error(), "invalid license token") {
		t.Errorf("expected 'invalid license token' error, got: %v", err)
	}
}

func TestLicenseInstall_CreatesDirectory(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	lic := license.License{
		ID:       "lic_mkdir",
		Email:    "mkdir@example.com",
		IssuedAt: time.Now().Unix(),
		Features: []string{license.FeatureAgents},
	}
	token, err := license.Issue(lic, priv)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	// Nested path that doesn't exist yet.
	tokenPath := filepath.Join(dir, "nested", "dir", "license.token")

	cmd := licenseInstallCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--path", tokenPath, token})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("install with nested dir: %v", err)
	}

	if _, err := os.Stat(tokenPath); err != nil {
		t.Errorf("token file not created: %v", err)
	}
	if runtime.GOOS != testOSWindows {
		info, err := os.Stat(filepath.Dir(tokenPath))
		if err != nil {
			t.Fatalf("stat parent dir: %v", err)
		}
		if info.Mode().Perm() != 0o750 {
			t.Errorf("parent dir mode = %04o, want 0750", info.Mode().Perm())
		}
	}
}

func TestLicenseInstall_OverwritesExisting(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)

	// Write first token.
	lic1 := license.License{
		ID:       "lic_old",
		Email:    "old@example.com",
		IssuedAt: time.Now().Unix(),
		Features: []string{license.FeatureAgents},
	}
	token1, _ := license.Issue(lic1, priv)

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "license.token")
	if err := os.WriteFile(tokenPath, []byte(token1), 0o600); err != nil {
		t.Fatal(err)
	}

	// Install second token over it.
	lic2 := license.License{
		ID:       "lic_new",
		Email:    "new@example.com",
		IssuedAt: time.Now().Unix(),
		Features: []string{license.FeatureAgents},
	}
	token2, _ := license.Issue(lic2, priv)

	cmd := licenseInstallCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--path", tokenPath, token2})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("install overwrite: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(tokenPath))
	if err != nil {
		t.Fatal(err)
	}
	// Decode the installed token to verify it's the new one.
	installed, err := license.Decode(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("decode installed token: %v", err)
	}
	if installed.ID != "lic_new" {
		t.Errorf("installed token ID = %q, want lic_new", installed.ID)
	}
}

func TestLicenseInstall_DefaultPath(t *testing.T) {
	// Override HOME so the default path lands in a temp dir.
	dir := t.TempDir()
	setTestHome(t, dir)

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	lic := license.License{
		ID:       "lic_default_path",
		Email:    "default@example.com",
		IssuedAt: time.Now().Unix(),
		Features: []string{license.FeatureAgents},
	}
	token, err := license.Issue(lic, priv)
	if err != nil {
		t.Fatal(err)
	}

	cmd := licenseInstallCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{token}) // no --path flag

	if err := cmd.Execute(); err != nil {
		t.Fatalf("install default path: %v", err)
	}

	expectedPath := filepath.Join(dir, licenseDefaultDir, licenseDefaultTokenFile)
	if _, err := os.Stat(expectedPath); err != nil {
		t.Errorf("token file not created at default path %s: %v", expectedPath, err)
	}
	output := buf.String()
	if !strings.Contains(output, expectedPath) {
		t.Error("expected default path in output")
	}
}

func TestLicenseInstall_NoExpiryOutput(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	lic := license.License{
		ID:       "lic_perpetual_install",
		Email:    "forever@example.com",
		IssuedAt: time.Now().Unix(),
		Features: []string{license.FeatureAgents},
		// No ExpiresAt = perpetual
	}
	token, err := license.Issue(lic, priv)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "license.token")

	cmd := licenseInstallCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--path", tokenPath, token})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("install: %v", err)
	}
	if !strings.Contains(buf.String(), "never") {
		t.Error("expected 'never' for perpetual license install")
	}
}

func TestLicenseKeygen_DefaultPath(t *testing.T) {
	dir := t.TempDir()
	setTestHome(t, dir)

	cmd := licenseKeygenCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{}) // no --out flag

	if err := cmd.Execute(); err != nil {
		t.Fatalf("keygen default path: %v", err)
	}

	expectedPriv := filepath.Join(dir, licenseDefaultDir, licensePrivKeyFile)
	if _, err := os.Stat(expectedPriv); err != nil {
		t.Errorf("private key not created at default path: %v", err)
	}
	expectedPub := filepath.Join(dir, licenseDefaultDir, licensePubKeyFile)
	if _, err := os.Stat(expectedPub); err != nil {
		t.Errorf("public key not created at default path: %v", err)
	}
}

func TestLicenseIssue_DefaultKeyPath(t *testing.T) {
	dir := t.TempDir()
	setTestHome(t, dir)

	// Generate keypair at default location.
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	keyDir := filepath.Join(dir, licenseDefaultDir)
	if err := os.MkdirAll(keyDir, 0o750); err != nil {
		t.Fatal(err)
	}
	privPath := filepath.Join(keyDir, licensePrivKeyFile)
	if err := signing.SavePrivateKey(priv, privPath); err != nil {
		t.Fatal(err)
	}

	cmd := licenseIssueCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	// No --key flag; should use default path.
	cmd.SetArgs([]string{
		"--email", "default@example.com",
		"--ledger", filepath.Join(dir, licenseLedgerFile),
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("issue with default key path: %v", err)
	}
	if !strings.Contains(buf.String(), "License issued") {
		t.Error("expected successful issue output")
	}
}

func TestLicenseIssue_BadExpiresFormat(t *testing.T) {
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	privPath := filepath.Join(dir, licensePrivKeyFile)
	_ = signing.SavePrivateKey(priv, privPath)

	cmd := licenseIssueCmd()
	cmd.SetArgs([]string{
		"--key", privPath,
		"--email", "test@example.com",
		"--expires", "not-a-date",
		"--ledger", filepath.Join(dir, licenseLedgerFile),
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for bad date format")
	}
	if !strings.Contains(err.Error(), "parse --expires") {
		t.Errorf("expected date parse error, got: %v", err)
	}
}

func TestLicenseIssue_MissingKeyFile(t *testing.T) {
	missingKey := filepath.Join(t.TempDir(), licensePrivKeyFile)

	cmd := licenseIssueCmd()
	cmd.SetArgs([]string{
		"--key", missingKey,
		"--email", "test@example.com",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing key file")
	}
	if !strings.Contains(err.Error(), "load private key") {
		t.Errorf("expected key load error, got: %v", err)
	}
}

func TestLicenseIssue_DefaultLedgerPath(t *testing.T) {
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	privPath := filepath.Join(dir, licensePrivKeyFile)
	_ = signing.SavePrivateKey(priv, privPath)

	cmd := licenseIssueCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	// No --ledger flag; should default to alongside the private key.
	cmd.SetArgs([]string{
		"--key", privPath,
		"--email", "test@example.com",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("issue with default ledger: %v", err)
	}

	expectedLedger := filepath.Join(dir, licenseLedgerFile)
	if _, err := os.Stat(expectedLedger); err != nil {
		t.Errorf("ledger not created at default path %s: %v", expectedLedger, err)
	}
	if !strings.Contains(buf.String(), expectedLedger) {
		t.Error("expected default ledger path in output")
	}
}

func TestLicenseIssue_LedgerWriteFailWarns(t *testing.T) {
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	privPath := filepath.Join(dir, licensePrivKeyFile)
	_ = signing.SavePrivateKey(priv, privPath)

	// Point ledger to a directory (can't write a file there).
	ledgerDir := filepath.Join(dir, "ledger-is-a-dir")
	if err := os.MkdirAll(ledgerDir, 0o750); err != nil {
		t.Fatal(err)
	}

	cmd := licenseIssueCmd()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{
		"--key", privPath,
		"--email", "test@example.com",
		"--ledger", ledgerDir, // directory, not a file
	})

	// Should succeed (ledger failure is a warning, not fatal).
	if err := cmd.Execute(); err != nil {
		t.Fatalf("issue should succeed despite ledger failure: %v", err)
	}
	if !strings.Contains(stderr.String(), "WARNING: failed to write ledger") {
		t.Error("expected ledger warning on stderr")
	}
	if !strings.Contains(stdout.String(), "License issued") {
		t.Error("expected successful issue output despite ledger warning")
	}
}

func TestAppendLedger_UnwritablePath(t *testing.T) {
	ledgerPath := filepath.Join(t.TempDir(), "missing", "ledger.jsonl")

	lic := license.License{
		ID:        "lic_unwritable",
		Email:     "test@example.com",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		Features:  []string{license.FeatureAgents},
	}
	err := appendLedger(ledgerPath, lic, "token")
	if err == nil {
		t.Fatal("expected error for unwritable ledger path")
	}
}

func TestAppendLedger_WithExpiry(t *testing.T) {
	dir := t.TempDir()
	ledgerPath := filepath.Join(dir, "test-ledger.jsonl")

	lic := license.License{
		ID:        "lic_expiry",
		Email:     "expiry@example.com",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(45 * 24 * time.Hour).Unix(),
		Features:  []string{license.FeatureAgents},
	}

	if err := appendLedger(ledgerPath, lic, "fake-token"); err != nil {
		t.Fatalf("appendLedger: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(ledgerPath))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "expires_at") {
		t.Error("expected expires_at in ledger entry")
	}
}

func TestLicenseKeygen_MkdirAllFails(t *testing.T) {
	dir := t.TempDir()
	// Create a regular file where MkdirAll expects a directory.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := licenseKeygenCmd()
	cmd.SetArgs([]string{"--out", filepath.Join(blocker, "subdir")})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when MkdirAll fails")
	}
	if !strings.Contains(err.Error(), "create output dir") {
		t.Errorf("expected 'create output dir' error, got: %v", err)
	}
}

func TestLicenseInstall_MkdirAllFails(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	lic := license.License{
		ID:       "lic_mkdirfail",
		Email:    "mkdir@example.com",
		IssuedAt: time.Now().Unix(),
		Features: []string{license.FeatureAgents},
	}
	token, err := license.Issue(lic, priv)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	// Create a regular file where MkdirAll expects a directory.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := licenseInstallCmd()
	cmd.SetArgs([]string{"--path", filepath.Join(blocker, "subdir", "license.token"), token})

	err = cmd.Execute()
	if err == nil {
		t.Fatal("expected error when MkdirAll fails")
	}
	if !strings.Contains(err.Error(), "create directory") {
		t.Errorf("expected 'create directory' error, got: %v", err)
	}
}

func TestLicenseInstall_WriteFileFails(t *testing.T) {
	if runtime.GOOS == testOSWindows {
		t.Skip("os.Chmod does not enforce Unix permission semantics on Windows")
	}

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	lic := license.License{
		ID:       "lic_writefail",
		Email:    "write@example.com",
		IssuedAt: time.Now().Unix(),
		Features: []string{license.FeatureAgents},
	}
	token, err := license.Issue(lic, priv)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	// Make the directory read-only so WriteFile fails.
	tokenPath := filepath.Join(dir, "license.token")
	if err := os.Chmod(dir, 0o500); err != nil { //nolint:gosec // directories need execute bit to be traversable; 0o500 is read-only for owner
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(dir, 0o750) //nolint:gosec // restoring standard directory permissions for test cleanup
	})

	cmd := licenseInstallCmd()
	cmd.SetArgs([]string{"--path", tokenPath, token})

	err = cmd.Execute()
	if err == nil {
		t.Fatal("expected error when WriteFile fails")
	}
	if !strings.Contains(err.Error(), "write license file") {
		t.Errorf("expected 'write license file' error, got: %v", err)
	}
}

func TestAppendLedger_Symlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real-file")
	if err := os.WriteFile(target, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "symlink")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	lic := license.License{ID: "lic_test", Email: "test@example.com"}
	err := appendLedger(link, lic, "token")
	if err == nil {
		t.Fatal("expected error for symlink ledger path")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected symlink error, got: %v", err)
	}
}
