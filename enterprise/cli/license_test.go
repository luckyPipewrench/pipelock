//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package entcli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestLicenseCmd(t *testing.T) {
	cmd := LicenseCmd()
	if cmd.Use != "license" {
		t.Errorf("Use = %q, want license", cmd.Use)
	}
	if len(cmd.Commands()) != 3 {
		t.Errorf("expected 3 subcommands (keygen, issue, inspect), got %d", len(cmd.Commands()))
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
