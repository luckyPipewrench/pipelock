// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/license"
)

func TestLicenseKeygen(t *testing.T) {
	dir := t.TempDir()

	cmd := rootCmd()
	cmd.SetArgs([]string{"license", "keygen", "--out", dir})
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(&strings.Builder{})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("keygen: %v", err)
	}

	// Verify key files were created.
	privPath := filepath.Join(dir, licensePrivKeyFile)
	pubPath := filepath.Join(dir, licensePubKeyFile)

	if _, err := os.Stat(privPath); err != nil {
		t.Errorf("private key not created: %v", err)
	}
	if _, err := os.Stat(pubPath); err != nil {
		t.Errorf("public key not created: %v", err)
	}

	// Verify output mentions key paths.
	output := buf.String()
	if !strings.Contains(output, "Private key:") {
		t.Error("output missing private key path")
	}
	if !strings.Contains(output, "Public key") {
		t.Error("output missing public key info")
	}

	// Verify private key has restricted permissions.
	info, err := os.Stat(privPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("private key perms = %o, want 0600", info.Mode().Perm())
	}
}

func TestLicenseKeygen_RefusesOverwrite(t *testing.T) {
	dir := t.TempDir()

	// Create existing key file.
	privPath := filepath.Join(dir, licensePrivKeyFile)
	if err := os.WriteFile(privPath, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"license", "keygen", "--out", dir})
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when key already exists")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error = %q, want 'already exists'", err)
	}
}

func TestLicenseIssue(t *testing.T) {
	dir := t.TempDir()

	// Generate keys first.
	cmd := rootCmd()
	cmd.SetArgs([]string{"license", "keygen", "--out", dir})
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("keygen: %v", err)
	}

	// Issue a license.
	keyPath := filepath.Join(dir, licensePrivKeyFile)
	ledgerPath := filepath.Join(dir, licenseLedgerFile)

	cmd = rootCmd()
	cmd.SetArgs([]string{
		"license", "issue",
		"--key", keyPath,
		"--email", "test@example.com",
		"--org", "TestCorp",
		"--expires", "2028-01-01",
		"--features", "agents",
		"--ledger", ledgerPath,
	})
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(&strings.Builder{})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("issue: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "test@example.com") {
		t.Error("output missing email")
	}
	if !strings.Contains(output, "TestCorp") {
		t.Error("output missing org")
	}
	if !strings.Contains(output, "2028-01-01") {
		t.Error("output missing expiry date")
	}
	if !strings.Contains(output, "pipelock_lic_v1_") {
		t.Error("output missing license token")
	}

	// Verify ledger was written.
	ledgerData, err := os.ReadFile(filepath.Clean(ledgerPath))
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	var entry ledgerEntry
	if err := json.Unmarshal(ledgerData, &entry); err != nil {
		t.Fatalf("unmarshal ledger: %v", err)
	}
	if entry.Email != "test@example.com" {
		t.Errorf("ledger email = %q, want test@example.com", entry.Email)
	}
}

func TestLicenseIssue_MissingEmail(t *testing.T) {
	dir := t.TempDir()

	// Generate keys.
	cmd := rootCmd()
	cmd.SetArgs([]string{"license", "keygen", "--out", dir})
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("keygen: %v", err)
	}

	// Issue without email.
	cmd = rootCmd()
	cmd.SetArgs([]string{
		"license", "issue",
		"--key", filepath.Join(dir, licensePrivKeyFile),
	})
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing email")
	}
	if !strings.Contains(err.Error(), "--email") {
		t.Errorf("error = %q, want mention of --email", err)
	}
}

func TestLicenseIssue_NoExpiry(t *testing.T) {
	dir := t.TempDir()

	cmd := rootCmd()
	cmd.SetArgs([]string{"license", "keygen", "--out", dir})
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("keygen: %v", err)
	}

	cmd = rootCmd()
	cmd.SetArgs([]string{
		"license", "issue",
		"--key", filepath.Join(dir, licensePrivKeyFile),
		"--email", "noexpiry@example.com",
		"--ledger", filepath.Join(dir, licenseLedgerFile),
	})
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(&strings.Builder{})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("issue: %v", err)
	}

	if !strings.Contains(buf.String(), "Expires:  never") {
		t.Error("expected 'never' for no-expiry license")
	}
}

func TestLicenseInspect(t *testing.T) {
	// Create a token to inspect.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = pub

	lic := license.License{
		ID:        "lic_inspect_test",
		Email:     "inspect@example.com",
		Org:       "InspectOrg",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour).Unix(),
		Features:  []string{license.FeatureAgents},
	}
	token, err := license.Issue(lic, priv)
	if err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"license", "inspect", token})
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(&strings.Builder{})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("inspect: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "lic_inspect_test") {
		t.Error("output missing license ID")
	}
	if !strings.Contains(output, "inspect@example.com") {
		t.Error("output missing email")
	}
	if !strings.Contains(output, "InspectOrg") {
		t.Error("output missing org")
	}
	if !strings.Contains(output, "not expired") {
		t.Error("expected 'not expired' status")
	}
}

func TestLicenseInspect_Expired(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	lic := license.License{
		ID:        "lic_expired_test",
		Email:     "expired@example.com",
		IssuedAt:  time.Now().Add(-48 * time.Hour).Unix(),
		ExpiresAt: time.Now().Add(-24 * time.Hour).Unix(),
		Features:  []string{license.FeatureAgents},
	}
	token, err := license.Issue(lic, priv)
	if err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"license", "inspect", token})
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(&strings.Builder{})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("inspect: %v", err)
	}

	if !strings.Contains(buf.String(), "EXPIRED") {
		t.Error("expected EXPIRED status for expired token")
	}
}

func TestLicenseInspect_BadToken(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"license", "inspect", "not-a-valid-token"})
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestAppendLedger(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test-ledger.jsonl")

	lic := license.License{
		ID:        "lic_ledger_test",
		Email:     "ledger@example.com",
		Org:       "LedgerOrg",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		Features:  []string{license.FeatureAgents},
	}

	if err := appendLedger(path, lic, "pipelock_lic_v1_test"); err != nil {
		t.Fatalf("appendLedger: %v", err)
	}

	// Append a second entry.
	lic.ID = "lic_ledger_test_2"
	if err := appendLedger(path, lic, "pipelock_lic_v1_test2"); err != nil {
		t.Fatalf("appendLedger second: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 ledger lines, got %d", len(lines))
	}

	var entry ledgerEntry
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("unmarshal first entry: %v", err)
	}
	if entry.ID != "lic_ledger_test" {
		t.Errorf("first entry ID = %q, want lic_ledger_test", entry.ID)
	}
	if entry.ExpiresAt == "" {
		t.Error("expected expires_at in ledger entry")
	}
}

func TestAppendLedger_RejectsSymlink(t *testing.T) {
	dir := t.TempDir()

	// Create a target and a symlink to it.
	target := filepath.Join(dir, "real-ledger.jsonl")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "symlink-ledger.jsonl")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	lic := license.License{
		ID:       "lic_symlink_test",
		Email:    "symlink@example.com",
		IssuedAt: time.Now().Unix(),
		Features: []string{license.FeatureAgents},
	}

	err := appendLedger(link, lic, "token")
	if err == nil {
		t.Fatal("expected error for symlink ledger path")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error = %q, want symlink mention", err)
	}
}

func TestLicenseInspect_NoExpiry(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	lic := license.License{
		ID:       "lic_no_exp",
		Email:    "noexp@example.com",
		IssuedAt: time.Now().Unix(),
		Features: []string{license.FeatureAgents},
	}
	token, err := license.Issue(lic, priv)
	if err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"license", "inspect", token})
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(&strings.Builder{})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("inspect: %v", err)
	}

	if !strings.Contains(buf.String(), "Expires:  never") {
		t.Error("expected 'never' for no-expiry token")
	}
}

func TestLicenseCmdInHelp(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"license", "--help"})
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	_ = cmd.Execute()
	output := buf.String()
	if !strings.Contains(output, "keygen") {
		t.Error("help missing keygen subcommand")
	}
	if !strings.Contains(output, "issue") {
		t.Error("help missing issue subcommand")
	}
	if !strings.Contains(output, "inspect") {
		t.Error("help missing inspect subcommand")
	}
}

func TestLicenseIssue_BadExpiry(t *testing.T) {
	dir := t.TempDir()

	cmd := rootCmd()
	cmd.SetArgs([]string{"license", "keygen", "--out", dir})
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("keygen: %v", err)
	}

	cmd = rootCmd()
	cmd.SetArgs([]string{
		"license", "issue",
		"--key", filepath.Join(dir, licensePrivKeyFile),
		"--email", "test@example.com",
		"--expires", "not-a-date",
	})
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid date format")
	}
	if !strings.Contains(err.Error(), "parse --expires") {
		t.Errorf("error = %q, want parse error", err)
	}
}

func TestLicenseIssue_BadKeyPath(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{
		"license", "issue",
		"--key", "/nonexistent/path/license.key",
		"--email", "test@example.com",
	})
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing key file")
	}
	if !strings.Contains(err.Error(), "load private key") {
		t.Errorf("error = %q, want load error", err)
	}
}

func TestLicenseInspect_NoOrgField(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	lic := license.License{
		ID:        "lic_no_org",
		Email:     "noorg@example.com",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		Features:  []string{license.FeatureAgents},
	}
	token, err := license.Issue(lic, priv)
	if err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"license", "inspect", token})
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(&strings.Builder{})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("inspect: %v", err)
	}

	// Without org, the Org line should be omitted.
	if strings.Contains(buf.String(), "Org:") {
		t.Error("expected Org line to be omitted when empty")
	}
}

func TestLicenseIssue_DefaultFeatures(t *testing.T) {
	dir := t.TempDir()

	cmd := rootCmd()
	cmd.SetArgs([]string{"license", "keygen", "--out", dir})
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("keygen: %v", err)
	}

	// Issue without --features flag.
	cmd = rootCmd()
	cmd.SetArgs([]string{
		"license", "issue",
		"--key", filepath.Join(dir, licensePrivKeyFile),
		"--email", "default@example.com",
		"--ledger", filepath.Join(dir, licenseLedgerFile),
	})
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(&strings.Builder{})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Default features should include "agents".
	if !strings.Contains(buf.String(), "agents") {
		t.Error("default features should include 'agents'")
	}
}

func TestAppendLedger_NoExpiry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test-ledger.jsonl")

	lic := license.License{
		ID:       "lic_no_exp",
		Email:    "noexp@example.com",
		IssuedAt: time.Now().Unix(),
		Features: []string{license.FeatureAgents},
	}

	if err := appendLedger(path, lic, "token"); err != nil {
		t.Fatalf("appendLedger: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}

	var entry ledgerEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if entry.ExpiresAt != "" {
		t.Errorf("expected empty expires_at for no-expiry, got %q", entry.ExpiresAt)
	}
}

// TestLicenseIssueAndInspectRoundTrip verifies the full keygen -> issue ->
// inspect workflow produces consistent output.
func TestLicenseIssueAndInspectRoundTrip(t *testing.T) {
	dir := t.TempDir()

	// Keygen.
	cmd := rootCmd()
	cmd.SetArgs([]string{"license", "keygen", "--out", dir})
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("keygen: %v", err)
	}

	// Issue.
	cmd = rootCmd()
	cmd.SetArgs([]string{
		"license", "issue",
		"--key", filepath.Join(dir, licensePrivKeyFile),
		"--email", "roundtrip@example.com",
		"--expires", "2029-06-15",
		"--ledger", filepath.Join(dir, licenseLedgerFile),
	})
	issueBuf := &strings.Builder{}
	cmd.SetOut(issueBuf)
	cmd.SetErr(&strings.Builder{})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Extract token from issue output.
	issueOutput := issueBuf.String()
	var token string
	for _, line := range strings.Split(issueOutput, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "pipelock_lic_v1_") {
			token = line
			break
		}
	}
	if token == "" {
		t.Fatalf("could not find token in issue output:\n%s", issueOutput)
	}

	// Inspect.
	cmd = rootCmd()
	cmd.SetArgs([]string{"license", "inspect", token})
	inspectBuf := &strings.Builder{}
	cmd.SetOut(inspectBuf)
	cmd.SetErr(&strings.Builder{})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("inspect: %v", err)
	}

	inspectOutput := inspectBuf.String()
	if !strings.Contains(inspectOutput, "roundtrip@example.com") {
		t.Error("inspect output missing email from issued token")
	}
	if !strings.Contains(inspectOutput, "2029-06-15") {
		t.Error("inspect output missing expiry date from issued token")
	}

	// Verify token from issue output is also in the ledger.
	ledgerData, err := os.ReadFile(filepath.Clean(filepath.Join(dir, licenseLedgerFile)))
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	if !strings.Contains(string(ledgerData), token) {
		t.Error("ledger does not contain the issued token")
	}
}
