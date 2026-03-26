//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package entcli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/license"
)

// --- appendLedger coverage tests (76.2% -> higher) ---

func TestAppendLedger_CreatesNewFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "new-ledger.jsonl")

	lic := license.License{
		ID:       "lic_new",
		Email:    "new@example.com",
		IssuedAt: time.Now().Unix(),
		Features: []string{license.FeatureAgents},
	}

	if err := appendLedger(path, lic, "token-abc"); err != nil {
		t.Fatalf("appendLedger new file: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "lic_new") {
		t.Error("expected license ID in new ledger")
	}

	// Verify permissions.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("permissions = %04o, want 0600", info.Mode().Perm())
	}
}

func TestAppendLedger_AppendsToExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing.jsonl")

	lic1 := license.License{
		ID:       "lic_first",
		Email:    "first@example.com",
		IssuedAt: time.Now().Unix(),
		Features: []string{license.FeatureAgents},
	}
	if err := appendLedger(path, lic1, "token-1"); err != nil {
		t.Fatal(err)
	}

	lic2 := license.License{
		ID:       "lic_second",
		Email:    "second@example.com",
		IssuedAt: time.Now().Unix(),
		Features: []string{license.FeatureAgents},
	}
	if err := appendLedger(path, lic2, "token-2"); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Errorf("expected 2 lines, got %d", len(lines))
	}

	// Verify each line is valid JSON.
	for i, line := range lines {
		var entry ledgerEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Errorf("line %d invalid JSON: %v", i+1, err)
		}
	}
}

func TestAppendLedger_WithExpiryField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "expiry.jsonl")

	lic := license.License{
		ID:        "lic_exp",
		Email:     "exp@example.com",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour).Unix(),
		Features:  []string{license.FeatureAgents},
	}
	if err := appendLedger(path, lic, "token-exp"); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}

	var entry ledgerEntry
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &entry); err != nil {
		t.Fatal(err)
	}
	if entry.ExpiresAt == "" {
		t.Error("expected expires_at in ledger entry")
	}
}

func TestAppendLedger_NoExpiry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "no-expiry.jsonl")

	lic := license.License{
		ID:       "lic_perp",
		Email:    "perp@example.com",
		IssuedAt: time.Now().Unix(),
		Features: []string{license.FeatureAgents},
		// ExpiresAt = 0 (perpetual)
	}
	if err := appendLedger(path, lic, "token-perp"); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}

	var entry ledgerEntry
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &entry); err != nil {
		t.Fatal(err)
	}
	if entry.ExpiresAt != "" {
		t.Errorf("expected empty expires_at for perpetual, got %q", entry.ExpiresAt)
	}
}

func TestAppendLedger_TokenHashPresent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hash.jsonl")

	lic := license.License{
		ID:       "lic_hash",
		Email:    "hash@example.com",
		IssuedAt: time.Now().Unix(),
		Features: []string{license.FeatureAgents},
	}
	if err := appendLedger(path, lic, "secret-token-value"); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}

	var entry ledgerEntry
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &entry); err != nil {
		t.Fatal(err)
	}

	// Token hash should be present and non-empty.
	if entry.TokenHash == "" {
		t.Error("expected non-empty token_hash")
	}
	// Should be 32 hex chars (16 bytes truncated SHA-256).
	if len(entry.TokenHash) != 32 {
		t.Errorf("token_hash length = %d, want 32", len(entry.TokenHash))
	}
	// Raw token should NOT appear in ledger.
	if strings.Contains(string(data), "secret-token-value") {
		t.Error("raw token should not appear in ledger")
	}
}

func TestAppendLedger_WithTierAndSubscription(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tier.jsonl")

	lic := license.License{
		ID:             "lic_tier",
		Email:          "tier@example.com",
		Org:            "Test Corp",
		IssuedAt:       time.Now().Unix(),
		Features:       []string{license.FeatureAgents},
		Tier:           "founding_pro",
		SubscriptionID: "sub_abc123",
	}
	if err := appendLedger(path, lic, "token-tier"); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}

	var entry ledgerEntry
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &entry); err != nil {
		t.Fatal(err)
	}
	if entry.Tier != "founding_pro" {
		t.Errorf("Tier = %q, want founding_pro", entry.Tier)
	}
	if entry.SubscriptionID != "sub_abc123" {
		t.Errorf("SubscriptionID = %q, want sub_abc123", entry.SubscriptionID)
	}
	if entry.Org != "Test Corp" {
		t.Errorf("Org = %q, want Test Corp", entry.Org)
	}
}

func TestAppendLedger_UnwritableDirectory(t *testing.T) {
	// Path inside nonexistent directory.
	path := filepath.Join(t.TempDir(), "missing", "deep", "ledger.jsonl")
	lic := license.License{
		ID:       "lic_err",
		Email:    "err@example.com",
		IssuedAt: time.Now().Unix(),
		Features: []string{license.FeatureAgents},
	}
	err := appendLedger(path, lic, "token")
	if err == nil {
		t.Fatal("expected error for unwritable directory")
	}
}

func TestAppendLedger_SymlinkRejected(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.jsonl")
	if err := os.WriteFile(target, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(dir, "link.jsonl")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	lic := license.License{
		ID:       "lic_sym",
		Email:    "sym@example.com",
		IssuedAt: time.Now().Unix(),
		Features: []string{license.FeatureAgents},
	}
	err := appendLedger(link, lic, "token")
	if err == nil {
		t.Fatal("expected error for symlink ledger path")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected symlink error, got: %v", err)
	}
}
