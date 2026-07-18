//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package entcli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// gateTestKey writes a fresh signing key and returns its path.
func gateTestKey(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privPath := filepath.Join(dir, licensePrivKeyFile)
	if err := signing.SavePrivateKey(priv, privPath); err != nil {
		t.Fatal(err)
	}
	return privPath
}

func runIssue(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := licenseIssueCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

// --- paidIssuanceReason unit table (the gate predicate) ---

func TestPaidIssuanceReason(t *testing.T) {
	future := time.Now().Add(24 * time.Hour).Unix()
	tests := []struct {
		name      string
		lic       license.License
		wantGated bool
	}{
		{"agents feature", license.License{Features: []string{license.FeatureAgents}, ExpiresAt: future}, true},
		{"assess feature", license.License{Features: []string{license.FeatureAssess}, ExpiresAt: future}, true},
		{"fleet feature", license.License{Features: []string{license.FeatureFleet}, ExpiresAt: future}, true},
		{"tier only, no features", license.License{Tier: "pro", ExpiresAt: future}, true},
		{"subscription only, no features/tier", license.License{SubscriptionID: "sub_1", ExpiresAt: future}, true},
		{"perpetual token with feature", license.License{Features: []string{license.FeatureAgents}}, true},
		{"truly free: no feature, no tier, no sub, has expiry", license.License{ExpiresAt: future}, false},
		{"truly free perpetual: nothing at all", license.License{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, gated := paidIssuanceReason(tc.lic)
			if gated != tc.wantGated {
				t.Fatalf("paidIssuanceReason gated=%v, want %v", gated, tc.wantGated)
			}
		})
	}
}

// --- Fail-closed negative: paid token, no break-glass -> REFUSED ---

func TestIssue_PaidFeature_NoBreakGlass_Refused(t *testing.T) {
	key := gateTestKey(t)
	out, err := runIssue(t,
		"--key", key,
		"--email", "buyer@vendor.example",
		"--features", "agents",
		"--expires", time.Now().Add(365*24*time.Hour).Format(time.DateOnly),
	)
	if err == nil {
		t.Fatalf("expected paid issuance to be refused, got success:\n%s", out)
	}
	if !strings.Contains(err.Error(), "refusing to issue a paid/revocable license") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- THE KEY BYPASS TEST: omit --tier/--subscription-id, pass paid --features.
// Must STILL be gated (gate keys on capability, not on label flags). ---

func TestIssue_PaidFeature_NoTierNoSub_StillGated(t *testing.T) {
	key := gateTestKey(t)
	// Attacker tries to slip a paid token past a label-based gate by omitting the
	// tier and subscription-id flags entirely; the feature alone is the paid
	// capability.
	out, err := runIssue(t,
		"--key", key,
		"--email", "attacker@vendor.example",
		"--features", "fleet",
		"--expires", time.Now().Add(365*24*time.Hour).Format(time.DateOnly),
		// deliberately NO --tier, NO --subscription-id
	)
	if err == nil {
		t.Fatalf("BYPASS: paid feature without tier/sub flags was issued:\n%s", out)
	}
	if !strings.Contains(err.Error(), "paid feature") {
		t.Fatalf("expected gate to cite the paid feature, got: %v", err)
	}
}

// The default --features is [agents] (paid). Issuing with no flags at all must
// STILL be gated — the default cannot be a silent bypass.
func TestIssue_DefaultFeaturesAreGated(t *testing.T) {
	key := gateTestKey(t)
	out, err := runIssue(t,
		"--key", key,
		"--email", "buyer@vendor.example",
		"--expires", time.Now().Add(365*24*time.Hour).Format(time.DateOnly),
	)
	if err == nil {
		t.Fatalf("BYPASS: default [agents] feature issued without break-glass:\n%s", out)
	}
}

// Perpetual paid token (no --expires) without break-glass must be refused.
func TestIssue_PerpetualPaid_NoBreakGlass_Refused(t *testing.T) {
	key := gateTestKey(t)
	out, err := runIssue(t,
		"--key", key,
		"--email", "buyer@vendor.example",
		"--features", "agents",
		// no --expires => perpetual
	)
	if err == nil {
		t.Fatalf("expected perpetual paid token to be refused:\n%s", out)
	}
}

// --- Free-only token (no paid feature, has expiry) -> ALLOWED ---

func TestIssue_FreeOnly_Allowed(t *testing.T) {
	key := gateTestKey(t)
	out, err := runIssue(t,
		"--key", key,
		"--email", "free@vendor.example",
		"--features", "", // explicitly empty: no paid capability
		"--expires", time.Now().Add(30*24*time.Hour).Format(time.DateOnly),
	)
	if err != nil {
		t.Fatalf("free issuance should be allowed, got: %v\n%s", err, out)
	}
	if !strings.Contains(out, "License issued") {
		t.Fatalf("expected success output, got:\n%s", out)
	}
}

// --- Break-glass path: paid token allowed AND emits a verifiable export ---

func TestIssue_BreakGlass_PaidAllowed_EmitsValidExport(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	keyPath := filepath.Join(dir, licensePrivKeyFile)
	if err := signing.SavePrivateKey(priv, keyPath); err != nil {
		t.Fatal(err)
	}
	exportPath := filepath.Join(dir, "export.json")

	out, err := runIssue(t,
		"--key", keyPath,
		"--email", "ops@vendor.example",
		"--features", "fleet",
		"--expires", time.Now().Add(365*24*time.Hour).Format(time.DateOnly),
		"--break-glass",
		"--export", exportPath,
	)
	if err != nil {
		t.Fatalf("break-glass paid issuance failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "License issued") {
		t.Fatalf("expected success, got:\n%s", out)
	}

	// Extract the token from output and confirm it is offline-signable / valid.
	token := extractTokenFromOutput(t, out)
	if _, err := license.Verify(token, pub); err != nil {
		t.Fatalf("break-glass token is not offline-verifiable: %v", err)
	}

	// The emitted export must parse and verify against the signer key, and bind
	// the FULL token hash.
	data, err := os.ReadFile(filepath.Clean(exportPath))
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	verified, err := license.ParseAndVerifyIssuanceExport(data, pub)
	if err != nil {
		t.Fatalf("export does not verify: %v", err)
	}
	if verified.Payload.TokenSHA256 != license.TokenSHA256Hex(token) {
		t.Fatal("export token hash does not bind the issued token")
	}
}

// Break-glass for a PAID token without --export must be refused (no blind mint).
func TestIssue_BreakGlass_PaidWithoutExport_Refused(t *testing.T) {
	key := gateTestKey(t)
	out, err := runIssue(t,
		"--key", key,
		"--email", "ops@vendor.example",
		"--features", "agents",
		"--expires", time.Now().Add(365*24*time.Hour).Format(time.DateOnly),
		"--break-glass",
		// no --export
	)
	if err == nil {
		t.Fatalf("break-glass paid mint without --export should be refused:\n%s", out)
	}
	if !strings.Contains(err.Error(), "requires --export") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Break-glass on a FREE token does not require --export (the gate never fired).
func TestIssue_BreakGlass_FreeToken_NoExportNeeded(t *testing.T) {
	key := gateTestKey(t)
	out, err := runIssue(t,
		"--key", key,
		"--email", "free@vendor.example",
		"--features", "",
		"--expires", time.Now().Add(30*24*time.Hour).Format(time.DateOnly),
		"--break-glass",
	)
	if err != nil {
		t.Fatalf("break-glass free issuance should succeed without export: %v\n%s", err, out)
	}
}

func extractTokenFromOutput(t *testing.T, out string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "pipelock_lic_") {
			return strings.TrimSpace(line)
		}
	}
	t.Fatalf("no token in output:\n%s", out)
	return ""
}

// Break-glass with an unwritable --export path surfaces the write error (does
// not silently succeed with no export).
func TestIssue_BreakGlass_UnwritableExport_Errors(t *testing.T) {
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	keyPath := filepath.Join(dir, licensePrivKeyFile)
	if err := signing.SavePrivateKey(priv, keyPath); err != nil {
		t.Fatal(err)
	}
	// Point --export at a path whose parent is a file, not a directory.
	notADir := filepath.Join(dir, "blocker")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runIssue(t,
		"--key", keyPath,
		"--email", "ops@vendor.example",
		"--features", "agents",
		"--expires", time.Now().Add(24*time.Hour).Format(time.DateOnly),
		"--break-glass",
		"--export", filepath.Join(notADir, "export.json"),
	)
	if err == nil {
		t.Fatalf("expected export write failure to error:\n%s", out)
	}
	if !strings.Contains(err.Error(), "write signed issuance export") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Sanity: the export written to disk is well-formed JSON with the wire shape.
func TestIssue_ExportFileShape(t *testing.T) {
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	keyPath := filepath.Join(dir, licensePrivKeyFile)
	if err := signing.SavePrivateKey(priv, keyPath); err != nil {
		t.Fatal(err)
	}
	exportPath := filepath.Join(dir, "export.json")
	if _, err := runIssue(t,
		"--key", keyPath,
		"--email", "ops@vendor.example",
		"--features", "agents",
		"--expires", time.Now().Add(24*time.Hour).Format(time.DateOnly),
		"--break-glass", "--export", exportPath,
	); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Clean(exportPath))
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatalf("export is not valid wire JSON: %v", err)
	}
	if wire.Payload == "" || wire.Signature == "" {
		t.Fatal("export missing payload or signature")
	}
}
