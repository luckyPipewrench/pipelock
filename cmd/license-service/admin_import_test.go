//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// writeBreakGlassExport mints a token with the service token key and writes a
// signed issuance export for it. Returns the export path, the signer public key
// hex, and the full token hash.
func writeBreakGlassExport(t *testing.T, tokenKeyPath string, lic license.License) (exportPath, pubHex, tokenHash string) {
	t.Helper()
	priv, err := signing.LoadPrivateKeyFile(tokenKeyPath)
	if err != nil {
		t.Fatalf("load token key: %v", err)
	}
	token, err := license.Issue(lic, priv)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	export, err := license.SignIssuanceExport(
		license.BuildIssuanceExportFromToken(token, lic, "", time.Now()), priv)
	if err != nil {
		t.Fatalf("sign export: %v", err)
	}
	data, err := json.Marshal(export)
	if err != nil {
		t.Fatalf("marshal export: %v", err)
	}
	exportPath = filepath.Join(t.TempDir(), "export.json")
	if err := os.WriteFile(exportPath, data, 0o600); err != nil {
		t.Fatalf("write export: %v", err)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("priv has no public half")
	}
	return exportPath, hex.EncodeToString(pub), license.TokenSHA256Hex(token)
}

func importBreakGlassLicense() license.License {
	now := time.Now()
	return license.License{
		ID:             "lic_cmd_break_glass",
		Email:          "ops@vendor.example",
		Org:            "Vendor Example",
		IssuedAt:       now.Unix(),
		ExpiresAt:      now.Add(365 * 24 * time.Hour).Unix(),
		Features:       []string{license.FeatureFleet},
		Tier:           "enterprise",
		SubscriptionID: "sub_cmd_break_glass",
	}
}

func TestRunImportIssuance_HappyPath(t *testing.T) {
	tokenKeyPath, _, _ := setAdminEnv(t)
	lic := importBreakGlassLicense()
	exportPath, pubHex, tokenHash := writeBreakGlassExport(t, tokenKeyPath, lic)

	if err := runImportIssuance(discardLog(), []string{
		"--export", exportPath,
		"--issuer-pubkey", pubHex,
		"--import-id", "imp_cmd_1",
	}); err != nil {
		t.Fatalf("runImportIssuance: %v", err)
	}

	// Reopen and confirm the record persisted with the full token hash.
	handler, cleanup, err := adminHandler(context.Background(), discardLog())
	if err != nil {
		t.Fatalf("adminHandler: %v", err)
	}
	defer cleanup()
	got, err := handler.GetImportedIssuance(context.Background(), lic.ID)
	if err != nil || got == nil {
		t.Fatalf("get: %v %v", got, err)
	}
	if got.TokenSHA256 != tokenHash {
		t.Fatal("imported record does not bind the full token hash")
	}
}

func TestRunRevokeImportedLicense_PublishesInSignedCRL(t *testing.T) {
	tokenKeyPath, _, _ := setAdminEnv(t)
	lic := importBreakGlassLicense()
	exportPath, pubHex, _ := writeBreakGlassExport(t, tokenKeyPath, lic)

	if err := runImportIssuance(discardLog(), []string{
		"--export", exportPath,
		"--issuer-pubkey", pubHex,
		"--import-id", "imp_cmd_revoke",
	}); err != nil {
		t.Fatalf("runImportIssuance: %v", err)
	}
	if err := runRevokeImportedLicense(discardLog(), []string{
		"--license-id", lic.ID,
		"--reason", "operator_test",
	}); err != nil {
		t.Fatalf("runRevokeImportedLicense: %v", err)
	}

	handler, cleanup, err := adminHandler(context.Background(), discardLog())
	if err != nil {
		t.Fatalf("adminHandler: %v", err)
	}
	defer cleanup()
	crl, err := handler.SignedCRL(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("SignedCRL: %v", err)
	}
	if _, ok := crl.RevocationFor(lic.ID); !ok {
		t.Fatalf("imported license %s missing from signed CRL", lic.ID)
	}
}

func TestRunImportIssuance_PubkeyFromFile(t *testing.T) {
	tokenKeyPath, _, _ := setAdminEnv(t)
	lic := importBreakGlassLicense()
	exportPath, pubHex, _ := writeBreakGlassExport(t, tokenKeyPath, lic)
	pubPath := filepath.Join(t.TempDir(), "issuer.pub")
	if err := os.WriteFile(pubPath, []byte(pubHex+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runImportIssuance(discardLog(), []string{
		"--export", exportPath,
		"--issuer-pubkey", pubPath, // path form, not hex
	}); err != nil {
		t.Fatalf("runImportIssuance (pubkey from file): %v", err)
	}
}

func TestRunImportIssuance_ReplayNoError(t *testing.T) {
	tokenKeyPath, _, _ := setAdminEnv(t)
	exportPath, pubHex, _ := writeBreakGlassExport(t, tokenKeyPath, importBreakGlassLicense())
	args := []string{"--export", exportPath, "--issuer-pubkey", pubHex, "--import-id", "imp_replay"}
	if err := runImportIssuance(discardLog(), args); err != nil {
		t.Fatalf("first import: %v", err)
	}
	// Identical replay: idempotent no-op, no error.
	if err := runImportIssuance(discardLog(), args); err != nil {
		t.Fatalf("replay should not error: %v", err)
	}
}

func TestRunImportIssuance_ConflictErrors(t *testing.T) {
	tokenKeyPath, _, _ := setAdminEnv(t)
	lic := importBreakGlassLicense()
	exportPath, pubHex, _ := writeBreakGlassExport(t, tokenKeyPath, lic)
	if err := runImportIssuance(discardLog(), []string{
		"--export", exportPath, "--issuer-pubkey", pubHex, "--import-id", "imp_a",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Same license id, different token (changed email) => conflict, non-nil error.
	conflicting := lic
	conflicting.Email = "different@vendor.example"
	conflictExport, _, _ := writeBreakGlassExport(t, tokenKeyPath, conflicting)
	err := runImportIssuance(discardLog(), []string{
		"--export", conflictExport, "--issuer-pubkey", pubHex, "--import-id", "imp_b",
	})
	if err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("expected conflict rejection error, got %v", err)
	}
}

func TestRunImportIssuance_BadSignatureRejected(t *testing.T) {
	tokenKeyPath, _, _ := setAdminEnv(t)
	exportPath, _, _ := writeBreakGlassExport(t, tokenKeyPath, importBreakGlassLicense())
	// Supply a WRONG issuer pubkey (a fresh key the export was not signed with).
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	importErr := runImportIssuance(discardLog(), []string{
		"--export", exportPath,
		"--issuer-pubkey", hex.EncodeToString(otherPub),
	})
	if importErr == nil {
		t.Fatal("expected bad-signature import to fail closed")
	}
}

func TestRunImportIssuance_MissingFlags(t *testing.T) {
	setAdminEnv(t)
	tests := []struct {
		name string
		args []string
	}{
		{"missing export", []string{"--issuer-pubkey", strings.Repeat("a", 64)}},
		{"missing pubkey", []string{"--export", "x.json"}},
		{"bad pubkey", []string{"--export", "x.json", "--issuer-pubkey", "not-a-key"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := runImportIssuance(discardLog(), tc.args); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

func TestRunRevokeImportedLicense_MissingOrUnknown(t *testing.T) {
	setAdminEnv(t)
	if err := runRevokeImportedLicense(discardLog(), nil); err == nil {
		t.Fatal("missing --license-id must error")
	}
	if err := runRevokeImportedLicense(discardLog(), []string{"--license-id", "lic_missing"}); err == nil {
		t.Fatal("unknown imported license must error")
	}
}

func TestRunImportIssuance_MissingExportFile(t *testing.T) {
	setAdminEnv(t)
	err := runImportIssuance(discardLog(), []string{
		"--export", filepath.Join(t.TempDir(), "nope.json"),
		"--issuer-pubkey", strings.Repeat("a", 64),
	})
	if err == nil || !strings.Contains(err.Error(), "read export") {
		t.Fatalf("expected read-export error, got %v", err)
	}
}

func TestRunListImportedIssuances(t *testing.T) {
	tokenKeyPath, _, _ := setAdminEnv(t)
	// Empty first.
	if err := runListImportedIssuances(discardLog(), nil); err != nil {
		t.Fatalf("list (empty): %v", err)
	}
	// Import one, then list.
	exportPath, pubHex, _ := writeBreakGlassExport(t, tokenKeyPath, importBreakGlassLicense())
	if err := runImportIssuance(discardLog(), []string{
		"--export", exportPath, "--issuer-pubkey", pubHex, "--import-id", "imp_list",
	}); err != nil {
		t.Fatalf("import: %v", err)
	}
	if err := runListImportedIssuances(discardLog(), nil); err != nil {
		t.Fatalf("list (populated): %v", err)
	}
}

func TestLoadIssuerPublicKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubHex := hex.EncodeToString(pub)

	t.Run("hex", func(t *testing.T) {
		got, err := loadIssuerPublicKey(pubHex)
		if err != nil || !got.Equal(pub) {
			t.Fatalf("hex load: %v", err)
		}
	})
	t.Run("file", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "k.pub")
		if err := os.WriteFile(p, []byte("  "+pubHex+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := loadIssuerPublicKey(p)
		if err != nil || !got.Equal(pub) {
			t.Fatalf("file load: %v", err)
		}
	})
	t.Run("garbage", func(t *testing.T) {
		if _, err := loadIssuerPublicKey("not-hex-not-a-file"); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("wrong size hex", func(t *testing.T) {
		if _, err := loadIssuerPublicKey("deadbeef"); err == nil {
			t.Fatal("expected wrong-size rejection")
		}
	})
}

func TestDispatchAdmin_ImportSubcommandsRecognized(t *testing.T) {
	for _, sub := range []string{"import-issuance", "list-imported-issuances", "revoke-imported-license"} {
		if !adminSubcommands[sub] {
			t.Fatalf("admin subcommand %q not registered", sub)
		}
	}
}
