//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/license"
)

// signTestExport mints a token with priv and returns a signed issuance export
// for it, plus the verifying public key.
func signTestExport(t *testing.T, priv ed25519.PrivateKey, lic license.License) ([]byte, ed25519.PublicKey, string) {
	t.Helper()
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
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("priv has no public half")
	}
	return data, pub, license.TokenSHA256Hex(token)
}

func breakGlassLicense() license.License {
	now := time.Now()
	return license.License{
		ID:             "lic_break_glass_import",
		Email:          "ops@vendor.example",
		Org:            "Vendor Example",
		IssuedAt:       now.Unix(),
		ExpiresAt:      now.Add(365 * 24 * time.Hour).Unix(),
		Features:       []string{license.FeatureFleet},
		Tier:           "enterprise",
		SubscriptionID: "sub_break_glass",
	}
}

func TestImportSignedIssuance_HappyPath(t *testing.T) {
	ts := newTestSetup(t)
	lic := breakGlassLicense()
	data, pub, tokenHash := signTestExport(t, ts.privateKey, lic)

	payload, outcome, err := ts.handler.ImportSignedIssuance(context.Background(), data, pub, "imp_1", time.Now())
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if outcome != ImportOutcomeImported {
		t.Fatalf("outcome = %q, want imported", outcome)
	}
	if payload.LicenseID != lic.ID {
		t.Fatalf("license id = %q", payload.LicenseID)
	}
	got, err := ts.handler.GetImportedIssuance(context.Background(), lic.ID)
	if err != nil || got == nil {
		t.Fatalf("get: %v %v", got, err)
	}
	if got.TokenSHA256 != tokenHash {
		t.Fatal("imported record does not bind the full token hash")
	}
}

func TestImportSignedIssuance_ReplayIsNoOp(t *testing.T) {
	ts := newTestSetup(t)
	data, pub, _ := signTestExport(t, ts.privateKey, breakGlassLicense())

	if _, _, err := ts.handler.ImportSignedIssuance(context.Background(), data, pub, "imp_1", time.Now()); err != nil {
		t.Fatalf("first import: %v", err)
	}
	_, outcome, err := ts.handler.ImportSignedIssuance(context.Background(), data, pub, "imp_1", time.Now())
	if err != nil {
		t.Fatalf("replay should not error: %v", err)
	}
	if outcome != ImportOutcomeReplay {
		t.Fatalf("outcome = %q, want replay", outcome)
	}
	all, _ := ts.handler.ListImportedIssuances(context.Background())
	if len(all) != 1 {
		t.Fatalf("replay created %d rows, want 1", len(all))
	}
}

func TestImportSignedIssuance_ConflictRejected(t *testing.T) {
	ts := newTestSetup(t)
	lic := breakGlassLicense()
	data, pub, _ := signTestExport(t, ts.privateKey, lic)
	if _, _, err := ts.handler.ImportSignedIssuance(context.Background(), data, pub, "imp_1", time.Now()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Same license id, DIFFERENT token (changed email -> different signed payload
	// -> different token hash), new import id => conflict, fail closed.
	conflicting := lic
	conflicting.Email = "different@vendor.example"
	data2, _, _ := signTestExport(t, ts.privateKey, conflicting)
	_, outcome, err := ts.handler.ImportSignedIssuance(context.Background(), data2, pub, "imp_2", time.Now())
	if !errors.Is(err, ErrIssuanceConflict) {
		t.Fatalf("expected ErrIssuanceConflict, got %v (outcome %q)", err, outcome)
	}
	if outcome != ImportOutcomeConflict {
		t.Fatalf("outcome = %q, want conflict", outcome)
	}
}

func TestImportSignedIssuance_BadSignatureRejected(t *testing.T) {
	ts := newTestSetup(t)
	lic := breakGlassLicense()
	data, _, _ := signTestExport(t, ts.privateKey, lic)
	// Verify against the WRONG key (a fresh keypair the export was not signed with).
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, _, importErr := ts.handler.ImportSignedIssuance(context.Background(), data, otherPub, "imp_1", time.Now())
	if importErr == nil {
		t.Fatal("expected wrong-key verification to fail closed")
	}
	all, _ := ts.handler.ListImportedIssuances(context.Background())
	if len(all) != 0 {
		t.Fatalf("a bad-signature export was imported: %d rows", len(all))
	}
}

func TestImportSignedIssuance_MalformedExportRejected(t *testing.T) {
	ts := newTestSetup(t)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		data []byte
	}{
		{"not json", []byte("{not json")},
		{"empty", []byte("")},
		{"oversize", make([]byte, 128*1024)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := ts.handler.ImportSignedIssuance(context.Background(), tc.data, pub, "imp_x", time.Now())
			if err == nil {
				t.Fatalf("expected rejection for %s", tc.name)
			}
		})
	}
}

func TestImportSignedIssuance_RequiresImportID(t *testing.T) {
	ts := newTestSetup(t)
	data, pub, _ := signTestExport(t, ts.privateKey, breakGlassLicense())
	if _, _, err := ts.handler.ImportSignedIssuance(context.Background(), data, pub, "", time.Now()); err == nil {
		t.Fatal("expected missing import id to be rejected")
	}
}

func TestListImportedIssuances_Empty(t *testing.T) {
	ts := newTestSetup(t)
	all, err := ts.handler.ListImportedIssuances(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 0 {
		t.Fatalf("expected empty, got %d", len(all))
	}
}
