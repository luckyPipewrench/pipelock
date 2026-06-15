//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/license"
)

func openImportTestDB(t *testing.T) *EntitlementDB {
	t.Helper()
	db, err := OpenEntitlementDB(t.Context(), ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func sampleImport() ImportedIssuance {
	now := time.Now().UTC().Truncate(time.Second)
	exp := now.Add(365 * 24 * time.Hour)
	return ImportedIssuance{
		LicenseID:      "lic_break_glass_1",
		TokenSHA256:    strings.Repeat("a", tokenSHA256HexLen),
		SubscriptionID: "sub_offline",
		IssuerKeyID:    "deadbeefkeyid",
		IssuedAt:       now,
		ExpiresAt:      &exp,
		ImportID:       "imp_1",
	}
}

func TestImportIssuance_RoundTrip(t *testing.T) {
	db := openImportTestDB(t)
	rec := sampleImport()
	if err := db.ImportIssuance(t.Context(), rec); err != nil {
		t.Fatalf("import: %v", err)
	}
	got, err := db.GetImportedIssuance(t.Context(), rec.LicenseID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil || got.TokenSHA256 != rec.TokenSHA256 || got.ImportID != rec.ImportID {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestImportIssuance_ReplayIsIdempotentNoOp(t *testing.T) {
	db := openImportTestDB(t)
	rec := sampleImport()
	if err := db.ImportIssuance(t.Context(), rec); err != nil {
		t.Fatalf("first import: %v", err)
	}
	// Identical re-import: reported as replay, no second row.
	err := db.ImportIssuance(t.Context(), rec)
	if !errors.Is(err, ErrIssuanceReplay) {
		t.Fatalf("expected ErrIssuanceReplay, got %v", err)
	}
	all, err := db.ListImportedIssuances(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("replay created %d rows, want 1", len(all))
	}
}

func TestImportIssuance_ConflictRejections(t *testing.T) {
	base := sampleImport()
	tests := []struct {
		name   string
		mutate func(r *ImportedIssuance)
	}{
		{"same license id, different token", func(r *ImportedIssuance) {
			r.TokenSHA256 = strings.Repeat("b", tokenSHA256HexLen)
			r.ImportID = "imp_2"
		}},
		{"same token, different license", func(r *ImportedIssuance) {
			r.LicenseID = "lic_other"
			r.ImportID = "imp_2"
		}},
		{"reused import id, different token", func(r *ImportedIssuance) {
			r.LicenseID = "lic_other"
			r.TokenSHA256 = strings.Repeat("c", tokenSHA256HexLen)
		}},
		{"same keys, different subscription (silent overwrite attempt)", func(r *ImportedIssuance) {
			r.SubscriptionID = "sub_attacker"
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db := openImportTestDB(t)
			if err := db.ImportIssuance(t.Context(), base); err != nil {
				t.Fatalf("seed: %v", err)
			}
			bad := base
			tc.mutate(&bad)
			err := db.ImportIssuance(t.Context(), bad)
			if !errors.Is(err, ErrIssuanceConflict) {
				t.Fatalf("expected ErrIssuanceConflict, got %v", err)
			}
			// The original record must be intact (no silent overwrite).
			got, gerr := db.GetImportedIssuance(t.Context(), base.LicenseID)
			if gerr != nil {
				t.Fatalf("get seeded record: %v", gerr)
			}
			if got == nil || got.SubscriptionID != base.SubscriptionID || got.TokenSHA256 != base.TokenSHA256 {
				t.Fatalf("original record was mutated: %+v", got)
			}
		})
	}
}

func TestImportIssuance_RejectsTruncatedHash(t *testing.T) {
	db := openImportTestDB(t)
	rec := sampleImport()
	// The truncated ledger hash (32 hex chars) must be rejected — it cannot be
	// the import key.
	rec.TokenSHA256 = strings.Repeat("a", 32)
	if err := db.ImportIssuance(t.Context(), rec); err == nil {
		t.Fatal("expected truncated hash to be rejected")
	}
}

func TestImportIssuance_RejectsNonHexHash(t *testing.T) {
	db := openImportTestDB(t)
	rec := sampleImport()
	rec.TokenSHA256 = strings.Repeat("z", tokenSHA256HexLen)
	if err := db.ImportIssuance(t.Context(), rec); err == nil {
		t.Fatal("expected non-hex token hash to be rejected")
	}
}

func TestImportIssuance_RejectsMissingFields(t *testing.T) {
	db := openImportTestDB(t)
	tests := []struct {
		name   string
		mutate func(r *ImportedIssuance)
	}{
		{"missing license id", func(r *ImportedIssuance) { r.LicenseID = "" }},
		{"missing issuer key id", func(r *ImportedIssuance) { r.IssuerKeyID = "" }},
		{"missing import id", func(r *ImportedIssuance) { r.ImportID = "" }},
		{"missing issued at", func(r *ImportedIssuance) { r.IssuedAt = time.Time{} }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := sampleImport()
			tc.mutate(&rec)
			if err := db.ImportIssuance(t.Context(), rec); err == nil {
				t.Fatalf("expected rejection for %s", tc.name)
			}
		})
	}
}

// TestImportIssuance_FromSignedExport proves the full break-glass flow: a token
// minted by a standalone signer + a signed export -> verify -> import. The
// import binds to the FULL token hash from the verified export.
func TestImportIssuance_FromSignedExport(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	lic := license.License{
		ID:             "lic_offline_xyz",
		Email:          "ops@vendor.example",
		Org:            "Vendor Example",
		IssuedAt:       now.Unix(),
		ExpiresAt:      now.Add(365 * 24 * time.Hour).Unix(),
		Features:       []string{license.FeatureFleet},
		Tier:           "enterprise",
		SubscriptionID: "sub_break_glass",
	}
	token, err := license.Issue(lic, priv)
	if err != nil {
		t.Fatal(err)
	}
	export, err := license.SignIssuanceExport(
		license.BuildIssuanceExportFromToken(token, lic, `["fleet"]`, now), priv)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(export)
	if err != nil {
		t.Fatalf("marshal export: %v", err)
	}

	verified, err := license.ParseAndVerifyIssuanceExport(data, pub)
	if err != nil {
		t.Fatalf("verify export: %v", err)
	}

	rec := importedIssuanceFromExport(verified.Payload, "imp_from_export")
	db := openImportTestDB(t)
	if err := db.ImportIssuance(t.Context(), rec); err != nil {
		t.Fatalf("import from export: %v", err)
	}
	got, err := db.GetImportedIssuance(t.Context(), lic.ID)
	if err != nil {
		t.Fatalf("get imported issuance: %v", err)
	}
	if got == nil || got.TokenSHA256 != license.TokenSHA256Hex(token) {
		t.Fatalf("imported record does not bind the full token hash: %+v", got)
	}
}

func TestImportedIssuanceEqual_ExpiryAndTimeBranches(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	exp := now.Add(time.Hour)
	exp2 := now.Add(2 * time.Hour)
	base := ImportedIssuance{
		LicenseID: "lic_1", TokenSHA256: "h", SubscriptionID: "s", IssuerKeyID: "k",
		IssuedAt: now, ImportID: "imp", ExpiresAt: &exp,
	}
	mkExpiry := func(e *time.Time) ImportedIssuance { r := base; r.ExpiresAt = e; return r }

	if !importedIssuanceEqual(base, base) {
		t.Fatal("identical records should be equal")
	}
	if importedIssuanceEqual(mkExpiry(nil), base) {
		t.Fatal("nil vs set expiry should differ")
	}
	if importedIssuanceEqual(base, mkExpiry(nil)) {
		t.Fatal("set vs nil expiry should differ")
	}
	if importedIssuanceEqual(base, mkExpiry(&exp2)) {
		t.Fatal("different expiry should differ")
	}
	bothNilA, bothNilB := mkExpiry(nil), mkExpiry(nil)
	if !importedIssuanceEqual(bothNilA, bothNilB) {
		t.Fatal("both-nil expiry should be equal")
	}
	diffIssued := base
	diffIssued.IssuedAt = now.Add(time.Minute)
	if importedIssuanceEqual(base, diffIssued) {
		t.Fatal("different issued_at should differ")
	}
}

// TestImportIssuance_NoExpiryRoundTrip covers the nil-expires storage path.
func TestImportIssuance_NoExpiryRoundTrip(t *testing.T) {
	db := openImportTestDB(t)
	rec := sampleImport()
	rec.ExpiresAt = nil // perpetual import
	if err := db.ImportIssuance(t.Context(), rec); err != nil {
		t.Fatalf("import: %v", err)
	}
	got, err := db.GetImportedIssuance(t.Context(), rec.LicenseID)
	if err != nil || got == nil {
		t.Fatalf("get: %v %v", got, err)
	}
	if got.ExpiresAt != nil {
		t.Fatalf("expected nil expiry, got %v", got.ExpiresAt)
	}
	// Replay the perpetual import: idempotent.
	if err := db.ImportIssuance(t.Context(), rec); !errors.Is(err, ErrIssuanceReplay) {
		t.Fatalf("expected replay, got %v", err)
	}
}

func TestGetImportedIssuance_NotFound(t *testing.T) {
	db := openImportTestDB(t)
	got, err := db.GetImportedIssuance(t.Context(), "lic_missing")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got != nil {
		t.Fatal("expected nil for missing license")
	}
}

// TestImportIssuance_DistinctRecordsNoCrossContamination imports many distinct
// issuances and verifies each is stored independently (no unique-key
// false-positive collisions across unrelated records).
func TestImportIssuance_DistinctRecordsNoCrossContamination(t *testing.T) {
	db := openImportTestDB(t)
	now := time.Now().UTC().Truncate(time.Second)
	const n = 16
	for i := 0; i < n; i++ {
		rec := ImportedIssuance{
			LicenseID:   fmt.Sprintf("lic_%02d", i),
			TokenSHA256: fmt.Sprintf("%064x", i),
			IssuerKeyID: "keyid",
			IssuedAt:    now,
			ImportID:    fmt.Sprintf("imp_%02d", i),
		}
		if err := db.ImportIssuance(t.Context(), rec); err != nil {
			t.Fatalf("import %d: %v", i, err)
		}
	}
	all, err := db.ListImportedIssuances(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != n {
		t.Fatalf("stored %d distinct rows, want %d", len(all), n)
	}
}

// isUniqueConstraintError must detect a REAL driver-level UNIQUE/PRIMARY KEY
// violation (so a race-lost INSERT is classified as a conflict) and must NOT
// misclassify a generic error (so disk/IO/cancellation surfaces as an error,
// not a phantom conflict).
func TestIsUniqueConstraintError(t *testing.T) {
	db := openImportTestDB(t)
	rec := sampleImport()
	if err := db.ImportIssuance(t.Context(), rec); err != nil {
		t.Fatalf("seed import: %v", err)
	}
	// Insert the same row directly, bypassing ImportIssuance's pre-INSERT lookup,
	// to force the driver to raise the constraint error.
	const insert = `
	INSERT INTO imported_issuances (
		license_id, token_sha256, subscription_id, issuer_key_id,
		issued_at, expires_at, import_id, imported_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	_, rawErr := db.db.ExecContext(t.Context(), insert,
		rec.LicenseID, rec.TokenSHA256, rec.SubscriptionID, rec.IssuerKeyID,
		rec.IssuedAt.UTC(), nullableTime(rec.ExpiresAt), rec.ImportID, rec.ImportedAt.UTC(),
	)
	if rawErr == nil {
		t.Fatal("expected a UNIQUE constraint violation on duplicate insert")
	}
	if !isUniqueConstraintError(rawErr) {
		t.Fatalf("real UNIQUE violation not detected: %v", rawErr)
	}
	if isUniqueConstraintError(errors.New("disk full")) {
		t.Fatal("generic error misclassified as a constraint violation")
	}
}
