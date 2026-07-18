//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/license"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// isUniqueConstraintError reports whether err is a SQLite UNIQUE/PRIMARY KEY
// constraint violation. Only such a violation means "a concurrent import won the
// race after our lookup" (a conflict); any other ExecContext error (disk full,
// I/O, context cancellation) must NOT be mislabeled as a conflict.
func isUniqueConstraintError(err error) bool {
	var serr *sqlite.Error
	if errors.As(err, &serr) {
		code := serr.Code()
		return code == sqlite3.SQLITE_CONSTRAINT_UNIQUE || code == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY
	}
	return false
}

// ImportedIssuance is a license token minted outside the service (offline-root
// break-glass / standalone CLI) and imported via a signed issuance export. It is
// the revocation surface for those tokens.
type ImportedIssuance struct {
	LicenseID      string
	TokenSHA256    string // FULL 64-hex sha256 of the exact token string
	SubscriptionID string
	IssuerKeyID    string
	IssuedAt       time.Time
	ExpiresAt      *time.Time
	ImportID       string
	ImportedAt     time.Time
}

// ImportOutcome is the result of an import attempt, for operator-facing
// reporting and audit logging.
type ImportOutcome string

const (
	// ImportOutcomeImported means a new record was durably written.
	ImportOutcomeImported ImportOutcome = "imported"
	// ImportOutcomeReplay means the identical issuance was already imported
	// (idempotent no-op, not an error).
	ImportOutcomeReplay ImportOutcome = "replay"
	// ImportOutcomeConflict means the import collided with a different existing
	// record on a unique key (rejected, fail closed).
	ImportOutcomeConflict ImportOutcome = "conflict"
)

var (
	// ErrIssuanceReplay means the exact same issuance (same license id, token
	// hash, and import id) was already imported. Re-importing is a no-op, not a
	// fault, so a retried import does not error — but the caller is told it was a
	// replay so it never double-counts.
	ErrIssuanceReplay = errors.New("issuance already imported")

	// ErrIssuanceConflict means an import collided with a DIFFERENT existing
	// record on a unique key (license id reused for a different token, token hash
	// reused for a different license, or import id reused). This is a hard
	// rejection: it never silently overwrites a recorded credential.
	ErrIssuanceConflict = errors.New("issuance import conflicts with an existing record")
)

// ImportIssuance durably records a license token minted outside the service.
// Replaying the identical import is reported as ErrIssuanceReplay (idempotent
// no-op); any unique-key collision with different data is ErrIssuanceConflict
// (hard rejection). It never overwrites an existing record — an import only ever
// adds a new credential to the revocation surface.
func (e *EntitlementDB) ImportIssuance(ctx context.Context, rec ImportedIssuance) error {
	if rec.LicenseID == "" {
		return errors.New("license_id is required")
	}
	if len(rec.TokenSHA256) != tokenSHA256HexLen {
		return fmt.Errorf("token_sha256 must be a %d-char hex sha256", tokenSHA256HexLen)
	}
	if _, err := hex.DecodeString(rec.TokenSHA256); err != nil {
		return fmt.Errorf("token_sha256 is not valid hex: %w", err)
	}
	if rec.IssuerKeyID == "" {
		return errors.New("issuer_key_id is required")
	}
	if rec.ImportID == "" {
		return errors.New("import_id is required")
	}
	if rec.IssuedAt.IsZero() {
		return errors.New("issued_at is required")
	}
	if rec.ImportedAt.IsZero() {
		rec.ImportedAt = time.Now().UTC()
	}

	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin import issuance transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	// Look up by EACH unique key independently. If any existing row matches one
	// key, the rest of the record must be byte-identical for it to be a replay;
	// otherwise it is a conflict. This catches every cross-collision (same
	// license/different token, same token/different license, reused import id).
	existing, found, err := lookupImportedIssuance(ctx, tx, rec)
	if err != nil {
		return err
	}
	if found {
		// Either outcome is read-only: roll back to RELEASE the connection.
		// Leaving the tx open here would leak the single pooled connection
		// (SetMaxOpenConns(1)) and deadlock the next import. The deferred
		// rollback handles this because committed stays false.
		if importedIssuanceEqual(existing, rec) {
			return ErrIssuanceReplay // idempotent no-op
		}
		return fmt.Errorf("%w: license_id=%s", ErrIssuanceConflict, rec.LicenseID)
	}

	const insert = `
	INSERT INTO imported_issuances (
		license_id, token_sha256, subscription_id, issuer_key_id,
		issued_at, expires_at, import_id, imported_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`
	if _, err := tx.ExecContext(ctx, insert,
		rec.LicenseID, rec.TokenSHA256, rec.SubscriptionID, rec.IssuerKeyID,
		rec.IssuedAt.UTC(), nullableTime(rec.ExpiresAt), rec.ImportID, rec.ImportedAt.UTC(),
	); err != nil {
		// A UNIQUE/PRIMARY KEY violation here means a concurrent import won the
		// race after our lookup: treat it as a conflict (fail closed). Any other
		// ExecContext error (disk full, I/O, context cancellation) is NOT a
		// conflict and must surface as a generic error so it is audited as such.
		if isUniqueConstraintError(err) {
			return fmt.Errorf("%w: license_id=%s", ErrIssuanceConflict, rec.LicenseID)
		}
		return fmt.Errorf("insert imported issuance: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit import issuance transaction: %w", err)
	}
	committed = true
	return nil
}

// lookupImportedIssuance returns any existing row that collides with rec on the
// license id, the token hash, or the import id (the three unique keys).
func lookupImportedIssuance(ctx context.Context, q entitlementQueryer, rec ImportedIssuance) (ImportedIssuance, bool, error) {
	const query = `
	SELECT license_id, token_sha256, subscription_id, issuer_key_id,
	       issued_at, expires_at, import_id, imported_at
	FROM imported_issuances
	WHERE license_id = ? OR token_sha256 = ? OR import_id = ?
	LIMIT 1
	`
	var (
		got     ImportedIssuance
		expires sql.NullTime
	)
	err := q.QueryRowContext(ctx, query, rec.LicenseID, rec.TokenSHA256, rec.ImportID).Scan(
		&got.LicenseID, &got.TokenSHA256, &got.SubscriptionID, &got.IssuerKeyID,
		&got.IssuedAt, &expires, &got.ImportID, &got.ImportedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return ImportedIssuance{}, false, nil
	}
	if err != nil {
		return ImportedIssuance{}, false, fmt.Errorf("lookup imported issuance: %w", err)
	}
	if expires.Valid {
		t := expires.Time.UTC()
		got.ExpiresAt = &t
	}
	return got, true, nil
}

// importedIssuanceEqual reports whether two records are the same import (so a
// retry is a replay, not a conflict). Compares the identity fields; imported_at
// is server-assigned and excluded.
func importedIssuanceEqual(a, b ImportedIssuance) bool {
	if a.LicenseID != b.LicenseID ||
		a.TokenSHA256 != b.TokenSHA256 ||
		a.SubscriptionID != b.SubscriptionID ||
		a.IssuerKeyID != b.IssuerKeyID ||
		a.ImportID != b.ImportID ||
		!a.IssuedAt.UTC().Equal(b.IssuedAt.UTC()) {
		return false
	}
	if (a.ExpiresAt == nil) != (b.ExpiresAt == nil) {
		return false
	}
	if a.ExpiresAt != nil && !a.ExpiresAt.UTC().Equal(b.ExpiresAt.UTC()) {
		return false
	}
	return true
}

// GetImportedIssuance returns a single imported issuance by license id, or
// (nil, nil) when not found.
func (e *EntitlementDB) GetImportedIssuance(ctx context.Context, licenseID string) (*ImportedIssuance, error) {
	const query = `
	SELECT license_id, token_sha256, subscription_id, issuer_key_id,
	       issued_at, expires_at, import_id, imported_at
	FROM imported_issuances
	WHERE license_id = ?
	`
	var (
		got     ImportedIssuance
		expires sql.NullTime
	)
	err := e.db.QueryRowContext(ctx, query, licenseID).Scan(
		&got.LicenseID, &got.TokenSHA256, &got.SubscriptionID, &got.IssuerKeyID,
		&got.IssuedAt, &expires, &got.ImportID, &got.ImportedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get imported issuance %s: %w", licenseID, err)
	}
	if expires.Valid {
		t := expires.Time.UTC()
		got.ExpiresAt = &t
	}
	return &got, nil
}

// ListImportedIssuances returns every imported issuance, ordered by license id
// for a deterministic listing.
func (e *EntitlementDB) ListImportedIssuances(ctx context.Context) ([]ImportedIssuance, error) {
	const query = `
	SELECT license_id, token_sha256, subscription_id, issuer_key_id,
	       issued_at, expires_at, import_id, imported_at
	FROM imported_issuances
	ORDER BY license_id ASC
	`
	rows, err := e.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list imported issuances: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var results []ImportedIssuance
	for rows.Next() {
		var (
			rec     ImportedIssuance
			expires sql.NullTime
		)
		if err := rows.Scan(
			&rec.LicenseID, &rec.TokenSHA256, &rec.SubscriptionID, &rec.IssuerKeyID,
			&rec.IssuedAt, &expires, &rec.ImportID, &rec.ImportedAt,
		); err != nil {
			return nil, fmt.Errorf("scan imported issuance: %w", err)
		}
		if expires.Valid {
			t := expires.Time.UTC()
			rec.ExpiresAt = &t
		}
		results = append(results, rec)
	}
	return results, rows.Err()
}

// importedIssuanceFromExport converts a VERIFIED issuance-export payload into an
// import record. Callers must pass a payload returned by
// license.ParseAndVerifyIssuanceExport (signature + issuer-key-id already
// checked); this only maps fields. importID is the server-assigned unique id.
func importedIssuanceFromExport(p license.IssuanceExportPayload, importID string) ImportedIssuance {
	rec := ImportedIssuance{
		LicenseID:      p.LicenseID,
		TokenSHA256:    p.TokenSHA256,
		SubscriptionID: p.SubscriptionID,
		IssuerKeyID:    p.IssuerKeyID,
		IssuedAt:       time.Unix(p.IssuedAt, 0).UTC(),
		ImportID:       importID,
		ImportedAt:     time.Now().UTC(),
	}
	if p.ExpiresAt > 0 {
		exp := time.Unix(p.ExpiresAt, 0).UTC()
		rec.ExpiresAt = &exp
	}
	return rec
}

func nullableTime(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return t.UTC()
}

// tokenSHA256HexLen is the length of a full hex-encoded sha256 (32 bytes -> 64
// hex chars). The import key MUST be the full hash, never the truncated ledger
// hash.
const tokenSHA256HexLen = 64
