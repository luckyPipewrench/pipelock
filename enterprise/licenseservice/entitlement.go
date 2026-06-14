//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	// Pure-Go SQLite driver (no CGO requirement).
	_ "modernc.org/sqlite"
)

// Entitlement represents a customer's subscription state and the last
// license token issued against it. The "last_license_*" fields enable
// idempotency: if the current subscription state matches the last-issued
// state, we skip re-issuing.
type Entitlement struct {
	SubscriptionID     string
	CustomerEmail      string
	ProductID          string
	Tier               string // "community", "founding_pro", "pro", "enterprise"
	BillingInterval    string // "month", "year"
	Status             string // "active", "canceled", "past_due", "unpaid"
	CurrentPeriodEnd   time.Time
	Founding           bool
	FoundingReservedAt *time.Time // set once when a founding slot is claimed; never cleared
	Org                string
	Features           string // JSON array of feature strings

	// Last-issued license state (for idempotency comparison).
	LastLicenseID        string
	LastLicenseIssuedAt  *time.Time
	LastLicenseExpiresAt *time.Time
	LastLicensePeriodEnd *time.Time
	LastLicenseTier      string
	LastLicenseInterval  string
	LastLicenseProductID string

	// Delivery tracking.
	LastDeliveryStatus    string // "sent", "failed", "pending"
	LastDeliveryAttemptAt *time.Time

	// Rolling refresh scheduling.
	NextRefreshAt *time.Time

	CreatedAt time.Time
	UpdatedAt time.Time
}

// RevokedLicenseRecord is a license ID that must be included in the signed CRL.
type RevokedLicenseRecord struct {
	LicenseID      string
	SubscriptionID string
	Reason         string
	RevokedAt      time.Time
}

// LicenseIssuance records each minted license token so subscription shutdown
// can revoke still-valid older refresh tokens, not just the latest one.
type LicenseIssuance struct {
	LicenseID      string
	SubscriptionID string
	ExpiresAt      time.Time
	IssuedAt       time.Time
}

// EntitlementDB manages the SQLite entitlement store.
type EntitlementDB struct {
	db *sql.DB
}

// ErrTerminalEntitlement means a stale active event tried to mint a license
// after this subscription was already recorded in a terminal state.
var ErrTerminalEntitlement = errors.New("entitlement is terminal")

type entitlementExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

type entitlementQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// OpenEntitlementDB opens (or creates) the SQLite database at path and
// runs migrations. The database uses WAL mode for concurrent read access.
func OpenEntitlementDB(ctx context.Context, path string) (*EntitlementDB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open entitlement db: %w", err)
	}

	// SQLite with database/sql uses a connection pool. For :memory: databases,
	// each connection gets a separate in-memory DB. Limit to 1 connection to
	// ensure all queries hit the same underlying database.
	db.SetMaxOpenConns(1)

	// WAL mode for better concurrent read performance.
	if _, err := db.ExecContext(ctx, "PRAGMA journal_mode=WAL"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("set WAL mode: %w", err)
	}

	// Foreign keys on (defensive, even though we have a single table now).
	if _, err := db.ExecContext(ctx, "PRAGMA foreign_keys=ON"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}

	edb := &EntitlementDB{db: db}
	if err := edb.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate entitlement db: %w", err)
	}

	return edb, nil
}

// Close closes the underlying database connection.
func (e *EntitlementDB) Close() error {
	return e.db.Close()
}

// migrate creates the entitlements table if it doesn't exist.
func (e *EntitlementDB) migrate(ctx context.Context) error {
	const ddl = `
	CREATE TABLE IF NOT EXISTS entitlements (
		subscription_id        TEXT PRIMARY KEY,
		customer_email         TEXT NOT NULL,
		product_id             TEXT NOT NULL,
		tier                   TEXT NOT NULL,
		billing_interval       TEXT NOT NULL,
		status                 TEXT NOT NULL,
		current_period_end     DATETIME NOT NULL,
		founding               BOOLEAN NOT NULL DEFAULT 0,
		founding_reserved_at   DATETIME,
		org                    TEXT NOT NULL DEFAULT '',
		features               TEXT NOT NULL DEFAULT '[]',

		last_license_id         TEXT NOT NULL DEFAULT '',
		last_license_issued_at  DATETIME,
		last_license_expires_at DATETIME,
		last_license_period_end DATETIME,
		last_license_tier       TEXT NOT NULL DEFAULT '',
		last_license_interval   TEXT NOT NULL DEFAULT '',
		last_license_product_id TEXT NOT NULL DEFAULT '',

		last_delivery_status     TEXT NOT NULL DEFAULT '',
		last_delivery_attempt_at DATETIME,

		next_refresh_at DATETIME,

		created_at DATETIME NOT NULL DEFAULT (datetime('now')),
		updated_at DATETIME NOT NULL DEFAULT (datetime('now'))
	);

	CREATE INDEX IF NOT EXISTS idx_entitlements_status ON entitlements(status);
	CREATE INDEX IF NOT EXISTS idx_entitlements_next_refresh ON entitlements(next_refresh_at);
	CREATE INDEX IF NOT EXISTS idx_entitlements_founding ON entitlements(founding);
	CREATE INDEX IF NOT EXISTS idx_entitlements_founding_reserved ON entitlements(founding_reserved_at);

	CREATE TABLE IF NOT EXISTS license_revocations (
		license_id      TEXT PRIMARY KEY,
		subscription_id TEXT NOT NULL,
		reason          TEXT NOT NULL,
		revoked_at      DATETIME NOT NULL,
		created_at      DATETIME NOT NULL DEFAULT (datetime('now'))
	);

	CREATE INDEX IF NOT EXISTS idx_license_revocations_subscription ON license_revocations(subscription_id);

	CREATE TABLE IF NOT EXISTS license_issuances (
		license_id      TEXT PRIMARY KEY,
		subscription_id TEXT NOT NULL,
		expires_at      DATETIME NOT NULL,
		issued_at       DATETIME NOT NULL,
		created_at      DATETIME NOT NULL DEFAULT (datetime('now'))
	);

	CREATE INDEX IF NOT EXISTS idx_license_issuances_subscription ON license_issuances(subscription_id);

	CREATE TABLE IF NOT EXISTS eval_orders (
		order_id           TEXT PRIMARY KEY,
		normalized_email   TEXT NOT NULL,
		product_id         TEXT NOT NULL DEFAULT '',
		total_amount       INTEGER NOT NULL DEFAULT 0,
		refunded_amount    INTEGER NOT NULL DEFAULT 0,
		currency           TEXT NOT NULL DEFAULT '',
		polar_paid         BOOLEAN NOT NULL DEFAULT 0,
		refund_state       TEXT NOT NULL DEFAULT 'none',
		fulfillment_state  TEXT NOT NULL DEFAULT 'none',
		revocation_state   TEXT NOT NULL DEFAULT 'none',
		gate_denial_reason TEXT NOT NULL DEFAULT '',
		license_id         TEXT NOT NULL DEFAULT '',
		created_at         DATETIME NOT NULL DEFAULT (datetime('now')),
		updated_at         DATETIME NOT NULL DEFAULT (datetime('now'))
	);

	CREATE INDEX IF NOT EXISTS idx_eval_orders_email ON eval_orders(normalized_email);

	CREATE TABLE IF NOT EXISTS webhook_deliveries (
		msg_id       TEXT PRIMARY KEY,
		event_type   TEXT NOT NULL DEFAULT '',
		resource_id  TEXT NOT NULL DEFAULT '',
		status       TEXT NOT NULL DEFAULT 'committed',
		committed_at DATETIME NOT NULL DEFAULT (datetime('now')),
		error_reason TEXT NOT NULL DEFAULT ''
	);

	-- crl_generation holds the issuer's monotonic CRL generation counter as a
	-- single row (id = 0). It is the durable high-water mark on the issuing
	-- side: NextCRLGeneration advances it atomically so every newly signed CRL
	-- carries a strictly higher generation than the one before, which is what
	-- lets consumers reject rolled-back CRLs.
	CREATE TABLE IF NOT EXISTS crl_generation (
		id         INTEGER PRIMARY KEY CHECK (id = 0),
		generation INTEGER NOT NULL DEFAULT 0
	);
	`
	_, err := e.db.ExecContext(ctx, ddl)
	return err
}

// Upsert inserts or updates an entitlement record. Updates the updated_at
// timestamp automatically.
func (e *EntitlementDB) Upsert(ctx context.Context, ent *Entitlement) error {
	if ent == nil {
		return errors.New("entitlement is nil")
	}
	if err := upsertEntitlement(ctx, e.db, ent); err != nil {
		return fmt.Errorf("upsert entitlement %s: %w", ent.SubscriptionID, err)
	}
	return nil
}

func upsertEntitlement(ctx context.Context, exec entitlementExecer, ent *Entitlement) error {
	const query = `
	INSERT INTO entitlements (
		subscription_id, customer_email, product_id, tier, billing_interval,
		status, current_period_end, founding, founding_reserved_at, org, features,
		last_license_id, last_license_issued_at, last_license_expires_at,
		last_license_period_end, last_license_tier, last_license_interval,
		last_license_product_id, last_delivery_status, last_delivery_attempt_at,
		next_refresh_at, created_at, updated_at
	) VALUES (
		?, ?, ?, ?, ?,
		?, ?, ?, ?, ?,
		?,
		?, ?, ?,
		?, ?, ?,
		?, ?, ?,
		?, datetime('now'), datetime('now')
	)
	ON CONFLICT(subscription_id) DO UPDATE SET
		customer_email         = excluded.customer_email,
		product_id             = excluded.product_id,
		tier                   = excluded.tier,
		billing_interval       = excluded.billing_interval,
		status                 = excluded.status,
		current_period_end     = excluded.current_period_end,
		founding               = excluded.founding,
		founding_reserved_at   = COALESCE(entitlements.founding_reserved_at, excluded.founding_reserved_at),
		org                    = excluded.org,
		features               = excluded.features,
		last_license_id        = excluded.last_license_id,
		last_license_issued_at = excluded.last_license_issued_at,
		last_license_expires_at= excluded.last_license_expires_at,
		last_license_period_end= excluded.last_license_period_end,
		last_license_tier      = excluded.last_license_tier,
		last_license_interval  = excluded.last_license_interval,
		last_license_product_id= excluded.last_license_product_id,
		last_delivery_status   = excluded.last_delivery_status,
		last_delivery_attempt_at = excluded.last_delivery_attempt_at,
		next_refresh_at        = excluded.next_refresh_at,
		updated_at             = datetime('now')
	`

	//nolint:gosec // G701 false positive: query is a const with parameterized placeholders, not concatenated
	_, err := exec.ExecContext(ctx, query,
		ent.SubscriptionID, ent.CustomerEmail, ent.ProductID, ent.Tier, ent.BillingInterval,
		ent.Status, ent.CurrentPeriodEnd, ent.Founding, ent.FoundingReservedAt, ent.Org,
		ent.Features,
		ent.LastLicenseID, ent.LastLicenseIssuedAt, ent.LastLicenseExpiresAt,
		ent.LastLicensePeriodEnd, ent.LastLicenseTier, ent.LastLicenseInterval,
		ent.LastLicenseProductID, ent.LastDeliveryStatus, ent.LastDeliveryAttemptAt,
		ent.NextRefreshAt,
	)
	return err
}

// GetBySubscriptionID retrieves a single entitlement by its Polar subscription ID.
// Returns nil, nil if not found.
func (e *EntitlementDB) GetBySubscriptionID(ctx context.Context, subID string) (*Entitlement, error) {
	const query = `
	SELECT
		subscription_id, customer_email, product_id, tier, billing_interval,
		status, current_period_end, founding, founding_reserved_at, org, features,
		last_license_id, last_license_issued_at, last_license_expires_at,
		last_license_period_end, last_license_tier, last_license_interval,
		last_license_product_id, last_delivery_status, last_delivery_attempt_at,
		next_refresh_at, created_at, updated_at
	FROM entitlements
	WHERE subscription_id = ?
	`

	ent := &Entitlement{}
	err := e.db.QueryRowContext(ctx, query, subID).Scan(
		&ent.SubscriptionID, &ent.CustomerEmail, &ent.ProductID, &ent.Tier, &ent.BillingInterval,
		&ent.Status, &ent.CurrentPeriodEnd, &ent.Founding, &ent.FoundingReservedAt, &ent.Org,
		&ent.Features,
		&ent.LastLicenseID, &ent.LastLicenseIssuedAt, &ent.LastLicenseExpiresAt,
		&ent.LastLicensePeriodEnd, &ent.LastLicenseTier, &ent.LastLicenseInterval,
		&ent.LastLicenseProductID, &ent.LastDeliveryStatus, &ent.LastDeliveryAttemptAt,
		&ent.NextRefreshAt, &ent.CreatedAt, &ent.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get entitlement %s: %w", subID, err)
	}
	return ent, nil
}

// ListDueForRefresh returns all active entitlements whose next_refresh_at
// is at or before the given time. Used by the cron loop to issue fresh tokens.
func (e *EntitlementDB) ListDueForRefresh(ctx context.Context, before time.Time) ([]*Entitlement, error) {
	const query = `
	SELECT
		subscription_id, customer_email, product_id, tier, billing_interval,
		status, current_period_end, founding, founding_reserved_at, org, features,
		last_license_id, last_license_issued_at, last_license_expires_at,
		last_license_period_end, last_license_tier, last_license_interval,
		last_license_product_id, last_delivery_status, last_delivery_attempt_at,
		next_refresh_at, created_at, updated_at
	FROM entitlements
	WHERE status = 'active'
	  AND next_refresh_at IS NOT NULL
	  AND next_refresh_at <= ?
	ORDER BY next_refresh_at ASC
	`

	rows, err := e.db.QueryContext(ctx, query, before)
	if err != nil {
		return nil, fmt.Errorf("list due for refresh: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var results []*Entitlement
	for rows.Next() {
		ent := &Entitlement{}
		if err := rows.Scan(
			&ent.SubscriptionID, &ent.CustomerEmail, &ent.ProductID, &ent.Tier, &ent.BillingInterval,
			&ent.Status, &ent.CurrentPeriodEnd, &ent.Founding, &ent.FoundingReservedAt, &ent.Org,
			&ent.Features,
			&ent.LastLicenseID, &ent.LastLicenseIssuedAt, &ent.LastLicenseExpiresAt,
			&ent.LastLicensePeriodEnd, &ent.LastLicenseTier, &ent.LastLicenseInterval,
			&ent.LastLicenseProductID, &ent.LastDeliveryStatus, &ent.LastDeliveryAttemptAt,
			&ent.NextRefreshAt, &ent.CreatedAt, &ent.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan entitlement row: %w", err)
		}
		results = append(results, ent)
	}
	return results, rows.Err()
}

// CountFounding returns the total number of entitlements that ever reserved
// a founding slot. Uses founding_reserved_at (immutable once set) instead of
// the founding bool (which tracks current product state and can change).
// This ensures the count never decreases when a subscriber changes products.
func (e *EntitlementDB) CountFounding(ctx context.Context) (int, error) {
	var count int
	err := e.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM entitlements WHERE founding_reserved_at IS NOT NULL",
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count founding: %w", err)
	}
	return count, nil
}

// UpdateDeliveryStatus updates just the delivery tracking fields after
// an email send attempt.
func (e *EntitlementDB) UpdateDeliveryStatus(ctx context.Context, subID, status string, attemptAt time.Time) error {
	const query = `
	UPDATE entitlements
	SET last_delivery_status = ?, last_delivery_attempt_at = ?, updated_at = datetime('now')
	WHERE subscription_id = ?
	`
	//nolint:gosec // G701 false positive: status is a parameterized value, not concatenated into SQL
	_, err := e.db.ExecContext(ctx, query, status, attemptAt, subID)
	if err != nil {
		return fmt.Errorf("update delivery status %s: %w", subID, err)
	}
	return nil
}

// UpdateNextRefresh sets the next_refresh_at timestamp for a subscription.
func (e *EntitlementDB) UpdateNextRefresh(ctx context.Context, subID string, nextRefresh time.Time) error {
	const query = `
	UPDATE entitlements
	SET next_refresh_at = ?, updated_at = datetime('now')
	WHERE subscription_id = ?
	`
	_, err := e.db.ExecContext(ctx, query, nextRefresh, subID)
	if err != nil {
		return fmt.Errorf("update next refresh %s: %w", subID, err)
	}
	return nil
}

// UpsertLicenseRevocation records a revoked license ID for CRL publication.
func (e *EntitlementDB) UpsertLicenseRevocation(ctx context.Context, rec RevokedLicenseRecord) error {
	if rec.LicenseID == "" {
		return errors.New("license_id is required")
	}
	if rec.SubscriptionID == "" {
		return errors.New("subscription_id is required")
	}
	if rec.Reason == "" {
		rec.Reason = "subscription_ended"
	}
	if rec.RevokedAt.IsZero() {
		rec.RevokedAt = time.Now().UTC()
	}
	const query = `
	INSERT INTO license_revocations (license_id, subscription_id, reason, revoked_at)
	VALUES (?, ?, ?, ?)
	ON CONFLICT(license_id) DO UPDATE SET
		subscription_id = excluded.subscription_id,
		reason = excluded.reason,
		revoked_at = excluded.revoked_at
	`
	_, err := e.db.ExecContext(ctx, query, rec.LicenseID, rec.SubscriptionID, rec.Reason, rec.RevokedAt)
	if err != nil {
		return fmt.Errorf("upsert license revocation %s: %w", rec.LicenseID, err)
	}
	return nil
}

// ListLicenseRevocations returns all currently published license revocations.
func (e *EntitlementDB) ListLicenseRevocations(ctx context.Context) ([]RevokedLicenseRecord, error) {
	const query = `
	SELECT r.license_id, r.subscription_id, r.reason, r.revoked_at
	FROM license_revocations AS r
	LEFT JOIN license_issuances i ON i.license_id = r.license_id
	WHERE i.expires_at IS NULL OR i.expires_at > ?
	ORDER BY r.license_id ASC
	`
	rows, err := e.db.QueryContext(ctx, query, time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("list license revocations: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var results []RevokedLicenseRecord
	for rows.Next() {
		var rec RevokedLicenseRecord
		if err := rows.Scan(&rec.LicenseID, &rec.SubscriptionID, &rec.Reason, &rec.RevokedAt); err != nil {
			return nil, fmt.Errorf("scan license revocation: %w", err)
		}
		results = append(results, rec)
	}
	return results, rows.Err()
}

// NextCRLGeneration atomically advances and returns the issuer's monotonic CRL
// generation counter. Each call returns a value strictly greater than every
// prior call's, persisted durably in SQLite so a service restart cannot rewind
// the counter and re-issue a lower-generation CRL. This is the issuer half of
// the revocation-rollback defense; the consumer rejects any CRL below its own
// accepted high-water mark.
func (e *EntitlementDB) NextCRLGeneration(ctx context.Context) (uint64, error) {
	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin crl generation transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Seed the single row if absent, then bump it. INSERT OR IGNORE keeps the
	// existing value when the row is already present.
	if _, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO crl_generation (id, generation) VALUES (0, 0)`); err != nil {
		return 0, fmt.Errorf("seed crl generation: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE crl_generation SET generation = generation + 1 WHERE id = 0`); err != nil {
		return 0, fmt.Errorf("advance crl generation: %w", err)
	}
	var generation uint64
	if err := tx.QueryRowContext(ctx,
		`SELECT generation FROM crl_generation WHERE id = 0`).Scan(&generation); err != nil {
		return 0, fmt.Errorf("read crl generation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit crl generation: %w", err)
	}
	return generation, nil
}

// InsertLicenseIssuance records a minted license token for later revocation.
func (e *EntitlementDB) InsertLicenseIssuance(ctx context.Context, issuance LicenseIssuance) error {
	if err := insertLicenseIssuance(ctx, e.db, issuance); err != nil {
		return fmt.Errorf("insert license issuance %s: %w", issuance.LicenseID, err)
	}
	return nil
}

// UpsertWithLicenseIssuance atomically records entitlement state and the
// license issuance. It refuses stale active events when the current persisted
// subscription state is already terminal.
func (e *EntitlementDB) UpsertWithLicenseIssuance(ctx context.Context, ent *Entitlement, issuance LicenseIssuance) error {
	if ent == nil {
		return errors.New("entitlement is nil")
	}
	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin entitlement issuance transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	terminal, status, err := currentEntitlementTerminal(ctx, tx, ent.SubscriptionID)
	if err != nil {
		return err
	}
	if terminal {
		return fmt.Errorf("%w: subscription %s status %s", ErrTerminalEntitlement, ent.SubscriptionID, status)
	}
	if err := upsertEntitlement(ctx, tx, ent); err != nil {
		return fmt.Errorf("upsert entitlement %s: %w", ent.SubscriptionID, err)
	}
	if err := insertLicenseIssuance(ctx, tx, issuance); err != nil {
		return fmt.Errorf("insert license issuance %s: %w", issuance.LicenseID, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit entitlement issuance transaction: %w", err)
	}
	committed = true
	return nil
}

func insertLicenseIssuance(ctx context.Context, exec entitlementExecer, issuance LicenseIssuance) error {
	if issuance.LicenseID == "" {
		return errors.New("license_id is required")
	}
	if issuance.SubscriptionID == "" {
		return errors.New("subscription_id is required")
	}
	if issuance.ExpiresAt.IsZero() {
		return errors.New("expires_at is required")
	}
	if issuance.IssuedAt.IsZero() {
		issuance.IssuedAt = time.Now().UTC()
	}
	const query = `
	INSERT INTO license_issuances (license_id, subscription_id, expires_at, issued_at)
	VALUES (?, ?, ?, ?)
	ON CONFLICT(license_id) DO NOTHING
	`
	_, err := exec.ExecContext(ctx, query, issuance.LicenseID, issuance.SubscriptionID, issuance.ExpiresAt, issuance.IssuedAt)
	return err
}

// ListUnexpiredLicenseIssuances returns every still-valid license minted for a subscription.
func (e *EntitlementDB) ListUnexpiredLicenseIssuances(ctx context.Context, subID string, now time.Time) ([]LicenseIssuance, error) {
	const query = `
	SELECT license_id, subscription_id, expires_at, issued_at
	FROM license_issuances
	WHERE subscription_id = ?
	  AND expires_at > ?
	ORDER BY issued_at ASC, license_id ASC
	`
	rows, err := e.db.QueryContext(ctx, query, subID, now.UTC())
	if err != nil {
		return nil, fmt.Errorf("list license issuances %s: %w", subID, err)
	}
	defer func() { _ = rows.Close() }()

	var results []LicenseIssuance
	for rows.Next() {
		var issuance LicenseIssuance
		if err := rows.Scan(&issuance.LicenseID, &issuance.SubscriptionID, &issuance.ExpiresAt, &issuance.IssuedAt); err != nil {
			return nil, fmt.Errorf("scan license issuance: %w", err)
		}
		results = append(results, issuance)
	}
	return results, rows.Err()
}

func currentEntitlementTerminal(ctx context.Context, q entitlementQueryer, subID string) (bool, string, error) {
	var status string
	err := q.QueryRowContext(ctx, "SELECT status FROM entitlements WHERE subscription_id = ?", subID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return false, "", nil
	}
	if err != nil {
		return false, "", fmt.Errorf("read current entitlement status %s: %w", subID, err)
	}
	return isTerminalEntitlementStatus(status), status, nil
}

func isTerminalEntitlementStatus(status string) bool {
	switch status {
	case statusCanceled, statusRevoked, statusUnpaid:
		return true
	default:
		return false
	}
}
