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
	SubscriptionID   string
	CustomerEmail    string
	ProductID        string
	Tier             string // "community", "founding_pro", "pro", "enterprise"
	BillingInterval  string // "month", "year"
	Status           string // "active", "canceled", "past_due", "unpaid"
	CurrentPeriodEnd time.Time
	Founding         bool
	Org              string
	Features         string // JSON array of feature strings

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

// EntitlementDB manages the SQLite entitlement store.
type EntitlementDB struct {
	db *sql.DB
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
	`
	_, err := e.db.ExecContext(ctx, ddl)
	return err
}

// Upsert inserts or updates an entitlement record. Updates the updated_at
// timestamp automatically.
func (e *EntitlementDB) Upsert(ctx context.Context, ent *Entitlement) error {
	const query = `
	INSERT INTO entitlements (
		subscription_id, customer_email, product_id, tier, billing_interval,
		status, current_period_end, founding, org, features,
		last_license_id, last_license_issued_at, last_license_expires_at,
		last_license_period_end, last_license_tier, last_license_interval,
		last_license_product_id, last_delivery_status, last_delivery_attempt_at,
		next_refresh_at, created_at, updated_at
	) VALUES (
		?, ?, ?, ?, ?,
		?, ?, ?, ?, ?,
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
	_, err := e.db.ExecContext(ctx, query,
		ent.SubscriptionID, ent.CustomerEmail, ent.ProductID, ent.Tier, ent.BillingInterval,
		ent.Status, ent.CurrentPeriodEnd, ent.Founding, ent.Org, ent.Features,
		ent.LastLicenseID, ent.LastLicenseIssuedAt, ent.LastLicenseExpiresAt,
		ent.LastLicensePeriodEnd, ent.LastLicenseTier, ent.LastLicenseInterval,
		ent.LastLicenseProductID, ent.LastDeliveryStatus, ent.LastDeliveryAttemptAt,
		ent.NextRefreshAt,
	)
	if err != nil {
		return fmt.Errorf("upsert entitlement %s: %w", ent.SubscriptionID, err)
	}
	return nil
}

// GetBySubscriptionID retrieves a single entitlement by its Polar subscription ID.
// Returns nil, nil if not found.
func (e *EntitlementDB) GetBySubscriptionID(ctx context.Context, subID string) (*Entitlement, error) {
	const query = `
	SELECT
		subscription_id, customer_email, product_id, tier, billing_interval,
		status, current_period_end, founding, org, features,
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
		&ent.Status, &ent.CurrentPeriodEnd, &ent.Founding, &ent.Org, &ent.Features,
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
		status, current_period_end, founding, org, features,
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
			&ent.Status, &ent.CurrentPeriodEnd, &ent.Founding, &ent.Org, &ent.Features,
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

// CountFounding returns the total number of entitlements that were ever
// marked as founding (including canceled/refunded). This count never decreases.
func (e *EntitlementDB) CountFounding(ctx context.Context) (int, error) {
	var count int
	err := e.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM entitlements WHERE founding = 1").Scan(&count)
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
