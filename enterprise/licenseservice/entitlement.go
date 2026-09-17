//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog"

	// Pure-Go SQLite driver (no CGO requirement).
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

const (
	trialSlotTakeoverUnclassified = "unclassified"
	trialSlotTakeoverVerified     = "verified"
	trialSlotTakeoverDrifted      = "drifted"
	trialSlotTakeoverUnverifiable = "unverifiable"
	trialSlotTakeoverOrphaned     = "orphaned"
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

// RevokedIntermediateRecord is an intermediate signing-cert serial that must be
// included in the published signed CRL. Revoking it invalidates every license
// token the intermediate signed.
type RevokedIntermediateRecord struct {
	Serial    string
	Reason    string
	RevokedAt time.Time
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

	// journalMode is the mode the database settled on at open time. See
	// enableWAL for why it is not guaranteed to be WAL.
	journalMode string

	// inMemory records that the operator asked for the :memory: sentinel, which
	// is the only configuration in which an ephemeral store is intended.
	inMemory bool
}

// journalModeWAL is the mode a file database is expected to run in.
const journalModeWAL = "wal"

// journalModeMemory is what an in-memory database reports. It can never be WAL.
const journalModeMemory = "memory"

// inMemoryPath is the configured path that asks for an ephemeral database.
const inMemoryPath = ":memory:"

// ErrTerminalEntitlement means a stale active event tried to mint a license
// after this subscription was already recorded in a terminal state.
var ErrTerminalEntitlement = errors.New("entitlement is terminal")

// ErrWebhookAlreadyCommitted means another delivery path already admitted this
// provider message ID. Callers must not perform side effects from freshly built
// state; they may retry delivery from the persisted record.
var ErrWebhookAlreadyCommitted = errors.New("webhook already committed")

// ErrActiveTrialExists means another order owns the unexpired trial slot for
// the entitlement's canonical customer email.
var ErrActiveTrialExists = errors.New("active trial already exists")

// ErrTrialEmailNotCanonical means the entitlement's customer email cannot be
// canonicalized, so it can hold no trial slot and the one-active-trial rule
// cannot be enforced for it. Granting a trial on this address is refused;
// merely RECORDING an entitlement is not, because refusing that would block
// revoking or status-mirroring a legacy row and buys no enforcement.
var ErrTrialEmailNotCanonical = errors.New("trial email cannot be canonicalized")

type entitlementExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

type entitlementQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// dsnPragmas are applied to every connection the driver opens.
//
// They belong in the connection string rather than in an Exec after opening,
// because a PRAGMA statement applies only to the connection that ran it: if
// database/sql replaces the pooled connection, the replacement would come back
// with no busy timeout and a concurrent trial claim would surface SQLITE_BUSY
// as a failed grant on the billing path.
//
// journal_mode is deliberately absent. It is a property of the database file
// rather than of a connection, so it is set once by enableWAL instead.
const dsnPragmas = "_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"

// entitlementDSN builds the driver connection string for path.
//
// A filesystem path becomes an absolute file: URI rather than being pasted in
// front of the parameters. The driver reads '?' as the start of its parameters
// even in a bare path, so concatenating would both select a different database
// and silently drop the pragmas for any operator whose configured path contains
// one. An explicit URI has the pragmas merged into its query so its own
// parameters and any fragment survive.
func entitlementDSN(path string) (string, error) {
	if path == inMemoryPath {
		return path + "?" + dsnPragmas, nil
	}
	if strings.HasPrefix(path, "file:") {
		return mergeDSNPragmas(path)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		// Abs only fails when the working directory is unavailable, and there
		// is no safe fallback: a relative path handed to fileURI would gain a
		// leading slash and silently name a database at the filesystem root
		// instead of the configured one. Refuse rather than open the wrong
		// entitlement state.
		return "", fmt.Errorf("resolve database path %q: %w", path, err)
	}
	return fileURI(filepath.ToSlash(absolute)), nil
}

// fileURI turns a slash-separated absolute path into a file: URI. A Windows
// path arrives as "C:/data/x.db" with no leading slash; without one the result
// is a relative URI reference and the driver would open a database beside the
// process instead of the configured one.
func fileURI(slashed string) string {
	if !strings.HasPrefix(slashed, "/") {
		slashed = "/" + slashed
	}
	u := url.URL{Scheme: "file", Path: slashed, RawQuery: dsnPragmas}
	return u.String()
}

// mergeDSNPragmas adds the pragmas to an operator-supplied file: URI without
// disturbing its own parameters.
//
// A fragment is refused rather than carried or quietly dropped. SQLite has no
// use for one, and this driver does not accept it: left in place it fails at
// the first query with "near \"#...\": syntax error", long after startup and
// pointing at nothing the operator can act on. Refusing here names the problem
// while the service is still starting.
func mergeDSNPragmas(uri string) (string, error) {
	parsed, err := url.Parse(uri)
	if err != nil {
		return "", fmt.Errorf("parse database uri: %w", err)
	}
	if parsed.Fragment != "" || strings.Contains(uri, "#") {
		return "", fmt.Errorf("database uri must not contain a fragment: %s", uri)
	}
	if parsed.RawQuery == "" {
		parsed.RawQuery = dsnPragmas
	} else {
		parsed.RawQuery += "&" + dsnPragmas
	}
	return parsed.String(), nil
}

// OpenEntitlementDB opens (or creates) the SQLite database at path and
// runs migrations. The database uses WAL mode for concurrent read access.
func OpenEntitlementDB(ctx context.Context, path string) (*EntitlementDB, error) {
	dsn, err := entitlementDSN(path)
	if err != nil {
		return nil, fmt.Errorf("build entitlement db connection string: %w", err)
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open entitlement db: %w", err)
	}

	// SQLite with database/sql uses a connection pool. For :memory: databases,
	// each connection gets a separate in-memory DB. Limit to 1 connection to
	// ensure all queries hit the same underlying database.
	db.SetMaxOpenConns(1)

	edb := &EntitlementDB{db: db, inMemory: path == inMemoryPath}

	// Ask for WAL before migrating so the migration itself runs under it, and
	// again afterwards if a lock was in the way the first time: by then the
	// migration has held and released its own lock, which is long enough for a
	// brief contender to have finished.
	mode, err := enableWAL(ctx, db)
	if err != nil {
		_ = db.Close()
		return nil, err
	}

	if err := edb.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate entitlement db: %w", err)
	}

	if mode != journalModeWAL {
		if retried, err := enableWAL(ctx, db); err != nil {
			_ = db.Close()
			return nil, err
		} else if retried != "" {
			mode = retried
		}
	}
	edb.journalMode = mode

	// A database that cannot become WAL because it is not on disk keeps nothing
	// across a restart, which empties the table the one-trial limit is read
	// from and hands every customer their trial back. Refuse it: a log line
	// does not stop that, and an operator who wanted an ephemeral store has the
	// :memory: sentinel to ask for one by name.
	//
	// journal_mode=MEMORY on a real on-disk database is a different and
	// legitimate setting, and it is not caught here: that database accepts the
	// WAL request above and reports "wal". Only a database with no file behind
	// it still answers "memory" after being asked.
	if mode == journalModeMemory && !edb.inMemory {
		_ = db.Close()
		return nil, fmt.Errorf(
			"entitlement database %q opens an in-memory database, which keeps no entitlement or trial state across a restart: point it at a file, or use %q to ask for an ephemeral database on purpose",
			path, inMemoryPath)
	}

	return edb, nil
}

// Close closes the underlying database connection.
func (e *EntitlementDB) Close() error {
	return e.db.Close()
}

// JournalMode reports the journal mode the database ended up in.
//
// A file database is expected to report "wal". Anything else means enableWAL
// could not take the exclusive lock it needs, which the caller reports so the
// condition does not pass silently.
func (e *EntitlementDB) JournalMode() string {
	return e.journalMode
}

// isBusyError reports whether err is SQLite refusing to take a lock another
// connection holds. Only that is transient; an I/O or corruption error is not.
func isBusyError(err error) bool {
	var serr *sqlite.Error
	if errors.As(err, &serr) {
		code := serr.Code()
		return code == sqlite3.SQLITE_BUSY || code == sqlite3.SQLITE_LOCKED
	}
	return false
}

// enableWAL puts the database in write-ahead logging mode and reports the mode
// it settled on.
//
// This cannot be a DSN pragma. Changing journal_mode needs an exclusive lock,
// and SQLite refuses that request immediately instead of waiting out
// busy_timeout, so a database another process held for even a moment would
// fail every connection the driver opened and the service would not start. A
// lock is a transient condition; refusing to boot over it is not a trade worth
// making, because trial-claim correctness rests on the transactional slot
// constraint rather than on WAL.
//
// Unlike busy_timeout and foreign_keys, journal_mode persists in the database
// file, so setting it once on any connection is enough.
func enableWAL(ctx context.Context, db *sql.DB) (string, error) {
	var mode string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&mode); err != nil {
		if isBusyError(err) {
			return "", nil
		}
		return "", fmt.Errorf("enable write-ahead logging: %w", err)
	}
	return strings.ToLower(mode), nil
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

	CREATE TABLE IF NOT EXISTS active_trial_slots (
		normalized_email              TEXT PRIMARY KEY,
		subscription_id               TEXT NOT NULL,
		expires_at                    DATETIME NOT NULL,
		takeover_state                TEXT NOT NULL DEFAULT 'unclassified',
		legacy_entitlement_expires_at DATETIME
	);

	-- trial_order_guards serializes a one-time trial issuance with an
	-- out-of-order refund for the same provider order. It is deliberately
	-- separate from eval_orders: trials are not evals, but they need one
	-- durable per-order row both paths can lock before issuing a credential.
	CREATE TABLE IF NOT EXISTS trial_order_guards (
		order_id       TEXT PRIMARY KEY,
		pending_refund BOOLEAN NOT NULL DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS license_revocations (
		license_id      TEXT PRIMARY KEY,
		subscription_id TEXT NOT NULL,
		reason          TEXT NOT NULL,
		revoked_at      DATETIME NOT NULL,
		created_at      DATETIME NOT NULL DEFAULT (datetime('now'))
	);

	CREATE INDEX IF NOT EXISTS idx_license_revocations_subscription ON license_revocations(subscription_id);

	-- revoked_intermediates is the durable issuer-side list of revoked
	-- intermediate signing certificates, keyed by serial. Revoking an
	-- intermediate (rotation or compromise) invalidates EVERY license token it
	-- signed. The published SignedCRL includes these as RevokedIntermediates so
	-- consumers fail closed. Without this table, intermediate revocation is a
	-- consumer-side illusion (the model and consumer check exist, but the issuer
	-- never publishes the serials).
	CREATE TABLE IF NOT EXISTS revoked_intermediates (
		serial      TEXT PRIMARY KEY,
		reason      TEXT NOT NULL,
		revoked_at  DATETIME NOT NULL,
		created_at  DATETIME NOT NULL DEFAULT (datetime('now'))
	);

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

	-- imported_issuances is the durable record of license tokens minted OUTSIDE
	-- the service (the offline-root break-glass / standalone-CLI path) and then
	-- imported via a SIGNED issuance export. It is the revocation surface for
	-- those tokens: the service can only revoke a token it knows about, and the
	-- local JSONL ledger (truncated, unsigned hash) cannot be the import source.
	--
	-- token_sha256 is the FULL 64-hex sha256 of the exact token string (not the
	-- truncated ledger hash), so an import is bound to the real credential.
	-- import_id is a unique, server-assigned id per import. The UNIQUE constraint
	-- on token_sha256 plus the PRIMARY KEY on license_id make a replayed export
	-- (same token, same id) a no-op and a conflicting export (same id, different
	-- token, or same token, different id) a hard rejection.
	CREATE TABLE IF NOT EXISTS imported_issuances (
		license_id      TEXT PRIMARY KEY,
		token_sha256    TEXT NOT NULL UNIQUE,
		subscription_id TEXT NOT NULL DEFAULT '',
		issuer_key_id   TEXT NOT NULL,
		issued_at       DATETIME NOT NULL,
		expires_at      DATETIME,
		import_id       TEXT NOT NULL UNIQUE,
		imported_at     DATETIME NOT NULL DEFAULT (datetime('now'))
	);

	CREATE INDEX IF NOT EXISTS idx_imported_issuances_subscription ON imported_issuances(subscription_id);
	CREATE INDEX IF NOT EXISTS idx_imported_issuances_issuer ON imported_issuances(issuer_key_id);
	`
	if _, err := e.db.ExecContext(ctx, ddl); err != nil {
		return err
	}
	if err := e.classifyLegacyTrialSlots(ctx); err != nil {
		return err
	}
	return e.backfillActiveTrialSlots(ctx)
}

// classifyLegacyTrialSlots makes the one-time judgement needed for rows that
// predate write-once slot expiry. Ordinary entitlement writes never touch this
// classification, so takeover does not depend on keeping two tables equal.
func (e *EntitlementDB) classifyLegacyTrialSlots(ctx context.Context) error {
	columns := []struct {
		name string
		ddl  string
	}{
		{"takeover_state", `ALTER TABLE active_trial_slots ADD COLUMN takeover_state TEXT NOT NULL DEFAULT 'unclassified'`},
		{"legacy_entitlement_expires_at", `ALTER TABLE active_trial_slots ADD COLUMN legacy_entitlement_expires_at DATETIME`},
	}
	for _, column := range columns {
		var exists bool
		if err := e.db.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM pragma_table_info('active_trial_slots') WHERE name = ?)`, column.name,
		).Scan(&exists); err != nil {
			return fmt.Errorf("inspect active trial slot column %s: %w", column.name, err)
		}
		if exists {
			continue
		}
		if _, err := e.db.ExecContext(ctx, column.ddl); err != nil {
			// Another service process can add the same column between the check
			// above and this statement. Re-read the schema rather than trusting
			// the error text: if the column is there now, the concurrent starter
			// did the work and this one has nothing left to do. Any other
			// failure still stops startup.
			var added bool
			if rerr := e.db.QueryRowContext(ctx,
				`SELECT EXISTS(SELECT 1 FROM pragma_table_info('active_trial_slots') WHERE name = ?)`, column.name,
			).Scan(&added); rerr != nil || !added {
				return fmt.Errorf("add active trial slot column %s: %w", column.name, err)
			}
		}
	}

	const classify = `
	UPDATE active_trial_slots
	SET legacy_entitlement_expires_at = (
			SELECT last_license_period_end FROM entitlements
			WHERE subscription_id = active_trial_slots.subscription_id
		),
		takeover_state = CASE
			WHEN NOT EXISTS (
				SELECT 1 FROM entitlements
				WHERE subscription_id = active_trial_slots.subscription_id
			) THEN ?
			WHEN EXISTS (
				SELECT 1 FROM entitlements
				WHERE subscription_id = active_trial_slots.subscription_id
				  AND tier IN (?, ?)
				  AND billing_interval = ?
				  AND last_license_period_end IS NOT NULL
				  AND last_license_period_end = active_trial_slots.expires_at
			) THEN ?
			WHEN EXISTS (
				SELECT 1 FROM entitlements
				WHERE subscription_id = active_trial_slots.subscription_id
				  AND tier IN (?, ?)
				  AND billing_interval = ?
				  AND last_license_period_end IS NOT NULL
			) THEN ?
			ELSE ?
		END
	WHERE takeover_state = ?
	`
	if _, err := e.db.ExecContext(ctx, classify,
		trialSlotTakeoverOrphaned,
		tierTrial, tierEnterpriseTrial, billingIntervalOneTime, trialSlotTakeoverVerified,
		tierTrial, tierEnterpriseTrial, billingIntervalOneTime, trialSlotTakeoverDrifted,
		trialSlotTakeoverUnverifiable, trialSlotTakeoverUnclassified,
	); err != nil {
		return fmt.Errorf("classify legacy active trial slots: %w", err)
	}
	return nil
}

// DuplicateActiveTrialEmails reports canonical emails that already hold more
// than one active trial entitlement, newest expiry first per email.
//
// The slot table can represent only ONE owner per canonical email, so the
// migration seeds the longest-running trial and leaves any others running.
// Enforcement therefore begins at the migration: pre-existing duplicates are
// preserved, not revoked, because terminating a customer's live paid trial is
// a business decision and not something a schema migration should do quietly.
// This method exists so that preservation is REPORTED rather than silent, and
// an operator can reconcile deliberately.
func (e *EntitlementDB) DuplicateActiveTrialEmails(ctx context.Context) (map[string][]string, error) {
	const query = `
	SELECT customer_email, subscription_id
	FROM entitlements
	WHERE tier IN (?, ?) AND status IN (?, ?) AND current_period_end > ?
	ORDER BY current_period_end DESC, subscription_id ASC
	`
	rows, err := e.db.QueryContext(ctx, query,
		tierTrial, tierEnterpriseTrial, statusActive, statusRevoked, time.Now().UTC(),
	)
	if err != nil {
		return nil, fmt.Errorf("read trial entitlements for duplicate report: %w", err)
	}
	defer func() { _ = rows.Close() }()

	byEmail := make(map[string][]string)
	for rows.Next() {
		var rawEmail, subscriptionID string
		if err := rows.Scan(&rawEmail, &subscriptionID); err != nil {
			return nil, fmt.Errorf("scan trial entitlement for duplicate report: %w", err)
		}
		canonical, nerr := NormalizeEmail(rawEmail)
		if nerr != nil {
			continue
		}
		byEmail[canonical] = append(byEmail[canonical], subscriptionID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate trial entitlements for duplicate report: %w", err)
	}
	for email, subs := range byEmail {
		if len(subs) < 2 {
			delete(byEmail, email)
		}
	}
	return byEmail, nil
}

// ReportDuplicateActiveTrials logs every customer email that already holds more
// than one active trial. It is called once at startup, after the migration, so
// the trials the slot table could not bring under the limit are named instead
// of preserved quietly. A read failure is reported and never fatal: the report
// is an operator signal, and refusing to start the service over it would trade
// a billing outage for a warning.
func (e *EntitlementDB) ReportDuplicateActiveTrials(ctx context.Context, log zerolog.Logger) {
	duplicates, err := e.DuplicateActiveTrialEmails(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("could not check for pre-existing duplicate active trials")
		return
	}
	// The order IDs are the reconciliation handle and the grouping already
	// says which of them belong to one customer, so the address itself adds
	// nothing an operator needs. Logs ship to a SIEM and are retained, and a
	// customer email in a log line is personal data this service has no reason
	// to put there.
	for _, subscriptions := range duplicates {
		log.Warn().
			Strs("subscription_ids", subscriptions).
			Msg("these orders are active trials for one customer; only the longest-running one holds the trial slot, the others keep running until they expire")
	}
}

// DriftedTrialSlotSubscription identifies one slot row whose expires_at
// disagrees with its owning entitlement's claim-time expiry.
type DriftedTrialSlotSubscription struct {
	SubscriptionID         string
	SlotExpiresAt          time.Time
	EntitlementClaimEndsAt time.Time
}

// TrialSlotExpiryDriftReport separates trial slots with an expiry disagreement
// from legacy rows whose claim-time expiry was never recorded. The latter
// cannot be verified, so they must not make a clean drift report look certain.
type TrialSlotExpiryDriftReport struct {
	Drifted                     []DriftedTrialSlotSubscription
	UnverifiableSubscriptionIDs []string
	OrphanedSubscriptionIDs     []string
}

// DriftedTrialSlots finds legacy active_trial_slots rows classified at
// migration whose expiry disagreed with the owning entitlement's recorded
// claim-time expiry. The immutable classification preserves that evidence
// without making takeover depend on later entitlement writes.
func (e *EntitlementDB) DriftedTrialSlots(ctx context.Context) ([]DriftedTrialSlotSubscription, error) {
	report, err := e.TrialSlotExpiryDriftReport(ctx)
	if err != nil {
		return nil, err
	}
	return report.Drifted, nil
}

// TrialSlotExpiryDriftReport reports the immutable classification recorded
// when legacy slot rows were migrated. It never reclassifies or repairs rows.
func (e *EntitlementDB) TrialSlotExpiryDriftReport(ctx context.Context) (TrialSlotExpiryDriftReport, error) {
	const query = `
	SELECT subscription_id, expires_at, legacy_entitlement_expires_at, takeover_state
	FROM active_trial_slots
	WHERE takeover_state <> ?
	ORDER BY subscription_id ASC
	`
	rows, err := e.db.QueryContext(ctx, query, trialSlotTakeoverVerified)
	if err != nil {
		return TrialSlotExpiryDriftReport{}, fmt.Errorf("read trial slot expiry drift report: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var report TrialSlotExpiryDriftReport
	for rows.Next() {
		var (
			d        DriftedTrialSlotSubscription
			claimEnd sql.NullTime
			state    string
		)
		if err := rows.Scan(&d.SubscriptionID, &d.SlotExpiresAt, &claimEnd, &state); err != nil {
			return TrialSlotExpiryDriftReport{}, fmt.Errorf("scan trial slot expiry drift report: %w", err)
		}
		switch state {
		case trialSlotTakeoverOrphaned:
			report.OrphanedSubscriptionIDs = append(report.OrphanedSubscriptionIDs, d.SubscriptionID)
		case trialSlotTakeoverUnverifiable, trialSlotTakeoverUnclassified:
			report.UnverifiableSubscriptionIDs = append(report.UnverifiableSubscriptionIDs, d.SubscriptionID)
		case trialSlotTakeoverDrifted:
			if !claimEnd.Valid {
				report.UnverifiableSubscriptionIDs = append(report.UnverifiableSubscriptionIDs, d.SubscriptionID)
				continue
			}
			d.SlotExpiresAt = d.SlotExpiresAt.UTC()
			d.EntitlementClaimEndsAt = claimEnd.Time.UTC()
			report.Drifted = append(report.Drifted, d)
		default:
			report.UnverifiableSubscriptionIDs = append(report.UnverifiableSubscriptionIDs, d.SubscriptionID)
		}
	}
	if err := rows.Err(); err != nil {
		return TrialSlotExpiryDriftReport{}, fmt.Errorf("iterate trial slot expiry drift report: %w", err)
	}
	return report, nil
}

// ReportDriftedTrialSlots logs every legacy trial slot classified as drifted
// or orphaned. It returns the legacy subscription IDs whose slots were
// unverifiable so the startup diagnostic can state that separately. It never
// repairs a row; see TrialSlotExpiryDriftReport.
func (e *EntitlementDB) ReportDriftedTrialSlots(ctx context.Context, log zerolog.Logger) []string {
	report, err := e.TrialSlotExpiryDriftReport(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("could not check for drifted trial slot expiries")
		return nil
	}
	for _, d := range report.Drifted {
		log.Warn().
			Str("subscription_id", d.SubscriptionID).
			Time("slot_expires_at", d.SlotExpiresAt).
			Time("entitlement_claim_expires_at", d.EntitlementClaimEndsAt).
			Msg("trial slot expiry disagrees with its entitlement's claim-time expiry; not auto-repaired, reconcile manually")
	}
	for _, subscriptionID := range report.OrphanedSubscriptionIDs {
		log.Warn().
			Str("subscription_id", subscriptionID).
			Msg("trial slot has no owning entitlement; not auto-repaired, reconcile manually")
	}
	return report.UnverifiableSubscriptionIDs
}

// ReportJournalMode records the journal mode the database is running in, and
// warns when a file database did not get write-ahead logging.
//
// Failing to take WAL is survivable and does not affect the one-trial limit,
// but it is not something to pass over in silence: another process held the
// database when this service started, and journal_mode persists in the file
// until something changes it. Restarting once nothing else has the database
// open is the operator's move, and the message says so.
func (e *EntitlementDB) ReportJournalMode(log zerolog.Logger) {
	mode := e.JournalMode()
	log.Info().Str("journal_mode", mode).Msg("entitlement database journal mode")

	if mode == journalModeWAL {
		return
	}

	// An in-memory database keeps its own mode and can never be WAL. Only the
	// one asked for by name gets here; OpenEntitlementDB refuses any other.
	if mode == journalModeMemory && e.inMemory {
		return
	}

	log.Warn().
		Str("journal_mode", mode).
		Msg("entitlement database is not in write-ahead logging mode because another process held it at startup; restart this service once nothing else has the database open")
}

// backfillActiveTrialSlots seeds one slot per canonical email from existing
// trial entitlements.
//
// It reads and groups in Go rather than in SQL for two reasons the SQL form got
// wrong. First, the slot is keyed by CANONICAL email, and only NormalizeEmail
// decides that, so "A@x.com" and "a@x.com" must collapse to one slot here or the
// migration itself seeds the bypass it exists to close. Second, the owner and
// the expiry must come from the SAME entitlement: an aggregate pairing
// MIN(subscription_id) with MAX(current_period_end) can hand the slot one
// trial's owner and another trial's end date, and a later write for that owner
// then shortens the slot while the longer trial is still running, freeing a
// trial early. Ties break on subscription_id so a rerun is deterministic.
func (e *EntitlementDB) backfillActiveTrialSlots(ctx context.Context) error {
	const selectTrials = `
	SELECT customer_email, subscription_id, current_period_end, last_license_period_end
	FROM entitlements
	WHERE tier IN (?, ?) AND status IN (?, ?) AND current_period_end > ?
	ORDER BY current_period_end DESC, subscription_id ASC
	`
	rows, err := e.db.QueryContext(ctx, selectTrials,
		tierTrial, tierEnterpriseTrial, statusActive, statusRevoked, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("read trial entitlements for slot backfill: %w", err)
	}
	defer func() { _ = rows.Close() }()

	type slot struct {
		subscriptionID       string
		expiresAt            time.Time
		takeoverState        string
		legacyEntitlementEnd *time.Time
	}
	// Rows arrive newest-expiry first, so the first canonical key wins and
	// later duplicates are skipped rather than overwriting a longer trial.
	claimed := make(map[string]slot)
	for rows.Next() {
		var rawEmail, subscriptionID string
		var expiresAt time.Time
		var claimEnd sql.NullTime
		if err := rows.Scan(&rawEmail, &subscriptionID, &expiresAt, &claimEnd); err != nil {
			return fmt.Errorf("scan trial entitlement for slot backfill: %w", err)
		}
		canonical, nerr := NormalizeEmail(rawEmail)
		if nerr != nil {
			// An address this package cannot canonicalize gets no slot. It is
			// not silently given one under a raw key, which would be a slot no
			// later claim could ever match.
			continue
		}
		if _, seen := claimed[canonical]; seen {
			continue
		}
		takeoverState := trialSlotTakeoverUnverifiable
		var legacyEntitlementEnd *time.Time
		if claimEnd.Valid {
			claimEndUTC := claimEnd.Time.UTC()
			legacyEntitlementEnd = &claimEndUTC
			takeoverState = trialSlotTakeoverDrifted
			if claimEndUTC.Equal(expiresAt.UTC()) {
				takeoverState = trialSlotTakeoverVerified
			}
		}
		claimed[canonical] = slot{
			subscriptionID:       subscriptionID,
			expiresAt:            expiresAt.UTC(),
			takeoverState:        takeoverState,
			legacyEntitlementEnd: legacyEntitlementEnd,
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate trial entitlements for slot backfill: %w", err)
	}

	const insertSlot = `
	INSERT OR IGNORE INTO active_trial_slots (
		normalized_email, subscription_id, expires_at, takeover_state, legacy_entitlement_expires_at
	) VALUES (?, ?, ?, ?, ?)
	`
	for email, s := range claimed {
		if _, err := e.db.ExecContext(ctx, insertSlot,
			email, s.subscriptionID, s.expiresAt, s.takeoverState, s.legacyEntitlementEnd,
		); err != nil {
			return fmt.Errorf("backfill active trial slot for %s: %w", s.subscriptionID, err)
		}
	}
	return nil
}

// Upsert inserts or updates an entitlement record. Updates the updated_at
// timestamp automatically.
func (e *EntitlementDB) Upsert(ctx context.Context, ent *Entitlement) error {
	if ent == nil {
		return errors.New("entitlement is nil")
	}
	if !isTrialTier(ent.Tier) {
		if err := upsertEntitlement(ctx, e.db, ent); err != nil {
			return fmt.Errorf("upsert entitlement %s: %w", ent.SubscriptionID, err)
		}
		return nil
	}
	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin trial entitlement transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if err := upsertEntitlement(ctx, tx, ent); err != nil {
		return fmt.Errorf("upsert entitlement %s: %w", ent.SubscriptionID, err)
	}
	// The slot table is the SOLE eligibility authority and records each
	// trial's ORIGINAL expiry immutably at claim time. Only an ACTIVE write
	// claims a slot; a non-active status (revoked, canceled, or a cron status
	// mirror) never touches active_trial_slots at all, so a cancellation or
	// revocation cannot shorten, extend, or otherwise drift the expiry that
	// was recorded when the trial was first claimed. The same email stays
	// denied a second trial until that original expiry passes, regardless of
	// what CurrentPeriodEnd this terminal write carries.
	if ent.Status == statusActive {
		err := claimActiveTrialSlot(ctx, tx, ent)
		if err != nil && !errors.Is(err, ErrTrialEmailNotCanonical) {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit trial entitlement transaction: %w", err)
	}
	committed = true
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
		last_license_period_end= COALESCE(excluded.last_license_period_end, entitlements.last_license_period_end),
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
	return getEntitlementBySubscriptionID(ctx, e.db, subID)
}

func getEntitlementBySubscriptionID(ctx context.Context, q entitlementQueryer, subID string) (*Entitlement, error) {
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
	err := q.QueryRowContext(ctx, query, subID).Scan(
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

// UpsertRevokedIntermediate records (or re-records) a revoked intermediate
// serial. Re-revoking the same serial is idempotent (ON CONFLICT update), so a
// replayed admin/webhook call cannot fault.
func (e *EntitlementDB) UpsertRevokedIntermediate(ctx context.Context, rec RevokedIntermediateRecord) error {
	if rec.Serial == "" {
		return errors.New("serial is required")
	}
	if rec.Reason == "" {
		rec.Reason = "rotated"
	}
	if rec.RevokedAt.IsZero() {
		rec.RevokedAt = time.Now().UTC()
	}
	const query = `
	INSERT INTO revoked_intermediates (serial, reason, revoked_at)
	VALUES (?, ?, ?)
	ON CONFLICT(serial) DO UPDATE SET
		reason = excluded.reason,
		revoked_at = excluded.revoked_at
	`
	if _, err := e.db.ExecContext(ctx, query, rec.Serial, rec.Reason, rec.RevokedAt); err != nil {
		return fmt.Errorf("upsert revoked intermediate %s: %w", rec.Serial, err)
	}
	return nil
}

// ListRevokedIntermediates returns every revoked intermediate serial for CRL
// publication, ordered by serial for a deterministic CRL payload.
func (e *EntitlementDB) ListRevokedIntermediates(ctx context.Context) ([]RevokedIntermediateRecord, error) {
	const query = `SELECT serial, reason, revoked_at FROM revoked_intermediates ORDER BY serial ASC`
	rows, err := e.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list revoked intermediates: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var results []RevokedIntermediateRecord
	for rows.Next() {
		var rec RevokedIntermediateRecord
		if err := rows.Scan(&rec.Serial, &rec.Reason, &rec.RevokedAt); err != nil {
			return nil, fmt.Errorf("scan revoked intermediate: %w", err)
		}
		results = append(results, rec)
	}
	return results, rows.Err()
}

// RecoverCRLGeneration raises the durable monotonic generation counter to at
// least `floor` if it is currently below it. This is the high-water RECOVERY
// path (P0.2): after a DB restore, the in-DB counter can be behind the highest
// generation already PUBLISHED in a signed CRL. Seeding the counter from the
// latest published signed CRL's generation (read off disk / object store, not
// the DB) ensures the next NextCRLGeneration cannot mint a generation a consumer
// has already accepted — which would otherwise let a restored, lower-generation
// CRL un-revoke a license. It never lowers the counter (monotonic).
func (e *EntitlementDB) RecoverCRLGeneration(ctx context.Context, floor uint64) (uint64, error) {
	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin crl generation recovery: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO crl_generation (id, generation) VALUES (0, 0)`); err != nil {
		return 0, fmt.Errorf("seed crl generation: %w", err)
	}
	// Only ever raise the counter — never lower it. SQLite max() of the existing
	// value and the floor is the monotonic ratchet.
	if _, err := tx.ExecContext(ctx,
		`UPDATE crl_generation SET generation = MAX(generation, ?) WHERE id = 0`, floor); err != nil {
		return 0, fmt.Errorf("recover crl generation: %w", err)
	}
	var generation uint64
	if err := tx.QueryRowContext(ctx,
		`SELECT generation FROM crl_generation WHERE id = 0`).Scan(&generation); err != nil {
		return 0, fmt.Errorf("read crl generation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit crl generation recovery: %w", err)
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
	return e.UpsertWithLicenseIssuanceAndWebhook(ctx, ent, issuance, "", "")
}

// UpsertWithLicenseIssuanceAndWebhook atomically records entitlement state,
// license issuance, and an optional webhook delivery commit marker.
func (e *EntitlementDB) UpsertWithLicenseIssuanceAndWebhook(ctx context.Context, ent *Entitlement, issuance LicenseIssuance, msgID, eventType string) error {
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

	if msgID != "" {
		admitted, err := admitWebhook(ctx, tx, msgID, eventType, ent.SubscriptionID)
		if err != nil {
			return fmt.Errorf("admit subscription webhook: %w", err)
		}
		if !admitted {
			return ErrWebhookAlreadyCommitted
		}
	}
	if isTrialTier(ent.Tier) {
		if err := reserveTrialRefundGuard(ctx, tx, ent); err != nil {
			return err
		}
		if err := claimActiveTrialSlot(ctx, tx, ent); err != nil {
			return err
		}
	}
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

// trialSlotKey is the canonical identity a trial slot is keyed by. The column
// is named normalized_email and must actually hold one: without this, "A@x.com"
// and "a@x.com" own separate slots and the one-active-trial rule buys nothing.
// It fails CLOSED. An address this package cannot canonicalize gets no slot,
// which denies a trial rather than handing out an unbounded one.
func trialSlotKey(ent *Entitlement) (string, error) {
	canonical, err := NormalizeEmail(ent.CustomerEmail)
	if err != nil {
		return "", fmt.Errorf("%w for %s: %w", ErrTrialEmailNotCanonical, ent.SubscriptionID, err)
	}
	return canonical, nil
}

func claimActiveTrialSlot(ctx context.Context, exec entitlementExecer, ent *Entitlement) error {
	email, err := trialSlotKey(ent)
	if err != nil {
		return err
	}
	// expires_at is write-once per owner: the same subscription retrying or
	// re-upserting its own active claim (idempotent redelivery, a later Upsert
	// with a different CurrentPeriodEnd) must never move the expiry it already
	// holds, or a terminal write with a stale/earlier period could reopen the
	// slot before the trial the operator sees is actually over. Only a claim
	// that is taking over an EXPIRED slot from a DIFFERENT owner sets a new
	// expiry.
	//
	// Write-once cuts the other way too: a later write that legitimately EXTENDS
	// the owner's trial cannot move the slot expiry either, so the slot can fall
	// due while the owner's trial is still running. Takeover therefore also
	// requires that the current owner holds no active entitlement that has not
	// yet ended. That condition can only refuse a claim, never admit one, so it
	// cannot reopen the stale-write hole the write-once rule closes.
	const query = `
	INSERT INTO active_trial_slots (normalized_email, subscription_id, expires_at, takeover_state)
	VALUES (?, ?, ?, ?)
	ON CONFLICT(normalized_email) DO UPDATE SET
		subscription_id = excluded.subscription_id,
		expires_at = CASE
			WHEN active_trial_slots.subscription_id = excluded.subscription_id
				THEN active_trial_slots.expires_at
			ELSE excluded.expires_at
		END
	WHERE active_trial_slots.subscription_id = excluded.subscription_id
	   OR (
		active_trial_slots.expires_at <= ?
		AND active_trial_slots.takeover_state = ?
		AND NOT EXISTS (
			SELECT 1 FROM entitlements
			WHERE subscription_id = active_trial_slots.subscription_id
			  AND status = ?
			  AND current_period_end > ?
		)
	)
	`
	now := time.Now().UTC()
	result, err := exec.ExecContext(ctx, query,
		email, ent.SubscriptionID, ent.CurrentPeriodEnd.UTC(), trialSlotTakeoverVerified,
		now, trialSlotTakeoverVerified, statusActive, now,
	)
	if err != nil {
		return fmt.Errorf("claim active trial slot for %s: %w", ent.SubscriptionID, err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read active trial slot result for %s: %w", ent.SubscriptionID, err)
	}
	if changed == 0 {
		return fmt.Errorf("%w for this email", ErrActiveTrialExists)
	}
	return nil
}

// UpsertWithWebhook atomically records entitlement state and an optional webhook
// delivery commit marker for subscription events that do not mint a token.
func (e *EntitlementDB) UpsertWithWebhook(ctx context.Context, ent *Entitlement, msgID, eventType string) error {
	if ent == nil {
		return errors.New("entitlement is nil")
	}
	if msgID == "" {
		return e.Upsert(ctx, ent)
	}
	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin entitlement webhook transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	admitted, err := admitWebhook(ctx, tx, msgID, eventType, ent.SubscriptionID)
	if err != nil {
		return fmt.Errorf("admit subscription webhook: %w", err)
	}
	if !admitted {
		return ErrWebhookAlreadyCommitted
	}
	if err := upsertEntitlement(ctx, tx, ent); err != nil {
		return fmt.Errorf("upsert entitlement %s: %w", ent.SubscriptionID, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit entitlement webhook transaction: %w", err)
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
