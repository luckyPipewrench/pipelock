//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"

	// Pure-Go SQLite driver.
	_ "modernc.org/sqlite"
)

const (
	defaultAuditQueryLimit = 100
	maxAuditQueryLimit     = 1000
	uintTextWidth          = 20
)

type SQLiteAuditStore struct {
	db *sql.DB
}

type AuditBatchSummary struct {
	BatchID         string    `json:"batch_id"`
	OrgID           string    `json:"org_id"`
	FleetID         string    `json:"fleet_id"`
	InstanceID      string    `json:"instance_id"`
	AuditSchema     int       `json:"audit_schema_version"`
	SeqStart        uint64    `json:"seq_start"`
	SeqEnd          uint64    `json:"seq_end"`
	EventCount      uint64    `json:"event_count"`
	PayloadSHA256   string    `json:"payload_sha256"`
	PayloadBytes    uint64    `json:"payload_bytes"`
	EnvelopeHash    string    `json:"envelope_hash"`
	SegmentTailHash string    `json:"segment_tail_hash"`
	DroppedCount    uint64    `json:"dropped_count"`
	EmittedAt       time.Time `json:"emitted_at"`
	ReceivedAt      time.Time `json:"received_at"`
	SignatureKeyIDs []string  `json:"signature_key_ids"`
}

type AuditBatchQuery struct {
	OrgID      string
	FleetID    string
	InstanceID string
	BatchID    string
	Limit      int
}

type AuditPruneResult struct {
	Deleted int64
	Before  time.Time
}

func OpenSQLiteAuditStore(ctx context.Context, path string) (*SQLiteAuditStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("conductor audit store path is required")
	}
	if ctx == nil {
		return nil, fmt.Errorf("%w: context", ErrAuditSinkRequired)
	}
	storePath, err := ensureAuditStoreFile(path)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", storePath)
	if err != nil {
		return nil, fmt.Errorf("open conductor audit store: %w", err)
	}
	db.SetMaxOpenConns(1)
	// PRAGMA order matters: WAL must be set before synchronous so the
	// synchronous mode applies to the WAL writer. synchronous=FULL forces
	// the WAL frames AND the rollback journal/wal index to be durably
	// fsynced before the COMMIT returns success — appropriate for an audit
	// sink where a power-loss-induced silent loss of accepted evidence is
	// worse than the throughput cost. busy_timeout protects against
	// SQLITE_BUSY when -wal/-shm files are momentarily contended (the
	// single-writer SetMaxOpenConns serializes app-side, but the SQLite
	// library can briefly contend on its own internal locks during
	// checkpointing).
	for _, p := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=FULL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
	} {
		if _, err := db.ExecContext(ctx, p); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("set conductor audit store pragma %q: %w", p, err)
		}
	}
	store := &SQLiteAuditStore{db: db}
	if err := store.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := chmodAuditStoreFiles(storePath); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func ensureAuditStoreFile(path string) (string, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return "", fmt.Errorf("conductor audit store path must be absolute: %s", path)
	}
	parent, err := secureDir(filepath.Dir(clean))
	if err != nil {
		return "", err
	}
	storePath := filepath.Join(parent, filepath.Base(clean))
	rel, err := filepath.Rel(parent, storePath)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		if err != nil {
			return "", fmt.Errorf("validate conductor audit store containment: %w", err)
		}
		return "", fmt.Errorf("conductor audit store path escapes parent: %s", clean)
	}
	file, err := openAuditStoreFileNoFollow(storePath, true)
	if errors.Is(err, os.ErrExist) {
		if info, statErr := os.Lstat(storePath); statErr == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return "", fmt.Errorf("conductor audit store path is a symlink: %s", storePath)
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return "", fmt.Errorf("stat conductor audit store: %w", statErr)
		}
		file, err = openAuditStoreFileNoFollow(storePath, false)
	}
	if err != nil {
		return "", fmt.Errorf("create conductor audit store: %w", err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("stat conductor audit store: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("conductor audit store path is not a regular file: %s", storePath)
	}
	if err := chmodAuditStorePath(storePath); err != nil {
		return "", err
	}
	return storePath, nil
}

func openAuditStoreFileNoFollow(path string, create bool) (*os.File, error) {
	flags := os.O_RDWR | auditStoreNoFollowFlag
	if create {
		flags |= os.O_CREATE | os.O_EXCL
	}
	//nolint:gosec // path is explicit operator configuration; parent is resolved and final component is opened with O_NOFOLLOW where available.
	return os.OpenFile(path, flags, bundleRecordFileMode)
}

func chmodAuditStoreFiles(path string) error {
	for _, candidate := range []string{path, path + "-wal", path + "-shm"} {
		if err := chmodAuditStorePath(candidate); err != nil {
			return err
		}
	}
	return nil
}

func chmodAuditStorePath(path string) error {
	if err := os.Chmod(path, bundleRecordFileMode); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("chmod conductor audit store %s: %w", path, err)
	}
	return nil
}

func (s *SQLiteAuditStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *SQLiteAuditStore) migrate(ctx context.Context) error {
	const ddl = `
	CREATE TABLE IF NOT EXISTS audit_batches (
		org_id               TEXT NOT NULL,
		fleet_id             TEXT NOT NULL,
		instance_id          TEXT NOT NULL,
		batch_id             TEXT NOT NULL,
		audit_schema_version INTEGER NOT NULL,
		seq_start            TEXT NOT NULL,
		seq_end              TEXT NOT NULL,
		event_count          TEXT NOT NULL,
		payload_sha256       TEXT NOT NULL,
		payload_bytes        TEXT NOT NULL,
		envelope_hash        TEXT NOT NULL,
		segment_tail_hash    TEXT NOT NULL,
		dropped_count        TEXT NOT NULL,
		emitted_at           DATETIME NOT NULL,
		received_at          DATETIME NOT NULL,
		signature_key_ids    TEXT NOT NULL,
		envelope_json        BLOB NOT NULL,
		payload_blob         BLOB NOT NULL,
		PRIMARY KEY (org_id, fleet_id, instance_id, batch_id)
	);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_conductor_audit_batches_envelope_hash
		ON audit_batches(envelope_hash);
	CREATE INDEX IF NOT EXISTS idx_conductor_audit_batches_namespace_received
		ON audit_batches(org_id, fleet_id, instance_id, received_at DESC);
	CREATE INDEX IF NOT EXISTS idx_conductor_audit_batches_namespace_sequence
		ON audit_batches(org_id, fleet_id, instance_id, seq_start, seq_end);
	`
	if _, err := s.db.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("migrate conductor audit store: %w", err)
	}
	return nil
}

func (s *SQLiteAuditStore) IngestAuditBatch(ctx context.Context, batch AcceptedAuditBatch) error {
	_, err := s.put(ctx, batch)
	return err
}

func (s *SQLiteAuditStore) put(ctx context.Context, batch AcceptedAuditBatch) (AuditBatchSummary, error) {
	if s == nil || s.db == nil {
		return AuditBatchSummary{}, ErrAuditSinkRequired
	}
	if ctx == nil {
		return AuditBatchSummary{}, fmt.Errorf("%w: context", ErrAuditSinkRequired)
	}
	if err := ctx.Err(); err != nil {
		return AuditBatchSummary{}, err
	}
	if err := validateAcceptedAuditBatch(batch); err != nil {
		return AuditBatchSummary{}, err
	}
	envelopeJSON, err := json.Marshal(batch.Envelope)
	if err != nil {
		return AuditBatchSummary{}, fmt.Errorf("marshal conductor audit envelope: %w", err)
	}
	keyIDsJSON, err := json.Marshal(signatureKeyIDs(batch.Envelope.Signatures))
	if err != nil {
		return AuditBatchSummary{}, fmt.Errorf("marshal conductor audit signature key ids: %w", err)
	}
	if batch.ReceivedAt.IsZero() {
		batch.ReceivedAt = time.Now().UTC()
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AuditBatchSummary{}, fmt.Errorf("begin conductor audit store transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var existingEnvelopeHash, existingPayloadHash string
	err = tx.QueryRowContext(ctx, `
		SELECT envelope_hash, payload_sha256
		FROM audit_batches
		WHERE org_id = ? AND fleet_id = ? AND instance_id = ? AND batch_id = ?
	`, batch.Envelope.OrgID, batch.Envelope.FleetID, batch.Envelope.InstanceID, batch.Envelope.BatchID).
		Scan(&existingEnvelopeHash, &existingPayloadHash)
	switch {
	case err == nil:
		if existingEnvelopeHash == batch.EnvelopeHash && strings.EqualFold(existingPayloadHash, batch.Envelope.PayloadSHA256) {
			summary, getErr := auditSummaryByKey(ctx, tx, batch.Envelope.OrgID, batch.Envelope.FleetID, batch.Envelope.InstanceID, batch.Envelope.BatchID)
			if getErr != nil {
				return AuditBatchSummary{}, getErr
			}
			if commitErr := tx.Commit(); commitErr != nil {
				return AuditBatchSummary{}, fmt.Errorf("commit duplicate conductor audit store transaction: %w", commitErr)
			}
			return summary, nil
		}
		return AuditBatchSummary{}, ErrAuditBatchConflict
	case !errors.Is(err, sql.ErrNoRows):
		return AuditBatchSummary{}, fmt.Errorf("check conductor audit duplicate: %w", err)
	}

	if err := detectAuditFork(ctx, tx, batch.Envelope); err != nil {
		return AuditBatchSummary{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_batches (
			org_id, fleet_id, instance_id, batch_id, audit_schema_version,
			seq_start, seq_end, event_count, payload_sha256, payload_bytes,
			envelope_hash, segment_tail_hash, dropped_count, emitted_at,
			received_at, signature_key_ids, envelope_json, payload_blob
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, batch.Envelope.OrgID, batch.Envelope.FleetID, batch.Envelope.InstanceID, batch.Envelope.BatchID,
		batch.Envelope.AuditSchemaVersion, formatAuditUint(batch.Envelope.SeqStart), formatAuditUint(batch.Envelope.SeqEnd),
		formatAuditUint(batch.Envelope.EventCount), batch.Envelope.PayloadSHA256, formatAuditUint(batch.Envelope.PayloadBytes),
		batch.EnvelopeHash, batch.Envelope.Chain.SegmentTailHash, formatAuditUint(batch.Envelope.Dropped.Count),
		batch.Envelope.EmittedAt.UTC(), batch.ReceivedAt.UTC(), string(keyIDsJSON), envelopeJSON,
		append([]byte(nil), batch.Payload...)); err != nil {
		return AuditBatchSummary{}, fmt.Errorf("insert conductor audit batch: %w", err)
	}
	summary, err := auditSummaryByKey(ctx, tx, batch.Envelope.OrgID, batch.Envelope.FleetID, batch.Envelope.InstanceID, batch.Envelope.BatchID)
	if err != nil {
		return AuditBatchSummary{}, err
	}
	if err := tx.Commit(); err != nil {
		return AuditBatchSummary{}, fmt.Errorf("commit conductor audit store transaction: %w", err)
	}
	return summary, nil
}

func validateAcceptedAuditBatch(batch AcceptedAuditBatch) error {
	if err := validateAuditEnvelopeHash(batch.EnvelopeHash); err != nil {
		return err
	}
	if err := batch.Identity.Validate(); err != nil {
		return err
	}
	if batch.Envelope.OrgID != batch.Identity.OrgID ||
		batch.Envelope.FleetID != batch.Identity.FleetID ||
		batch.Envelope.InstanceID != batch.Identity.InstanceID {
		return conductor.ErrAudienceMismatch
	}
	if err := batch.Envelope.Validate(); err != nil {
		return err
	}
	if err := batch.Envelope.ValidatePayload(batch.Payload); err != nil {
		return err
	}
	hash, err := batch.Envelope.CanonicalHash()
	if err != nil {
		return err
	}
	if hash != batch.EnvelopeHash {
		return fmt.Errorf("%w: envelope_hash mismatch", ErrInvalidStoreRecord)
	}
	return nil
}

func validateAuditEnvelopeHash(hash string) error {
	if len(hash) != sha256.Size*2 {
		return fmt.Errorf("%w: envelope_hash", ErrInvalidStoreRecord)
	}
	if _, err := hex.DecodeString(hash); err != nil {
		return fmt.Errorf("%w: envelope_hash", ErrInvalidStoreRecord)
	}
	return nil
}

func (s *SQLiteAuditStore) ListAuditBatches(ctx context.Context, q AuditBatchQuery) ([]AuditBatchSummary, error) {
	if s == nil || s.db == nil {
		return nil, ErrAuditSinkRequired
	}
	if ctx == nil {
		return nil, fmt.Errorf("%w: context", ErrAuditSinkRequired)
	}
	limit := normalizeAuditLimit(q.Limit)
	query := `
		SELECT batch_id, org_id, fleet_id, instance_id, audit_schema_version,
			seq_start, seq_end, event_count, payload_sha256, payload_bytes,
			envelope_hash, segment_tail_hash, dropped_count, emitted_at,
			received_at, signature_key_ids
		FROM audit_batches
		WHERE 1 = 1`
	args := make([]any, 0, 5)
	if q.OrgID != "" {
		query += " AND org_id = ?"
		args = append(args, q.OrgID)
	}
	if q.FleetID != "" {
		query += " AND fleet_id = ?"
		args = append(args, q.FleetID)
	}
	if q.InstanceID != "" {
		query += " AND instance_id = ?"
		args = append(args, q.InstanceID)
	}
	if q.BatchID != "" {
		query += " AND batch_id = ?"
		args = append(args, q.BatchID)
	}
	query += " ORDER BY received_at DESC, org_id, fleet_id, instance_id, seq_start DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query conductor audit batches: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []AuditBatchSummary
	for rows.Next() {
		summary, err := scanAuditSummary(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, summary)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan conductor audit batch rows: %w", err)
	}
	return out, nil
}

func (s *SQLiteAuditStore) GetAuditBatch(ctx context.Context, orgID, fleetID, instanceID, batchID string) (AuditBatchSummary, bool, error) {
	if s == nil || s.db == nil {
		return AuditBatchSummary{}, false, ErrAuditSinkRequired
	}
	if ctx == nil {
		return AuditBatchSummary{}, false, fmt.Errorf("%w: context", ErrAuditSinkRequired)
	}
	summary, err := auditSummaryByKey(ctx, s.db, orgID, fleetID, instanceID, batchID)
	if errors.Is(err, sql.ErrNoRows) {
		return AuditBatchSummary{}, false, nil
	}
	if err != nil {
		return AuditBatchSummary{}, false, err
	}
	return summary, true, nil
}

func (s *SQLiteAuditStore) PruneAuditBatchesBefore(ctx context.Context, before time.Time) (AuditPruneResult, error) {
	if s == nil || s.db == nil {
		return AuditPruneResult{}, ErrAuditSinkRequired
	}
	if ctx == nil {
		return AuditPruneResult{}, fmt.Errorf("%w: context", ErrAuditSinkRequired)
	}
	if before.IsZero() {
		return AuditPruneResult{}, fmt.Errorf("%w: audit retention cutoff", ErrInvalidStoreRecord)
	}
	cutoff := before.UTC()
	result, err := s.db.ExecContext(ctx, `DELETE FROM audit_batches WHERE received_at < ?`, cutoff)
	if err != nil {
		return AuditPruneResult{}, fmt.Errorf("prune conductor audit batches: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return AuditPruneResult{}, fmt.Errorf("count pruned conductor audit batches: %w", err)
	}
	return AuditPruneResult{Deleted: deleted, Before: cutoff}, nil
}

type auditSummaryScanner interface {
	Scan(...any) error
}

type auditSummaryQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func auditSummaryByKey(ctx context.Context, q auditSummaryQueryer, orgID, fleetID, instanceID, batchID string) (AuditBatchSummary, error) {
	return scanAuditSummary(q.QueryRowContext(ctx, `
		SELECT batch_id, org_id, fleet_id, instance_id, audit_schema_version,
			seq_start, seq_end, event_count, payload_sha256, payload_bytes,
			envelope_hash, segment_tail_hash, dropped_count, emitted_at,
			received_at, signature_key_ids
		FROM audit_batches
		WHERE org_id = ? AND fleet_id = ? AND instance_id = ? AND batch_id = ?
	`, orgID, fleetID, instanceID, batchID))
}

func scanAuditSummary(row auditSummaryScanner) (AuditBatchSummary, error) {
	var summary AuditBatchSummary
	var seqStart, seqEnd, eventCount, payloadBytes, droppedCount, keyIDsJSON string
	if err := row.Scan(
		&summary.BatchID, &summary.OrgID, &summary.FleetID, &summary.InstanceID,
		&summary.AuditSchema, &seqStart, &seqEnd, &eventCount,
		&summary.PayloadSHA256, &payloadBytes, &summary.EnvelopeHash,
		&summary.SegmentTailHash, &droppedCount, &summary.EmittedAt,
		&summary.ReceivedAt, &keyIDsJSON,
	); err != nil {
		return AuditBatchSummary{}, err
	}
	var err error
	if summary.SeqStart, err = parseAuditUintField("seq_start", seqStart); err != nil {
		return AuditBatchSummary{}, err
	}
	if summary.SeqEnd, err = parseAuditUintField("seq_end", seqEnd); err != nil {
		return AuditBatchSummary{}, err
	}
	if summary.EventCount, err = parseAuditUintField("event_count", eventCount); err != nil {
		return AuditBatchSummary{}, err
	}
	if summary.PayloadBytes, err = parseAuditUintField("payload_bytes", payloadBytes); err != nil {
		return AuditBatchSummary{}, err
	}
	if summary.DroppedCount, err = parseAuditUintField("dropped_count", droppedCount); err != nil {
		return AuditBatchSummary{}, err
	}
	if err := json.Unmarshal([]byte(keyIDsJSON), &summary.SignatureKeyIDs); err != nil {
		return AuditBatchSummary{}, fmt.Errorf("decode conductor audit signature key ids: %w", err)
	}
	return summary, nil
}

// detectAuditFork rejects writes whose [SeqStart, SeqEnd] range overlaps any
// previously accepted batch from the same (org, fleet, instance) AND whose
// payload SHA256 or segment-tail hash diverges from the existing record.
// This is the conductor-side defense against an instance that re-attempts
// audit batches with rewritten history: signed envelopes alone don't prevent
// it, since the follower's own signing key produces both records. Returning
// [ErrAuditForkDetected] also signals followers to stop retrying.
func detectAuditFork(ctx context.Context, tx *sql.Tx, env conductor.AuditBatchEnvelope) error {
	rows, err := tx.QueryContext(ctx, `
		SELECT envelope_json
		FROM audit_batches
		WHERE org_id = ? AND fleet_id = ? AND instance_id = ?
		  AND seq_end   >= ?
		  AND seq_start <= ?
	`, env.OrgID, env.FleetID, env.InstanceID, formatAuditUint(env.SeqStart), formatAuditUint(env.SeqEnd))
	if err != nil {
		return fmt.Errorf("query conductor audit sequence overlaps: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return fmt.Errorf("scan conductor audit overlap: %w", err)
		}
		var existing conductor.AuditBatchEnvelope
		if err := json.Unmarshal(raw, &existing); err != nil {
			return fmt.Errorf("decode stored conductor audit envelope: %w", err)
		}
		if env.ForksWith(existing) {
			return ErrAuditForkDetected
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("scan conductor audit overlaps: %w", err)
	}
	return nil
}

func signatureKeyIDs(signatures []conductor.SignatureProof) []string {
	out := make([]string, 0, len(signatures))
	for _, sig := range signatures {
		out = append(out, sig.SignerKeyID)
	}
	return out
}

func normalizeAuditLimit(limit int) int {
	if limit <= 0 {
		return defaultAuditQueryLimit
	}
	if limit > maxAuditQueryLimit {
		return maxAuditQueryLimit
	}
	return limit
}

// formatAuditUint encodes a uint64 as a zero-padded 20-digit decimal string.
// SQLite's INTEGER type is signed int64, which cannot represent uint64 values
// above 2^63-1 (a legitimate sequence number for a long-lived follower) and
// would silently roll over to negative. Zero-padded text preserves
// lexicographic-equals-numeric comparison across the full uint64 range, so
// the (seq_start, seq_end) range index and the seq_end >= ? / seq_start <= ?
// overlap query in detectAuditFork remain correct. All producers MUST go
// through this function; mixing widths breaks the lex ordering.
func formatAuditUint(value uint64) string {
	return fmt.Sprintf("%0*d", uintTextWidth, value)
}

func parseAuditUintField(name, value string) (uint64, error) {
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("decode %s: %w", name, err)
	}
	return parsed, nil
}
