//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package sink

import (
	"context"
	"database/sql"
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
	defaultQueryLimit = 100
	maxQueryLimit     = 1000
	// uintTextWidth zero-pads stored uint64s so SQLite's lexicographic
	// TEXT comparison matches numeric order across different digit
	// counts. Without padding, "9" > "100" lexically — that wrecks
	// range queries on the namespace_sequence index and makes
	// detectFork unsound the moment we use SQL overlap checks.
	uintTextWidth = 20
)

type Store struct {
	db *sql.DB
}

func OpenStore(ctx context.Context, path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("fleet sink store path is required")
	}
	clean := filepath.Clean(path)
	if err := os.MkdirAll(filepath.Dir(clean), 0o700); err != nil {
		return nil, fmt.Errorf("create fleet sink store parent: %w", err)
	}
	storePath, err := ensureStoreFile(clean)
	if err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", storePath)
	if err != nil {
		return nil, fmt.Errorf("open fleet sink store: %w", err)
	}
	db.SetMaxOpenConns(1)

	if _, err := db.ExecContext(ctx, "PRAGMA journal_mode=WAL"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("set WAL mode: %w", err)
	}
	if _, err := db.ExecContext(ctx, "PRAGMA foreign_keys=ON"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}

	s := &Store{db: db}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	// SQLite may create sidecar files for WAL mode. Audit payloads
	// contain raw evidence, so keep the database and any sidecars
	// owner-only even under a permissive umask.
	if err := chmodStoreFiles(storePath); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func ensureStoreFile(path string) (string, error) {
	clean := filepath.Clean(path)
	parent, err := filepath.EvalSymlinks(filepath.Dir(clean))
	if err != nil {
		return "", fmt.Errorf("resolve fleet sink store parent: %w", err)
	}
	storePath := filepath.Join(parent, filepath.Base(clean))
	rel, err := filepath.Rel(parent, storePath)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		if err != nil {
			return "", fmt.Errorf("validate fleet sink store containment: %w", err)
		}
		return "", fmt.Errorf("fleet sink store path escapes parent: %s", clean)
	}

	f, err := openStoreFileNoFollow(storePath, true)
	if errors.Is(err, os.ErrExist) {
		if info, statErr := os.Lstat(storePath); statErr == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return "", fmt.Errorf("fleet sink store path is a symlink: %s", storePath)
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return "", fmt.Errorf("stat fleet sink store: %w", statErr)
		}
		f, err = openStoreFileNoFollow(storePath, false)
	}
	if err != nil {
		return "", fmt.Errorf("create fleet sink store: %w", err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("stat opened fleet sink store: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("fleet sink store path is not a regular file: %s", storePath)
	}
	if err := chmodStorePath(storePath); err != nil {
		return "", err
	}
	return storePath, nil
}

func openStoreFileNoFollow(path string, create bool) (*os.File, error) {
	flags := os.O_RDWR | storeNoFollowFlag
	if create {
		flags |= os.O_CREATE | os.O_EXCL
	}
	//nolint:gosec // path is explicit operator configuration; parent is resolved and final component is opened with O_NOFOLLOW where available.
	return os.OpenFile(path, flags, 0o600)
}

func chmodStoreFiles(path string) error {
	for _, candidate := range []string{path, path + "-wal", path + "-shm"} {
		if err := chmodStorePath(candidate); err != nil {
			return err
		}
	}
	return nil
}

func chmodStorePath(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("chmod fleet sink store %s: %w", path, err)
	}
	return nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate(ctx context.Context) error {
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
		canonical_hash       TEXT NOT NULL,
		segment_tail_hash    TEXT NOT NULL,
		dropped_count        TEXT NOT NULL,
		emitted_at           DATETIME NOT NULL,
		received_at          DATETIME NOT NULL,
		signature_key_ids    TEXT NOT NULL,
		informational_dlp    TEXT NOT NULL DEFAULT '[]',
		envelope_json        BLOB NOT NULL,
		payload_blob         BLOB NOT NULL,
		PRIMARY KEY (org_id, fleet_id, instance_id, batch_id)
	);
	CREATE INDEX IF NOT EXISTS idx_audit_batches_namespace_received
		ON audit_batches(org_id, fleet_id, instance_id, received_at DESC);
	CREATE INDEX IF NOT EXISTS idx_audit_batches_namespace_sequence
		ON audit_batches(org_id, fleet_id, instance_id, seq_start, seq_end);
	CREATE INDEX IF NOT EXISTS idx_audit_batches_batch_id
		ON audit_batches(batch_id);
	`
	if _, err := s.db.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("migrate fleet sink store: %w", err)
	}
	return nil
}

func (s *Store) Put(ctx context.Context, batch acceptedBatch, informational []string) (PutResult, error) {
	if s == nil || s.db == nil {
		return PutResult{}, ErrMissingStore
	}
	if err := batch.Envelope.Validate(); err != nil {
		return PutResult{}, fmt.Errorf("validate audit batch before store: %w", err)
	}
	envelopeJSON, err := json.Marshal(batch.Envelope)
	if err != nil {
		return PutResult{}, fmt.Errorf("marshal audit batch envelope: %w", err)
	}
	keyIDsJSON, err := json.Marshal(signatureKeyIDs(batch.Envelope.Signatures))
	if err != nil {
		return PutResult{}, fmt.Errorf("marshal signature key ids: %w", err)
	}
	informationalJSON, err := json.Marshal(informational)
	if err != nil {
		return PutResult{}, fmt.Errorf("marshal informational DLP labels: %w", err)
	}
	if batch.ReceivedAt.IsZero() {
		batch.ReceivedAt = time.Now().UTC()
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PutResult{}, fmt.Errorf("begin fleet sink store transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var existingHash, existingPayloadHash string
	err = tx.QueryRowContext(ctx, `
		SELECT canonical_hash, payload_sha256
		FROM audit_batches
		WHERE org_id = ? AND fleet_id = ? AND instance_id = ? AND batch_id = ?
	`, batch.Envelope.OrgID, batch.Envelope.FleetID, batch.Envelope.InstanceID, batch.Envelope.BatchID).
		Scan(&existingHash, &existingPayloadHash)
	switch {
	case err == nil:
		if existingHash == batch.CanonicalHash && strings.EqualFold(existingPayloadHash, batch.Envelope.PayloadSHA256) {
			summary, getErr := summaryByKey(ctx, tx, batch.Envelope.OrgID, batch.Envelope.FleetID, batch.Envelope.InstanceID, batch.Envelope.BatchID)
			if getErr != nil {
				return PutResult{}, getErr
			}
			if commitErr := tx.Commit(); commitErr != nil {
				return PutResult{}, fmt.Errorf("commit duplicate fleet sink transaction: %w", commitErr)
			}
			return PutResult{Summary: summary, Duplicate: true}, nil
		}
		return PutResult{}, ErrBatchConflict
	case !errors.Is(err, sql.ErrNoRows):
		return PutResult{}, fmt.Errorf("check duplicate audit batch: %w", err)
	}

	if err := detectFork(ctx, tx, batch.Envelope); err != nil {
		return PutResult{}, err
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_batches (
			org_id, fleet_id, instance_id, batch_id, audit_schema_version,
			seq_start, seq_end, event_count, payload_sha256, payload_bytes,
			canonical_hash, segment_tail_hash, dropped_count, emitted_at,
			received_at, signature_key_ids, informational_dlp, envelope_json, payload_blob
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, batch.Envelope.OrgID, batch.Envelope.FleetID, batch.Envelope.InstanceID, batch.Envelope.BatchID,
		batch.Envelope.AuditSchemaVersion, formatUint(batch.Envelope.SeqStart), formatUint(batch.Envelope.SeqEnd),
		formatUint(batch.Envelope.EventCount), batch.Envelope.PayloadSHA256, formatUint(batch.Envelope.PayloadBytes),
		batch.CanonicalHash, batch.Envelope.Chain.SegmentTailHash, formatUint(batch.Envelope.Dropped.Count),
		batch.Envelope.EmittedAt.UTC(), batch.ReceivedAt.UTC(), string(keyIDsJSON), string(informationalJSON),
		envelopeJSON, batch.Payload); err != nil {
		return PutResult{}, fmt.Errorf("insert audit batch: %w", err)
	}

	summary, err := summaryByKey(ctx, tx, batch.Envelope.OrgID, batch.Envelope.FleetID, batch.Envelope.InstanceID, batch.Envelope.BatchID)
	if err != nil {
		return PutResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return PutResult{}, fmt.Errorf("commit fleet sink store transaction: %w", err)
	}
	return PutResult{Summary: summary}, nil
}

func (s *Store) List(ctx context.Context, q Query) ([]BatchSummary, error) {
	limit := normalizeLimit(q.Limit)
	query := `
		SELECT batch_id, org_id, fleet_id, instance_id, audit_schema_version,
			seq_start, seq_end, event_count, payload_sha256, payload_bytes,
			canonical_hash, segment_tail_hash, dropped_count, emitted_at,
			received_at, signature_key_ids, informational_dlp
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
		return nil, fmt.Errorf("query audit batches: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []BatchSummary
	for rows.Next() {
		summary, err := scanSummary(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, summary)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan audit batch rows: %w", err)
	}
	return out, nil
}

func (s *Store) Get(ctx context.Context, orgID, fleetID, instanceID, batchID string) (BatchSummary, bool, error) {
	summary, err := summaryByKey(ctx, s.db, orgID, fleetID, instanceID, batchID)
	if errors.Is(err, sql.ErrNoRows) {
		return BatchSummary{}, false, nil
	}
	if err != nil {
		return BatchSummary{}, false, err
	}
	return summary, true, nil
}

type summaryScanner interface {
	Scan(...any) error
}

type summaryQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func summaryByKey(ctx context.Context, q summaryQueryer, orgID, fleetID, instanceID, batchID string) (BatchSummary, error) {
	return scanSummary(q.QueryRowContext(ctx, `
		SELECT batch_id, org_id, fleet_id, instance_id, audit_schema_version,
			seq_start, seq_end, event_count, payload_sha256, payload_bytes,
			canonical_hash, segment_tail_hash, dropped_count, emitted_at,
			received_at, signature_key_ids, informational_dlp
		FROM audit_batches
		WHERE org_id = ? AND fleet_id = ? AND instance_id = ? AND batch_id = ?
	`, orgID, fleetID, instanceID, batchID))
}

func scanSummary(row summaryScanner) (BatchSummary, error) {
	var summary BatchSummary
	var seqStart, seqEnd, eventCount, payloadBytes, droppedCount string
	var keyIDsJSON, informationalJSON string
	if err := row.Scan(
		&summary.BatchID, &summary.OrgID, &summary.FleetID, &summary.InstanceID,
		&summary.AuditSchema, &seqStart, &seqEnd, &eventCount,
		&summary.PayloadSHA256, &payloadBytes, &summary.CanonicalHash,
		&summary.SegmentTailHash, &droppedCount, &summary.EmittedAt,
		&summary.ReceivedAt, &keyIDsJSON, &informationalJSON,
	); err != nil {
		return BatchSummary{}, err
	}
	var err error
	if summary.SeqStart, err = parseUintField("seq_start", seqStart); err != nil {
		return BatchSummary{}, err
	}
	if summary.SeqEnd, err = parseUintField("seq_end", seqEnd); err != nil {
		return BatchSummary{}, err
	}
	if summary.EventCount, err = parseUintField("event_count", eventCount); err != nil {
		return BatchSummary{}, err
	}
	if summary.PayloadBytes, err = parseUintField("payload_bytes", payloadBytes); err != nil {
		return BatchSummary{}, err
	}
	if summary.DroppedCount, err = parseUintField("dropped_count", droppedCount); err != nil {
		return BatchSummary{}, err
	}
	if err := json.Unmarshal([]byte(keyIDsJSON), &summary.SignatureKeyIDs); err != nil {
		return BatchSummary{}, fmt.Errorf("decode signature key ids: %w", err)
	}
	if err := json.Unmarshal([]byte(informationalJSON), &summary.InformationalDLP); err != nil {
		return BatchSummary{}, fmt.Errorf("decode informational DLP labels: %w", err)
	}
	return summary, nil
}

// detectFork uses the namespace_sequence index to load only the rows
// whose [seq_start, seq_end] overlaps the incoming envelope, then
// unmarshals just those to call ForksWith for the (PayloadSHA256 OR
// SegmentTailHash) equivocation check. Without the SQL-level overlap
// filter this scans the entire namespace per ingest, which is an
// unbounded DoS vector once an instance accumulates batches.
func detectFork(ctx context.Context, tx *sql.Tx, env conductor.AuditBatchEnvelope) error {
	rows, err := tx.QueryContext(ctx, `
		SELECT envelope_json
		FROM audit_batches
		WHERE org_id = ? AND fleet_id = ? AND instance_id = ?
		  AND seq_end   >= ?
		  AND seq_start <= ?
	`, env.OrgID, env.FleetID, env.InstanceID,
		formatUint(env.SeqStart), formatUint(env.SeqEnd))
	if err != nil {
		return fmt.Errorf("query audit sequence overlaps: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return fmt.Errorf("scan audit overlap: %w", err)
		}
		var existing conductor.AuditBatchEnvelope
		if err := json.Unmarshal(raw, &existing); err != nil {
			return fmt.Errorf("decode stored audit envelope: %w", err)
		}
		if env.ForksWith(existing) {
			return ErrForkDetected
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("scan audit overlaps: %w", err)
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

func normalizeLimit(limit int) int {
	if limit <= 0 {
		return defaultQueryLimit
	}
	if limit > maxQueryLimit {
		return maxQueryLimit
	}
	return limit
}

func formatUint(value uint64) string {
	return fmt.Sprintf("%0*d", uintTextWidth, value)
}

func parseUintField(name, value string) (uint64, error) {
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("decode %s: %w", name, err)
	}
	return parsed, nil
}
