//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
)

// AuditBatchEvidence is the local-only raw evidence view used by offline report
// minting. It is deliberately not exposed through the Conductor HTTP query API.
type AuditBatchEvidence struct {
	Summary  AuditBatchSummary
	Envelope conductor.AuditBatchEnvelope
	Payload  []byte
}

type AuditEvidenceQuery struct {
	OrgID        string
	FleetID      string
	ReceivedFrom time.Time
	ReceivedTo   time.Time
	Limit        int
}

func (s *SQLiteAuditStore) ListAuditBatchEvidence(ctx context.Context, q AuditEvidenceQuery) ([]AuditBatchEvidence, error) {
	if s == nil || s.db == nil {
		return nil, ErrAuditSinkRequired
	}
	if ctx == nil {
		return nil, fmt.Errorf("%w: context", ErrAuditSinkRequired)
	}
	if q.OrgID == "" || q.FleetID == "" {
		return nil, fmt.Errorf("%w: org_id and fleet_id required", ErrInvalidStoreRecord)
	}
	if q.ReceivedFrom.IsZero() || q.ReceivedTo.IsZero() || !q.ReceivedTo.After(q.ReceivedFrom) {
		return nil, fmt.Errorf("%w: invalid evidence time window", ErrInvalidStoreRecord)
	}

	// Report minting must never silently truncate its evidence set: a signed
	// report attests to a source-batch set and completeness for [from, to), so an
	// undisclosed cut would misstate what it proves. Probe one past the effective
	// limit and fail closed if the window holds more, instead of paginating.
	limit := normalizeAuditLimit(q.Limit)
	rows, err := s.db.QueryContext(ctx, `
		SELECT batch_id, org_id, fleet_id, instance_id, audit_schema_version,
			seq_start, seq_end, event_count, payload_sha256, payload_bytes,
			envelope_hash, segment_tail_hash, dropped_count, emitted_at,
			received_at, signature_key_ids, envelope_json, payload_blob
		FROM audit_batches
		WHERE org_id = ? AND fleet_id = ? AND received_at >= ? AND received_at < ?
		ORDER BY org_id, fleet_id, instance_id, seq_start, seq_end, received_at, batch_id
		LIMIT ?
	`, q.OrgID, q.FleetID, q.ReceivedFrom.UTC(), q.ReceivedTo.UTC(), limit+1)
	if err != nil {
		return nil, fmt.Errorf("query conductor audit evidence: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []AuditBatchEvidence
	for rows.Next() {
		if len(out) == limit {
			return nil, fmt.Errorf("%w: window matched more than %d audit batches; narrow --from/--to or raise --limit (max %d)",
				ErrAuditEvidenceTruncated, limit, maxAuditQueryLimit)
		}
		ev, err := scanAuditEvidence(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan conductor audit evidence rows: %w", err)
	}
	return out, nil
}

type auditEvidenceScanner interface {
	Scan(...any) error
}

func scanAuditEvidence(row auditEvidenceScanner) (AuditBatchEvidence, error) {
	var summary AuditBatchSummary
	var seqStart, seqEnd, eventCount, payloadBytes, droppedCount, keyIDsJSON string
	var envelopeJSON, payload []byte
	if err := row.Scan(
		&summary.BatchID, &summary.OrgID, &summary.FleetID, &summary.InstanceID,
		&summary.AuditSchema, &seqStart, &seqEnd, &eventCount,
		&summary.PayloadSHA256, &payloadBytes, &summary.EnvelopeHash,
		&summary.SegmentTailHash, &droppedCount, &summary.EmittedAt,
		&summary.ReceivedAt, &keyIDsJSON, &envelopeJSON, &payload,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AuditBatchEvidence{}, err
		}
		return AuditBatchEvidence{}, fmt.Errorf("scan conductor audit evidence: %w", err)
	}
	var err error
	if summary.SeqStart, err = parseAuditUintField("seq_start", seqStart); err != nil {
		return AuditBatchEvidence{}, err
	}
	if summary.SeqEnd, err = parseAuditUintField("seq_end", seqEnd); err != nil {
		return AuditBatchEvidence{}, err
	}
	if summary.EventCount, err = parseAuditUintField("event_count", eventCount); err != nil {
		return AuditBatchEvidence{}, err
	}
	if summary.PayloadBytes, err = parseAuditUintField("payload_bytes", payloadBytes); err != nil {
		return AuditBatchEvidence{}, err
	}
	if summary.DroppedCount, err = parseAuditUintField("dropped_count", droppedCount); err != nil {
		return AuditBatchEvidence{}, err
	}
	if err := json.Unmarshal([]byte(keyIDsJSON), &summary.SignatureKeyIDs); err != nil {
		return AuditBatchEvidence{}, fmt.Errorf("decode conductor audit signature key ids: %w", err)
	}
	var envelope conductor.AuditBatchEnvelope
	if err := json.Unmarshal(envelopeJSON, &envelope); err != nil {
		return AuditBatchEvidence{}, fmt.Errorf("decode conductor audit envelope evidence: %w", err)
	}
	if err := envelope.ValidatePayload(payload); err != nil {
		return AuditBatchEvidence{}, fmt.Errorf("%w: stored payload: %w", ErrInvalidStoreRecord, err)
	}
	envelopeHash, err := envelope.CanonicalHash()
	if err != nil {
		return AuditBatchEvidence{}, fmt.Errorf("%w: stored envelope hash: %w", ErrInvalidStoreRecord, err)
	}
	if envelopeHash != summary.EnvelopeHash {
		return AuditBatchEvidence{}, fmt.Errorf("%w: stored envelope_hash mismatch", ErrInvalidStoreRecord)
	}
	return AuditBatchEvidence{
		Summary:  summary,
		Envelope: envelope,
		Payload:  append([]byte(nil), payload...),
	}, nil
}
