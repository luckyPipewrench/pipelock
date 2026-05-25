// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/conductor"
)

type FileAuditSpool struct {
	dir string
}

type spooledAuditBatch struct {
	Identity     FollowerIdentity             `json:"identity"`
	Envelope     conductor.AuditBatchEnvelope `json:"envelope"`
	EnvelopeHash string                       `json:"envelope_hash"`
	Payload      []byte                       `json:"payload"`
	ReceivedAt   time.Time                    `json:"received_at"`
}

func OpenFileAuditSpool(dir string) (*FileAuditSpool, error) {
	resolved, err := secureDir(dir)
	if err != nil {
		return nil, err
	}
	return &FileAuditSpool{dir: resolved}, nil
}

func (s *FileAuditSpool) IngestAuditBatch(ctx context.Context, batch AcceptedAuditBatch) error {
	if s == nil {
		return ErrAuditSinkRequired
	}
	if ctx == nil {
		return fmt.Errorf("%w: context", ErrAuditSinkRequired)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateSpoolEnvelopeHash(batch.EnvelopeHash); err != nil {
		return err
	}
	if err := batch.Identity.Validate(); err != nil {
		return err
	}
	actualHash, err := batch.Envelope.CanonicalHash()
	if err != nil {
		return err
	}
	if actualHash != batch.EnvelopeHash {
		return fmt.Errorf("%w: envelope_hash mismatch", ErrInvalidStoreRecord)
	}
	record := spooledAuditBatch{
		Identity:     batch.Identity,
		Envelope:     batch.Envelope,
		EnvelopeHash: batch.EnvelopeHash,
		Payload:      append([]byte(nil), batch.Payload...),
		ReceivedAt:   batch.ReceivedAt.UTC(),
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("conductor audit spool marshal batch: %w", err)
	}
	data = append(data, '\n')
	return durableWrite(filepath.Join(s.dir, batch.EnvelopeHash+".json"), data, bundleRecordFileMode)
}

func validateSpoolEnvelopeHash(hash string) error {
	if len(hash) != sha256.Size*2 {
		return fmt.Errorf("%w: envelope_hash", ErrInvalidStoreRecord)
	}
	if _, err := hex.DecodeString(hash); err != nil {
		return fmt.Errorf("%w: envelope_hash", ErrInvalidStoreRecord)
	}
	return nil
}
