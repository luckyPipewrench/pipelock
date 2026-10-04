// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
)

// TornSnapshot identifies the exact observed shard and complete-line boundary.
type TornSnapshot struct {
	Size   int64
	SHA256 string
	Offset int64
}

// CaptureTornEvidence hashes an unchanged, no-follow shard and validates its
// damage classification. validate also sees valid final JSON without a newline;
// complete sees only newline-terminated entries. No evidence bytes are changed.
// A positive maxBytes applies the caller's offline read ceiling; zero streams
// without a whole-shard ceiling, like live tail inspection.
func CaptureTornEvidence(path string, maxBytes int64, validate, complete func(Entry) error) (TornSnapshot, error) {
	f, info, err := openRegularEvidenceFile(path, validateEvidenceFileAccess())
	if err != nil {
		return TornSnapshot{}, err
	}
	defer func() { _ = f.Close() }()
	if maxBytes > 0 && info.Size() > maxBytes {
		return TornSnapshot{}, ErrEvidenceReadLimitExceeded
	}
	err = inspectJSONLTail(f, info, path, evidenceTailValidator(validate))
	var torn *TornTailError
	if !errors.As(err, &torn) {
		if err == nil {
			err = errors.New("recovery shard is not torn")
		}
		return TornSnapshot{}, err
	}
	if err := inspectJSONLRecords(io.NewSectionReader(f, 0, torn.Offset), path, evidenceTailValidator(complete), false); err != nil {
		return TornSnapshot{}, err
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(f, 0, info.Size())); err != nil {
		return TornSnapshot{}, err
	}
	if err := ensureEvidenceFileUnchanged(f, info); err != nil {
		return TornSnapshot{}, err
	}
	return TornSnapshot{Size: info.Size(), SHA256: hex.EncodeToString(h.Sum(nil)), Offset: torn.Offset}, nil
}
