//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
)

const (
	maxReadModelIndexBytes            = 1 << 20
	maxEvidenceVerificationFileBytes  = 8 << 20
	maxEvidenceVerificationTotalBytes = 32 << 20
	maxEvidenceVerificationFiles      = 256
)

var errEvidenceVerificationTooLarge = errors.New("source too large")

var errBoundedFileTooLarge = errors.New("file too large")

type OperabilityHealth struct {
	DeliveryConfigured bool
	Delivery           DeliveryHealth
	DeliveryError      string
	IndexConfigured    bool
	IndexFresh         bool
	IndexStatus        string
	Index              ReadModelIndex
}

func (m *ReadModel) OperabilityHealth() OperabilityHealth {
	health := OperabilityHealth{
		DeliveryConfigured: m.deliveryInboxPath != "",
		IndexConfigured:    m.readModelIndexPath != "",
	}
	if health.DeliveryConfigured {
		delivery, err := LoadDeliveryHealth(m.deliveryInboxPath)
		if err != nil {
			health.DeliveryError = "DELIVERY HEALTH UNAVAILABLE — persisted inbox could not be read"
		} else {
			health.Delivery = delivery
		}
	}
	if health.IndexConfigured {
		index, fresh, err := InspectReadModelIndex(m.readModelIndexPath, m.receiptDir)
		health.Index = index
		health.IndexFresh = fresh
		switch {
		case err != nil:
			if errors.Is(err, errEvidenceVerificationTooLarge) {
				health.IndexStatus = "READ MODEL UNVERIFIED — source too large"
			} else {
				health.IndexStatus = "READ MODEL UNAVAILABLE — index or source evidence could not be verified"
			}
		case !fresh:
			health.IndexStatus = "READ MODEL STALE — source evidence changed; rebuild required"
		default:
			health.IndexStatus = "Read model matches its recorded source evidence"
		}
	}
	return health
}

func LoadDeliveryHealth(path string) (DeliveryHealth, error) {
	data, err := readBoundedDeliveryInbox(path)
	if err != nil {
		return DeliveryHealth{}, fmt.Errorf("read delivery inbox: %w", err)
	}
	var state deliveryInboxState
	if err := decodeStrictJSON(data, &state); err != nil || validateDeliveryState(state) != nil {
		return DeliveryHealth{}, errors.New("read delivery inbox: invalid persisted state")
	}
	return deliveryHealthFromState(state), nil
}

func InspectReadModelIndex(indexPath, sourceDir string) (ReadModelIndex, bool, error) {
	data, err := readFileLimit(indexPath, maxReadModelIndexBytes)
	if err != nil {
		return ReadModelIndex{}, false, fmt.Errorf("read model index: %w", err)
	}
	var index ReadModelIndex
	if err := decodeStrictJSON(data, &index); err != nil || index.RebuildVersion != rebuildVersion || len(index.Sources) == 0 {
		return ReadModelIndex{}, false, errors.New("read model index: invalid schema")
	}
	paths, err := boundedEvidencePaths(sourceDir)
	if err != nil {
		return index, false, fmt.Errorf("read model source directory: %w", err)
	}
	if len(paths) != len(index.Sources) {
		return index, false, nil
	}
	if err := validateReadModelIndex(index); err != nil {
		return index, false, errors.New("read model index: invalid schema")
	}
	for position, source := range index.Sources {
		if filepath.Base(source.File) != source.File {
			return index, false, errors.New("read model index: unsafe source path")
		}
		if source.File != filepath.Base(paths[position]) {
			return index, false, nil
		}
	}
	var total int64
	for position, path := range paths {
		sum, size, err := boundedEvidenceSHA256(path, maxEvidenceVerificationTotalBytes-total)
		if err != nil {
			return index, false, fmt.Errorf("verify read model sources: %w", err)
		}
		total += size
		if hex.EncodeToString(sum) != index.Sources[position].SHA256 {
			return index, false, nil
		}
	}
	return index, true, nil
}

func validateReadModelIndex(index ReadModelIndex) error {
	if index.RebuildVersion != rebuildVersion || index.RebuiltAt.IsZero() || len(index.Sources) == 0 || index.Staleness.CheckedAt.IsZero() {
		return errors.New("missing required index metadata")
	}
	combined := sha256.New()
	entryCount := 0
	maxInt := int(^uint(0) >> 1)
	first := index.Sources[0]
	aggregate := IndexRange{FirstTime: first.FirstTime, LastTime: first.LastTime, FirstSeq: first.FirstSeq, LastSeq: first.LastSeq}
	seen := make(map[string]struct{}, len(index.Sources))
	for _, source := range index.Sources {
		if filepath.Base(source.File) != source.File || source.File == "" || source.EntryCount <= 0 || source.FirstTime.IsZero() || source.LastTime.IsZero() || source.FirstTime.After(source.LastTime) || source.FirstSeq > source.LastSeq {
			return errors.New("invalid source metadata")
		}
		if _, exists := seen[source.File]; exists {
			return errors.New("duplicate source metadata")
		}
		seen[source.File] = struct{}{}
		digest, err := hex.DecodeString(source.SHA256)
		if err != nil || len(digest) != sha256.Size {
			return errors.New("invalid source digest")
		}
		_, _ = combined.Write([]byte(source.File))
		_, _ = combined.Write(digest)
		if source.EntryCount > maxInt-entryCount {
			return errors.New("entry count exceeds platform limit")
		}
		entryCount += source.EntryCount
		if source.FirstTime.Before(aggregate.FirstTime) {
			aggregate.FirstTime = source.FirstTime
		}
		if source.LastTime.After(aggregate.LastTime) {
			aggregate.LastTime = source.LastTime
		}
		if source.FirstSeq < aggregate.FirstSeq {
			aggregate.FirstSeq = source.FirstSeq
		}
		if source.LastSeq > aggregate.LastSeq {
			aggregate.LastSeq = source.LastSeq
		}
	}
	if entryCount != index.EntryCount || aggregate != index.SourceRange || index.Staleness.SourceHash != hex.EncodeToString(combined.Sum(nil)) || index.Staleness.Status != "fresh_at_rebuild" {
		return errors.New("inconsistent index metadata")
	}
	return nil
}

func readFileLimit(path string, limit int64) ([]byte, error) {
	file, _, err := openRegularDashboardFile(path, "read model index")
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errBoundedFileTooLarge
	}
	return data, nil
}

func boundedEvidenceSHA256(path string, remaining int64) ([]byte, int64, error) {
	if remaining <= 0 {
		return nil, 0, errEvidenceVerificationTooLarge
	}
	file, info, err := openRegularEvidence(path)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = file.Close() }()
	if info.Size() > maxEvidenceVerificationFileBytes || info.Size() > remaining {
		return nil, 0, errEvidenceVerificationTooLarge
	}
	hash := sha256.New()
	limit := min(int64(maxEvidenceVerificationFileBytes), remaining)
	written, err := io.Copy(hash, io.LimitReader(file, limit+1))
	if err != nil {
		return nil, 0, err
	}
	if written > limit {
		return nil, 0, errEvidenceVerificationTooLarge
	}
	after, err := file.Stat()
	if err != nil || after.Size() != info.Size() || after.ModTime() != info.ModTime() {
		return nil, 0, errors.New("source changed during verification")
	}
	return hash.Sum(nil), written, nil
}
