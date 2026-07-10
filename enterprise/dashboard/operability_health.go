//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
)

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
			health.IndexStatus = "READ MODEL UNAVAILABLE — index or source evidence could not be verified"
		case !fresh:
			health.IndexStatus = "READ MODEL STALE — source evidence changed; rebuild required"
		default:
			health.IndexStatus = "Read model matches its recorded source evidence"
		}
	}
	return health
}

func LoadDeliveryHealth(path string) (DeliveryHealth, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return DeliveryHealth{}, fmt.Errorf("read delivery inbox: %w", err)
	}
	var state deliveryInboxState
	if err := decodeStrictJSON(data, &state); err != nil || validateDeliveryState(state) != nil {
		return DeliveryHealth{}, errors.New("read delivery inbox: invalid persisted state")
	}
	health := DeliveryHealth{Dropped: state.Dropped, DeadLetters: len(state.DeadLetters), UpdatedAt: state.UpdatedAt}
	for _, attempt := range state.Attempts {
		if err := validateDeliveryAttempt(attempt); err != nil {
			return DeliveryHealth{}, fmt.Errorf("read delivery inbox: invalid attempt: %w", err)
		}
		switch attempt.Status {
		case DeliveryQueued:
			health.Queued++
		case DeliveryDelivered:
			health.Delivered++
		case DeliveryFailed:
			health.Failed++
		}
	}
	return health, nil
}

func InspectReadModelIndex(indexPath, sourceDir string) (ReadModelIndex, bool, error) {
	data, err := os.ReadFile(filepath.Clean(indexPath))
	if err != nil {
		return ReadModelIndex{}, false, fmt.Errorf("read model index: %w", err)
	}
	var index ReadModelIndex
	if err := decodeStrictJSON(data, &index); err != nil || index.RebuildVersion != rebuildVersion || len(index.Sources) == 0 {
		return ReadModelIndex{}, false, errors.New("read model index: invalid schema")
	}
	paths, err := evidencePaths(sourceDir)
	if err != nil {
		return index, false, fmt.Errorf("read model source directory: %w", err)
	}
	if len(paths) != len(index.Sources) {
		return index, false, nil
	}
	for position, source := range index.Sources {
		if filepath.Base(source.File) != source.File {
			return index, false, errors.New("read model index: unsafe source path")
		}
		if source.File != filepath.Base(paths[position]) {
			return index, false, nil
		}
	}
	expected, err := buildReadModelIndex(paths, index.RebuiltAt)
	if err != nil {
		return index, false, fmt.Errorf("verify read model sources: %w", err)
	}
	if !slices.Equal(index.Sources, expected.Sources) || index.SourceRange != expected.SourceRange ||
		index.EntryCount != expected.EntryCount || index.Staleness != expected.Staleness {
		return index, false, nil
	}
	return index, true, nil
}
