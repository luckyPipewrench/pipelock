// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"errors"
	"fmt"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// WalkReceiptsFromSessionDir reads receipts in the same order and under the
// same extraction policy as ExtractReceiptsFromSessionDir, retaining no chain.
// The callback must not retain receipts if it needs bounded memory.
func WalkReceiptsFromSessionDir(dir, sessionID string, consume func(Receipt) error) error {
	if consume == nil {
		return errors.New("session receipt consumer is required")
	}
	return recorder.WalkSessionEntries(dir, sessionID, func(e recorder.Entry) error {
		if e.Type == recorderEntryType {
			r, err := receiptFromEntry(e)
			if err != nil {
				return fmt.Errorf("receipt at seq %d: %w", e.Sequence, err)
			}
			return consume(*r)
		}
		if !knownRecorderEntryType(e.Type) {
			return fmt.Errorf("%w: %q at seq %d", ErrUnexpectedRecorderEntryType, e.Type, e.Sequence)
		}
		return nil
	})
}
