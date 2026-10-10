// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"errors"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// WalkReceiptsFromSessionDir reads receipts in the same order and under the
// same extraction policy as ExtractReceiptsFromSessionDir, retaining no chain.
// The callback must not retain receipts if it needs bounded memory.
func WalkReceiptsFromSessionDir(dir, sessionID string, consume func(Receipt) error) error {
	if consume == nil {
		return errors.New("session receipt consumer is required")
	}
	return recorder.WalkSessionHistory(dir, sessionID, func(e recorder.Entry) error {
		r, ok, err := receiptFromChainEntry(e)
		if err != nil || !ok {
			return err
		}
		return consume(r)
	})
}
