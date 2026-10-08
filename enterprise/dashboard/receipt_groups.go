//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"errors"
	"fmt"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

var errReceiptGroupNeedsVerification = errors.New("receipt group evidence requires group verification")

// requireSingleSessionEvidence prevents shard-only read models from claiming
// a complete evidence view over a receipt group. Group verdicts are available
// through the receipt verifier, which checks every shard and signed manifest.
func (m *ReadModel) requireSingleSessionEvidence() error {
	present, err := receipt.ReceiptGroupEvidencePresent(m.receiptDir, dashboardEvidenceDirectoryEntryLimit)
	if err != nil {
		return fmt.Errorf("inspect receipt group evidence: %w", err)
	}
	if present {
		return fmt.Errorf("%w; session-only dashboard view is unavailable", errReceiptGroupNeedsVerification)
	}
	return nil
}
