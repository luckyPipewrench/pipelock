// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"fmt"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// hasReceiptGroupArtifacts is a conservative maintenance guard. Commands
// that only understand one run session must not certify or rewrite a group.
func hasReceiptGroupArtifacts(dir string) (bool, error) {
	present, err := receipt.ReceiptGroupEvidencePresent(dir, 0)
	if err != nil {
		return false, fmt.Errorf("inspect receipt group evidence: %w", err)
	}
	return present, nil
}
