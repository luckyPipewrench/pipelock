// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestResponseScanFailureProducesStructuralBlock(t *testing.T) {
	got := evidenceFromInjection(scanner.ResponseScanResult{ScanError: "context canceled"}, config.ActionWarn)
	if len(got) != 1 || got[0].Action != config.ActionBlock || got[0].Scanner != scanner.DecideStructuralLabel || got[0].Pattern != "" {
		t.Fatalf("incomplete scan must produce structural block evidence: %+v", got)
	}
}
