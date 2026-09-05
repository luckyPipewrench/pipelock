// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package capture

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestReplayResponseScanFailureBlocksWithoutInjection(t *testing.T) {
	cfg := config.Defaults()
	cfg.ResponseScanning.Action = config.ActionWarn
	re := ReplayEngine{cfg: cfg}
	got := re.responseResultToReplay(config.ActionAllow, scanner.ResponseScanResult{ScanError: "context canceled"})
	if got.CandidateAction != config.ActionBlock || !got.Changed || len(got.CandidateFindings) != 0 {
		t.Fatalf("incomplete scan must block without fabricated injection findings: %+v", got)
	}
}
