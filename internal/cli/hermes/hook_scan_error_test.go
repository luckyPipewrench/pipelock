// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package hermes

import (
	"context"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestHookCanceledResponseScanBlocksAsError(t *testing.T) {
	cfg := config.Defaults()
	cfg.DLP.ScanEnv = false
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := scanCombined(ctx, sc, "ordinary content", "tool result", directionInbound)
	if got.Decision != "block" || !strings.Contains(got.Reason, "scan failed") || strings.Contains(got.Reason, "injection match") {
		t.Fatalf("incomplete scan must block as an error: %+v", got)
	}
}
