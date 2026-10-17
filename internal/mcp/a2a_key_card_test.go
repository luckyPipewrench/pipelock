// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"fmt"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

// Card joins omit object keys and the field-aware walk gives keys only
// entropy checks, so a whole-key card must reach the per-key pass both
// within the walk budget and in the overflow pass beyond it.
func TestA2AWholeKeyCardWithinAndBeyondBudget(t *testing.T) {
	sc := testA2AScanner(t)
	t.Cleanup(sc.Close)
	cfg := enabledA2ACfg()
	cfg.Action = config.ActionWarn
	card := cardtest.Number()
	for _, count := range []int{100, 10500} {
		t.Run(fmt.Sprintf("%d", count), func(t *testing.T) {
			body := a2aWideBody(count, "hello")
			body = body[:len(body)-1] + `,"k":{"` + card + `":"x"}}`
			got := ScanA2ARequestBody(t.Context(), []byte(body), sc, cfg)
			if got.Clean || len(got.DLPFindings) == 0 {
				t.Fatalf("whole-key card lost: %+v", got)
			}
			if got.BudgetExceeded != (count > 100) {
				t.Fatalf("BudgetExceeded = %v", got.BudgetExceeded)
			}
		})
	}
}
