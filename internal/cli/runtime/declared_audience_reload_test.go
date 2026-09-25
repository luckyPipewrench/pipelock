// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestReloadDowngradeRejectReason_DeclaredCredentialAudience(t *testing.T) {
	t.Parallel()
	old := config.Defaults()
	updated := old.Clone()
	updated.DLP.GitHubEnterpriseHosts = []string{"ghe.example.com"}
	warnings := config.ValidateReload(old, updated)

	balanced := reloadDowngradeRejectReason(old, updated, warnings)
	if balanced != "" {
		t.Fatalf("balanced widening rejected: %q", balanced)
	}

	strict := old.Clone()
	strict.Mode = config.ModeStrict
	strictNext := updated.Clone()
	strictNext.Mode = config.ModeStrict
	if reason := reloadDowngradeRejectReason(strict, strictNext, config.ValidateReload(strict, strictNext)); reason != "strict mode" {
		t.Fatalf("strict widening rejection = %q", reason)
	}

	receipts := old.Clone()
	receipts.FlightRecorder.RequireReceipts = true
	receiptsNext := updated.Clone()
	receiptsNext.FlightRecorder.RequireReceipts = true
	reason := reloadDowngradeRejectReason(receipts, receiptsNext, config.ValidateReload(receipts, receiptsNext))
	if !strings.Contains(reason, "flight_recorder.require_receipts") {
		t.Fatalf("require_receipts widening rejection = %q", reason)
	}
}
