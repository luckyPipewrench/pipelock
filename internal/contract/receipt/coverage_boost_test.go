// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt_test

import (
	"encoding/json"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/contract/receipt"
)

// Hits the empty/null guard in decodeStrict.

func TestDecodeStrict_RejectsEmptyPayload(t *testing.T) {
	t.Parallel()
	err := callValidator(t, receipt.PayloadProxyDecision, json.RawMessage(""))
	if err == nil {
		t.Error("expected error for empty payload, got nil")
	}
}

func TestDecodeStrict_RejectsNullPayload(t *testing.T) {
	t.Parallel()
	err := callValidator(t, receipt.PayloadProxyDecision, json.RawMessage("null"))
	if err == nil {
		t.Error("expected error for null payload, got nil")
	}
}
