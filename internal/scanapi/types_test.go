// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanapi

import (
	"strings"
	"testing"
)

func TestGenerateScanID(t *testing.T) {
	id := generateScanID()
	if !strings.HasPrefix(id, "scan-") {
		t.Errorf("expected scan- prefix, got %q", id)
	}
	// "scan-" (5) + 16 hex chars = 21
	if len(id) != 21 {
		t.Errorf("expected length 21, got %d: %q", len(id), id)
	}

	// Uniqueness
	id2 := generateScanID()
	if id == id2 {
		t.Error("expected unique scan IDs")
	}
}

func TestScanResponse_MarshalClean(t *testing.T) {
	resp := Response{
		Status:        "completed",
		Decision:      "allow",
		Kind:          "url",
		ScanID:        "scan-abc123",
		EngineVersion: "1.3.0",
		DurationMS:    12,
	}
	// Findings should be omitted when nil
	if resp.Findings != nil {
		t.Error("expected nil findings for clean scan")
	}
}
