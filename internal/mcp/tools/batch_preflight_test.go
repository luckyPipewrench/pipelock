// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package tools

import "testing"

// A batch rejected because one element's tools field is malformed must leave
// the drift baseline exactly as it was, whatever order the elements arrive in.
func TestScanToolsBatch_RejectedBatchLeavesDriftBaselineUnchanged(t *testing.T) {
	sc := testScanner(t)
	tests := []struct {
		name  string
		batch string
	}{
		{"empty list before malformed", `[{"jsonrpc":"2.0","id":1,"result":{"tools":[]}},{"jsonrpc":"2.0","id":2,"result":{"tools":"x"}}]`},
		{"populated list before malformed", `[{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"echo","description":"Echoes its input."}]}},{"jsonrpc":"2.0","id":2,"result":{"tools":[1]}}]`},
		{"malformed before empty list", `[{"jsonrpc":"2.0","id":1,"result":{"tools":{}}},{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}]`},
		{"unreadable definition after valid list", `[{"jsonrpc":"2.0","id":1,"result":{"tools":[]}},{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":42}]}}]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseline := NewToolBaseline()
			cfg := &ToolScanConfig{Action: "block", Baseline: baseline, DetectDrift: true}
			result := ScanTools([]byte(tt.batch), sc, cfg)
			if result.Clean {
				t.Fatalf("batch with a malformed tools field scanned clean: %+v", result)
			}
			if baseline.HasBaseline() {
				t.Fatal("rejected batch recorded tool hashes in the drift baseline")
			}
			baseline.mu.Lock()
			established := baseline.driftEstablished
			baseline.mu.Unlock()
			if established {
				t.Fatal("rejected batch established the drift baseline")
			}
		})
	}
}
