// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCardJSONToolCallScalarLeaves(t *testing.T) {
	h := newTestHandler(t)
	card := "4111" + strings.Repeat("1", 12)
	for _, tt := range []struct {
		name      string
		arguments any
		decision  string
	}{
		{"string exponent", map[string]any{"result": card + "e1"}, DecisionDeny},
		{"string large exponent", map[string]any{"result": card + "e10001"}, DecisionDeny},
		{"string negative exponent", map[string]any{"result": "-" + card + "E-10001"}, DecisionDeny},
		{"string large fraction", map[string]any{"result": card + "." + strings.Repeat("7", 4097)}, DecisionDeny},
		{"array string exponent", []any{card + "e10001", "ordinary report"}, DecisionDeny},
		{"numeric fraction", map[string]any{"result": json.Number("0." + card)}, DecisionAllow},
		{"benign string exponent", map[string]any{"result": "1e10001"}, DecisionAllow},
		{"benign string integer", map[string]any{"result": strings.Repeat("7", 4097)}, DecisionAllow},
		{"number run", []any{4111, 1111, 1111, 1111}, DecisionWarn},
		{"number run and string exponent", map[string]any{"ids": []any{4111, 1111, 1111, 1111}, "result": card + "e10001"}, DecisionDeny},
	} {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{"kind": KindToolCall, "input": map[string]any{"tool_name": "report", "arguments": tt.arguments}})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/scan", strings.NewReader(string(body)))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+testToken)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			var result Response
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if w.Code != http.StatusOK || result.Status != StatusCompleted || result.Decision != tt.decision {
				t.Fatalf("status=%d scan=%s decision=%s want=%s", w.Code, result.Status, result.Decision, tt.decision)
			}
			if tt.decision != DecisionAllow && len(result.Findings) == 0 {
				t.Fatal("decision lacks a finding")
			}
		})
	}
}
