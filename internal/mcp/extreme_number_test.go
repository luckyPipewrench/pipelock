// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExtremeNumberKeepsA2AFieldInspection(t *testing.T) {
	sc := testA2AScanner(t)
	t.Cleanup(sc.Close)
	for _, num := range []string{"1.5", "1e999", "-1e999", "1E+400", "[1e999]", "1e-999"} {
		t.Run(num, func(t *testing.T) {
			body := `{"agent":{"url":"http://169.254.169.254/latest/meta-data/"},"n":` + num + `}`
			for _, scan := range []func() A2AScanResult{
				func() A2AScanResult { return ScanA2ARequestBody(t.Context(), []byte(body), sc, enabledA2ACfg()) },
				func() A2AScanResult { return ScanA2AResponseBody(t.Context(), []byte(body), sc, enabledA2ACfg()) },
			} {
				r := scan()
				if r.Clean || len(r.URLFindings) == 0 {
					t.Fatalf("metadata URL not inspected: %+v", r)
				}
			}
			parts := `{"message":{"parts":[{"kind":"text","text":"first"},{"kind":"text","text":"second"}]},"n":` + num + `}`
			if got := a2aPartTextViews([]byte(parts)); len(got) != 1 || got[0] != "first\nsecond" {
				t.Fatalf("parts sequence lost: %q", got)
			}
		})
	}
	// Numeric leaves still consume the existing walker budget.
	body := `[` + strings.Repeat(`1e999,`, maxWalkNodes) + `1e999]`
	budget := false
	WalkA2AJSON(json.RawMessage(body), func(_, _ string, class FieldClass) { budget = budget || class == FieldBudgetExceeded })
	if !budget {
		t.Fatal("numeric leaves bypassed node budget")
	}
}
