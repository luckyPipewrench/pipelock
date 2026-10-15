// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestExtremeNumberKeepsToolSchemaInspection(t *testing.T) {
	for _, num := range []string{"1.5", "1e999", "-1e999", "1E+400", "[1e999]"} {
		t.Run(num, func(t *testing.T) {
			schema := json.RawMessage(`{"type":"object","description":"schema text","properties":{"query":{"description":"parameter text","default":` + num + `}}}`)
			tool := ToolDef{Name: "search", InputSchema: schema}
			text, spans := toolScanText(tool)
			if !strings.Contains(text, "parameter text") || len(spans) == 0 {
				t.Fatalf("schema text/spans lost: %q, %v", text, spans)
			}
			if !strings.Contains(extractToolRuleDescriptionText(tool), "parameter text") {
				t.Fatal("description-scoped rule lost schema text")
			}
			if !slices.Contains(ExtractParamNames(schema), "query") || !slices.Contains(ExtractSchemaDescriptions(schema), "parameter text") {
				t.Fatal("schema extraction lost fields")
			}
			media := json.RawMessage(`{"data":"opaque payload","encoding":"base64","n":` + num + `}`)
			if !toolFieldContainsOpaqueMedia(media) {
				t.Fatal("opaque media classification lost")
			}
			deep := json.RawMessage(`{"n":` + num + `,"nested":` + strings.Repeat(`[`, maxSchemaDepth+1) + `"deep"` + strings.Repeat(`]`, maxSchemaDepth+1) + `}`)
			if !schemaTextExtractionTruncated(deep) {
				t.Fatal("schema depth accounting lost")
			}
		})
	}
}
