// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestClassifyToolsListResult(t *testing.T) {
	tests := []struct {
		name string
		raw  json.RawMessage
		want ToolsListShape
	}{
		{"nil", nil, ToolsListAbsent},
		{"null", json.RawMessage(`null`), ToolsListAbsent},
		{"not an object", json.RawMessage(`"text"`), ToolsListAbsent},
		{"invalid json", json.RawMessage(`{`), ToolsListAbsent},
		{"no tools key", json.RawMessage(`{"content":[]}`), ToolsListAbsent},
		{"empty array", json.RawMessage(`{"tools":[]}`), ToolsListValid},
		{"objects", json.RawMessage(`{"tools":[{"name":"a"},{"name":"b"}],"nextCursor":"c2"}`), ToolsListValid},
		{"tools null", json.RawMessage(`{"tools":null}`), ToolsListMalformed},
		{"tools string", json.RawMessage(`{"tools":"oops"}`), ToolsListMalformed},
		{"tools number", json.RawMessage(`{"tools":1}`), ToolsListMalformed},
		{"tools object", json.RawMessage(`{"tools":{"name":"a"}}`), ToolsListMalformed},
		{"string element", json.RawMessage(`{"tools":[{"name":"a"},"x"]}`), ToolsListMalformed},
		{"null element", json.RawMessage(`{"tools":[null]}`), ToolsListMalformed},
		{"invalid array", json.RawMessage(`{"tools":[invalid]}`), ToolsListAbsent},
		{"capitalized key", json.RawMessage(`{"Tools":[{"name":"a"}]}`), ToolsListMalformed},
		{"upper key", json.RawMessage(`{"TOOLS":[{"name":"a"}]}`), ToolsListMalformed},
		{"mixed case key", json.RawMessage(`{"tOoLs":[{"name":"a"}]}`), ToolsListMalformed},
		{"long s key", json.RawMessage("{\"tool\u017f\":[{\"name\":\"a\"}]}"), ToolsListMalformed},
		{"exact and alias keys", json.RawMessage(`{"tools":[],"Tools":[{"name":"a"}]}`), ToolsListMalformed},
		{"alias with empty array", json.RawMessage(`{"Tools":[]}`), ToolsListMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClassifyToolsListResult(tt.raw); got != tt.want {
				t.Errorf("ClassifyToolsListResult() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScanToolsForMethod_MalformedShape(t *testing.T) {
	sc := testScanner(t)
	const malformed = `{"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"a","description":"fine"},"x"]}}`
	tests := []struct {
		name       string
		line       string
		method     string
		wantReject bool
	}{
		{"no method", malformed, "", true},
		{"tools/list", malformed, "tools/list", true},
		{"other method", malformed, "tools/call", false},
		{"batch element", `[` + malformed + `]`, "", true},
		{"batch with clean sibling", `[{"jsonrpc":"2.0","id":1,"result":{"tools":[]}},` + malformed + `]`, "", true},
		{"tools string", `{"jsonrpc":"2.0","id":3,"result":{"tools":"oops"}}`, "tools/list", true},
		{"empty array valid", `{"jsonrpc":"2.0","id":3,"result":{"tools":[]}}`, "tools/list", false},
		{"error response", `{"jsonrpc":"2.0","id":3,"error":{"code":-1,"message":"x"}}`, "tools/list", false},
	}
	for _, action := range []string{config.ActionWarn, config.ActionBlock} {
		for _, tt := range tests {
			t.Run(action+"/"+tt.name, func(t *testing.T) {
				cfg := &ToolScanConfig{Action: action, Baseline: NewToolBaseline(), DetectDrift: true}
				got := ScanToolsForMethod([]byte(tt.line), sc, cfg, tt.method)
				rejected := got.IsToolsList && !got.Clean && got.ResourceLimit == "tool_definition_uninspectable"
				if rejected != tt.wantReject {
					t.Fatalf("rejected=%v want %v: %+v", rejected, tt.wantReject, got)
				}
				if rejected && got.ResourceDetail == "" {
					t.Error("rejection must carry an operator-visible detail")
				}
				if rejected && !strings.Contains(tt.line, `"tools":[]`) && cfg.Baseline.HasBaseline() {
					t.Error("a rejected response must not establish a baseline")
				}
			})
		}
	}
}

func TestToolDefKeyAliasesRejected(t *testing.T) {
	sc := testScanner(t)
	tests := []struct {
		name string
		tool string
	}{
		{"description alias after exact", `{"name":"a","description":"first","Description":"second"}`},
		{"description alias only", `{"name":"a","DESCRIPTION":"text"}`},
		{"name alias", `{"name":"a","Name":"b"}`},
		{"inputSchema alias", `{"name":"a","inputschema":{}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[` + tt.tool + `]}}`)
			got := ScanTools(line, sc, &ToolScanConfig{Action: config.ActionWarn, Baseline: NewToolBaseline()})
			if got.Clean || got.ResourceLimit != "tool_definition_uninspectable" {
				t.Fatalf("aliased tool key not rejected: %+v", got)
			}
		})
	}
}
