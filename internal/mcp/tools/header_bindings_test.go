// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestExtractHeaderBindings_CurrentSpecConstraints(t *testing.T) {
	valid := json.RawMessage(`{"type":"object","properties":{"tenant":{"type":"string","x-mcp-header":"Tenant"},"nested":{"type":"object","properties":{"count":{"type":"integer","x-mcp-header":"Count"}}}}}`)
	bindings, err := ExtractHeaderBindings(valid)
	if err != nil {
		t.Fatalf("valid schema: %v", err)
	}
	foundNested := false
	for _, binding := range bindings {
		if binding.HeaderName == "Count" && len(binding.Path) == 2 && binding.Path[0] == "nested" && binding.Path[1] == "count" {
			foundNested = true
		}
	}
	if len(bindings) != 2 || !foundNested {
		t.Fatalf("bindings = %#v, want direct and nested property contracts", bindings)
	}

	for _, schema := range []string{
		`{"type":"object","properties":{"x":{"type":"number","x-mcp-header":"X"}}}`,
		`{"type":"object","properties":{"x":{"type":"string","x-mcp-header":"bad name"}}}`,
		`{"type":"object","properties":{"x":{"type":"string","x-mcp-header":"Same"},"y":{"type":"boolean","x-mcp-header":"same"}}}`,
		`{"type":"object","properties":{"x":{"oneOf":[{"type":"string","x-mcp-header":"X"}]}}}`,
		`{"type":"object","properties":{"x":{"$ref":"#/$defs/x"}},"$defs":{"x":{"type":"string","x-mcp-header":"X"}}}`,
	} {
		if _, err := ExtractHeaderBindings(json.RawMessage(schema)); err == nil {
			t.Fatalf("invalid schema accepted: %s", schema)
		}
	}
}

func TestToolBaseline_HeaderBindingsReplaceAndClear(t *testing.T) {
	baseline := NewToolBaseline()
	defs := []ToolDef{{Name: "echo", InputSchema: json.RawMessage(`{"type":"object","properties":{"region":{"type":"string","x-mcp-header":"Region"}}}`)}}
	baseline.SetToolHeaderBindings(defs)
	if bindings, ok := baseline.HeaderBindings("echo"); !ok || bindings["region"].Type != "string" {
		t.Fatalf("stored bindings = %#v ok=%v", bindings, ok)
	}
	baseline.ClearToolHeaderBindings(defs)
	if _, ok := baseline.HeaderBindings("echo"); ok {
		t.Fatal("warned/invalid definition left a stale header contract")
	}
}

func TestToolBaseline_HeaderBindingsErrorAndCopyBoundaries(t *testing.T) {
	var nilBaseline *ToolBaseline
	if bindings, ok := nilBaseline.HeaderBindings("echo"); ok || bindings != nil {
		t.Fatalf("nil baseline returned bindings = %#v ok=%v", bindings, ok)
	}

	baseline := &ToolBaseline{}
	valid := ToolDef{Name: "echo", InputSchema: json.RawMessage(`{"type":"object","properties":{"region":{"type":"string","x-mcp-header":"Region"}}}`)}
	baseline.SetToolHeaderBindings([]ToolDef{valid})
	bindings, ok := baseline.HeaderBindings("echo")
	if !ok {
		t.Fatal("valid definition did not initialize the header contract map")
	}
	bindings["region"] = HeaderBinding{HeaderName: "mutated", Path: []string{"mutated"}}
	stored, ok := baseline.HeaderBindings("echo")
	if !ok || stored["region"].HeaderName != "Region" || stored["region"].Path[0] != "region" {
		t.Fatalf("caller mutation changed stored binding: %#v ok=%v", stored, ok)
	}

	invalid := ToolDef{Name: "echo", InputSchema: json.RawMessage(`{"type":"object","properties":{"region":{"type":"number","x-mcp-header":"Region"}}}`)}
	baseline.SetToolHeaderBindings([]ToolDef{invalid})
	if _, ok := baseline.HeaderBindings("echo"); ok {
		t.Fatal("invalid replacement retained the previous header contract")
	}
}

func TestExtractHeaderBindings_DecodeAndShapeErrors(t *testing.T) {
	if bindings, err := ExtractHeaderBindings(nil); err != nil || bindings != nil {
		t.Fatalf("empty schema = %#v, %v; want nil, nil", bindings, err)
	}

	for _, schema := range []string{
		`{`,
		`[]`,
		`{"type":"object","properties":[]}`,
		`{"type":"object","properties":{"x":[{"x-mcp-header":"X"}]}}`,
	} {
		if _, err := ExtractHeaderBindings(json.RawMessage(schema)); err == nil {
			t.Fatalf("invalid schema accepted: %s", schema)
		}
	}
}

func TestToolBaseline_HeaderBindingsRespectCaps(t *testing.T) {
	baseline := NewToolBaseline()
	schema := json.RawMessage(`{"type":"object","properties":{"region":{"type":"string","x-mcp-header":"Region"}}}`)
	defs := make([]ToolDef, maxBaselineTools+1)
	for i := range defs {
		defs[i] = ToolDef{Name: fmt.Sprintf("tool-%d", i), InputSchema: schema}
	}
	baseline.SetToolHeaderBindings(defs)
	if got := len(baseline.headerBindings); got != maxBaselineTools {
		t.Fatalf("header contract tools = %d, want cap %d", got, maxBaselineTools)
	}
	if _, ok := baseline.HeaderBindings(fmt.Sprintf("tool-%d", maxBaselineTools)); ok {
		t.Fatal("tool beyond baseline cap received a header contract")
	}

	properties := make([]string, maxToolHeaderBindings+1)
	for i := range properties {
		properties[i] = fmt.Sprintf(`"p%d":{"type":"string","x-mcp-header":"H%d"}`, i, i)
	}
	oversized := json.RawMessage(`{"type":"object","properties":{` + strings.Join(properties, ",") + `}}`)
	if _, err := ExtractHeaderBindings(oversized); err == nil {
		t.Fatalf("schema above per-tool header cap %d was accepted", maxToolHeaderBindings)
	}
}
