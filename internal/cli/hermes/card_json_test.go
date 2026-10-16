// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package hermes

import (
	"encoding/json"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestCardJSONHookTypes(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s := scanner.MustNew(cfg)
	t.Cleanup(s.Close)
	card := "41111111" + "11111111"
	groups := "4111,1111" + ",1111,1111"
	stringGroups := `"4111","1111","1111","1111"`
	halves := `"41111111","11111111"`
	for _, hook := range []string{HookPreToolCall, HookTransformToolResult, HookPreGatewayDispatch} {
		for _, tt := range []struct {
			input string
			block bool
		}{
			{`{"n":0.` + card + `}`, false},
			{`{"ids":[` + groups + `]}`, false},
			{`{"bbox":[` + groups + `]}`, false},
			{`[` + groups + `]`, false},
			{`{"":[` + groups + `]}`, false},
			{`{"-":[` + groups + `]}`, false},
			{`{"x-":[` + groups + `]}`, false},
			{`{"n":"` + card + `"}`, true},
			{`{"n":` + card + `}`, true},
			{`{"n":` + card + `.1}`, true},
			{`[` + stringGroups + `]`, true},
			{`[` + halves + `]`, true},
			{`{"n":"0.` + card + `"}`, true},
			{`"0.` + card + `"`, true},
			{`{"n":"{\"n\":0.` + card + `}"}`, true},
		} {
			result := evaluate(t.Context(), s, &HookEvent{HookEventName: hook, ToolName: "report", ToolInput: json.RawMessage(tt.input)})
			if (result.Decision == DecisionBlock) != tt.block {
				t.Fatalf("hook=%s input=%s decision=%+v want block=%v", hook, tt.input, result, tt.block)
			}
		}
	}
}

func TestCardJSONSharedHookCorpus(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s := scanner.MustNew(cfg)
	t.Cleanup(s.Close)
	for _, hook := range []string{HookPreToolCall, HookTransformToolResult, HookPreGatewayDispatch} {
		for _, tt := range cardtest.JSONCases() {
			t.Run(hook+"/"+tt.Name, func(t *testing.T) {
				result := evaluate(t.Context(), s, &HookEvent{HookEventName: hook, ToolName: "report", ToolInput: json.RawMessage(tt.Body)})
				if (result.Decision != DecisionBlock) != (tt.Clean || tt.Warn) {
					t.Fatalf("decision=%s clean=%v warn=%v", result.Decision, tt.Clean, tt.Warn)
				}
				if tt.Warn && len(result.warnings) != 1 {
					t.Fatalf("missing warning record: %+v", result)
				}
			})
		}
	}
}
