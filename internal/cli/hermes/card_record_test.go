// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package hermes

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestCardJSONTerminalEnvelopeRecords(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s := scanner.MustNew(cfg)
	t.Cleanup(s.Close)
	for _, hook := range []string{HookPreToolCall, HookTransformToolResult, HookPreGatewayDispatch} {
		for _, tt := range cardtest.StringifiedJSONCases() {
			t.Run(hook+"/"+tt.Name, func(t *testing.T) {
				body := json.RawMessage(tt.Body)
				result := evaluate(t.Context(), s, &HookEvent{HookEventName: hook, ToolName: hermesTerminalTool, ToolInput: body})
				if (result.Decision == DecisionBlock) != (!tt.Clean && !tt.Warn) {
					t.Fatalf("decision=%s clean=%v warn=%v", result.Decision, tt.Clean, tt.Warn)
				}
				if tt.Warn && len(result.warnings) != 1 {
					t.Fatal("serialized output lacks one operator record")
				}
			})
		}
	}
}

func TestCardJSONHookRecordOnSuccessfulExit(t *testing.T) {
	for _, hook := range []string{HookPreToolCall, HookTransformToolResult, HookPreGatewayDispatch} {
		for _, input := range []json.RawMessage{json.RawMessage(`[4111,1111,1111,1111]`), json.RawMessage(`{"output":"[4111.0,1111.0,1111.0,1111.0]","exit_code":0,"error":null}`)} {
			event, err := json.Marshal(HookEvent{HookEventName: hook, ToolName: hermesTerminalTool, ToolInput: input})
			if err != nil {
				t.Fatal(err)
			}
			cmd := hookCmd()
			var out, record bytes.Buffer
			cmd.SetIn(bytes.NewReader(event))
			cmd.SetOut(&out)
			cmd.SetErr(&record)
			if err := cmd.ExecuteContext(t.Context()); err != nil {
				t.Fatal(err)
			}
			var decision HookDecision
			if err := json.Unmarshal(out.Bytes(), &decision); err != nil || decision.Decision == DecisionBlock {
				t.Fatalf("hook did not allow warning: %v", err)
			}
			if strings.Count(record.String(), "number-only JSON card run") != 1 || !strings.Contains(record.String(), "action=warn") {
				t.Fatalf("missing unique operator record: %q", record.String())
			}
		}
	}
}

func TestCardJSONHookInspectionLimits(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s := scanner.MustNew(cfg)
	t.Cleanup(s.Close)
	for _, hook := range []string{HookPreToolCall, HookTransformToolResult, HookPreGatewayDispatch} {
		for _, body := range []string{`[1e10001]`, `[` + strings.Repeat("9", 4097) + `]`, strings.Repeat("[", 65) + "1" + strings.Repeat("]", 65)} {
			decision := evaluate(t.Context(), s, &HookEvent{HookEventName: hook, ToolInput: json.RawMessage(body)})
			if decision.Decision != DecisionBlock {
				t.Fatal("hook inspection limit did not refuse")
			}
		}
	}
}

func TestCardJSONHookRecordsWarningBesideBlockingRun(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s := scanner.MustNew(cfg)
	t.Cleanup(s.Close)
	body := json.RawMessage(`{"a":["4111","1111","1111","1111"],"break":"report","ids":[4111,1111,1111,1111]}`)
	for _, hook := range []string{HookPreToolCall, HookTransformToolResult, HookPreGatewayDispatch} {
		decision := evaluate(t.Context(), s, &HookEvent{HookEventName: hook, ToolInput: body})
		if decision.Decision != DecisionBlock || len(decision.warnings) != 1 {
			t.Fatal("blocking string run hid the number-only operator record")
		}
	}
}
