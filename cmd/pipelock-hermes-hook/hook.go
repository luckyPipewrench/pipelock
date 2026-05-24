// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/extract"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// Hermes hook event names recognised by this binary. The set mirrors the
// hooks registered by the bundled Python plugin. Any other event name is
// treated as a contract violation and blocks. New upstream hooks need an
// explicit classification here so scanner-bearing surfaces cannot silently
// downgrade to allow.
const (
	HookPreToolCall         = "pre_tool_call"
	HookTransformToolResult = "transform_tool_result"
	HookPreGatewayDispatch  = "pre_gateway_dispatch"
	HookOnSessionStart      = "on_session_start"
	HookOnSessionEnd        = "on_session_end"
)

// Decision strings emitted in HookDecision.Decision. Match Hermes' shell-hook
// vocabulary so the agent can act on them without translation.
const (
	DecisionBlock = "block"
)

// HookEvent is the inbound JSON shape Hermes pipes on stdin for every shell
// hook invocation. Field names match Hermes' documented wire schema so the
// same payload works for both the bundled plugin and an operator who hooks
// pipelock-hermes-hook directly from `~/.hermes/config.yaml`.
type HookEvent struct {
	HookEventName string          `json:"hook_event_name"`
	ToolName      string          `json:"tool_name,omitempty"`
	ToolInput     json.RawMessage `json:"tool_input,omitempty"`
	SessionID     string          `json:"session_id,omitempty"`
	CWD           string          `json:"cwd,omitempty"`
	Extra         json.RawMessage `json:"extra,omitempty"`
}

// HookDecision is the outbound JSON shape written to stdout. An empty struct
// (`{}`) means "allow"; Decision="block" tells Hermes to refuse the action.
// Context is reserved for the pre_llm_call hook contract but is unused at
// this release.
type HookDecision struct {
	Decision string `json:"decision,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Context  string `json:"context,omitempty"`
}

// blockDecision is the canonical fail-closed response. Constructed via a
// helper rather than inlined so every emit site uses the same JSON shape.
func blockDecision(reason string) HookDecision {
	return HookDecision{Decision: DecisionBlock, Reason: reason}
}

// allowDecision is the canonical "no findings" response. Defined alongside
// blockDecision so callers don't reach for a zero-value HookDecision literal,
// which would be easy to typo in a way that silently emits the wrong shape.
func allowDecision() HookDecision {
	return HookDecision{}
}

// evaluate dispatches the parsed event to the right scanner path and returns
// the decision to emit. The function takes a *scanner.Scanner rather than a
// *config.Config so callers can reuse a single scanner across invocations
// (the binary itself is one-shot, but tests instantiate one scanner per
// test case).
func evaluate(ctx context.Context, sc *scanner.Scanner, event *HookEvent) HookDecision {
	switch event.HookEventName {
	case HookPreToolCall:
		return scanToolInput(ctx, sc, event)
	case HookTransformToolResult:
		return scanToolResult(ctx, sc, event)
	case HookPreGatewayDispatch:
		return scanGatewayDispatch(ctx, sc, event)
	case HookOnSessionStart, HookOnSessionEnd:
		// Observer hooks. The current release emits no decision; a
		// follow-up release may hook these to receipt emission.
		return allowDecision()
	case "":
		// Empty event name is a contract violation. Fail closed.
		return blockDecision("pipelock-hermes-hook: missing hook_event_name")
	default:
		return blockDecision(fmt.Sprintf("pipelock-hermes-hook: unsupported hook_event_name %q", event.HookEventName))
	}
}

// scanToolInput runs DLP + injection scans on the tool arguments. The agent
// is about to invoke this tool with these arguments — finding a secret or
// an injection here is the strongest reason to block in the entire flow.
func scanToolInput(ctx context.Context, sc *scanner.Scanner, event *HookEvent) HookDecision {
	text := extractToolInputText(event.ToolInput)
	return scanCombined(ctx, sc, text, fmt.Sprintf("tool %q arguments", event.ToolName))
}

// scanToolResult runs the same combined scan on the tool's response text.
// The deep-dive doc flags this as the hook that pipelock uniquely closes for
// Hermes: Hermes itself runs no injection scanning on tool results today.
func scanToolResult(ctx context.Context, sc *scanner.Scanner, event *HookEvent) HookDecision {
	text := extractToolInputText(event.ToolInput)
	return scanCombined(ctx, sc, text, fmt.Sprintf("tool %q result", event.ToolName))
}

// scanGatewayDispatch handles inbound messaging-platform text (Telegram,
// Discord, Slack). The event arrives before the agent loop ever starts,
// which makes this the cheapest place to drop adversarial messages.
func scanGatewayDispatch(ctx context.Context, sc *scanner.Scanner, event *HookEvent) HookDecision {
	text := extractToolInputText(event.ToolInput)
	return scanCombined(ctx, sc, text, "inbound gateway dispatch")
}

// scanCombined applies DLP and response/injection scans to text and returns
// a block decision on the first finding. Empty text short-circuits to allow:
// nothing to scan means nothing to flag, and emitting a spurious block on
// an empty-arguments tool call would be a denial of service.
func scanCombined(ctx context.Context, sc *scanner.Scanner, text, surface string) HookDecision {
	if strings.TrimSpace(text) == "" {
		return allowDecision()
	}

	if dlp := sc.ScanTextForDLP(ctx, text); !dlp.Clean && len(dlp.Matches) > 0 {
		first := dlp.Matches[0]
		return blockDecision(fmt.Sprintf("pipelock DLP match on %s: %s (severity=%s)",
			surface, first.PatternName, first.Severity))
	}

	if resp := sc.ScanResponse(ctx, text); !resp.Clean && len(resp.Matches) > 0 {
		first := resp.Matches[0]
		return blockDecision(fmt.Sprintf("pipelock injection match on %s: %s",
			surface, first.PatternName))
	}

	return allowDecision()
}

// extractToolInputText collapses the structured tool_input JSON value into a
// single text blob suitable for the scanner. The implementation reuses
// extract.AllStringsFromJSON so JSON object keys are scanned too; agents can
// exfiltrate by putting secrets in argument names just as easily as values.
//
// Strings are joined with newlines so adjacent values aren't accidentally
// concatenated into a substring that no individual field actually contains.
// Mirrors the MCP proxy join policy at the same layer.
func extractToolInputText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	// Some Hermes events carry tool_input as a plain JSON string (gateway
	// text, simple shell commands). Try the string case first so we don't
	// drop into the recursive walker for what is already a leaf value.
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		return asString
	}
	strs := extract.AllStringsFromJSON(raw)
	if len(strs) == 0 {
		return ""
	}
	return strings.Join(strs, "\n")
}
