// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package hermes

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/extract"
	"github.com/luckyPipewrench/pipelock/internal/rules"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// defaultHookTimeout caps an individual hook invocation. Hermes' default
// shell-hook ceiling is 60s; we exit well before that so the agent never sees
// pipelock as the slow link.
const defaultHookTimeout = 25 * time.Second

// maxHookPayloadBytes bounds stdin so a malformed or hostile hook invocation
// cannot force the command to buffer unbounded tool output. Oversize payloads
// fail closed like any other unreadable hook input.
const maxHookPayloadBytes = 4 * 1024 * 1024

// Hermes hook event names recognised by the hook command. The set mirrors the
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

// DecisionBlock is emitted in HookDecision.Decision to tell Hermes to refuse
// the action. Matches Hermes' shell-hook vocabulary.
const DecisionBlock = "block"

// HookEvent is the inbound JSON shape Hermes pipes on stdin for every hook
// invocation. Field names match Hermes' documented wire schema so the same
// payload works for both the bundled plugin and an operator who wires
// `pipelock hermes hook` directly from `~/.hermes/config.yaml`.
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
// Context is reserved for the pre_llm_call hook contract but is unused at this
// release.
type HookDecision struct {
	Decision string `json:"decision,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Context  string `json:"context,omitempty"`
}

// hookCmd returns the `pipelock hermes hook` subcommand. Hermes invokes it as
// a subprocess per hook event, piping a JSON payload on stdin and reading a
// JSON decision off stdout. The command is fail-closed: any internal error
// (stdin read failure, malformed payload, config load failure, oversize
// payload, timeout) produces a block decision.
func hookCmd() *cobra.Command {
	var configFile string
	var timeout time.Duration

	cmd := &cobra.Command{
		Use:   "hook",
		Short: "Scan a Hermes Agent hook event from stdin (subprocess entrypoint)",
		Long: `Bridges a single Hermes Agent hook event into pipelock's scanner pipeline.

Reads a JSON Hermes hook event on stdin, runs the appropriate scan (DLP and
prompt-injection), and writes a JSON decision to stdout. Fail-closed: any
error path emits a block decision.

This is the subprocess entrypoint the bundled Python plugin invokes (installed
via 'pipelock hermes install'). Operators can also wire it directly from
~/.hermes/config.yaml under hooks: with no Python runtime involvement.

Wire schema (stdin):

  {"hook_event_name": "pre_tool_call",
   "tool_name": "...", "tool_input": {...},
   "session_id": "...", "cwd": "...",
   "extra": {...}}

Wire schema (stdout):

  {"decision": "block", "reason": "..."}    or    {}

Exit code is 0 when the command completes successfully; the decision JSON
drives Hermes-side behaviour.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()
			return runHook(ctx, cmd, configFile)
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "",
		"pipelock config file path (defaults to built-in defaults if unset)")
	cmd.Flags().DurationVar(&timeout, "timeout", defaultHookTimeout,
		"per-invocation timeout; falls back to a block decision on expiry")

	return cmd
}

// runHook is the post-flag-parse entry point. Split out from RunE so tests can
// drive it with a fully constructed context and synthetic stdin.
func runHook(ctx context.Context, cmd *cobra.Command, configFile string) error {
	if ctx == nil {
		ctx = context.Background()
	}

	stdout := cmd.OutOrStdout()
	stderr := cmd.ErrOrStderr()

	raw, err := readAllWithCtx(ctx, cmd.InOrStdin(), maxHookPayloadBytes)
	if err != nil {
		return emitDecision(stdout, blockDecision(fmt.Sprintf("pipelock hermes hook: stdin read failed: %v", err)))
	}
	if len(raw) == 0 {
		return emitDecision(stdout, blockDecision("pipelock hermes hook: empty stdin"))
	}

	var event HookEvent
	if err := json.Unmarshal(raw, &event); err != nil {
		return emitDecision(stdout, blockDecision(fmt.Sprintf("pipelock hermes hook: invalid hook event JSON: %v", err)))
	}

	cfg, err := cliutil.LoadConfigOrDefault(configFile)
	if err != nil {
		return emitDecision(stdout, blockDecision(fmt.Sprintf("pipelock hermes hook: config load failed: %v", err)))
	}

	cfg, _ = cfg.ResolveRuntime(config.RuntimeResolveOpts{
		Mode: config.RuntimeMCPScan,
		MergeBundles: func(c *config.Config) {
			// Bundle merge errors are surfaced via stderr only; an empty
			// bundle set still produces a valid (core-pattern-only) scanner.
			// Blocking the whole hook on a bundle parse error would be a
			// hostile-rules denial-of-service vector.
			result := rules.MergeIntoConfig(c, cliutil.Version)
			for _, e := range result.Errors {
				_, _ = fmt.Fprintf(stderr, "pipelock hermes hook: warning: bundle %s: %s\n", e.Name, e.Reason)
			}
		},
	})

	sc := scanner.New(cfg)
	defer sc.Close()

	decision := evaluate(ctx, sc, &event)
	return emitDecision(stdout, decision)
}

// blockDecision is the canonical fail-closed response.
func blockDecision(reason string) HookDecision {
	return HookDecision{Decision: DecisionBlock, Reason: reason}
}

// allowDecision is the canonical "no findings" response. Defined alongside
// blockDecision so callers don't reach for a zero-value HookDecision literal,
// which would be easy to typo into the wrong shape.
func allowDecision() HookDecision {
	return HookDecision{}
}

// evaluate dispatches the parsed event to the right scanner path and returns
// the decision to emit.
func evaluate(ctx context.Context, sc *scanner.Scanner, event *HookEvent) HookDecision {
	switch event.HookEventName {
	case HookPreToolCall:
		// Outbound: the agent is invoking a tool; arguments may egress.
		text, truncated := extractToolInputText(event.ToolInput)
		if truncated {
			return blockDecision("pipelock: tool arguments exceed maximum inspectable nesting depth")
		}
		return scanCombined(ctx, sc, text,
			fmt.Sprintf("tool %q arguments", event.ToolName), directionOutbound)
	case HookTransformToolResult:
		// Inbound: a tool result flowing back to the agent.
		text, truncated := extractToolInputText(event.ToolInput)
		if truncated {
			return blockDecision("pipelock: tool result exceeds maximum inspectable nesting depth")
		}
		return scanCombined(ctx, sc, text,
			fmt.Sprintf("tool %q result", event.ToolName), directionInbound)
	case HookPreGatewayDispatch:
		// Inbound: an operator->agent message being dispatched.
		text, truncated := extractToolInputText(event.ToolInput)
		if truncated {
			return blockDecision("pipelock: gateway dispatch exceeds maximum inspectable nesting depth")
		}
		return scanCombined(ctx, sc, text,
			"inbound gateway dispatch", directionInbound)
	case HookOnSessionStart, HookOnSessionEnd:
		// Observer hooks. The current release emits no decision; a follow-up
		// release may hook these to receipt emission.
		return allowDecision()
	case "":
		return blockDecision("pipelock hermes hook: missing hook_event_name")
	default:
		return blockDecision(fmt.Sprintf("pipelock hermes hook: unsupported hook_event_name %q", event.HookEventName))
	}
}

// scanDirection classifies a hook event for DLP scan selection.
//
//   - directionOutbound: text the agent is SENDING (a tool call's arguments may
//     egress). Gets the full DLP scan, including the agent's-own-secret exfil
//     checks (env-var and file-secret value matching) — this is the surface
//     where a secret actually leaves.
//   - directionInbound: text the agent is RECEIVING (an operator->agent gateway
//     dispatch, or a tool result flowing back). Gets injection scanning plus DLP
//     WITHOUT the exfil checks: a value the agent received is not something it
//     exfiltrated, so running the exfil checks here only false-positives and
//     gags normal operation. Generic detectors (regex patterns, seed phrases,
//     canary, hostname-exfil) still run in both directions.
type scanDirection int

const (
	directionOutbound scanDirection = iota
	directionInbound
)

// scanCombined applies DLP and response/injection scans to text and returns a
// block decision on the first finding. The direction selects the DLP variant
// (see scanDirection). Empty text short-circuits to allow: nothing to scan
// means nothing to flag, and a spurious block on an empty-arguments tool call
// would be a denial of service.
func scanCombined(ctx context.Context, sc *scanner.Scanner, text, surface string, dir scanDirection) HookDecision {
	if strings.TrimSpace(text) == "" {
		return allowDecision()
	}

	// Outbound runs the full exfil-aware scan; inbound skips the agent's-own-
	// secret exfil checks. Exactly one variant runs — calling the full scan for
	// an inbound event would run the exfil checks and emit warn telemetry before
	// being discarded. Injection scanning (ScanResponse) runs regardless: a
	// poisoned tool result or operator message is the real inbound threat.
	var dlp scanner.TextDLPResult
	if dir == directionInbound {
		dlp = sc.ScanTextForDLPInbound(ctx, text)
	} else {
		dlp = sc.ScanTextForDLP(ctx, text)
	}
	if !dlp.Clean && len(dlp.Matches) > 0 {
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
// single text blob for the scanner. It reuses extract.AllStringsFromJSON so
// JSON object keys are scanned too: an agent can exfiltrate by putting secrets
// in argument names just as easily as in values. Strings are joined with
// newlines so adjacent values aren't concatenated into a substring no field
// actually contains.
func extractToolInputText(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	// Some Hermes events carry tool_input as a plain JSON string (gateway
	// text, simple shell commands). Try the string case first so we don't
	// drop into the recursive walker for what is already a leaf value.
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		return asString, false
	}
	extracted := extract.AllStringsFromJSONResult(raw)
	strs := extracted.Strings
	if len(strs) == 0 {
		return "", extracted.Truncated
	}
	return strings.Join(strs, "\n"), extracted.Truncated
}

// readAllWithCtx is io.ReadAll bounded by ctx and a byte ceiling. If ctx fires
// before the read completes, the call returns ctx.Err and the in-flight read
// goroutine finishes when the OS unblocks it (the process is one-shot, so the
// leak is harmless). Returning early lets the caller emit a block decision
// inside Hermes' hook-timeout window.
func readAllWithCtx(ctx context.Context, r io.Reader, maxBytes int64) ([]byte, error) {
	type readResult struct {
		data []byte
		err  error
	}
	ch := make(chan readResult, 1)
	go func() {
		limit := maxBytes
		if limit <= 0 {
			limit = maxHookPayloadBytes
		}
		data, err := io.ReadAll(io.LimitReader(r, limit+1))
		if err == nil && int64(len(data)) > limit {
			err = fmt.Errorf("stdin payload exceeds %d byte limit", limit)
			data = nil
		}
		ch <- readResult{data: data, err: err}
	}()
	select {
	case res := <-ch:
		return res.data, res.err
	case <-ctx.Done():
		return nil, fmt.Errorf("stdin read aborted: %w", ctx.Err())
	}
}

// emitDecision writes decision as a single JSON object plus a trailing
// newline. The newline keeps the output friendly to operators piping through
// `jq` without breaking Hermes' parse (Hermes reads until EOF and re-parses).
func emitDecision(w io.Writer, decision HookDecision) error {
	buf, err := json.Marshal(decision)
	if err != nil {
		return fmt.Errorf("pipelock hermes hook: marshal decision: %w", err)
	}
	if _, err := w.Write(append(buf, '\n')); err != nil {
		return fmt.Errorf("pipelock hermes hook: write decision: %w", err)
	}
	return nil
}
