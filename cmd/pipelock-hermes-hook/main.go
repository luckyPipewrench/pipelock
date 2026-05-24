// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package main is the entry point for pipelock-hermes-hook, a small one-shot
// binary that bridges Hermes Agent (Nous Research) hook events into pipelock's
// scanner pipeline.
//
// Hermes invokes the binary as a subprocess per hook event, piping a JSON
// payload on stdin and reading a JSON decision off stdout. The wire schema
// matches Hermes' standard shell-hook protocol so operators can wire pipelock
// in either via the bundled Python plugin or directly from ~/.hermes/config.yaml.
//
// The MVP release supports five hook events:
//
//	pre_tool_call          DLP + injection scan on tool arguments (can block)
//	transform_tool_result  DLP + injection scan on tool output (can block)
//	pre_gateway_dispatch   DLP + injection scan on inbound platform text
//	on_session_start       observer (no decision)
//	on_session_end         observer (no decision)
//
// The binary is fail-closed: any internal error — stdin read failure, malformed
// payload, config load failure, scanner construction failure, timeout —
// produces a block decision. Pipelock's hard rule (`Never bypass fail-closed
// defaults`) extends to this surface unchanged.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/rules"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// defaultTimeout caps an individual hook invocation. Hermes' default shell-
// hook ceiling is 60s; we exit well before that so the agent never sees the
// pipelock subprocess as the slow link.
const defaultTimeout = 25 * time.Second

// maxHookPayloadBytes bounds stdin so a malformed or hostile hook invocation
// cannot force the one-shot binary to buffer unbounded tool output. Oversize
// payloads fail closed like any other unreadable hook input.
const maxHookPayloadBytes = 4 * 1024 * 1024

func main() {
	if err := newRootCmd().Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(cliutil.ExitCodeOf(err))
	}
}

func newRootCmd() *cobra.Command {
	var configFile string
	var timeout time.Duration

	cmd := &cobra.Command{
		Use:   "pipelock-hermes-hook",
		Short: "Hermes Agent shell-hook bridge for pipelock scanning",
		Long: `Bridges Hermes Agent hook events into pipelock's scanner pipeline.

Reads a JSON Hermes hook event on stdin, runs the appropriate scan (DLP
and prompt-injection), and writes a JSON decision to stdout. The binary is
fail-closed: any error path emits a block decision.

The integration is registered automatically by the bundled Python plugin
(installed via 'pipelock hermes install'). Operators can also wire the
binary directly from ~/.hermes/config.yaml under hooks: with no Python
runtime involvement.

Wire schema (stdin):

  {"hook_event_name": "pre_tool_call",
   "tool_name": "...", "tool_input": {...},
   "session_id": "...", "cwd": "...",
   "extra": {...}}

Wire schema (stdout):

  {"decision": "block", "reason": "..."}    or    {}

Exit code is always 0 when the binary completed successfully; the decision
JSON drives Hermes-side behaviour.`,
		Version:       cliutil.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()
			return run(ctx, cmd, configFile)
		},
	}

	cmd.PersistentFlags().StringVarP(&configFile, "config", "c", "",
		"pipelock config file path (defaults to built-in defaults if unset)")
	cmd.PersistentFlags().DurationVar(&timeout, "timeout", defaultTimeout,
		"per-invocation timeout; falls back to a block decision on expiry")

	return cmd
}

// run is the post-flag-parse entry point. Split out from RunE so tests can
// drive it with a fully constructed context and synthetic stdin without
// touching cobra wiring.
func run(ctx context.Context, cmd *cobra.Command, configFile string) error {
	if ctx == nil {
		ctx = context.Background()
	}

	stdout := cmd.OutOrStdout()
	stderr := cmd.ErrOrStderr()

	raw, err := readAllWithCtx(ctx, cmd.InOrStdin(), maxHookPayloadBytes)
	if err != nil {
		return emit(stdout, blockDecision(fmt.Sprintf("pipelock-hermes-hook: stdin read failed: %v", err)))
	}
	if len(raw) == 0 {
		return emit(stdout, blockDecision("pipelock-hermes-hook: empty stdin"))
	}

	var event HookEvent
	if err := json.Unmarshal(raw, &event); err != nil {
		return emit(stdout, blockDecision(fmt.Sprintf("pipelock-hermes-hook: invalid hook event JSON: %v", err)))
	}

	cfg, err := cliutil.LoadConfigOrDefault(configFile)
	if err != nil {
		return emit(stdout, blockDecision(fmt.Sprintf("pipelock-hermes-hook: config load failed: %v", err)))
	}

	cfg, _ = cfg.ResolveRuntime(config.RuntimeResolveOpts{
		Mode: config.RuntimeMCPScan,
		MergeBundles: func(c *config.Config) {
			// Bundle merge errors are surfaced via stderr only; an empty
			// bundle set still produces a valid (core-pattern-only)
			// scanner. Blocking the whole hook on a bundle parse error
			// would be a hostile-rules denial-of-service vector.
			result := rules.MergeIntoConfig(c, cliutil.Version)
			for _, e := range result.Errors {
				_, _ = fmt.Fprintf(stderr, "pipelock-hermes-hook: warning: bundle %s: %s\n", e.Name, e.Reason)
			}
		},
	})

	sc := scanner.New(cfg)
	defer sc.Close()

	decision := evaluate(ctx, sc, &event)
	return emit(stdout, decision)
}

// readAllWithCtx is io.ReadAll bounded by ctx. If ctx fires before the read
// completes, the call returns ctx.Err and the in-flight read goroutine
// eventually finishes when the OS unblocks it (the binary is exiting, so the
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

// emit writes decision as a single JSON object followed by a trailing
// newline. The newline keeps the output friendly to operators piping the
// binary through `jq` during debugging without breaking Hermes' JSON parse:
// Hermes consumes the stream by reading until EOF and re-parsing.
func emit(w io.Writer, decision HookDecision) error {
	buf, err := json.Marshal(decision)
	if err != nil {
		// json.Marshal can fail on HookDecision only if a future field
		// somehow encodes an unsupported type. Treat it as a programming
		// error worth surfacing rather than swallowing.
		return fmt.Errorf("pipelock-hermes-hook: marshal decision: %w", err)
	}
	if _, err := w.Write(append(buf, '\n')); err != nil {
		return fmt.Errorf("pipelock-hermes-hook: write decision: %w", err)
	}
	return nil
}
