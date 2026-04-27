// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package learn provides the `pipelock learn` command tree for the v2.4
// learn-and-lock observation pipeline. The `observe` subverb runs the
// proxy in capture mode and writes a hash-chained recorder JSONL stream
// to the configured capture directory; entries carry an event_kind
// classifier that the downstream compile stage consumes. The privacy
// enforcer surface lives in internal/contract/privacy and is structural
// plumbing for the next phase, not active enforcement at observe time.
//
// Future commits add `compile`, `review`, `shadow`, `ratify`, `forget`,
// `promote`, and `rollback` subverbs as the corresponding pipeline
// stages ship.
package learn

import "github.com/spf13/cobra"

// Cmd returns the parent `pipelock learn` command. Wired into root in
// internal/cli/root.go.
func Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "learn",
		Short: "Run the learn-and-lock observation pipeline",
		Long: `Learn-and-lock pipeline.

Phase 1 (observe): pipelock learn observe --capture-dir <dir>
  Runs the proxy in capture mode with the learn observation pipeline
  enabled. Hash-chained recorder JSONL accumulates in <dir>; later
  pipeline stages compile a behavioral contract from the captured
  evidence.`,
	}
	cmd.AddCommand(observeCmd())
	return cmd
}
