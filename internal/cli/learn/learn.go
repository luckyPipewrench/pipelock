// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package learn provides the `pipelock learn` command tree for the
// contract-compile observation pipeline. The `observe` subverb runs the
// proxy in capture mode and writes a hash-chained recorder JSONL stream
// to the configured capture directory; entries carry an event_kind
// classifier that the downstream compile stage consumes. The privacy
// enforcer surface lives in internal/contract/privacy and is structural
// plumbing for the next phase, not active enforcement at observe time.
//
// `split` and `pin` are the operator-affordance subverbs that mutate a
// candidate contract YAML before ratification. `split` demotes a
// collapsed normalization segment back into its literal values;
// `pin` adds a per-rule reserved literal so subsequent recompiles
// cannot collapse it. Both operate at the yaml.Node level to preserve
// formatting and comments, both write atomically, and both are
// idempotent.
//
// The compile and review subverbs produce candidate artifacts. Later lifecycle
// subverbs handle shadowing, ratification, promotion, rollback, and erasure
// workflows.
package learn

import "github.com/spf13/cobra"

// Cmd returns the parent `pipelock learn` command. Wired into root in
// internal/cli/root.go.
func Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "learn",
		Short: "Run the contract-compile observation pipeline",
		Long: `Contract-compile observation and operator-affordance commands.

Observe: pipelock learn observe --capture-dir <dir>
  Runs the proxy in capture mode with the observation pipeline
  enabled. Hash-chained recorder JSONL accumulates in <dir>; later
  pipeline stages compile a behavioral contract from the captured
  evidence.

Compile and review:
  pipelock learn compile --agent <name> [--input <glob>]
  pipelock learn review <candidate.yaml>
  pipelock learn shadow --contract <candidate.yaml> --sessions <dir>
  pipelock learn diff <shadow-a.json> <shadow-b.json>
  pipelock learn ratify --candidate <candidate.yaml> --interactive
  pipelock learn promote --contract <hash> --selector <agent|glob|default>
  pipelock learn rollback --to <manifest-hash>
  pipelock learn forget --candidate <candidate.yaml> --rule-id <id> --reason <legal>

Operator affordances (mutate candidate YAML before ratification):
  pipelock learn split --candidate <path> --rule <rule_id> [--index N] [--out <path>]
  pipelock learn pin   --candidate <path> --rule <rule_id> --segment <value> [--out <path>]`,
	}
	cmd.AddCommand(observeCmd())
	cmd.AddCommand(compileCmd())
	cmd.AddCommand(reviewCmd())
	cmd.AddCommand(shadowCmd())
	cmd.AddCommand(diffCmd())
	cmd.AddCommand(ratifyCmd())
	cmd.AddCommand(promoteCmd())
	cmd.AddCommand(rollbackCmd())
	cmd.AddCommand(forgetCmd())
	cmd.AddCommand(splitCmd())
	cmd.AddCommand(pinCmd())
	return cmd
}
