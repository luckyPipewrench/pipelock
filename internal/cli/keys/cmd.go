// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package keys implements the `pipelock keys` operator CLI: a unified view of
// every signing-key purpose Pipelock recognises, where each key is expected to
// come from, whether it is present and readable by the calling user, and
// whether it parses as the expected key type.
//
// Today this information is scattered across many surfaces (flight-recorder
// config, mediation-envelope config, deployment-level key files produced by
// `pipelock signing key generate`, the conductor trust roster, the rules
// trusted-key list, and the build-embedded license verification key). The
// `keys status` subcommand collapses all of those into one report so an
// operator can answer "are my signing keys set up correctly" without consulting
// seven different places.
//
// Security: this command NEVER prints, logs, or returns private key bytes or
// any other secret material. It reports only the purpose, expected source,
// resolved path, presence, readability, validity, key type, and (for present
// public material) the canonical sha256 fingerprint. To check validity it may
// parse a private key, but the parsed bytes are discarded immediately and never
// emitted.
package keys

import (
	"github.com/spf13/cobra"
)

// Flag names shared across keys subcommands. Centralised so help text and
// resolution order stay consistent with the rest of the CLI (doctor, check,
// session).
const (
	flagConfig = "config"
	flagJSON   = "json"
	flagHome   = "home"
)

// Usage strings shared across subcommands so goconst stays quiet and the help
// text matches the doctor/check resolution chain operators already know.
const (
	usageConfig = "pipelock config file path (default: PIPELOCK_CONFIG env, ~/.config/pipelock/pipelock.yaml, or /etc/pipelock/pipelock.yaml)"
	usageJSON   = "machine-readable JSON output"
	usageHome   = "pipelock home directory (default ~/.pipelock, or set PIPELOCK_HOME); overrides the root --home flag for this command"
)

// Cmd is the parent command for `pipelock keys`. Exported so the root CLI can
// register it alongside the other top-level commands.
func Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keys",
		Short: "Inspect Pipelock signing keys",
		Long: `Operator commands for Pipelock's signing keys.

Pipelock uses distinct Ed25519 signing keys for distinct purposes (runtime
receipts, contract signing, rules packages, deployment trust roots, and the
Conductor control plane). The information about where each key lives is spread
across config files, deployment-level key files, and the trust roster.

Use these commands to get a single, consistent view of that state.

Examples:
  pipelock keys status
  pipelock keys status --config /etc/pipelock/pipelock.yaml
  pipelock keys status --json`,
	}
	cmd.AddCommand(statusCmd())
	return cmd
}
