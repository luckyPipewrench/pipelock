// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package main is the entry point for pipelock-verifier, a self-contained
// binary that verifies Pipelock receipts, receipt chains, and Audit Packets.
//
// The binary is deliberately separate from `pipelock` so callers (CI runners,
// auditors, third parties) can drop in just the verifier without provisioning
// the full firewall stack. There is no network surface, no proxy, no scanner,
// and no config reload. It reads files, validates them, and exits.
//
// Subcommands:
//
//	audit-packet PATH   Validate an Audit Packet directory (packet.json plus
//	                    sibling artifacts) against the v0 schema, then
//	                    re-verify the embedded receipt chain and confirm the
//	                    packet's claimed verdict / receipt_count / totals
//	                    match the chain's actual contents.
//	chain PATH          Verify a v1 or v2 receipt chain (single .jsonl file
//	                    or a session directory).
//	evidence PATH       Alias for chain.
//	receipt PATH        Verify a single v1 or v2 receipt JSON file.
//
// All subcommands accept --key (raw hex, public-key text, or file path) for
// trusted verification, and --json for machine-readable output. Exit codes:
// 0 valid, 1 invalid, 2 error, 64 usage error.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

const exitUsage = 64

func main() {
	root := newRootCmd()
	if err := root.Execute(); err != nil {
		// cobra prints the error itself; we map it to a structured exit code.
		os.Exit(exitCodeFor(err))
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "pipelock-verifier",
		Short: "Verify Pipelock receipts and Audit Packets",
		Long: `pipelock-verifier validates Pipelock action receipts, EvidenceReceipt v2
envelopes, receipt chains, and Audit Packets against their schema and signing rules. It is a
self-contained binary with no network surface; consumers can drop it into a
CI runner, an auditor's laptop, or an isolated environment.`,
		SilenceUsage:  true,
		SilenceErrors: false,
		Version:       cliutil.Version,
	}
	root.SetFlagErrorFunc(usageFlagError)
	root.SetVersionTemplate(fmt.Sprintf(
		"pipelock-verifier %s (commit %s, built %s, %s)\n",
		cliutil.Version, cliutil.GitCommit, cliutil.BuildDate, cliutil.GoVersion,
	))

	root.AddCommand(newAuditPacketCmd())
	root.AddCommand(newChainCmd())
	root.AddCommand(newReceiptCmd())
	root.AddCommand(newReplayCmd())
	root.AddCommand(newAARPCmd())

	return root
}

func exactOneArg(cmd *cobra.Command, args []string) error {
	if err := cobra.ExactArgs(1)(cmd, args); err != nil {
		return cliutil.ExitCodeError(exitUsage, err)
	}
	return nil
}

func usageFlagError(_ *cobra.Command, err error) error {
	return cliutil.ExitCodeError(exitUsage, err)
}
