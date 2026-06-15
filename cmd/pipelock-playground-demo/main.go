// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package main is the entry point for pipelock-playground-demo, a local
// demonstration binary that drives a deterministic toy agent through a real
// Pipelock proxy, captures signed decision receipts into an evidence JSONL,
// and assembles them into an offline-verifiable Audit Packet.
//
// Subcommands:
//
//	run        Drive the demo agent through the proxy and produce evidence.
//	reset      Clear state from a previous run.
//	verify     Verify a previously produced Audit Packet directory.
//	fallback   Run the demo in fallback (offline/replay) mode.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

func main() {
	root := newRootCmd()
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "pipelock-playground-demo",
		Short: "Pipelock Playground local demo engine",
		Long: `pipelock-playground-demo runs a deterministic toy agent through a real
Pipelock proxy, captures signed decision receipts, and assembles them into an
offline-verifiable Audit Packet. It is used to produce live evidence for the
Pipelock Playground.`,
		SilenceUsage:  true,
		SilenceErrors: false,
		Version:       cliutil.Version,
	}
	root.SetVersionTemplate(fmt.Sprintf(
		"pipelock-playground-demo %s (commit %s, built %s, %s)\n",
		cliutil.Version, cliutil.GitCommit, cliutil.BuildDate, cliutil.GoVersion,
	))

	root.AddCommand(newRunCmd())
	root.AddCommand(newResetCmd())
	root.AddCommand(newVerifyCmd())
	root.AddCommand(newFallbackCmd())

	return root
}

func newRunCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "run",
		Short: "Drive the demo agent and produce evidence",
		RunE: func(_ *cobra.Command, _ []string) error {
			return fmt.Errorf("not implemented")
		},
	}
}

func newResetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reset",
		Short: "Clear state from a previous demo run",
		RunE: func(_ *cobra.Command, _ []string) error {
			return fmt.Errorf("not implemented")
		},
	}
}

func newVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Verify a previously produced Audit Packet",
		RunE: func(_ *cobra.Command, _ []string) error {
			return fmt.Errorf("not implemented")
		},
	}
}

func newFallbackCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "fallback",
		Short: "Run the demo in fallback (offline/replay) mode",
		RunE: func(_ *cobra.Command, _ []string) error {
			return fmt.Errorf("not implemented")
		},
	}
}
