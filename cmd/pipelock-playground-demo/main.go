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
	"github.com/luckyPipewrench/pipelock/internal/playground"
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
	var orchKey string
	cmd := &cobra.Command{
		Use:   "verify <rundir>",
		Short: "Verify a previously produced demo run (offline, all-or-nothing)",
		Long: `Performs all-or-nothing offline verification of a playground demo run
directory. The trust root is the single --orchestrator-key; pipelock and
collector keys are taken from the verified manifest, NOT trusted blindly.

Exit code 0 = every check passed. Non-zero = at least one check failed.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rep, err := playground.VerifyRun(args[0], orchKey)
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			for _, c := range rep.Checks {
				status := "PASS"
				if !c.OK {
					status = "FAIL"
				}
				_, _ = fmt.Fprintf(w, "[%s] %s", status, c.Name)
				if c.Reason != "" {
					_, _ = fmt.Fprintf(w, " -- %s", c.Reason)
				}
				_, _ = fmt.Fprintln(w)
			}
			_, _ = fmt.Fprintln(w)
			if rep.OK {
				_, _ = fmt.Fprintf(w, "VERIFY OK  run_nonce=%s observed=%d\n", rep.RunNonce, rep.ObservedCount)
				return nil
			}
			return fmt.Errorf("VERIFY FAILED: one or more checks did not pass")
		},
	}
	cmd.Flags().StringVar(&orchKey, "orchestrator-key", "", "hex-encoded orchestrator Ed25519 public key (trust root)")
	_ = cmd.MarkFlagRequired("orchestrator-key")
	return cmd
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
