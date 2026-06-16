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
	var (
		contained bool
		runDir    string
		scenario  string
		color     bool
		runNonce  string
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Drive the demo agent and produce evidence",
		Long: `Runs the playground demo: boots a real Pipelock proxy, drives a
deterministic toy agent through it, captures signed decision receipts, assembles
an offline-verifiable Audit Packet, and renders the mediator timeline.

Exit 0 = run verified successfully. Non-zero = verification failed or run error.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			w := cmd.OutOrStdout()
			if contained {
				// Register the real (host-only) containment hook. Its Setup
				// requires root + an installed `pipelock contain`; the
				// host-containment witness probe runs as the contained agent
				// user and fails loudly rather than silently running
				// uncontained.
				playground.SetContainmentHook(playground.NewRealContainmentHook(""))
			}
			rep, err := playground.RunDemo(cmd.Context(), w, playground.DemoOpts{
				Contained:  contained,
				ScenarioID: scenario,
				RunNonce:   runNonce,
				RunDir:     runDir,
				Color:      color,
			})
			if err != nil {
				return err
			}
			if !rep.OK {
				return fmt.Errorf("demo run verification failed")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&contained, "contained", false, "run in kernel-containment mode (requires Task 7 hook)")
	cmd.Flags().StringVar(&runDir, "run-dir", "", "directory for run artifacts (required)")
	cmd.Flags().StringVar(&scenario, "scenario", playground.LiveDemoScenarioID, "scenario ID to run")
	cmd.Flags().BoolVar(&color, "color", false, "enable ANSI color output")
	cmd.Flags().StringVar(&runNonce, "run-nonce", "", "unique run identifier (default: generated)")
	_ = cmd.MarkFlagRequired("run-dir")
	return cmd
}

func newResetCmd() *cobra.Command {
	var runDir string
	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Clear state from a previous demo run",
		Long: `Removes all artifacts from a previous demo run directory, making it safe
to reuse for a new run. Idempotent: calling reset on an empty or nonexistent
directory succeeds.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := playground.Reset(runDir); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Reset complete: %s\n", runDir)
			return nil
		},
	}
	cmd.Flags().StringVar(&runDir, "run-dir", "", "directory to reset (required)")
	_ = cmd.MarkFlagRequired("run-dir")
	return cmd
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
	var orchKey string
	cmd := &cobra.Command{
		Use:   "fallback <rundir>",
		Short: "Replay a pre-recorded demo run with REPLAY watermark",
		Long: `Replays a pre-recorded run directory with a visible REPLAY watermark,
the packet hash, and the verifier command. Re-runs offline verification to
confirm the recorded evidence is still valid.

Exit 0 = recorded run verifies. Non-zero = verification failed.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			w := cmd.OutOrStdout()
			rep, err := playground.Fallback(w, args[0], orchKey)
			if err != nil {
				return err
			}
			if !rep.OK {
				return fmt.Errorf("fallback: recorded run verification failed")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&orchKey, "orchestrator-key", "", "hex-encoded orchestrator Ed25519 public key (trust root)")
	_ = cmd.MarkFlagRequired("orchestrator-key")
	return cmd
}
