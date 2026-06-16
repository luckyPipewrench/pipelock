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
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

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
	root.AddCommand(newBundleCmd())
	root.AddCommand(newKeygenOrchestratorCmd())

	return root
}

// resolveOrchestratorKeyPath decides which orchestrator signing key a run uses.
// An explicitly-set --orchestrator-key-file is honored verbatim (the load fails
// closed if unreadable). When the flag is unset, the installed stable key is
// used automatically if present, otherwise an ephemeral per-run key (empty path).
func resolveOrchestratorKeyPath(flagVal string, changed bool) string {
	if changed {
		return flagVal
	}
	def := playground.DefaultOrchestratorKeyPath()
	if def == "" {
		return ""
	}
	if _, err := os.Stat(def); err == nil {
		return def
	}
	return ""
}

func newKeygenOrchestratorCmd() *cobra.Command {
	var (
		out   string
		force bool
	)
	cmd := &cobra.Command{
		Use:   "keygen-orchestrator",
		Short: "Generate the stable orchestrator signing key for the playground demo",
		Long: `Generates the stable "Pipelock Playground" demo orchestrator keypair and
writes the hex-encoded private key to --out (default: the standard config path).
Prints the public key hex to publish as PublishedOrchestratorPubKeyHex.

The demo key has no security stakes (it proves the mechanism, not an identity),
but it is generated once and never rotated so "verify with our published key"
stays stable. This command refuses to overwrite an existing key unless --force.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if out == "" {
				out = playground.DefaultOrchestratorKeyPath()
			}
			if out == "" {
				return fmt.Errorf("could not determine a key path; pass --out")
			}
			pubHex, err := playground.GenerateOrchestratorKey(out, force)
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(w, "wrote orchestrator private key: %s\n", out)
			_, _ = fmt.Fprintf(w, "public key (publish as PublishedOrchestratorPubKeyHex):\n  %s\n", pubHex)
			return nil
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "output path for the private key (default: standard config path)")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing key (rotates the stable demo key)")
	return cmd
}

func newBundleCmd() *cobra.Command {
	var (
		orchKey string
		outPath string
	)
	cmd := &cobra.Command{
		Use:   "bundle <rundir>",
		Short: "Generate the viewer bundle.json from a verified demo run",
		Long: `Generates the offline-verifiable viewer bundle from a completed run
directory. The scripted narrative is hydrated with the run's REAL signed proof:
the receipt chain, the collector witness, the host-containment witness (contained
runs), and the offline verification result. The run must verify under the
published orchestrator key (or an explicit --orchestrator-key), so the bundle can
never overstate what was proven.

Output goes to --out (default: stdout).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			b, err := playground.GenerateBundle(args[0], orchKey)
			if err != nil {
				return err
			}
			// SetEscapeHTML(false): the chat HTML carries literal <code> tags;
			// the default encoder would emit <code>, which is valid but
			// unreadable and diverges from the viewer's hand-authored bundle.
			var buf bytes.Buffer
			enc := json.NewEncoder(&buf)
			enc.SetEscapeHTML(false)
			enc.SetIndent("", "  ")
			if err := enc.Encode(b); err != nil {
				return fmt.Errorf("marshal bundle: %w", err)
			}
			data := bytes.TrimRight(buf.Bytes(), "\n")
			if outPath == "" {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(data))
				return nil
			}
			if err := os.WriteFile(filepath.Clean(outPath), data, 0o600); err != nil {
				return fmt.Errorf("write bundle: %w", err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", outPath)
			return nil
		},
	}
	cmd.Flags().StringVar(&orchKey, "orchestrator-key", playground.PublishedOrchestratorPubKeyHex, "hex-encoded orchestrator Ed25519 public key (trust root)")
	cmd.Flags().StringVar(&outPath, "out", "", "output file (default: stdout)")
	return cmd
}

func newRunCmd() *cobra.Command {
	var (
		contained   bool
		runDir      string
		scenario    string
		color       bool
		runNonce    string
		orchKeyFile string
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
				Contained:           contained,
				ScenarioID:          scenario,
				RunNonce:            runNonce,
				RunDir:              runDir,
				Color:               color,
				OrchestratorKeyPath: resolveOrchestratorKeyPath(orchKeyFile, cmd.Flags().Changed("orchestrator-key-file")),
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
	cmd.Flags().StringVar(&orchKeyFile, "orchestrator-key-file", "", "path to the stable orchestrator signing key (default: the installed published demo key, else an ephemeral per-run key)")
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
	cmd.Flags().StringVar(&orchKey, "orchestrator-key", playground.PublishedOrchestratorPubKeyHex, "hex-encoded orchestrator Ed25519 public key (trust root)")
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
	cmd.Flags().StringVar(&orchKey, "orchestrator-key", playground.PublishedOrchestratorPubKeyHex, "hex-encoded orchestrator Ed25519 public key (trust root)")
	return cmd
}
