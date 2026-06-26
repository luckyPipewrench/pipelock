// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/playground"
)

func newVerifyRunCmd() *cobra.Command {
	var (
		orchKey  string
		jsonMode bool
	)

	cmd := &cobra.Command{
		Use:   "verify-run RUNDIR",
		Short: "Verify a playground demo run directory (full offline trust chain)",
		Long: `Performs all-or-nothing offline verification of a playground demo run
directory. The trust root is the single --orchestrator-key (defaults to the
published Pipelock Playground key); all other keys (pipelock, collector) are
taken from the verified manifest, NOT trusted blindly.

The full chain checks:
  1. Launch manifest signature under the orchestrator key.
  2. Audit Packet (receipt chain + totals) under the manifest's pipelock key.
  3. Collector witness signature under the manifest's collector key.
  4. Witness binds the run (nonce + manifest hash).
  5. Red-case calibration is present and genuine.
  6. Live demo semantic receipts are present.
  7. Host-containment witness (contained runs only).

Exit code 0 = every check passed. Non-zero = at least one check failed.`,
		Args: exactOneArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			rep, err := playground.VerifyRun(args[0], orchKey)
			if err != nil {
				return err
			}

			w := cmd.OutOrStdout()

			if jsonMode {
				enc := json.NewEncoder(w)
				enc.SetIndent("", "  ")
				if err := enc.Encode(rep); err != nil {
					return fmt.Errorf("encode verify-run JSON report: %w", err)
				}
				if !rep.OK {
					return cliutil.ExitCodeError(1, fmt.Errorf("VERIFY FAILED: one or more checks did not pass"))
				}
				return nil
			}

			for _, c := range rep.Checks {
				label := "PASS"
				if !c.OK {
					label = "FAIL"
				}
				_, _ = fmt.Fprintf(w, "[%s] %s", label, c.Name)
				if c.Reason != "" {
					_, _ = fmt.Fprintf(w, " -- %s", c.Reason)
				}
				_, _ = fmt.Fprintln(w)
			}
			_, _ = fmt.Fprintln(w)
			if rep.OK {
				_, _ = fmt.Fprintf(w, "result: VALID  run_nonce=%s observed=%d\n", rep.RunNonce, rep.ObservedCount)
				return nil
			}
			return cliutil.ExitCodeError(1, fmt.Errorf("VERIFY FAILED: one or more checks did not pass"))
		},
	}
	cmd.Flags().StringVar(&orchKey, "orchestrator-key", playground.PublishedOrchestratorPubKeyHex, "hex-encoded orchestrator Ed25519 public key (trust root)")
	cmd.Flags().BoolVar(&jsonMode, "json", false, "emit machine-readable JSON output")
	return cmd
}
