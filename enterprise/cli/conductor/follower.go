//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/emergency"
	"github.com/luckyPipewrench/pipelock/internal/license"
)

// followerCmd groups local, follower-side Conductor recovery commands. These run
// on the follower host (against its on-disk conductor state), not over the mTLS
// control-plane API.
func followerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "follower",
		Short: "Local follower-side Conductor recovery commands",
	}
	cmd.AddCommand(followerResetReplayStateCmd())
	return cmd
}

type followerResetReplayOptions struct {
	stateDir       string
	confirm        bool
	licenseCRLFile string
}

func followerResetReplayStateCmd() *cobra.Command {
	opts := followerResetReplayOptions{}
	cmd := &cobra.Command{
		Use:   "reset-replay-state",
		Short: "Reset a follower's local remote-kill replay state to a clean baseline (offline recovery)",
		Long: `reset-replay-state rewrites the follower's local remote-kill replay state
under --state-dir to a clean, no-decision baseline so a wedged follower can start.

A follower that enrolled but has no valid replay state fails closed at startup
with "conductor remote kill replay state missing while follower context is
present". This is the explicit reset that error refers to. It writes a baseline
with counter 0 and no kill decision; the follower then boots and re-fetches the
authoritative kill state from the Conductor on its next poll, so a genuinely
active fleet kill is restored (its counter exceeds 0).

Safety posture (mirrors 'conductor store repair'):
  - Without --confirm the command is a DRY RUN: it reports what it would write
    and changes nothing.
  - With --confirm it overwrites the local replay state. This deliberately resets
    local replay protection to 0; only run it as an operator recovering a wedged
    follower, never on a healthy one.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateFollowerResetReplayStateOptions(opts); err != nil {
				return err
			}
			if _, err := license.VerifyFleetWithOptions(license.FleetVerifyInputs{CRLFile: opts.licenseCRLFile}); err != nil {
				return err
			}
			return runFollowerResetReplayState(cmd, opts)
		},
	}
	cmd.Flags().StringVar(&opts.stateDir, "state-dir", "", "follower conductor bundle cache dir (conductor.bundle_cache_dir); the replay state lives here (required)")
	cmd.Flags().BoolVar(&opts.confirm, "confirm", false, "actually overwrite the replay state; without this the command is a dry run")
	cmd.Flags().StringVar(&opts.licenseCRLFile, "license-crl-file", "", "signed license revocation list file; falls back to PIPELOCK_LICENSE_CRL_FILE")
	return cmd
}

func runFollowerResetReplayState(cmd *cobra.Command, opts followerResetReplayOptions) error {
	if err := validateFollowerResetReplayStateOptions(opts); err != nil {
		return err
	}
	statePath := filepath.Join(opts.stateDir, emergency.RemoteKillStateFileName)
	out := cmd.OutOrStdout()
	if !opts.confirm {
		_, _ = fmt.Fprintf(out, "DRY RUN: would reset remote-kill replay state at %s to a clean baseline (counter 0, no decision).\n", statePath)
		_, _ = fmt.Fprintln(out, "Re-run with --confirm to apply. The follower will re-sync the authoritative kill state from the Conductor on its next poll.")
		return nil
	}
	if err := emergency.ResetReplayStateToBaseline(statePath, time.Now().UTC()); err != nil {
		return fmt.Errorf("reset remote-kill replay state: %w", err)
	}
	_, _ = fmt.Fprintf(out, "reset remote-kill replay state at %s to a clean baseline; restart the follower if it is wedged.\n", statePath)
	return nil
}

func validateFollowerResetReplayStateOptions(opts followerResetReplayOptions) error {
	if opts.stateDir == "" {
		return fmt.Errorf("--state-dir is required")
	}
	return nil
}
