// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package selfupdate

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

// Cmd returns the top-level "update" command (alias "upgrade").
func Cmd() *cobra.Command {
	var (
		checkOnly bool
		version   string
		assumeYes bool
		doRollOut bool
		asJSON    bool
		insecure  bool
	)

	cmd := &cobra.Command{
		Use:     "update",
		Aliases: []string{"upgrade"},
		Short:   "Update Pipelock to the latest verified release",
		Long: `Check for, download, verify, and install a newer Pipelock release,
replacing the running binary in place.

The update is FAIL-CLOSED: it aborts and leaves the installed binary untouched
on any verification failure. Every release archive is verified against the
published SHA256 checksums; when a cosign binary is on PATH the checksums file
is also verified against its keyless publisher signature (GitHub Actions OIDC).
If cosign is absent, the updater fails closed by default. Use
--insecure-skip-signature only for an explicit checksum-only recovery flow.

The previous binary is saved to <binary>.bak so "pipelock update --rollback"
can restore it. When downgrading to a release that predates the update command
(before v2.8.0), the updater warns that --rollback will not be available from
the downgraded binary and prints the manual recovery command.

Examples:
  pipelock update --check              # report current vs latest, change nothing
  pipelock update                      # interactive update to the latest release
  pipelock update --yes                # update without the confirmation prompt
  pipelock update --version v2.7.0     # install a specific release tag
  pipelock update --rollback           # restore the previous binary
  pipelock update --insecure-skip-signature`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if checkOnly && doRollOut {
				return fmt.Errorf("use only one of --check / --rollback")
			}
			opts := &Options{
				CurrentVersion:         cliutil.Version,
				TargetVersion:          strings.TrimSpace(version),
				CheckOnly:              checkOnly,
				AssumeYes:              assumeYes,
				JSON:                   asJSON,
				AllowUnsignedChecksums: insecure,
				Stdout:                 cmd.OutOrStdout(),
				Stderr:                 cmd.ErrOrStderr(),
			}
			return runCommand(cmd.Context(), cmd, opts, doRollOut)
		},
	}

	cmd.Flags().BoolVar(&checkOnly, "check", false, "report current vs latest and whether an update is available; make no changes")
	cmd.Flags().StringVar(&version, "version", "", "install a specific release tag (e.g. v2.7.0) instead of the latest")
	cmd.Flags().BoolVarP(&assumeYes, "yes", "y", false, "skip the interactive confirmation prompt")
	cmd.Flags().BoolVar(&doRollOut, "rollback", false, "restore the previous binary from the backup saved by a prior update")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit machine-readable JSON status")
	cmd.Flags().BoolVar(&insecure, "insecure-skip-signature", false, "allow checksum-only update if cosign is unavailable (publisher identity is not verified)")

	return cmd
}

// runCommand wires flags to the Options API and handles output/prompting.
func runCommand(ctx context.Context, cmd *cobra.Command, opts *Options, doRollback bool) error {
	switch {
	case doRollback:
		st, err := opts.Rollback(ctx)
		if err != nil {
			return emitErr(cmd, opts, st, err)
		}
		return emit(cmd, opts, st, fmt.Sprintf("Rolled back to previous binary from %s.", st.BackupPath))

	case opts.CheckOnly:
		st, err := opts.Check(ctx)
		if err != nil {
			return emitErr(cmd, opts, st, err)
		}
		msg := fmt.Sprintf("Current: %s\nLatest:  %s", display(st.CurrentVersion), st.LatestVersion)
		if st.UpdateAvailable {
			msg += "\nAn update is available. Run `pipelock update` to install it."
		} else {
			msg += "\nYou are running the latest release."
		}
		return emit(cmd, opts, st, msg)

	default:
		// Confirm before a destructive update unless --yes or --json.
		if !opts.AssumeYes && !opts.JSON {
			pre, err := opts.Check(ctx)
			if err != nil {
				return emitErr(cmd, opts, pre, err)
			}
			if !pre.UpdateAvailable && opts.TargetVersion == "" {
				return emit(cmd, opts, pre, "You are running the latest release. Nothing to do.")
			}
			if !confirm(cmd, fmt.Sprintf("Update Pipelock from %s to %s? [y/N]: ",
				display(pre.CurrentVersion), pre.LatestVersion)) {
				return emit(cmd, opts, pre, "Update cancelled.")
			}
		}
		st, err := opts.Run(ctx)
		if err != nil {
			if errors.Is(err, ErrUpToDate) {
				return emit(cmd, opts, st, "You are running the latest release. Nothing to do.")
			}
			return emitErr(cmd, opts, st, err)
		}
		msg := fmt.Sprintf("Updated to %s. Previous binary saved at %s.", st.LatestVersion, st.BackupPath)
		return emit(cmd, opts, st, msg)
	}
}

// display normalizes a possibly-empty/dev version for human output.
func display(v string) string {
	if v == "" {
		return "unknown"
	}
	return v
}

// confirm reads a y/N answer from stdin.
func confirm(cmd *cobra.Command, prompt string) bool {
	_, _ = fmt.Fprint(cmd.OutOrStdout(), prompt)
	r := bufio.NewReader(cmd.InOrStdin())
	line, _ := r.ReadString('\n')
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes"
}

// emit prints either JSON status or a human message, then returns nil.
func emit(cmd *cobra.Command, opts *Options, st *Status, human string) error {
	if opts.JSON {
		return printJSON(cmd, st)
	}
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), human)
	return nil
}

// emitErr prints status as JSON (with the error) if --json, else returns the
// error for cobra to render. The status is always whatever state we reached.
func emitErr(cmd *cobra.Command, opts *Options, st *Status, err error) error {
	if opts.JSON && st != nil {
		// Emit best-effort status alongside a non-zero exit via the returned error.
		_ = printJSONWithError(cmd, st, err)
	}
	return err
}

func printJSON(cmd *cobra.Command, st *Status) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(st)
}

func printJSONWithError(cmd *cobra.Command, st *Status, err error) error {
	type withErr struct {
		*Status
		Error string `json:"error"`
	}
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(withErr{Status: st, Error: err.Error()})
}
