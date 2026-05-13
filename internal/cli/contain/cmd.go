// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

// stubMessage is the body of the "not yet implemented" error returned by
// every subcommand except verify.
const stubMessage = "not yet implemented in v0.1"

// Cmd returns the `pipelock contain` cobra command tree.
func Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "contain",
		Short: "Workstation containment for AI agents",
		Long: `Install, verify, and roll back a kernel-enforced containment model
for AI agents on Fedora workstations.

The model splits a single workstation into three system users
(operator / pipelock-proxy / cc-agent) and uses nftables owner-match
rules to force every agent process through the Pipelock proxy.

In v0.1 only ` + "`verify`" + ` is implemented; the mutating subcommands
(install, rollback, add-tool, ca-refresh) are registered but return a
"not yet implemented" error.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.AddCommand(
		verifyCmd(),
		installCmd(),
		rollbackCmd(),
		addToolCmd(),
		caRefreshCmd(),
	)

	return cmd
}

// installCmd is the v0.1 stub for `pipelock contain install`.
func installCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install the containment model (creates users, unit, nft rules, wrappers)",
		Long: `Will create the pipelock-proxy and cc-agent system users, migrate the
user-mode systemd unit to a system unit, install nftables rules, write
wrapper scripts, install the sudoers entry, and bootstrap the
combined-ca.pem.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cliutil.ExitCodeError(cliutil.ExitConfig, errors.New(stubMessage))
		},
	}
	return cmd
}

// rollbackCmd is the v0.1 stub for `pipelock contain rollback`.
func rollbackCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rollback",
		Short: "Roll back the containment model (undoes install idempotently)",
		Long: `Will reverse install: remove the nft table, disable the system unit,
restore the user unit, remove wrappers, optionally remove users.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cliutil.ExitCodeError(cliutil.ExitConfig, errors.New(stubMessage))
		},
	}
	return cmd
}

// addToolNamePattern bounds tool names to a small alphabet so that the
// generated wrapper path is safe to construct without shell quoting.
var addToolNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,30}$`)

// addToolCmd is the v0.1 stub for `pipelock contain add-tool`.
func addToolCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add-tool <name>",
		Short: "Drop a new /usr/local/bin/cc-<name> wrapper",
		Long: `Will install a wrapper at /usr/local/bin/cc-<name> that execs
cc-launch <name>.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if !addToolNamePattern.MatchString(args[0]) {
				return cliutil.ExitCodeError(
					cliutil.ExitConfig,
					fmt.Errorf("invalid tool name %q (expected [a-z0-9][a-z0-9_-]{0,30})", args[0]),
				)
			}
			return cliutil.ExitCodeError(cliutil.ExitConfig, errors.New(stubMessage))
		},
	}
	return cmd
}

// caRefreshCmd is the v0.1 stub for `pipelock contain ca-refresh`.
func caRefreshCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ca-refresh",
		Short: "Rebuild /etc/pipelock/combined-ca.pem after CA rotation",
		Long: `Will re-export the Pipelock TLS-MITM CA and rebuild
/etc/pipelock/combined-ca.pem.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cliutil.ExitCodeError(cliutil.ExitConfig, errors.New(stubMessage))
		},
	}
	return cmd
}
