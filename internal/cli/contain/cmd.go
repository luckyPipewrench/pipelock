// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"github.com/spf13/cobra"
)

// Cmd returns the `pipelock contain` cobra command tree.
func Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "contain",
		Short: "Host containment for AI coding agents",
		Long: `Install, verify, and roll back a kernel-enforced containment model
for AI coding agents on Linux hosts.

The model splits a single host into three system users
(operator / pipelock-proxy / pipelock-agent) and uses nftables owner-match
rules to force every agent process through the Pipelock proxy.

Subcommands:
  install     Create users, systemd unit, nft rules, wrappers, sudoers.
  verify      Run read-only probes; report pass/fail/skip.
  doctor      Live self-test of the runtime contract; report remediation.
  rollback    Undo install (idempotent).
  add-tool    Drop a new /usr/local/bin/plk-<name> wrapper.
  grant-workspace
              Grant pipelock-agent ACL access to a project directory.
  revoke-workspace
              Revoke pipelock-agent ACL access from a project directory.
  ca-refresh  Rebuild the combined CA bundle after a CA rotation.

All mutating subcommands accept --dry-run to print the planned actions
without touching state.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.AddCommand(
		verifyCmd(),
		doctorCmd(),
		installCmd(),
		rollbackCmd(),
		addToolCmd(),
		grantWorkspaceCmd(),
		revokeWorkspaceCmd(),
		caRefreshCmd(),
	)

	return cmd
}
