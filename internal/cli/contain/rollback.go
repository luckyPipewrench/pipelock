// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

// rollbackOpts is the flag bag for rollback.
type rollbackOpts struct {
	dryRun     bool
	keepData   bool
	keepUsers  bool
	purgeUsers bool // explicit --purge-users override; takes precedence over keepUsers
}

func rollbackCmd() *cobra.Command {
	var opts rollbackOpts

	cmd := &cobra.Command{
		Use:   "rollback",
		Short: "Roll back the containment model (undoes install idempotently)",
		Long: `Reverse the changes made by ` + "`pipelock contain install`" + `.

Always tries every cleanup action — a partial uninstall left from a prior
crashed run is still safe to call rollback on. Per-action failures are
accumulated and reported, but the chain does not stop.

By default, /etc/pipelock and /var/lib/pipelock are preserved (--keep-data
defaults true). Users are removed by default; pass --keep-users to keep
pipelock-proxy and pipelock-agent in place (useful when re-installing soon).

Must be run as root.

Exit codes:
  0  All actions completed (or already in target state).
  1  One or more actions failed.
  2  Precondition error (not root, missing executable).`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !opts.dryRun && os.Geteuid() != 0 {
				return cliutil.ExitCodeError(cliutil.ExitConfig, errors.New("rollback must be run as root (use sudo)"))
			}
			env := defaultInstallEnv(cmd.OutOrStdout())
			return runRollback(cmd.Context(), env, opts)
		},
	}

	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "print the planned rollback actions without mutating state")
	cmd.Flags().BoolVar(&opts.keepData, "keep-data", true, "preserve /etc/pipelock and /var/lib/pipelock (default true)")
	cmd.Flags().BoolVar(&opts.keepUsers, "keep-users", false, "preserve the pipelock-proxy and pipelock-agent users")
	cmd.Flags().BoolVar(&opts.purgeUsers, "purge-users", false, "force user deletion even if --keep-users is set (sticky safety net)")

	return cmd
}

// runRollback walks every cleanup action in install-reverse order. Each
// action is implemented as a step where apply is the cleanup itself. We
// invoke them directly rather than going through runSteps because we want
// to continue past per-action failures.
func runRollback(ctx context.Context, env *installEnv, opts rollbackOpts) error {
	if ctx == nil {
		ctx = context.Background()
	}
	// The cobra RunE wrapper does the os.Geteuid root check; tests drive
	// this function directly with fakes.

	actions := rollbackActions(opts)

	if opts.dryRun {
		printPlan(env.out, "pipelock contain rollback — planned actions:", actions)
		return nil
	}

	_, _ = fmt.Fprintln(env.out, "pipelock contain rollback")
	if err := runUndo(ctx, env, env.out, actions); err != nil {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, err)
	}
	_, _ = fmt.Fprintln(env.out, "rollback complete.")
	return nil
}

// rollbackActions enumerates the cleanup steps in the order install
// applied them, so that runUndo (which walks reverse) executes them in
// proper reverse order:
//
//   - sudoers off first (so any stray plk-* wrapper invocation stops being
//     no-password authorized immediately)
//   - then wrappers (so even if sudoers is restored, the wrappers are gone)
//   - then nft rules (so future `plk-launch` attempts stop being firewalled
//     before we go and remove the firewall)
//   - then service (so we don't leave a running pipelock pointed at a
//     half-removed config dir)
//   - then artifacts (binary, CA, integrity pin)
//   - finally users + dirs (controlled by --keep-* flags)
//
// The runUndo helper walks the slice in reverse, so the steps are LISTED in
// install order for readability but EXECUTED in reverse.
func rollbackActions(opts rollbackOpts) []step {
	return []step{
		// Install ordering, executed in reverse by runUndo.
		actionPreserve("preflight (no-op for rollback)"),
		actionMaybeDeleteUser(opts, true),  // proxy
		actionMaybeDeleteUser(opts, false), // agent
		actionMaybeRemoveDir(opts, "config", func(e *installEnv) string { return e.configDir }),
		actionMaybeRemoveDir(opts, "data", func(e *installEnv) string { return e.dataDir }),
		// Revoke MUST execute (in reverse walk: first) before the agent
		// user is deleted AND before the config dir removal wipes the
		// inventory file. List position controls reverse-walk priority,
		// so revoke sits at a higher index than both blockers.
		actionRevokeWorkspaceACLs(opts),
		actionPreserve("pipelock.yaml (kept with --keep-data)"),
		actionPreserve("config chown (resolved by dir removal)"),
		actionPreserve("data chown (resolved by dir removal)"),
		actionRemovePath("pipelock binary", func(e *installEnv) string { return e.pipelockTarget }),
		actionRemovePath("integrity pin", func(e *installEnv) string { return e.integrityPin }),
		actionPreserve("user-mode pipelock (operator decides whether to re-enable)"),
		actionRemoveSystemUnit(),
		actionDisablePipelockService(),
		actionRemovePath("pipelock CA export", func(e *installEnv) string { return e.caExportPath }),
		actionRemovePath("combined CA bundle", func(e *installEnv) string { return e.caBundlePath }),
		actionRemoveNFTRules(),
		actionRemovePath("plk-launch tools.list", func(e *installEnv) string { return e.toolsListPath }),
		actionRemovePath("node undici shim", undiciShimPathOrDefault),
		actionRemoveWrapper("plk-launch", "plk-launch"),
		actionRemoveWrapper("plk meta-wrapper", "plk"),
		actionRemoveToolWrappers(),
		actionRemoveUtilityWrappers(),
		actionRemovePath("login-shell runtime contract", profileScriptPathOrDefault),
		actionRemoveAgentToolConfigs(),
		actionRemovePath("wrapper inventory", func(e *installEnv) string { return e.wrapperInvPath }),
		actionRemoveSudoers(),
	}
}

// actionRevokeWorkspaceACLs removes workspace ACLs before rollback deletes
// pipelock-agent. That prevents orphan numeric ACL entries if the UID is later
// reused by an unrelated account. The on-disk inventory is preserved when
// --keep-data is set so a subsequent install + grant-workspace round trip
// can rebuild ACLs from the saved mapping; otherwise it is removed alongside
// other rollback artifacts.
func actionRevokeWorkspaceACLs(opts rollbackOpts) step {
	return step{
		name: "revoke-workspace-acls",
		desc: "revoke workspace ACLs tracked in /etc/pipelock/contain/workspaces.json",
		undo: func(ctx context.Context, env *installEnv) error {
			inv, err := loadWorkspaceInventory(env)
			if err != nil {
				return err
			}
			if len(inv.Workspaces) == 0 {
				return nil
			}
			commands, err := workspaceRevokeAllCommands(env, inv.Workspaces, env.agentUserName)
			if err != nil {
				return err
			}
			if err := runWorkspaceCommands(ctx, env, commands); err != nil {
				return err
			}
			if opts.keepData {
				return nil
			}
			if err := env.removeFile(env.workspaceInvPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove %s: %w", env.workspaceInvPath, err)
			}
			_ = env.removeFile(env.workspaceInvPath + ".bak")
			return nil
		},
	}
}

// actionPreserve is a no-op slot used to keep the rollback list aligned
// with the install list 1:1. Each slot is logged in --dry-run so the
// operator can see the action being intentionally skipped.
func actionPreserve(desc string) step {
	return step{
		name: "preserve",
		desc: desc,
		undo: func(context.Context, *installEnv) error { return nil },
	}
}

// actionRemovePath removes a file managed by the install. Missing files
// are not an error.
func actionRemovePath(desc string, pathFn func(*installEnv) string) step {
	return step{
		name: "remove-" + desc,
		desc: "remove " + desc,
		undo: func(_ context.Context, env *installEnv) error {
			path := pathFn(env)
			if err := env.removeFile(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove %s: %w", path, err)
			}
			// Also drop the .bak if present.
			_ = env.removeFile(path + ".bak")
			return nil
		},
	}
}

// actionMaybeDeleteUser deletes pipelock-proxy or pipelock-agent unless
// --keep-users is set. --purge-users overrides --keep-users.
func actionMaybeDeleteUser(opts rollbackOpts, proxyUser bool) step {
	label := "agent"
	if proxyUser {
		label = "proxy"
	}
	return step{
		name: "delete-" + label + "-user",
		desc: "delete " + label + " user (skipped when --keep-users is set)",
		undo: func(ctx context.Context, env *installEnv) error {
			if opts.keepUsers && !opts.purgeUsers {
				return nil
			}
			name := env.agentUserName
			if proxyUser {
				name = env.proxyUserName
			}
			if _, err := env.lookupUser(name); err != nil {
				if errors.As(err, new(user.UnknownUserError)) {
					return nil
				}
				return fmt.Errorf("user lookup %s: %w", name, err)
			}
			return runOrErr(ctx, env, "userdel", "-r", name)
		},
	}
}

// actionMaybeRemoveDir removes /etc/pipelock or /var/lib/pipelock when the
// operator explicitly passes --keep-data=false. Default keeps them in
// place: the most common rollback case is re-installing soon, and losing
// /etc/pipelock means redoing TLS init and config.
func actionMaybeRemoveDir(opts rollbackOpts, label string, pathFn func(*installEnv) string) step {
	return step{
		name: "remove-dir-" + label,
		desc: "remove " + label + " directory (skipped unless --keep-data=false)",
		undo: func(_ context.Context, env *installEnv) error {
			if opts.keepData {
				return nil
			}
			path := pathFn(env)
			if err := os.RemoveAll(filepath.Clean(path)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("rm -rf %s: %w", path, err)
			}
			return nil
		},
	}
}

// actionRemoveSystemUnit removes the pipelock.service unit and reloads
// systemd so it stops being known.
func actionRemoveSystemUnit() step {
	return step{
		name: "remove-system-unit",
		desc: "remove /etc/systemd/system/pipelock.service",
		undo: func(ctx context.Context, env *installEnv) error {
			if err := env.removeFile(env.systemUnitPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove %s: %w", env.systemUnitPath, err)
			}
			_ = env.removeFile(env.systemUnitPath + ".bak")
			_, _, _ = env.runCmd(ctx, "systemctl", "daemon-reload")
			return nil
		},
	}
}

// actionDisablePipelockService disables + stops the system service if
// present. Missing service is fine.
func actionDisablePipelockService() step {
	return step{
		name: "disable-pipelock-service",
		desc: "systemctl disable --now pipelock.service",
		undo: func(ctx context.Context, env *installEnv) error {
			out, code, _ := env.runCmd(ctx, "systemctl", "list-unit-files", "pipelock.service", "--no-legend")
			if code != 0 || out == "" {
				return nil
			}
			_, _, _ = env.runCmd(ctx, "systemctl", "disable", "--now", "pipelock")
			return nil
		},
	}
}

// actionRemoveNFTRules deletes the table, removes the rules file, and
// restores/removes the managed persistence include. We do NOT disable
// nftables.service: the operator may have had it enabled before our install.
func actionRemoveNFTRules() step {
	return step{
		name: "remove-nft-rules",
		desc: "drop pipelock_containment table and remove nftables persistence include",
		undo: func(ctx context.Context, env *installEnv) error {
			_, _, _ = env.runCmd(ctx, "nft", "delete", "table", "inet", defaultNFTTable)
			if err := env.removeFile(env.nftRulesPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove %s: %w", env.nftRulesPath, err)
			}
			_ = env.removeFile(env.nftRulesPath + ".bak")
			return restoreOrRemoveNFTMainInclude(env)
		},
	}
}

// actionRemoveWrapper removes one named wrapper from the wrapper dir.
func actionRemoveWrapper(label, name string) step {
	return step{
		name: "remove-" + label,
		desc: "remove /usr/local/bin/" + name,
		undo: func(_ context.Context, env *installEnv) error {
			path := filepath.Join(env.wrapperDir, name)
			if err := env.removeFile(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove %s: %w", path, err)
			}
			_ = env.removeFile(path + ".bak")
			return nil
		},
	}
}

// actionRemoveToolWrappers removes every wrapper listed in the inventory.
// Falls back to the static defaultToolWrappers list when the inventory is
// missing - that's the case when rollback runs against a half-installed
// system where the inventory was never written.
func actionRemoveToolWrappers() step {
	return step{
		name: "remove-tool-wrappers",
		desc: "remove plk-* tool wrappers listed in /etc/pipelock/contain/wrappers.json",
		undo: func(_ context.Context, env *installEnv) error {
			wrappers := readWrapperInventory(env)
			for _, w := range wrappers {
				path := filepath.Join(env.wrapperDir, w)
				if err := env.removeFile(path); err != nil && !errors.Is(err, os.ErrNotExist) {
					return fmt.Errorf("remove %s: %w", path, err)
				}
				_ = env.removeFile(path + ".bak")
			}
			return nil
		},
	}
}

// actionRemoveUtilityWrappers removes the pipelock-curl/python/node known-good
// wrappers placed on the agent PATH by stepWriteUtilityWrappers.
func actionRemoveUtilityWrappers() step {
	return step{
		name: "remove-utility-wrappers",
		desc: "remove pipelock-curl/python/node wrappers",
		undo: func(_ context.Context, env *installEnv) error {
			for _, w := range pipelockUtilityWrappers {
				path := filepath.Join(env.wrapperDir, w)
				if err := env.removeFile(path); err != nil && !errors.Is(err, os.ErrNotExist) {
					return fmt.Errorf("remove %s: %w", path, err)
				}
				_ = env.removeFile(path + ".bak")
			}
			return nil
		},
	}
}

// actionRemoveAgentToolConfigs removes the per-tool config files written into
// the agent home. A full rollback that deletes the agent user already removes
// the home (userdel -r); this handles the --keep-users case where the home
// survives. If install replaced a pre-existing config, restoreBackup preserves
// that operator state instead of deleting the .bak.
func actionRemoveAgentToolConfigs() step {
	return step{
		name: "remove-agent-tool-configs",
		desc: "remove git/npm/pip/cargo proxy config from the agent home",
		undo: func(_ context.Context, env *installEnv) error {
			home := agentHomeDir(env)
			var errs []error
			for _, cfg := range agentToolConfigs() {
				path := filepath.Join(home, cfg.rel)
				if err := restoreBackup(env, path); err != nil {
					errs = append(errs, err)
				}
			}
			return errors.Join(errs...)
		},
	}
}

// readWrapperInventory loads the wrapper list from /etc/pipelock/contain/
// wrappers.json. On any error (missing, malformed, unreadable) it returns
// the static defaultToolWrappers set so rollback never silently leaves
// installed wrappers behind.
func readWrapperInventory(env *installEnv) []string {
	data, err := env.readFile(env.wrapperInvPath)
	if err != nil {
		if wrappers := wrappersFromToolsList(env); len(wrappers) > 0 {
			return wrappers
		}
		return append([]string(nil), defaultToolWrappers...)
	}
	var inv wrapperInventory
	if err := json.Unmarshal(data, &inv); err != nil || len(inv.Wrappers) == 0 {
		if wrappers := wrappersFromToolsList(env); len(wrappers) > 0 {
			return wrappers
		}
		return append([]string(nil), defaultToolWrappers...)
	}
	return inv.Wrappers
}

func wrappersFromToolsList(env *installEnv) []string {
	entries, err := readToolsList(env)
	if err != nil {
		return nil
	}
	return wrapperNamesForEntries(entries)
}

// actionRemoveSudoers removes /etc/sudoers.d/50-pipelock-agent.
func actionRemoveSudoers() step {
	return step{
		name: "remove-sudoers",
		desc: "remove /etc/sudoers.d/50-pipelock-agent",
		undo: func(_ context.Context, env *installEnv) error {
			if err := env.removeFile(env.sudoersPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove %s: %w", env.sudoersPath, err)
			}
			_ = env.removeFile(env.sudoersPath + ".bak")
			return nil
		},
	}
}
