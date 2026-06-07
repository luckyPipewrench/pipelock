// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

const (
	workspaceModeReadOnly  = "read-only"
	workspaceModeReadWrite = "read-write"
)

type workspaceOpts struct {
	allowSystemPath bool
	dryRun          bool
	mode            string
	agentUser       string
}

type workspaceCommand struct {
	name string
	args []string
}

type workspaceInventory struct {
	Workspaces []workspaceGrant `json:"workspaces"`
}

type workspaceGrant struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
}

var deniedWorkspacePrefixes = []string{
	"/",
	"/bin",
	"/boot",
	"/dev",
	"/etc",
	"/lib",
	"/lib64",
	"/opt",
	"/proc",
	"/root",
	"/run",
	"/sbin",
	"/sys",
	"/usr",
	"/var",
}

// Note: workspace inventory read-modify-write is not protected against
// concurrent invocations. Operators should not run grant-workspace or
// revoke-workspace in parallel against the same host; the JSON file can
// be corrupted by interleaved writes. Pipelock contain is a host-local
// admin tool, so this is acceptable in the current threat model.

func grantWorkspaceCmd() *cobra.Command {
	var opts workspaceOpts

	cmd := &cobra.Command{
		Use:   "grant-workspace <path>",
		Short: "Grant pipelock-agent ACL access to a workspace",
		Long: `Grant the contained agent user access to one workspace directory.

This fixes the common EACCES case where plk-claude/plk-codex run correctly
under nftables containment, but cannot read or edit the operator's project
directory. The command grants execute-only traversal on parent directories and
read-only ACLs by default only inside the named workspace. Use --mode read-write
when the contained agent should edit files in place.

The workspace path should live under an operator-owned project tree. System
paths such as /etc, /usr, /var, /proc, /sys, /root, and / are rejected by
default because granting parent traversal there widens the contained agent's
filesystem reach. If the workspace path sits in a directory writable by someone
other than the operator, ACLs may apply to an unexpected inode.

Must be run as root.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !opts.dryRun && os.Geteuid() != 0 {
				return cliutil.ExitCodeError(cliutil.ExitConfig, errors.New("grant-workspace must be run as root (use sudo)"))
			}
			if opts.agentUser == "" {
				opts.agentUser = defaultAgentUser
			}
			if err := validateContainUsername("agent user", opts.agentUser); err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			env := defaultInstallEnv(cmd.OutOrStdout())
			env.agentUserName = opts.agentUser
			return runGrantWorkspace(cmd.Context(), env, args[0], opts)
		},
	}

	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "print planned ACL commands without mutating state")
	cmd.Flags().BoolVar(&opts.allowSystemPath, "allow-system-path", false, "allow granting ACLs under protected system path prefixes")
	cmd.Flags().StringVar(&opts.mode, "mode", workspaceModeReadOnly, "workspace ACL mode: read-only or read-write")
	cmd.Flags().StringVar(&opts.agentUser, "agent-user", defaultAgentUser, "contained agent user to grant access to")

	return cmd
}

func revokeWorkspaceCmd() *cobra.Command {
	var opts workspaceOpts

	cmd := &cobra.Command{
		Use:   "revoke-workspace <path>",
		Short: "Revoke pipelock-agent ACL access from a workspace",
		Long: `Revoke ACL access previously granted by pipelock contain grant-workspace.

This removes the contained agent user's access ACLs from the workspace and
removes execute-only traversal ACLs from parent directories that are no longer
needed by other tracked workspaces.

Must be run as root.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !opts.dryRun && os.Geteuid() != 0 {
				return cliutil.ExitCodeError(cliutil.ExitConfig, errors.New("revoke-workspace must be run as root (use sudo)"))
			}
			if opts.agentUser == "" {
				opts.agentUser = defaultAgentUser
			}
			if err := validateContainUsername("agent user", opts.agentUser); err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			env := defaultInstallEnv(cmd.OutOrStdout())
			env.agentUserName = opts.agentUser
			return runRevokeWorkspace(cmd.Context(), env, args[0], opts)
		},
	}

	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "print planned ACL commands without mutating state")
	cmd.Flags().StringVar(&opts.agentUser, "agent-user", defaultAgentUser, "contained agent user to revoke access from")

	return cmd
}

func runGrantWorkspace(ctx context.Context, env *installEnv, path string, opts workspaceOpts) error {
	if ctx == nil {
		ctx = context.Background()
	}
	mode := opts.mode
	if mode == "" {
		mode = workspaceModeReadOnly
	}
	if mode != workspaceModeReadWrite && mode != workspaceModeReadOnly {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("invalid --mode %q (want read-write or read-only)", mode))
	}
	workspace, err := resolveWorkspaceDir(env, path, opts.allowSystemPath)
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, err)
	}
	commands := workspaceACLCommands(workspace, env.agentUserName, mode)
	if opts.dryRun {
		_, _ = fmt.Fprintf(env.out, "pipelock contain grant-workspace %s - planned:\n", workspace)
		for i, c := range commands {
			_, _ = fmt.Fprintf(env.out, "  %d. %s %s\n", i+1, c.name, strings.Join(shellQuoteArgs(c.args), " "))
		}
		_, _ = fmt.Fprintf(env.out, "  %d. record grant in %s\n", len(commands)+1, env.workspaceInvPath)
		return nil
	}
	if err := runWorkspaceCommands(ctx, env, commands); err != nil {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, err)
	}
	if err := recordWorkspaceGrant(env, workspaceGrant{Path: workspace, Mode: mode}); err != nil {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("record workspace grant: %w", err))
	}
	_, _ = fmt.Fprintf(env.out, "granted %s access to %s for %s.\n", mode, workspace, env.agentUserName)
	return nil
}

func runRevokeWorkspace(ctx context.Context, env *installEnv, path string, opts workspaceOpts) error {
	if ctx == nil {
		ctx = context.Background()
	}
	inv, err := loadWorkspaceInventory(env)
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("read workspace inventory: %w", err))
	}
	workspace, workspaceExists, err := resolveWorkspaceForRevoke(env, path, inv)
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, err)
	}
	remaining := workspaceGrantsExcept(inv.Workspaces, workspace)
	commands := workspaceRevokeCommands(workspace, env.agentUserName, ancestorsNeededBy(remaining), workspaceExists)
	if opts.dryRun {
		_, _ = fmt.Fprintf(env.out, "pipelock contain revoke-workspace %s - planned:\n", workspace)
		for i, c := range commands {
			_, _ = fmt.Fprintf(env.out, "  %d. %s %s\n", i+1, c.name, strings.Join(shellQuoteArgs(c.args), " "))
		}
		_, _ = fmt.Fprintf(env.out, "  %d. update %s\n", len(commands)+1, env.workspaceInvPath)
		return nil
	}
	if err := runWorkspaceCommands(ctx, env, commands); err != nil {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, err)
	}
	if err := writeWorkspaceInventory(env, workspaceInventory{Workspaces: remaining}); err != nil {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("update workspace inventory: %w", err))
	}
	_, _ = fmt.Fprintf(env.out, "revoked workspace access to %s for %s.\n", workspace, env.agentUserName)
	return nil
}

func resolveWorkspaceForRevoke(env *installEnv, path string, inv workspaceInventory) (string, bool, error) {
	workspace, err := resolveWorkspaceDir(env, path, true)
	if err == nil {
		return workspace, true, nil
	}
	if strings.TrimSpace(path) == "" {
		return "", false, err
	}
	abs, absErr := filepath.Abs(filepath.Clean(path))
	if absErr != nil {
		return "", false, fmt.Errorf("resolve workspace path: %w", absErr)
	}
	for _, grant := range inv.Workspaces {
		if grant.Path == abs {
			return abs, false, nil
		}
	}
	return "", false, err
}

func resolveWorkspaceDir(env *installEnv, path string, allowSystemPath bool) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("workspace path is empty")
	}
	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("resolve workspace path: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("resolve workspace symlinks %s: %w", abs, err)
	}
	info, err := env.stat(resolved)
	if err != nil {
		return "", fmt.Errorf("stat workspace %s: %w", resolved, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("workspace %s is not a directory", resolved)
	}
	if !allowSystemPath {
		if denied := deniedWorkspacePrefix(resolved); denied != "" {
			return "", fmt.Errorf("workspace %s is under protected system path %s (choose an operator project directory or pass --allow-system-path explicitly)", resolved, denied)
		}
	}
	return resolved, nil
}

func workspaceACLCommands(workspace, agentUser, mode string) []workspaceCommand {
	perms := "rwX"
	if mode == workspaceModeReadOnly {
		perms = "rX"
	}
	var commands []workspaceCommand
	ancestors := workspaceAncestors(workspace)
	if len(ancestors) > 0 {
		args := []string{"-m", "u:" + agentUser + ":--x"}
		args = append(args, ancestors...)
		commands = append(commands, workspaceCommand{name: "setfacl", args: args})
	}
	commands = append(commands,
		workspaceCommand{name: "setfacl", args: []string{"-R", "-m", "u:" + agentUser + ":" + perms, workspace}},
		workspaceCommand{name: "find", args: []string{workspace, "-mindepth", "1", "-type", "d", "-exec", "setfacl", "-m", "d:u:" + agentUser + ":" + perms, "{}", "+"}},
	)
	commands = append(commands, credentialLockCommands(workspace, agentUser)...)
	return commands
}

func credentialLockCommands(root, agentUser string) []workspaceCommand {
	matchArgs := credentialFindMatchArgs()
	findSetfacl := append([]string{root, "-type", "f"}, matchArgs...)
	findSetfacl = append(findSetfacl, "-exec", "setfacl", "-x", "u:"+agentUser, "{}", "+")
	findChmod := append([]string{root, "-type", "f"}, matchArgs...)
	findChmod = append(findChmod, "-exec", "chmod", "0600", "{}", "+")
	return []workspaceCommand{
		{name: "find", args: findSetfacl},
		{name: "find", args: findChmod},
	}
}

func credentialFindMatchArgs() []string {
	return []string{
		"(",
		"-name", "auth.json",
		"-o", "-name", ".claude.json",
		"-o", "-name", ".credentials.json",
		"-o", "-name", "*.token",
		")",
	}
}

func workspaceRevokeCommands(workspace, agentUser string, keepAncestors map[string]bool, workspaceExists bool) []workspaceCommand {
	var commands []workspaceCommand
	if workspaceExists {
		commands = append(commands,
			workspaceCommand{name: "setfacl", args: []string{"-R", "-x", "u:" + agentUser, workspace}},
			workspaceCommand{name: "find", args: []string{workspace, "-type", "d", "-exec", "setfacl", "-x", "d:u:" + agentUser, "{}", "+"}},
		)
	}
	var ancestors []string
	for _, ancestor := range workspaceAncestors(workspace) {
		if !keepAncestors[ancestor] {
			ancestors = append(ancestors, ancestor)
		}
	}
	if len(ancestors) > 0 {
		args := []string{"-x", "u:" + agentUser}
		args = append(args, ancestors...)
		commands = append(commands, workspaceCommand{name: "setfacl", args: args})
	}
	return commands
}

func workspaceRevokeAllCommands(env *installEnv, grants []workspaceGrant, agentUser string) ([]workspaceCommand, error) {
	seenWorkspaces := make(map[string]bool, len(grants))
	seenAncestors := map[string]bool{}
	var commands []workspaceCommand
	for _, grant := range grants {
		if seenWorkspaces[grant.Path] {
			continue
		}
		seenWorkspaces[grant.Path] = true
		if _, err := env.stat(grant.Path); err == nil {
			commands = append(commands,
				workspaceCommand{name: "setfacl", args: []string{"-R", "-x", "u:" + agentUser, grant.Path}},
				workspaceCommand{name: "find", args: []string{grant.Path, "-type", "d", "-exec", "setfacl", "-x", "d:u:" + agentUser, "{}", "+"}},
			)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("stat workspace %s: %w", grant.Path, err)
		}
		for _, ancestor := range workspaceAncestors(grant.Path) {
			seenAncestors[ancestor] = true
		}
	}
	if len(seenAncestors) > 0 {
		ancestors := make([]string, 0, len(seenAncestors))
		for ancestor := range seenAncestors {
			ancestors = append(ancestors, ancestor)
		}
		slices.Sort(ancestors)
		args := []string{"-x", "u:" + agentUser}
		args = append(args, ancestors...)
		commands = append(commands, workspaceCommand{name: "setfacl", args: args})
	}
	return commands, nil
}

func workspaceAncestors(workspace string) []string {
	clean := filepath.Clean(workspace)
	var reversed []string
	for parent := filepath.Dir(clean); parent != "." && parent != "/" && parent != clean; parent = filepath.Dir(parent) {
		reversed = append(reversed, parent)
	}
	ancestors := make([]string, 0, len(reversed))
	for i := len(reversed) - 1; i >= 0; i-- {
		ancestors = append(ancestors, reversed[i])
	}
	return ancestors
}

func deniedWorkspacePrefix(path string) string {
	clean := filepath.Clean(path)
	for _, prefix := range deniedWorkspacePrefixes {
		if prefix == "/" {
			if clean == "/" {
				return prefix
			}
			continue
		}
		if clean == prefix || strings.HasPrefix(clean, prefix+string(os.PathSeparator)) {
			return prefix
		}
	}
	return ""
}

func runWorkspaceCommands(ctx context.Context, env *installEnv, commands []workspaceCommand) error {
	for _, c := range commands {
		out, code, err := env.runCmd(ctx, c.name, c.args...)
		if err != nil {
			return fmt.Errorf("%s: %w", c.name, err)
		}
		if code != 0 {
			return fmt.Errorf("%s exit %d: %s", c.name, code, oneLine(out))
		}
	}
	return nil
}

func recordWorkspaceGrant(env *installEnv, grant workspaceGrant) error {
	inv, err := loadWorkspaceInventory(env)
	if err != nil {
		return err
	}
	replaced := false
	for i, existing := range inv.Workspaces {
		if existing.Path == grant.Path {
			inv.Workspaces[i] = grant
			replaced = true
			break
		}
	}
	if !replaced {
		inv.Workspaces = append(inv.Workspaces, grant)
	}
	slices.SortFunc(inv.Workspaces, func(a, b workspaceGrant) int {
		return strings.Compare(a.Path, b.Path)
	})
	return writeWorkspaceInventory(env, inv)
}

func readWorkspaceInventory(env *installEnv) workspaceInventory {
	inv, err := loadWorkspaceInventory(env)
	if err != nil {
		return workspaceInventory{}
	}
	return inv
}

func loadWorkspaceInventory(env *installEnv) (workspaceInventory, error) {
	data, err := env.readFile(env.workspaceInvPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return workspaceInventory{}, nil
		}
		return workspaceInventory{}, err
	}
	var inv workspaceInventory
	if err := json.Unmarshal(data, &inv); err != nil {
		return workspaceInventory{}, fmt.Errorf("parse %s: %w", env.workspaceInvPath, err)
	}
	return inv, nil
}

func writeWorkspaceInventory(env *installEnv, inv workspaceInventory) error {
	if err := env.mkdirAll(filepath.Dir(env.workspaceInvPath), modeDirTraversable); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(env.workspaceInvPath), err)
	}
	if err := env.chmod(filepath.Dir(env.workspaceInvPath), modeDirTraversable); err != nil {
		return fmt.Errorf("chmod %s: %w", filepath.Dir(env.workspaceInvPath), err)
	}
	data, err := json.MarshalIndent(inv, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal workspace inventory: %w", err)
	}
	data = append(data, '\n')
	return backupAndWrite(env, env.workspaceInvPath, data, modeAllowListReadable)
}

func workspaceGrantsExcept(grants []workspaceGrant, path string) []workspaceGrant {
	out := make([]workspaceGrant, 0, len(grants))
	for _, grant := range grants {
		if grant.Path != path {
			out = append(out, grant)
		}
	}
	return out
}

func ancestorsNeededBy(grants []workspaceGrant) map[string]bool {
	needed := map[string]bool{}
	for _, grant := range grants {
		for _, ancestor := range workspaceAncestors(grant.Path) {
			needed[ancestor] = true
		}
	}
	return needed
}

func shellQuoteArgs(args []string) []string {
	out := make([]string, 0, len(args))
	for _, arg := range args {
		out = append(out, shellQuote(arg))
	}
	return out
}
