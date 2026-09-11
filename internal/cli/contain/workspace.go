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
	"slices"
	"strings"
	"time"

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
	reason          string
	expires         string
}

type workspaceCommand struct {
	name string
	args []string
}

type workspaceInventory struct {
	Workspaces []workspaceGrant `json:"workspaces"`
}

// workspaceGrant records one ACL grant plus its lifecycle metadata. The
// metadata fields are all omitempty and optional so an inventory written by an
// older Pipelock (path+mode only) loads unchanged and renders as a "legacy
// grant, no metadata" row rather than failing to parse. Timestamps are RFC3339
// in UTC.
type workspaceGrant struct {
	Path    string `json:"path"`
	Mode    string `json:"mode"`
	Owner   string `json:"owner,omitempty"`   // operator who granted it (SUDO_USER, else current user)
	Reason  string `json:"reason,omitempty"`  // optional free-text justification
	Created string `json:"created,omitempty"` // when the grant was recorded
	Expires string `json:"expires,omitempty"` // empty = never; a grant past this is refused at launch/verify
	// AgentUser is the contained user the ACL was granted to, so a host that
	// contains more than one agent user can list each one's grants alone.
	AgentUser string `json:"agent_user,omitempty"`
}

// isLegacyGrant reports whether a grant carries none of the lifecycle metadata
// fields, i.e. it was written by a Pipelock that predates this feature.
func (g workspaceGrant) isLegacyGrant() bool {
	return g.Owner == "" && g.Reason == "" && g.Created == "" && g.Expires == "" && g.AgentUser == ""
}

// appliesTo reports whether this grant governs the named contained agent user.
// A grant recorded with an explicit AgentUser belongs to that user alone; a
// legacy grant (written before the field existed) carries no identity and is
// therefore attributed to every agent user, because refusing to honour it would
// silently drop an ACL that is still live on disk.
//
// This is the single predicate every grant consumer uses - list-workspaces,
// `contain run` preflight, and `contain verify` - so one agent user's grant can
// never gate, expire, or be verified against another's launch.
func (g workspaceGrant) appliesTo(agentUser string) bool {
	return g.AgentUser == "" || g.AgentUser == agentUser
}

// grantsForAgent filters an inventory down to the grants that govern agentUser.
func grantsForAgent(grants []workspaceGrant, agentUser string) []workspaceGrant {
	out := make([]workspaceGrant, 0, len(grants))
	for _, g := range grants {
		if g.appliesTo(agentUser) {
			out = append(out, g)
		}
	}
	return out
}

// expired reports whether the grant's expiry (if any) is at or before now. A
// malformed Expires value fails CLOSED (returns an error) so a corrupted
// timestamp is treated as a launch/verify failure, never silently as
// "not expired".
func (g workspaceGrant) expired(now time.Time) (bool, error) {
	if strings.TrimSpace(g.Expires) == "" {
		return false, nil
	}
	exp, err := time.Parse(time.RFC3339, g.Expires)
	if err != nil {
		return false, fmt.Errorf("workspace %s has a malformed expiry %q: %w", g.Path, g.Expires, err)
	}
	return !now.Before(exp), nil
}

// grantStatus returns a short human status for list-workspaces: "legacy",
// "expired", or "active". A malformed expiry surfaces as "invalid-expiry" so an
// operator sees the corruption rather than a misleading "active".
func (g workspaceGrant) grantStatus(now time.Time) string {
	if g.isLegacyGrant() {
		return "legacy"
	}
	exp, err := g.expired(now)
	if err != nil {
		return "invalid-expiry"
	}
	if exp {
		return "expired"
	}
	return "active"
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
			if !opts.dryRun {
				if err := requireContainPrivilege("grant-workspace"); err != nil {
					return cliutil.ExitCodeError(cliutil.ExitConfig, err)
				}
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
	cmd.Flags().StringVar(&opts.reason, "reason", "", "optional justification recorded with the grant")
	cmd.Flags().StringVar(&opts.expires, "expires", "", "grant expiry as a Go duration (e.g. 720h) or an RFC3339 timestamp; an expired grant is refused at launch and fails verify")

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
			if !opts.dryRun {
				if err := requireContainPrivilege("revoke-workspace"); err != nil {
					return cliutil.ExitCodeError(cliutil.ExitConfig, err)
				}
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
	created := envNow(env)
	grant := workspaceGrant{
		Path:      workspace,
		Mode:      mode,
		Owner:     grantOwner(env),
		Reason:    strings.TrimSpace(opts.reason),
		Created:   created.Format(time.RFC3339),
		AgentUser: env.agentUserName,
	}
	if strings.TrimSpace(opts.expires) != "" {
		expiry, err := parseGrantExpiry(opts.expires, created)
		if err != nil {
			return cliutil.ExitCodeError(cliutil.ExitConfig, err)
		}
		grant.Expires = expiry.UTC().Format(time.RFC3339)
	}
	commands := workspaceACLCommands(workspace, env.agentUserName, mode)
	if opts.dryRun {
		_, _ = fmt.Fprintf(env.out, "pipelock contain grant-workspace %s - planned:\n", workspace)
		for i, c := range commands {
			_, _ = fmt.Fprintf(env.out, "  %d. %s %s\n", i+1, c.name, strings.Join(shellQuoteArgs(c.args), " "))
		}
		_, _ = fmt.Fprintf(env.out, "  %d. record grant in %s (owner %s, expires %s)\n",
			len(commands)+1, env.workspaceInvPath, grant.Owner, grantExpiryLabel(grant))
		return nil
	}
	if err := runWorkspaceCommands(ctx, env, commands); err != nil {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, err)
	}
	if err := recordWorkspaceGrant(env, grant); err != nil {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("record workspace grant: %w", err))
	}
	_, _ = fmt.Fprintf(env.out, "granted %s access to %s for %s (owner %s, expires %s).\n",
		mode, workspace, env.agentUserName, grant.Owner, grantExpiryLabel(grant))
	return nil
}

// envNow returns env.now() when set, falling back to time.Now. Keeps timestamp
// generation deterministic under test without every caller having to check.
func envNow(env *installEnv) time.Time {
	if env.now != nil {
		return env.now()
	}
	return time.Now()
}

// grantOwner resolves who is recording the grant: SUDO_USER (the operator
// behind sudo) first, then the current OS user, then "unknown". Never fails the
// grant on a lookup miss - ownership metadata is advisory, not a gate.
func grantOwner(env *installEnv) string {
	if op := strings.TrimSpace(env.operatorUser); op != "" {
		return op
	}
	if u, err := user.Current(); err == nil && strings.TrimSpace(u.Username) != "" {
		return u.Username
	}
	return "unknown"
}

// parseGrantExpiry accepts either a Go duration (relative to created) or an
// absolute RFC3339 timestamp. A duration must be positive; an absolute time
// must be in the future relative to created. Fails CLOSED: an unparseable or
// already-past value is a config error, never a silently-ignored expiry.
func parseGrantExpiry(raw string, created time.Time) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if dur, err := time.ParseDuration(raw); err == nil {
		if dur <= 0 {
			return time.Time{}, fmt.Errorf("invalid --expires %q: duration must be positive", raw)
		}
		return created.Add(dur), nil
	}
	ts, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid --expires %q: want a Go duration (e.g. 720h) or an RFC3339 timestamp", raw)
	}
	if !ts.After(created) {
		return time.Time{}, fmt.Errorf("invalid --expires %q: timestamp is not in the future", raw)
	}
	return ts, nil
}

// grantExpiryLabel renders a grant's expiry for operator output: "never" when
// unset, otherwise the recorded RFC3339 value.
func grantExpiryLabel(g workspaceGrant) string {
	if strings.TrimSpace(g.Expires) == "" {
		return "never"
	}
	return g.Expires
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
	remaining := workspaceGrantsExcept(inv.Workspaces, workspace, env.agentUserName)
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

func listWorkspacesCmd() *cobra.Command {
	var agentUser string
	cmd := &cobra.Command{
		Use:   "list-workspaces",
		Short: "List recorded pipelock-agent workspace grants",
		Long: `List the workspace grants recorded for the contained agent.

Answers "what can the agent reach today, and why" from one command: each row
shows the path, ACL mode, owner, when it was granted, when it expires, and a
status. An EXPIRED grant is refused by contain run and fails contain verify,
but its ACLs stay on disk until you run revoke-workspace - expiry gates the
launch, it does not remove the ACL.

Read-only; safe to run without root.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if agentUser == "" {
				agentUser = defaultAgentUser
			}
			if err := validateContainUsername("agent user", agentUser); err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			env := defaultInstallEnv(cmd.OutOrStdout())
			env.agentUserName = agentUser
			return runListWorkspaces(env)
		},
	}
	cmd.Flags().StringVar(&agentUser, "agent-user", defaultAgentUser, "contained agent user whose grants to list")
	return cmd
}

func runListWorkspaces(env *installEnv) error {
	inv, err := loadWorkspaceInventory(env)
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("read workspace inventory: %w", err))
	}
	// Legacy grants carry no agent user and are shown for every agent user;
	// grants recorded with one are shown only for that user.
	rows := grantsForAgent(inv.Workspaces, env.agentUserName)
	if len(rows) == 0 {
		_, _ = fmt.Fprintf(env.out, "no workspace grants recorded for %s in %s\n", env.agentUserName, env.workspaceInvPath)
		return nil
	}
	now := envNow(env)
	_, _ = fmt.Fprintf(env.out, "%-40s  %-10s  %-12s  %-20s  %-20s  %-14s  %s\n",
		"PATH", "MODE", "OWNER", "CREATED", "EXPIRES", "STATUS", "REASON")
	for _, g := range rows {
		_, _ = fmt.Fprintf(env.out, "%-40s  %-10s  %-12s  %-20s  %-20s  %-14s  %s\n",
			g.Path, valueOrDash(g.Mode), valueOrDash(g.Owner),
			valueOrDash(g.Created), grantExpiryLabel(g), g.grantStatus(now), valueOrDash(g.Reason))
	}
	return nil
}

func valueOrDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

// expiredWorkspaceGrants returns the paths of every grant that has passed its
// expiry as of now, plus the first malformed-expiry error if any. Callers
// (contain run, contain verify) use it to fail CLOSED: any expired grant means
// the recorded window has passed while the ACL is still live, so the launch is
// refused until the operator re-grants or revokes.
func expiredWorkspaceGrants(grants []workspaceGrant, now time.Time) ([]string, error) {
	var expired []string
	for _, g := range grants {
		isExpired, err := g.expired(now)
		if err != nil {
			return nil, err
		}
		if isExpired {
			expired = append(expired, g.Path)
		}
	}
	return expired, nil
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
	// A grant is identified by (Path, AgentUser), not by Path alone: a host that
	// contains two agent users can hold a live ACL on the same directory for each
	// of them, and keying on Path would make the second grant silently destroy
	// the first one's record (including its expiry) while its ACL stayed live.
	// A legacy row (no AgentUser) is upgraded in place by the first grant that
	// names a user for that path, because it is the same ACL gaining an identity.
	replaced := false
	for i, existing := range inv.Workspaces {
		if existing.Path != grant.Path {
			continue
		}
		if existing.AgentUser == grant.AgentUser || existing.AgentUser == "" {
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
	return loadWorkspaceInventoryFrom(env.readFile, env.workspaceInvPath)
}

// loadWorkspaceInventoryFrom reads and parses the workspace inventory from an
// arbitrary readFile/path pair so both the installEnv-based commands and the
// probeEnv-based contain run/verify paths share one loader. A missing file is
// an empty inventory (install never ran, or no grants yet), not an error.
func loadWorkspaceInventoryFrom(readFile func(string) ([]byte, error), path string) (workspaceInventory, error) {
	data, err := readFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return workspaceInventory{}, nil
		}
		return workspaceInventory{}, err
	}
	var inv workspaceInventory
	if err := json.Unmarshal(data, &inv); err != nil {
		return workspaceInventory{}, fmt.Errorf("parse %s: %w", path, err)
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

// workspaceGrantsExcept drops the grants revoking path for agentUser removes.
// Revocation strips the ACL for ONE agent user, so another user's grant on the
// same path survives: dropping it would leave that user's ACL live on disk with
// no record of it. A legacy row on that path is dropped, because it cannot be
// attributed and the revoke may well be removing exactly it.
func workspaceGrantsExcept(grants []workspaceGrant, path, agentUser string) []workspaceGrant {
	out := make([]workspaceGrant, 0, len(grants))
	for _, grant := range grants {
		if grant.Path == path && grant.appliesTo(agentUser) {
			continue
		}
		out = append(out, grant)
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
