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
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

// addToolNamePattern bounds tool names to a small alphabet so the wrapper
// path is safe to construct without shell quoting (a-z0-9, _-, max 31
// chars, must start with [a-z0-9]).
var addToolNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,30}$`)

// addToolOpts collects flag state for the add-tool subcommand.
type addToolOpts struct {
	dryRun bool
	target string
}

func addToolCmd() *cobra.Command {
	var opts addToolOpts

	cmd := &cobra.Command{
		Use:   "add-tool <name>",
		Short: "Drop a new /usr/local/bin/plk-<name> wrapper",
		Long: `Install a wrapper at /usr/local/bin/plk-<name> that execs
` + "`plk-launch <name>`" + ` and records the new wrapper in the contain
wrapper inventory used by ` + "`pipelock contain verify`" + `.

Validates that the target tool resolves to an executable on pipelock-agent's
PATH so the wrapper isn't installed pointing at nothing. Pass --target
to override the auto-detected path.

Must be run as root.

Exit codes:
  0  Wrapper installed (or already in place).
  1  Failed to write wrapper / update inventory.
  2  Invalid tool name, target missing, or precondition error.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if !addToolNamePattern.MatchString(name) {
				return cliutil.ExitCodeError(
					cliutil.ExitConfig,
					fmt.Errorf("invalid tool name %q (expected [a-z0-9][a-z0-9_-]{0,30})", name),
				)
			}
			if !opts.dryRun && os.Geteuid() != 0 {
				return cliutil.ExitCodeError(cliutil.ExitConfig, errors.New("add-tool must be run as root (use sudo)"))
			}
			env := defaultInstallEnv(cmd.OutOrStdout())
			return runAddTool(cmd.Context(), env, name, opts)
		},
	}

	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "print planned actions without mutating state")
	cmd.Flags().StringVar(&opts.target, "target", "", "explicit path to the target tool (default: command -v <name> from pipelock-agent's PATH)")

	return cmd
}

// runAddTool is the testable entry point.
func runAddTool(ctx context.Context, env *installEnv, name string, opts addToolOpts) error {
	if ctx == nil {
		ctx = context.Background()
	}
	// The cobra RunE wrapper does the os.Geteuid root check; tests drive
	// this function directly with fakes.

	wrapperName := "plk-" + name
	wrapperPath := filepath.Join(env.wrapperDir, wrapperName)

	// Desired wrapper body is known before target resolution, but idempotency
	// also depends on tools.list and is checked after target validation.
	desiredBody := renderToolWrapper(env, name)
	existing, readErr := env.readFile(wrapperPath)
	alreadyInInventory := wrapperInInventory(env, wrapperName)

	// Target resolution. --target trumps. Otherwise we run `command -v` AS
	// pipelock-agent so the lookup uses pipelock-agent's PATH, not root's,
	// and does not depend on a separate which(1) package.
	target := opts.target
	if target == "" {
		out, code, err := env.runCmd(ctx, "sudo", "-n", "-u", env.agentUserName, "--",
			"env", "PATH="+agentExecPath(env.agentUserName), "sh", "-c", `command -v -- "$1"`, "sh", name)
		if err != nil {
			return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("resolve tool %q in pipelock-agent's PATH: %w", name, err))
		}
		if code != 0 {
			return cliutil.ExitCodeError(
				cliutil.ExitConfig,
				fmt.Errorf("tool %q not found in pipelock-agent's PATH (pass --target if it lives elsewhere)", name),
			)
		}
		target = strings.TrimSpace(out)
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("could not resolve target for %q", name))
	}
	target = filepath.Clean(target)
	if !filepath.IsAbs(target) {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("target %q must be an absolute path", target))
	}
	info, err := env.lstat(target)
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("target %q: %w", target, err))
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("target %q is a symlink; pass the resolved executable path", target))
	}
	if info.IsDir() {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("target %q is a directory", target))
	}
	if info.Mode().Perm()&0o111 == 0 {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("target %q is not executable", target))
	}
	if out, code, err := env.runCmd(ctx, "sudo", "-n", "-u", env.agentUserName, "--", "test", "-x", target); err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("validate target %q as %s: %w", target, env.agentUserName, err))
	} else if code != 0 {
		return cliutil.ExitCodeError(cliutil.ExitConfig,
			fmt.Errorf("target %q is not executable by %s (sudo test exit=%d: %s)", target, env.agentUserName, code, oneLine(out)))
	}

	if opts.dryRun {
		_, _ = fmt.Fprintf(env.out, "pipelock contain add-tool %s — planned:\n", name)
		_, _ = fmt.Fprintf(env.out, "  1. write %s (mode 0o755)\n", wrapperPath)
		_, _ = fmt.Fprintf(env.out, "  2. append %q to %s\n", wrapperName, env.wrapperInvPath)
		_, _ = fmt.Fprintf(env.out, "  3. allow %q via %s\n", name, env.toolsListPath)
		return nil
	}

	allowListTarget := target
	if readErr == nil && string(existing) == desiredBody && alreadyInInventory && toolEntryMatches(env, name, allowListTarget) {
		_, _ = fmt.Fprintf(env.out, "wrapper %s already installed and inventoried — nothing to do.\n", wrapperPath)
		return nil
	}

	if err := backupAndWrite(env, wrapperPath, []byte(desiredBody), modeWrapperExec); err != nil {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("write %s: %w", wrapperPath, err))
	}
	if err := appendInventory(env, wrapperName); err != nil {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("update inventory: %w", err))
	}
	// Add to the plk-launch runtime allow-list. The --target value, when
	// provided, is baked in here so plk-launch execs the exact binary the
	// operator approved instead of re-resolving via PATH at runtime. An
	// empty target falls back to pipelock-agent's PATH lookup.
	if _, err := upsertToolEntry(env, name, allowListTarget); err != nil {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("update tools.list: %w", err))
	}

	_, _ = fmt.Fprintf(env.out, "installed wrapper %s -> plk-launch %s (target %s).\n", wrapperPath, name, target)
	return nil
}

func toolEntryMatches(env *installEnv, name, target string) bool {
	entries, err := readToolsList(env)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if entry.name == name {
			return entry.target == target
		}
	}
	return false
}

// wrapperInInventory returns true if the inventory file lists name. A
// missing or unparseable inventory yields false (callers will rewrite it).
func wrapperInInventory(env *installEnv, name string) bool {
	data, err := env.readFile(env.wrapperInvPath)
	if err != nil {
		return false
	}
	var inv wrapperInventory
	if err := json.Unmarshal(data, &inv); err != nil {
		return false
	}
	for _, w := range inv.Wrappers {
		if w == name {
			return true
		}
	}
	return false
}

// appendInventory adds name to the inventory file if not already present.
// Creates the file (and its directory) if missing.
func appendInventory(env *installEnv, name string) error {
	dir := filepath.Dir(env.wrapperInvPath)
	if err := ensureSafeDirectory(env, dir); err != nil {
		return err
	}
	if err := env.mkdirAll(dir, modeDirTraversable); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	if err := env.chmod(dir, modeDirTraversable); err != nil {
		return fmt.Errorf("chmod %s: %w", dir, err)
	}
	var inv wrapperInventory
	data, err := env.readFile(env.wrapperInvPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("read inventory %s: %w", env.wrapperInvPath, err)
		}
	} else {
		if err := json.Unmarshal(data, &inv); err != nil {
			return fmt.Errorf("parse inventory %s: %w", env.wrapperInvPath, err)
		}
	}
	for _, w := range inv.Wrappers {
		if w == name {
			return nil
		}
	}
	inv.Wrappers = append(inv.Wrappers, name)
	out, err := json.MarshalIndent(inv, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal inventory: %w", err)
	}
	return backupAndWrite(env, env.wrapperInvPath, append(out, '\n'), modeAllowListReadable)
}
