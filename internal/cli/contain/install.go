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
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

// installOpts collects the flag-derived state for runInstall. Mirrored as
// fields on installEnv so the step functions can read them without holding
// a reference to the flag layer.
type installOpts struct {
	dryRun         bool
	operatorUser   string
	proxyPort      int
	pipelockBinary string
	configSource   string
}

var containUsernamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// containToolNameRegex is the shared regex that both plk-launch and the plk
// meta-wrapper enforce on operator-supplied tool names. Keeping a single
// source of truth prevents the two wrappers from drifting and letting a name
// through one layer that the other rejects. The regex is rendered as a bash
// =~ pattern in both scripts.
const containToolNameRegex = "^[a-z0-9][a-z0-9_-]{0,30}$"

// installCmd builds the `pipelock contain install` cobra command.
func installCmd() *cobra.Command {
	var opts installOpts

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install the containment model (creates users, unit, nft rules, wrappers)",
		Long: `Install the kernel-enforced workstation containment model.

Creates the pipelock-proxy and pipelock-agent system users, migrates the
user-mode systemd unit to a system unit, installs nftables owner-match
rules, writes wrapper scripts, installs the sudoers entry, and bootstraps
the combined CA bundle.

Must be run as root. Each step is idempotent: rerunning install on a
fully-installed system is a no-op. If a step fails, every previously-
applied step is rolled back before exit so the system never settles in a
partial state.

The installed binary is pinned at install time (SHA-256 stored in
/etc/pipelock/integrity/binary-pin.sha256); subsequent verify runs
re-hash and compare so a swapped binary is caught on the next probe.

Flags let CI and reviewers see the planned commands before running.

Exit codes:
  0  All steps applied (or already in place).
  1  A step failed; earlier applied steps were rolled back.
  2  Precondition error (not root, missing executable, bad --config).`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validatePort(opts.proxyPort); err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			if !opts.dryRun && os.Geteuid() != 0 {
				return cliutil.ExitCodeError(cliutil.ExitConfig, errors.New("install must be run as root (use sudo)"))
			}
			env := defaultInstallEnv(cmd.OutOrStdout())
			if opts.operatorUser != "" {
				env.operatorUser = opts.operatorUser
			}
			env.proxyPort = opts.proxyPort
			env.pipelockBinary = opts.pipelockBinary
			return runInstall(cmd.Context(), env, opts)
		},
	}

	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "print the planned steps without mutating state")
	cmd.Flags().StringVar(&opts.operatorUser, "operator-user", "", "operator user the pipelock-agent wrappers run from (default: $SUDO_USER)")
	cmd.Flags().IntVar(&opts.proxyPort, "proxy-port", defaultProxyPort, "pipelock listen port baked into wrappers and the unit")
	cmd.Flags().StringVar(&opts.pipelockBinary, "pipelock-binary", "", "path to the pipelock binary to install (default: current process)")
	cmd.Flags().StringVar(&opts.configSource, "config", "", "source pipelock.yaml to copy to /etc/pipelock/pipelock.yaml")

	return cmd
}

// systemctlActive is the literal systemd-reports-active state. Extracted
// because the install + verify code both compare against it and goconst
// flags repeated string literals.
const (
	systemctlActive  = "active"
	systemctlEnabled = "enabled"
)

// runInstall is the runtime entry point. Separated from installCmd so tests
// can drive it directly with a fake installEnv.
//
// Preconditions (operator-user resolvable, --config file readable, source
// binary readable) are checked BEFORE the step loop so they exit
// ExitConfig. The cobra RunE handler is responsible for the os.Geteuid
// root check; this function trusts its caller.
func runInstall(ctx context.Context, env *installEnv, opts installOpts) error {
	if ctx == nil {
		ctx = context.Background()
	}
	env.archivedBackups = make(map[string][]string)
	if opts.operatorUser != "" {
		env.operatorUser = opts.operatorUser
	}

	if env.operatorUser == "" && opts.operatorUser == "" {
		return cliutil.ExitCodeError(cliutil.ExitConfig,
			errors.New("operator user not set; rerun via sudo (SUDO_USER) or pass --operator-user"))
	}
	if err := validateContainUsername("operator user", env.operatorUser); err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, err)
	}
	if _, err := env.lookupUser(env.operatorUser); err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("lookup operator user %s: %w", env.operatorUser, err))
	}
	if opts.configSource != "" {
		opts.configSource = filepath.Clean(opts.configSource)
		if info, err := env.stat(opts.configSource); err != nil {
			return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("--config %q: %w", opts.configSource, err))
		} else if info.IsDir() {
			return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("--config %q is a directory", opts.configSource))
		}
	}

	// Resolve --pipelock-binary defaults early. If not supplied, use the
	// currently-running binary path; that's the only safe TOFU source
	// because the operator just invoked it as root.
	if env.pipelockBinary == "" {
		self, err := env.selfPath()
		if err != nil {
			return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("locate pipelock binary: %w", err))
		}
		env.pipelockBinary = filepath.Clean(self)
	} else {
		env.pipelockBinary = filepath.Clean(env.pipelockBinary)
	}
	if info, err := env.stat(env.pipelockBinary); err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("--pipelock-binary %q: %w", env.pipelockBinary, err))
	} else if info.IsDir() {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("--pipelock-binary %q is a directory", env.pipelockBinary))
	}

	steps := installSteps(opts)

	if opts.dryRun {
		printPlan(env.out, "pipelock contain install — planned steps:", steps)
		return nil
	}

	_, _ = fmt.Fprintln(env.out, "pipelock contain install")
	_, err := runSteps(ctx, env, env.out, steps)
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, err)
	}
	_, _ = fmt.Fprintln(env.out, "install complete — run `pipelock contain verify` to confirm.")
	return nil
}

func validateContainUsername(label, name string) error {
	if !containUsernamePattern.MatchString(name) {
		return fmt.Errorf("invalid %s %q (expected Linux username [a-z_][a-z0-9_-]{0,31})", label, name)
	}
	return nil
}

// installSteps returns the ordered step list for install. Order is
// load-bearing:
//
//   - Users created before anything that chown's to them.
//   - Config/data dirs before the service unit (the unit references them).
//   - Binary installed before the integrity pin (we hash what we'll run).
//   - Pipelock service running before the CA export (the export uses the
//     running instance's state).
//   - Combined CA built before nft rules (nft enforcement makes pipelock-agent's
//     first invocation fail without a CA to validate TLS).
//   - Wrappers + sudoers last (operators only exercise them once the
//     boundary is enforceable).
func installSteps(opts installOpts) []step {
	return []step{
		stepPreflight(opts),
		stepCreateUser(true),  // proxy
		stepCreateUser(false), // agent
		// /etc/pipelock must be traversable by pipelock-agent so the wrappers
		// can reach /etc/pipelock/{ca.pem,combined-ca.pem,contain/tools.list}.
		// /var/lib/pipelock holds capture data and stays pipelock-proxy-private.
		stepCreateDir("config", func(e *installEnv) string { return e.configDir }, modeDirTraversable),
		stepCreateDir("data", func(e *installEnv) string { return e.dataDir }, modeDirPrivate),
		stepWritePipelockConfig(opts),
		stepChownToProxy("config", func(e *installEnv) string { return e.configDir }),
		stepChownToProxy("data", func(e *installEnv) string { return e.dataDir }),
		stepInstallPipelockBinary(),
		stepWriteIntegrityPin(),
		stepStopUserService(),
		stepWriteSystemUnit(),
		stepEnableSystemUnit(),
		stepExportPipelockCA(),
		stepWriteCombinedCABundle(),
		stepInstallNFTRules(),
		stepWriteToolsList(),
		stepWriteLaunchWrapper(),
		stepWriteMetaWrapper(),
		stepWriteToolWrappers(),
		stepWriteWrapperInventory(),
		stepInstallSudoers(),
	}
}

// stepWriteToolsList seeds /etc/pipelock/contain/tools.list with only the
// default tools that pipelock-agent can actually execute. add-tool appends;
// rollback removes. The file is pipelock-agent-readable; root-owned directory
// write permissions gate allow-list mutation.
func stepWriteToolsList() step {
	return step{
		name: "write-tools-list",
		desc: "write /etc/pipelock/contain/tools.list (plk-launch runtime allow-list)",
		apply: func(_ context.Context, env *installEnv) (bool, error) {
			// /etc/pipelock/contain must be traversable by pipelock-agent so the
			// wrapper can open tools.list. The file itself is world-readable
			// (modeAllowListReadable); mutation is gated by directory write
			// perms which only root holds.
			if err := env.mkdirAll(filepath.Dir(env.toolsListPath), modeDirTraversable); err != nil {
				return false, fmt.Errorf("mkdir %s: %w", filepath.Dir(env.toolsListPath), err)
			}
			if err := env.chmod(filepath.Dir(env.toolsListPath), modeDirTraversable); err != nil {
				return false, fmt.Errorf("chmod %s: %w", filepath.Dir(env.toolsListPath), err)
			}
			defaults := resolvableDefaultToolEntries(env)
			if len(defaults) == 0 {
				return false, errors.New("no default agent tools found in pipelock-agent PATH (/home/pipelock-agent/.local/bin:/usr/local/bin:/usr/bin:/bin); install a tool such as claude into /usr/local/bin or use add-tool after install")
			}
			entries, err := readToolsList(env)
			if err != nil {
				if !errors.Is(err, os.ErrNotExist) {
					return false, fmt.Errorf("read tools.list: %w", err)
				}
				if err := writeToolsList(env, defaults); err != nil {
					return false, err
				}
				return true, nil
			}
			merged, changed := mergeDefaultToolEntries(entries, defaults)
			if !changed {
				return false, nil
			}
			if err := writeToolsList(env, merged); err != nil {
				return false, err
			}
			return true, nil
		},
		undo: func(_ context.Context, env *installEnv) error {
			return restoreBackup(env, env.toolsListPath)
		},
	}
}

// renderDefaultToolsList emits the v0.2 default allow-list. Format is
// well-known across plk-launch + add-tool + readToolsList: one line per
// entry, tab-separated NAME and absolute TARGET path (empty target means
// "use pipelock-agent PATH at runtime"). Lines beginning with '#' and blank
// lines are comments — preserved on rewrite so an operator can leave a
// note.
func renderDefaultToolsList() string {
	return renderToolsList(defaultToolEntriesWithoutTargets())
}

// defaultToolNames mirrors defaultToolWrappers minus the "plk-" prefix.
func defaultToolNames() []string {
	out := make([]string, 0, len(defaultToolWrappers))
	for _, w := range defaultToolWrappers {
		out = append(out, strings.TrimPrefix(w, "plk-"))
	}
	return out
}

func defaultToolEntriesWithoutTargets() []toolsListEntry {
	names := defaultToolNames()
	out := make([]toolsListEntry, 0, len(names))
	for _, name := range names {
		out = append(out, toolsListEntry{name: name})
	}
	return out
}

func resolvableDefaultToolEntries(env *installEnv) []toolsListEntry {
	names := defaultToolNames()
	out := make([]toolsListEntry, 0, len(names))
	for _, name := range names {
		target, ok := resolveToolInAgentPath(env, name)
		if ok {
			out = append(out, toolsListEntry{name: name, target: target})
		}
	}
	return out
}

func resolveToolInAgentPath(env *installEnv, name string) (string, bool) {
	for _, dir := range filepath.SplitList(agentExecPath(env.agentUserName)) {
		if dir == "" {
			continue
		}
		candidate := filepath.Join(dir, name)
		info, err := env.stat(candidate)
		if err == nil && !info.IsDir() && info.Mode().Perm()&0o111 != 0 {
			return candidate, true
		}
	}
	return "", false
}

func mergeDefaultToolEntries(existing, defaults []toolsListEntry) ([]toolsListEntry, bool) {
	defaultNames := make(map[string]bool, len(defaultToolWrappers))
	for _, name := range defaultToolNames() {
		defaultNames[name] = true
	}
	merged := make([]toolsListEntry, 0, len(existing)+len(defaults))
	merged = append(merged, defaults...)
	for _, e := range existing {
		if defaultNames[e.name] {
			continue
		}
		merged = append(merged, e)
	}
	return merged, !toolsListEntriesEqual(existing, merged)
}

// toolsListEntry is one row of /etc/pipelock/contain/tools.list.
type toolsListEntry struct {
	name   string
	target string // empty = resolve via pipelock-agent PATH at runtime
}

// readToolsList parses the runtime allow-list. Blank and comment lines
// are ignored, but malformed policy lines fail closed: tools.list is an
// enforcement artifact, so corruption must be visible to install/verify.
func readToolsList(env *installEnv) ([]toolsListEntry, error) {
	data, err := env.readFile(env.toolsListPath)
	if err != nil {
		return nil, err
	}
	return parseToolsList(data)
}

func parseToolsList(data []byte) ([]toolsListEntry, error) {
	var entries []toolsListEntry
	for lineNo, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("malformed tools.list line %d: missing tab separator", lineNo+1)
		}
		name := strings.TrimSpace(parts[0])
		if !addToolNamePattern.MatchString(name) {
			return nil, fmt.Errorf("malformed tools.list line %d: invalid tool name %q", lineNo+1, name)
		}
		target := strings.TrimSpace(parts[1])
		if target != "" && !filepath.IsAbs(target) {
			return nil, fmt.Errorf("malformed tools.list line %d: target %q is not absolute", lineNo+1, target)
		}
		entries = append(entries, toolsListEntry{name: name, target: target})
	}
	return entries, nil
}

// writeToolsList renders entries back to disk preserving the header
// comments produced by renderDefaultToolsList. Used by add-tool.
func writeToolsList(env *installEnv, entries []toolsListEntry) error {
	dir := filepath.Dir(env.toolsListPath)
	if err := ensureSafeDirectory(env, dir); err != nil {
		return err
	}
	if err := env.mkdirAll(dir, modeDirTraversable); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	if err := env.chmod(dir, modeDirTraversable); err != nil {
		return fmt.Errorf("chmod %s: %w", dir, err)
	}
	return backupAndWrite(env, env.toolsListPath, []byte(renderToolsList(entries)), modeAllowListReadable)
}

func renderToolsList(entries []toolsListEntry) string {
	var b strings.Builder
	b.WriteString("# Managed by `pipelock contain install / add-tool`. " +
		"One tool per line, tab-separated NAME\\tTARGET.\n" +
		"# Empty TARGET means: resolve via pipelock-agent's PATH at exec time.\n")
	for _, e := range entries {
		b.WriteString(e.name)
		b.WriteByte('\t')
		b.WriteString(e.target)
		b.WriteByte('\n')
	}
	return b.String()
}

// upsertToolEntry inserts or updates a tool entry in the allow-list.
// Returns (changed, error). When changed=false the file already contained
// an identical entry; caller can short-circuit instead of rewriting.
func upsertToolEntry(env *installEnv, name, target string) (bool, error) {
	entries, err := readToolsList(env)
	if err != nil {
		// Missing file: start fresh with the defaults plus this entry.
		if errors.Is(err, os.ErrNotExist) {
			entries = resolvableDefaultToolEntries(env)
		} else {
			return false, fmt.Errorf("read tools.list: %w", err)
		}
	}
	for i := range entries {
		if entries[i].name == name {
			if entries[i].target == target {
				return false, nil
			}
			entries[i].target = target
			return true, writeToolsList(env, entries)
		}
	}
	entries = append(entries, toolsListEntry{name: name, target: target})
	return true, writeToolsList(env, entries)
}

func toolsListEntriesEqual(a, b []toolsListEntry) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Step 1: preflight
// ---------------------------------------------------------------------------

func stepPreflight(_ installOpts) step {
	return step{
		name: "preflight",
		desc: "preflight: required binaries present (useradd / systemctl / nft / visudo)",
		apply: func(_ context.Context, _ *installEnv) (bool, error) {
			for _, b := range []string{"useradd", "userdel", "systemctl", "nft", "visudo"} {
				if err := expectExec(b); err != nil {
					return false, err
				}
			}
			return true, nil
		},
		// Preflight is read-only. Nothing to undo.
		undo: nil,
	}
}

// ---------------------------------------------------------------------------
// Step 2/3: create system users
// ---------------------------------------------------------------------------

// stepCreateUser builds a step that creates either pipelock-proxy or
// pipelock-agent. proxyUser=true means we're creating the proxy user (no login
// shell, /var/lib/pipelock-proxy home). Otherwise pipelock-agent (bash shell so
// tools can resolve PATH/HOME, /home/pipelock-agent home).
func stepCreateUser(proxyUser bool) step {
	pick := func(env *installEnv) (name, shell, home string) {
		if proxyUser {
			return env.proxyUserName, "/usr/sbin/nologin", "/var/lib/" + env.proxyUserName
		}
		return env.agentUserName, "/bin/bash", "/home/" + env.agentUserName
	}
	return step{
		name: func() string {
			if proxyUser {
				return "create-proxy-user"
			}
			return "create-agent-user"
		}(),
		desc: func() string {
			if proxyUser {
				return "create pipelock-proxy system user (no login shell)"
			}
			return "create pipelock-agent system user (bash shell, denied direct egress)"
		}(),
		apply: func(ctx context.Context, env *installEnv) (bool, error) {
			name, shell, home := pick(env)
			if _, err := env.lookupUser(name); err == nil {
				return false, nil // already exists
			} else if !errors.As(err, new(user.UnknownUserError)) {
				return false, fmt.Errorf("user lookup %s: %w", name, err)
			}
			args := []string{
				"--system",
				"--shell", shell,
				"--home-dir", home,
				"--create-home",
				"--user-group",
				name,
			}
			return true, runOrErr(ctx, env, "useradd", args...)
		},
		undo: func(ctx context.Context, env *installEnv) error {
			name, _, _ := pick(env)
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

// ---------------------------------------------------------------------------
// Step 4/5: create system dirs
// ---------------------------------------------------------------------------

func stepCreateDir(label string, pathFn func(*installEnv) string, mode os.FileMode) step {
	return step{
		name: "create-dir-" + label,
		desc: "create " + label + " directory",
		apply: func(_ context.Context, env *installEnv) (bool, error) {
			path := pathFn(env)
			info, err := env.lstat(path)
			if err == nil {
				if info.Mode()&os.ModeSymlink != 0 {
					return false, fmt.Errorf("%s is a symlink; refusing to create install directory", path)
				}
				if !info.IsDir() {
					return false, fmt.Errorf("%s exists and is not a directory", path)
				}
				// Even if dir exists, ensure mode matches.
				if err := env.chmod(path, mode); err != nil {
					return false, fmt.Errorf("chmod %s: %w", path, err)
				}
				return false, nil
			}
			if !errors.Is(err, os.ErrNotExist) {
				return false, fmt.Errorf("stat %s: %w", path, err)
			}
			if err := rejectSymlinkParents(env, path); err != nil {
				return false, err
			}
			if err := env.mkdirAll(path, mode); err != nil {
				return false, fmt.Errorf("mkdir %s: %w", path, err)
			}
			if err := env.chmod(path, mode); err != nil {
				return false, fmt.Errorf("chmod %s: %w", path, err)
			}
			return true, nil
		},
		undo: func(_ context.Context, env *installEnv) error {
			path := pathFn(env)
			// Only remove if it's empty AND we created it. We don't keep a
			// flag; we just refuse to remove non-empty dirs to avoid losing
			// operator data.
			if err := env.removeFile(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil // best-effort; dir non-empty or in use
			}
			return nil
		},
	}
}

// ---------------------------------------------------------------------------
// Step 6: write pipelock.yaml
// ---------------------------------------------------------------------------

func stepWritePipelockConfig(opts installOpts) step {
	const targetName = "pipelock.yaml"
	var migrated []migratedConfigArtifact
	var configWritten bool
	return step{
		name: "write-pipelock-config",
		desc: "write /etc/pipelock/pipelock.yaml (from --config, with home-path migration)",
		apply: func(_ context.Context, env *installEnv) (bool, error) {
			migrated = nil
			configWritten = false
			if opts.configSource == "" {
				return false, nil
			}
			dst := filepath.Join(env.configDir, targetName)
			data, err := env.readFile(opts.configSource)
			if err != nil {
				return false, fmt.Errorf("read --config %s: %w", opts.configSource, err)
			}
			data, migrated, err = migratePipelockConfigForContain(env, opts.configSource, data)
			if err != nil {
				_ = cleanupMigratedConfigArtifacts(env, migrated)
				return false, err
			}
			// Compare with the existing config (if any). Identical -> skip
			// silently. Different -> overwrite with .bak, and print a loud
			// warning so an operator running install twice with different
			// --config values is never silently misled about which one is
			// live. The previous "skip if exists" behaviour hid that case.
			if existing, err := env.readFile(dst); err == nil {
				if bytesEqual(existing, data) {
					return len(migrated) > 0, nil
				}
				_, _ = fmt.Fprintf(env.out,
					"  WARN: --config %s differs from existing %s; overwriting (prior content saved to %s.bak)\n",
					opts.configSource, dst, dst)
			}
			if err := backupAndWrite(env, dst, data, modeConfigSecret); err != nil {
				_ = cleanupMigratedConfigArtifacts(env, migrated)
				return false, err
			}
			configWritten = true
			return true, nil
		},
		undo: func(_ context.Context, env *installEnv) error {
			dst := filepath.Join(env.configDir, targetName)
			var configErr error
			if configWritten {
				configErr = restoreBackup(env, dst)
			}
			return errors.Join(configErr, cleanupMigratedConfigArtifacts(env, migrated))
		},
	}
}

// bytesEqual compares two byte slices without dragging in the bytes
// import for one call site. Equivalent to bytes.Equal.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Step 7/8: chown dirs to pipelock-proxy
// ---------------------------------------------------------------------------

func stepChownToProxy(label string, pathFn func(*installEnv) string) step {
	return step{
		name: "chown-" + label,
		desc: "chown " + label + " directory to pipelock-proxy:pipelock-proxy",
		apply: func(_ context.Context, env *installEnv) (bool, error) {
			path := pathFn(env)
			uid, gid, err := uidGidFor(env, env.proxyUserName)
			if err != nil {
				return false, err
			}
			return true, walkAndChown(env, path, uid, gid)
		},
		// undo intentionally absent: chown back to root is safe and what
		// removing /etc/pipelock on a follow-up rollback would do anyway.
		undo: nil,
	}
}

// walkAndChown chowns path and every descendant. Used because the runbook
// runs `chown -R` and the install needs the same recursive ownership.
func walkAndChown(env *installEnv, root string, uid, gid int) error {
	root = filepath.Clean(root)
	return filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walk %s: %w", p, err)
		}
		p = filepath.Clean(p)
		rel, err := filepath.Rel(root, p)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return fmt.Errorf("refusing to chown path outside %s: %s", root, p)
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if err := env.chown(p, uid, gid); err != nil {
			return fmt.Errorf("chown %s: %w", p, err)
		}
		return nil
	})
}

// ---------------------------------------------------------------------------
// Step 9: install pipelock binary
// ---------------------------------------------------------------------------

func stepInstallPipelockBinary() step {
	return step{
		name: "install-pipelock-binary",
		desc: "install pipelock binary to /usr/local/bin/pipelock (0o755)",
		apply: func(_ context.Context, env *installEnv) (bool, error) {
			data, err := env.readFile(env.pipelockBinary)
			if err != nil {
				return false, fmt.Errorf("read source binary: %w", err)
			}

			// Idempotency: if /usr/local/bin/pipelock exists AND its sha256
			// matches the source, skip. This makes rerunning install over an
			// up-to-date system a no-op.
			if pathExists(env, env.pipelockTarget) {
				srcHash, err := env.hashFile(env.pipelockBinary)
				if err != nil {
					return false, err
				}
				dstHash, err := env.hashFile(env.pipelockTarget)
				if err == nil && srcHash == dstHash {
					return false, nil
				}
			}
			if err := backupAndWrite(env, env.pipelockTarget, data, modeWrapperExec); err != nil {
				return false, err
			}
			return true, nil
		},
		undo: func(_ context.Context, env *installEnv) error {
			return restoreBackup(env, env.pipelockTarget)
		},
	}
}

// ---------------------------------------------------------------------------
// Step 10: write integrity pin
// ---------------------------------------------------------------------------

func stepWriteIntegrityPin() step {
	return step{
		name: "write-integrity-pin",
		desc: "pin installed binary SHA-256 (TOFU) to /etc/pipelock/integrity/binary-pin.sha256",
		apply: func(_ context.Context, env *installEnv) (bool, error) {
			if !pathExists(env, env.pipelockTarget) {
				return false, fmt.Errorf("pipelock binary not installed at %s", env.pipelockTarget)
			}
			if err := env.mkdirAll(env.integrityDir, modeDirSystem); err != nil {
				return false, fmt.Errorf("mkdir %s: %w", env.integrityDir, err)
			}
			hash, err := env.hashFile(env.pipelockTarget)
			if err != nil {
				return false, err
			}
			contents := []byte(hash + "\n")

			// Idempotency: if the pin already matches, skip.
			if existing, err := env.readFile(env.integrityPin); err == nil {
				if strings.TrimSpace(string(existing)) == hash {
					if err := ensureIntegrityOwnership(env); err != nil {
						return false, err
					}
					return false, nil
				}
			}
			if err := backupAndWrite(env, env.integrityPin, contents, modePinSecret); err != nil {
				return false, err
			}
			// Pin file ownership: pipelock-proxy owns the private
			// integrity directory and pin. pipelock-agent cannot traverse it.
			if err := ensureIntegrityOwnership(env); err != nil {
				return false, err
			}
			return true, nil
		},
		undo: func(_ context.Context, env *installEnv) error {
			return restoreBackup(env, env.integrityPin)
		},
	}
}

func ensureIntegrityOwnership(env *installEnv) error {
	uid, gid, err := uidGidFor(env, env.proxyUserName)
	if err != nil {
		return err
	}
	if err := env.chmod(env.integrityDir, modeDirPrivate); err != nil {
		return fmt.Errorf("chmod %s: %w", env.integrityDir, err)
	}
	if err := env.chown(env.integrityDir, uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", env.integrityDir, err)
	}
	if err := env.chmod(env.integrityPin, modePinSecret); err != nil {
		return fmt.Errorf("chmod %s: %w", env.integrityPin, err)
	}
	if err := env.chown(env.integrityPin, uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", env.integrityPin, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Step 11: stop the user-mode pipelock service
// ---------------------------------------------------------------------------

func stepStopUserService() step {
	var stopped bool
	return step{
		name: "stop-user-pipelock",
		desc: "stop the operator's user-mode pipelock.service (if running)",
		apply: func(ctx context.Context, env *installEnv) (bool, error) {
			if env.operatorUser == "" {
				return false, nil
			}
			// Best-effort: query is-active first; only stop if active.
			out, _, _ := env.runCmd(ctx, "systemctl", "--user", "-M", env.operatorUser+"@.host", "is-active", "pipelock")
			if strings.TrimSpace(out) != systemctlActive {
				return false, nil
			}
			if err := runOrErr(ctx, env, "systemctl", "--user", "-M", env.operatorUser+"@.host", "stop", "pipelock"); err != nil {
				return true, err
			}
			stopped = true
			return true, nil
		},
		// undo restarts only when this install attempt actually stopped
		// the operator service. It deliberately does not enable/disable
		// the unit, preserving the operator's previous enablement state.
		undo: func(ctx context.Context, env *installEnv) error {
			if env.operatorUser == "" || !stopped {
				return nil
			}
			return runOrErr(ctx, env, "systemctl", "--user", "-M", env.operatorUser+"@.host", "start", "pipelock")
		},
	}
}

// ---------------------------------------------------------------------------
// Step 12: write the system pipelock.service unit
// ---------------------------------------------------------------------------

func stepWriteSystemUnit() step {
	return step{
		name: "write-system-unit",
		desc: "write /etc/systemd/system/pipelock.service",
		apply: func(_ context.Context, env *installEnv) (bool, error) {
			body := renderSystemUnit(env)
			// Idempotency: only write if content differs.
			if existing, err := env.readFile(env.systemUnitPath); err == nil && string(existing) == body {
				return false, nil
			}
			if err := backupAndWrite(env, env.systemUnitPath, []byte(body), modeUnitFile); err != nil {
				return false, err
			}
			return true, nil
		},
		undo: func(ctx context.Context, env *installEnv) error {
			if err := restoreBackup(env, env.systemUnitPath); err != nil {
				return err
			}
			_, _, _ = env.runCmd(ctx, "systemctl", "daemon-reload")
			return nil
		},
	}
}

// renderSystemUnit produces the pipelock.service body. Inline here so tests
// can call it directly without a tmpdir. The hardening directives mirror
// the runbook; the firewall is the real boundary, these are defense in
// depth.
func renderSystemUnit(env *installEnv) string {
	configPath := filepath.Join(env.configDir, "pipelock.yaml")
	capturePath := filepath.Join(env.dataDir, "captures")
	return strings.Join([]string{
		"[Unit]",
		"Description=Pipelock AI Egress Proxy",
		"Documentation=https://github.com/luckyPipewrench/pipelock",
		"After=network-online.target",
		"Wants=network-online.target",
		"",
		"[Service]",
		"Type=simple",
		"User=" + env.proxyUserName,
		"Group=" + env.proxyUserName,
		"ExecStart=" + env.pipelockTarget + " run --config " + configPath + " --capture-output " + capturePath,
		"Restart=on-failure",
		"RestartSec=5",
		"",
		"NoNewPrivileges=true",
		"ProtectSystem=strict",
		"ProtectHome=true",
		"ReadWritePaths=" + env.dataDir,
		"PrivateTmp=true",
		"ProtectKernelTunables=true",
		"ProtectKernelModules=true",
		"ProtectControlGroups=true",
		"RestrictNamespaces=true",
		"LockPersonality=true",
		"MemoryDenyWriteExecute=true",
		"RestrictRealtime=true",
		"RestrictSUIDSGID=true",
		"",
		"[Install]",
		"WantedBy=multi-user.target",
		"",
	}, "\n")
}

// ---------------------------------------------------------------------------
// Step 13: daemon-reload + enable --now
// ---------------------------------------------------------------------------

func stepEnableSystemUnit() step {
	var preStateKnown bool
	var wasActive bool
	var wasEnabled bool
	return step{
		name: "enable-system-pipelock",
		desc: "systemctl daemon-reload + enable --now pipelock.service",
		apply: func(ctx context.Context, env *installEnv) (bool, error) {
			if err := runOrErr(ctx, env, "systemctl", "daemon-reload"); err != nil {
				return false, err
			}
			activeOut, _, _ := env.runCmd(ctx, "systemctl", "is-active", "pipelock")
			enabledOut, _, _ := env.runCmd(ctx, "systemctl", "is-enabled", "pipelock")
			wasActive = strings.TrimSpace(activeOut) == systemctlActive
			wasEnabled = strings.TrimSpace(enabledOut) == systemctlEnabled
			preStateKnown = true
			if wasActive && wasEnabled {
				// Re-issuing enable when already enabled is a no-op anyway,
				// but skip to keep the dry-run/run output clean.
				return false, nil
			}
			return true, runOrErr(ctx, env, "systemctl", "enable", "--now", "pipelock")
		},
		undo: func(ctx context.Context, env *installEnv) error {
			if !preStateKnown {
				// Explicit rollback command path: no apply pre-state exists,
				// so remove the containment-managed system service.
				_, _, _ = env.runCmd(ctx, "systemctl", "disable", "--now", "pipelock")
				_, _, _ = env.runCmd(ctx, "systemctl", "daemon-reload")
				return nil
			}
			if !wasEnabled {
				_, _, _ = env.runCmd(ctx, "systemctl", "disable", "pipelock")
			}
			if !wasActive {
				_, _, _ = env.runCmd(ctx, "systemctl", "stop", "pipelock")
			}
			_, _, _ = env.runCmd(ctx, "systemctl", "daemon-reload")
			return nil
		},
	}
}

// ---------------------------------------------------------------------------
// Step 14: export pipelock TLS CA
// ---------------------------------------------------------------------------

func stepExportPipelockCA() step {
	wrote := false
	return step{
		name: "export-pipelock-ca",
		desc: "export pipelock TLS-MITM CA to /etc/pipelock/ca.pem",
		apply: func(ctx context.Context, env *installEnv) (bool, error) {
			wrote = false
			if pathExists(env, env.caExportPath) {
				return false, nil
			}
			// Run as pipelock-proxy so the CA lookup uses the running
			// instance's data dir layout. The pipelock CLI writes the CA
			// PEM to stdout via `tls show-ca` — there is no --output flag,
			// so we capture stdout here and write the file in Go after a
			// PEM-shape sanity check.
			if err := exportPipelockCA(ctx, env); err != nil {
				return false, err
			}
			wrote = true
			return true, nil
		},
		undo: func(_ context.Context, env *installEnv) error {
			if !wrote {
				return nil
			}
			if err := env.removeFile(env.caExportPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove %s: %w", env.caExportPath, err)
			}
			return nil
		},
	}
}

// ---------------------------------------------------------------------------
// Step 15: write /etc/pipelock/combined-ca.pem
// ---------------------------------------------------------------------------

func stepWriteCombinedCABundle() step {
	return step{
		name: "write-combined-ca",
		desc: "build /etc/pipelock/combined-ca.pem (system bundle + pipelock CA)",
		apply: func(_ context.Context, env *installEnv) (bool, error) {
			sys, err := env.readFile(defaultSystemCABundle)
			if err != nil {
				return false, fmt.Errorf("read system CA bundle %s: %w", defaultSystemCABundle, err)
			}
			pl, err := env.readFile(env.caExportPath)
			if err != nil {
				return false, fmt.Errorf("read pipelock CA %s: %w", env.caExportPath, err)
			}
			bundle := append([]byte{}, sys...)
			if len(bundle) > 0 && bundle[len(bundle)-1] != '\n' {
				bundle = append(bundle, '\n')
			}
			bundle = append(bundle, pl...)

			if existing, err := env.readFile(env.caBundlePath); err == nil && string(existing) == string(bundle) {
				return false, nil
			}
			if err := backupAndWrite(env, env.caBundlePath, bundle, modeCAReadable); err != nil {
				return false, err
			}
			return true, nil
		},
		undo: func(_ context.Context, env *installEnv) error {
			return restoreBackup(env, env.caBundlePath)
		},
	}
}

// ---------------------------------------------------------------------------
// Step 16: nftables rules (write + validate + load + enable service)
// ---------------------------------------------------------------------------

func stepInstallNFTRules() step {
	return step{
		name: "install-nft-rules",
		desc: "write + load /etc/nftables.d/50-pipelock-containment.nft + persist via nftables.service",
		apply: func(ctx context.Context, env *installEnv) (bool, error) {
			operatorUID, err := operatorUIDFromEnv(env)
			if err != nil {
				return false, err
			}
			proxyUID, agentUID, err := resolveUIDs(env)
			if err != nil {
				return false, err
			}
			body := renderNFTRules(operatorUID, proxyUID, agentUID, env.proxyPort, env.nftTableOrDefault(), env.nftChainOrDefault())

			rulesMatch := false
			if existing, err := env.readFile(env.nftRulesPath); err == nil {
				rulesMatch = string(existing) == body
			} else if !errors.Is(err, os.ErrNotExist) {
				return false, fmt.Errorf("read %s: %w", env.nftRulesPath, err)
			}
			tableLoaded := false
			liveRulesDrifted := false
			if out, code, _ := env.runCmd(ctx, "nft", "list", "table", "inet", env.nftTableOrDefault()); code == 0 {
				tableLoaded = true
				liveRulesDrifted = !liveNFTContainmentMatches(out, env.nftChainOrDefault(), env.proxyPort)
			}

			rulesChanged := false
			if !rulesMatch {
				if err := env.mkdirAll(filepath.Dir(env.nftRulesPath), modeDirReadable); err != nil {
					return false, fmt.Errorf("mkdir %s: %w", filepath.Dir(env.nftRulesPath), err)
				}
				if err := env.chmod(filepath.Dir(env.nftRulesPath), modeDirReadable); err != nil {
					return false, fmt.Errorf("chmod %s: %w", filepath.Dir(env.nftRulesPath), err)
				}
				if err := backupAndWrite(env, env.nftRulesPath, []byte(body), modeNFTFile); err != nil {
					return false, err
				}
				rulesChanged = true
			}
			mainChanged, err := ensureNFTMainIncludesRules(env)
			if err != nil {
				return false, err
			}
			if mainChanged {
				_, _ = fmt.Fprintf(env.out, "WARN: added %s include to %s for nftables.service persistence\n", env.nftRulesPath, env.nftMainPath)
			}
			if !rulesChanged && !mainChanged && tableLoaded && !liveRulesDrifted {
				return false, nil
			}
			// Validate before loading.
			if err := runOrErr(ctx, env, "nft", "-c", "-f", env.nftRulesPath); err != nil {
				return false, fmt.Errorf("nft validation failed: %w", err)
			}
			if err := runOrErr(ctx, env, "nft", "-c", "-f", env.nftMainPath); err != nil {
				return false, fmt.Errorf("nft persistence validation failed: %w", err)
			}
			if tableLoaded && (rulesChanged || liveRulesDrifted) {
				captureNFTPreState(ctx, env)
				// nft -f merges into an existing table. Drop our managed table
				// first so stale rules from an older contain install cannot
				// survive beside the new ruleset.
				_, _, _ = env.runCmd(ctx, "nft", "delete", "table", "inet", env.nftTableOrDefault())
				tableLoaded = false
			}
			if !tableLoaded || rulesChanged || liveRulesDrifted {
				captureNFTPreState(ctx, env)
				if err := runOrErr(ctx, env, "nft", "-f", env.nftRulesPath); err != nil {
					return false, fmt.Errorf("nft load failed: %w", err)
				}
			}
			captureNFTPreState(ctx, env)
			if err := runOrErr(ctx, env, "systemctl", "enable", "nftables.service"); err != nil {
				return false, fmt.Errorf("enable nftables.service: %w", err)
			}
			return true, nil
		},
		undo: func(ctx context.Context, env *installEnv) error {
			// Drop the managed table best-effort, restore any previous live
			// table captured during this install attempt, then restore files.
			_, _, _ = env.runCmd(ctx, "nft", "delete", "table", "inet", env.nftTableOrDefault())
			if err := restorePreviousNFTState(ctx, env); err != nil {
				return err
			}
			if err := restoreBackup(env, env.nftRulesPath); err != nil {
				return err
			}
			if err := restoreOrRemoveNFTMainInclude(env); err != nil {
				return err
			}
			if env.prevNftablesStateKnown && !env.prevNftablesEnabled {
				if err := runOrErr(ctx, env, "systemctl", "disable", "nftables.service"); err != nil {
					return fmt.Errorf("restore nftables.service disabled state: %w", err)
				}
			}
			return nil
		},
	}
}

func captureNFTPreState(ctx context.Context, env *installEnv) {
	if env.prevNFTTableDump == "" {
		out, code, err := env.runCmd(ctx, "nft", "list", "table", "inet", env.nftTableOrDefault())
		if err == nil && code == 0 {
			env.prevNFTTableDump = out
		}
	}
	if !env.prevNftablesStateKnown {
		_, code, err := env.runCmd(ctx, "systemctl", "is-enabled", "nftables.service")
		if err == nil {
			env.prevNftablesEnabled = code == 0
			env.prevNftablesStateKnown = true
		}
	}
}

func restorePreviousNFTState(ctx context.Context, env *installEnv) error {
	if strings.TrimSpace(env.prevNFTTableDump) == "" {
		return nil
	}
	restorePath := env.nftRulesPath + ".restore"
	if err := env.writeFile(restorePath, []byte(env.prevNFTTableDump), modeConfigSecret); err != nil {
		return fmt.Errorf("write nft restore file %s: %w", restorePath, err)
	}
	defer func() { _ = env.removeFile(restorePath) }()
	if err := runOrErr(ctx, env, "nft", "-f", restorePath); err != nil {
		return fmt.Errorf("restore previous nft table: %w", err)
	}
	return nil
}

func liveNFTContainmentMatches(out, chainName string, proxyPort int) bool {
	return chainHasSkuidDrop(out, chainName) &&
		chainHasAgentProxyLoopbackAllow(out, chainName, proxyPort) &&
		!chainHasBroadLoopbackAccept(out, chainName)
}

func nftRulesIncludeLine(path string) string {
	return fmt.Sprintf("include %q", path)
}

func ensureNFTMainIncludesRules(env *installEnv) (bool, error) {
	if err := env.mkdirAll(filepath.Dir(env.nftMainPath), modeDirReadable); err != nil {
		return false, fmt.Errorf("mkdir %s: %w", filepath.Dir(env.nftMainPath), err)
	}
	if err := env.chmod(filepath.Dir(env.nftMainPath), modeDirReadable); err != nil {
		return false, fmt.Errorf("chmod %s: %w", filepath.Dir(env.nftMainPath), err)
	}

	includeLine := nftRulesIncludeLine(env.nftRulesPath)
	data, err := env.readFile(env.nftMainPath)
	if err == nil && nftMainHasInclude(string(data), includeLine) {
		return false, nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("read %s: %w", env.nftMainPath, err)
	}

	var body string
	if errors.Is(err, os.ErrNotExist) || len(data) == 0 {
		body = "# Pipelock containment persistence\n" + includeLine + "\n"
	} else {
		body = strings.TrimRight(string(data), "\n") + "\n\n# Pipelock containment persistence\n" + includeLine + "\n"
	}
	if err := backupAndWrite(env, env.nftMainPath, []byte(body), modeNFTMainConfig); err != nil {
		return false, fmt.Errorf("write %s: %w", env.nftMainPath, err)
	}
	return true, nil
}

func nftMainHasInclude(body, includeLine string) bool {
	for _, line := range strings.Split(body, "\n") {
		if strings.TrimSpace(line) == includeLine {
			return true
		}
	}
	return false
}

func restoreOrRemoveNFTMainInclude(env *installEnv) error {
	bak := env.nftMainPath + ".bak"
	if _, err := env.stat(bak); err == nil {
		return restoreBackupIfPresent(env, env.nftMainPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", bak, err)
	}
	return removeNFTMainInclude(env)
}

func removeNFTMainInclude(env *installEnv) error {
	data, err := env.readFile(env.nftMainPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read %s: %w", env.nftMainPath, err)
	}
	includeLine := nftRulesIncludeLine(env.nftRulesPath)
	lines := strings.Split(string(data), "\n")
	kept := lines[:0]
	changed := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == includeLine {
			changed = true
			if len(kept) > 0 && strings.TrimSpace(kept[len(kept)-1]) == "# Pipelock containment persistence" {
				kept = kept[:len(kept)-1]
			}
			continue
		}
		if trimmed == "# Pipelock containment persistence" && i+1 < len(lines) && strings.TrimSpace(lines[i+1]) == includeLine {
			changed = true
			continue
		}
		kept = append(kept, line)
	}
	if !changed {
		return nil
	}
	body := strings.TrimRight(strings.Join(kept, "\n"), "\n")
	if body != "" {
		body += "\n"
	}
	return env.writeFile(env.nftMainPath, []byte(body), modeNFTMainConfig)
}

// nftTableOrDefault returns the configured nft table or the package
// default. Helper makes tests easier to read.
func (e *installEnv) nftTableOrDefault() string {
	return defaultNFTTable
}

func (e *installEnv) nftChainOrDefault() string {
	return defaultNFTChain
}

// operatorUIDFromEnv returns the numeric UID for the operator-side user.
func operatorUIDFromEnv(env *installEnv) (int, error) {
	if env.operatorUser == "" {
		return 0, errors.New("operator user not set")
	}
	u, err := env.lookupUser(env.operatorUser)
	if err != nil {
		return 0, fmt.Errorf("lookup operator user %s: %w", env.operatorUser, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, fmt.Errorf("parse uid for %s: %w", env.operatorUser, err)
	}
	return uid, nil
}

// renderNFTRules emits the table definition. Matches the runbook one-to-one
// with concrete UIDs interpolated.
func renderNFTRules(operatorUID, proxyUID, agentUID, proxyPort int, table, chain string) string {
	return fmt.Sprintf(`# Pipelock containment ruleset (managed by pipelock contain install).
	# operator=%d  pipelock-proxy=%d  pipelock-agent=%d  proxy-port=%d
	table inet %s {
	    chain %s {
	        type filter hook output priority filter; policy accept;

	        meta skuid %d accept
	        meta skuid %d accept

	        meta skuid %d ip daddr 127.0.0.1 tcp dport %d accept
	        meta skuid %d drop
	    }
	}
	`, operatorUID, proxyUID, agentUID, proxyPort, table, chain,
		operatorUID, proxyUID, agentUID, proxyPort, agentUID)
}

// ---------------------------------------------------------------------------
// Step 17: write plk-launch
// ---------------------------------------------------------------------------

func stepWriteLaunchWrapper() step {
	return step{
		name: "write-plk-launch",
		desc: "write /usr/local/bin/plk-launch (runs AS pipelock-agent with proxy env)",
		apply: func(_ context.Context, env *installEnv) (bool, error) {
			body := renderLaunchWrapper(env)
			path := filepath.Join(env.wrapperDir, "plk-launch")
			if existing, err := env.readFile(path); err == nil && string(existing) == body {
				_ = env.chmod(path, modeWrapperExec)
				return false, nil
			}
			if err := backupAndWrite(env, path, []byte(body), modeWrapperExec); err != nil {
				return false, err
			}
			return true, nil
		},
		undo: func(_ context.Context, env *installEnv) error {
			path := filepath.Join(env.wrapperDir, "plk-launch")
			return restoreBackup(env, path)
		},
	}
}

// renderLaunchWrapper emits the plk-launch script body. plk-launch reads
// the runtime allow-list at /etc/pipelock/contain/tools.list and refuses
// to exec any tool that isn't in it. The allow-list itself is root-owned
// but pipelock-agent-readable; root-owned directory permissions gate mutation,
// so plk-launch's tool argument can be operator-controlled without
// granting arbitrary command execution as pipelock-agent.
//
// Per the locked sudo-shape decision: per-tool wrappers do the outer
// sudo, plk-launch already runs AS pipelock-agent, no nested sudo here.
func renderLaunchWrapper(env *installEnv) string {
	port := strconv.Itoa(env.proxyPort)
	proxy := "http://127.0.0.1:" + port
	return strings.Join([]string{
		"#!/bin/bash",
		"# Managed by `pipelock contain install`. Edits are clobbered on next install.",
		"# Runs AS pipelock-agent. Validates the tool name against the install-time",
		"# allow-list (root-mutated, pipelock-agent-readable at " + env.toolsListPath + ") before exec.",
		"set -euo pipefail",
		"",
		"TOOLS_LIST=" + shellQuote(env.toolsListPath),
		"",
		`if [[ $# -lt 1 ]]; then`,
		`    echo "usage: plk-launch <tool> [args...]" >&2`,
		`    exit 2`,
		`fi`,
		`TOOL="$1"; shift`,
		"",
		`# Reject tool names that violate the shared install-time regex.`,
		`# Same pattern is enforced in the plk meta-wrapper so the two`,
		`# layers never drift.`,
		`if [[ ! "$TOOL" =~ ` + containToolNameRegex + ` ]]; then`,
		`    echo "plk-launch: invalid tool name $TOOL" >&2`,
		`    exit 3`,
		`fi`,
		"",
		`if [[ ! -r "$TOOLS_LIST" ]]; then`,
		`    echo "plk-launch: missing allow-list at $TOOLS_LIST (run pipelock contain install)" >&2`,
		`    exit 4`,
		`fi`,
		"",
		`# Look up the tool in the allow-list. The file format is one entry`,
		`# per line, tab-separated NAME\tTARGET. Empty TARGET means "resolve`,
		`# at runtime via the pipelock-agent PATH".`,
		`TARGET=""`,
		`FOUND=0`,
		`while IFS= read -r line; do`,
		`    case "$line" in ''|'#'*) continue ;; esac`,
		`    if [[ "$line" != *$'\t'* ]]; then`,
		`        echo "plk-launch: malformed allow-list entry missing tab separator" >&2`,
		`        exit 9`,
		`    fi`,
		`    IFS=$'\t' read -r name target <<< "$line"`,
		`    case "$name" in *[!a-z0-9_-]*|"") echo "plk-launch: malformed allow-list entry for $name" >&2; exit 9 ;; esac`,
		`    if [[ -n "$target" && "$target" != /* ]]; then`,
		`        echo "plk-launch: malformed allow-list target $target for $name" >&2`,
		`        exit 9`,
		`    fi`,
		`    if [[ "$name" == "$TOOL" ]]; then`,
		`        TARGET="$target"`,
		`        FOUND=1`,
		`        break`,
		`    fi`,
		`done < "$TOOLS_LIST"`,
		"",
		`if (( FOUND == 0 )); then`,
		`    echo "plk-launch: tool $TOOL not in pipelock contain allow-list" >&2`,
		`    exit 5`,
		`fi`,
		"",
		`# Resolve target. If tools.list baked in an absolute path, use it.`,
		`# Otherwise look up the binary in the SAME PATH we will exec under,`,
		`# not the wrapper process's inherited PATH — sudo's secure_path or`,
		`# the caller's environment would otherwise leak through.`,
		"AGENT_PATH=" + agentExecPath(env.agentUserName),
		`if [[ -z "$TARGET" ]]; then`,
		`    TARGET="$(PATH="$AGENT_PATH" command -v "$TOOL")" || {`,
		`        echo "plk-launch: $TOOL not found in pipelock-agent PATH" >&2`,
		`        exit 6`,
		`    }`,
		`fi`,
		`if [[ "$TARGET" != /* ]]; then`,
		`    echo "plk-launch: refusing non-absolute target $TARGET for $TOOL" >&2`,
		`    exit 7`,
		`fi`,
		`if [[ ! -x "$TARGET" ]]; then`,
		`    echo "plk-launch: target $TARGET for $TOOL is not executable" >&2`,
		`    exit 8`,
		`fi`,
		"",
		"exec env \\",
		"    HOME=/home/" + env.agentUserName + " \\",
		"    HTTPS_PROXY=" + proxy + " \\",
		"    HTTP_PROXY=" + proxy + " \\",
		"    ALL_PROXY=" + proxy + " \\",
		"    NO_PROXY=127.0.0.1,localhost \\",
		"    NODE_EXTRA_CA_CERTS=" + env.caExportPath + " \\",
		"    SSL_CERT_FILE=" + env.caBundlePath + " \\",
		"    REQUESTS_CA_BUNDLE=" + env.caBundlePath + " \\",
		"    CURL_CA_BUNDLE=" + env.caBundlePath + " \\",
		`    PATH="$AGENT_PATH" \`,
		`    "$TARGET" "$@"`,
		"",
	}, "\n")
}

// shellQuote single-quotes a string for safe inclusion in a bash literal.
// Escapes embedded single quotes. The tools-list path comes from an
// installEnv field controlled by the operator (--config / defaults), not
// from agent input, but quoting it makes the rendered script robust to
// future refactors.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// ---------------------------------------------------------------------------
// Step 18: write per-tool wrappers for allow-listed tools.
// ---------------------------------------------------------------------------

func stepWriteMetaWrapper() step {
	return step{
		name: "write-plk-meta-wrapper",
		desc: "write /usr/local/bin/plk (dispatches to plk-launch)",
		apply: func(_ context.Context, env *installEnv) (bool, error) {
			body := renderMetaWrapper(env)
			path := filepath.Join(env.wrapperDir, "plk")
			if existing, err := env.readFile(path); err == nil && string(existing) == body {
				_ = env.chmod(path, modeWrapperExec)
				return false, nil
			}
			if err := backupAndWrite(env, path, []byte(body), modeWrapperExec); err != nil {
				return false, err
			}
			return true, nil
		},
		undo: func(_ context.Context, env *installEnv) error {
			path := filepath.Join(env.wrapperDir, "plk")
			return restoreBackup(env, path)
		},
	}
}

func renderMetaWrapper(env *installEnv) string {
	return strings.Join([]string{
		"#!/bin/bash",
		"# Managed by `pipelock contain install`. Edits are clobbered on next install.",
		"set -euo pipefail",
		"",
		`if [[ $# -lt 1 ]]; then`,
		`    echo "usage: plk <tool> [args...]" >&2`,
		`    exit 2`,
		`fi`,
		`if [[ ! "$1" =~ ` + containToolNameRegex + ` ]]; then`,
		`    echo "plk: invalid tool name $1" >&2`,
		`    exit 3`,
		`fi`,
		"TOOLS_LIST=" + shellQuote(env.toolsListPath),
		`if [[ ! -s "$TOOLS_LIST" ]]; then`,
		`    echo "plk: missing or empty allow-list at $TOOLS_LIST (run pipelock contain install)" >&2`,
		`    exit 4`,
		`fi`,
		"exec sudo -n -u " + env.agentUserName + " " + filepath.Join(env.wrapperDir, "plk-launch") + ` "$@"`,
		"",
	}, "\n")
}

func stepWriteToolWrappers() step {
	var touched []string
	return step{
		name: "write-tool-wrappers",
		desc: "write plk-* wrappers for allow-listed tools",
		apply: func(_ context.Context, env *installEnv) (bool, error) {
			touched = nil
			restoreTouched := func(cause error) (bool, error) {
				var errs []error
				errs = append(errs, cause)
				for i := len(touched) - 1; i >= 0; i-- {
					if err := restoreBackup(env, touched[i]); err != nil {
						errs = append(errs, err)
					}
				}
				return false, errors.Join(errs...)
			}
			entries, err := readToolsList(env)
			if err != nil {
				return false, fmt.Errorf("read tools.list: %w", err)
			}
			desired := wrapperNamesForEntries(entries)
			desiredSet := make(map[string]bool, len(desired))
			for _, wrapper := range desired {
				desiredSet[wrapper] = true
				name := strings.TrimPrefix(wrapper, "plk-")
				path := filepath.Join(env.wrapperDir, wrapper)
				body := renderToolWrapper(env, name)
				if existing, err := env.readFile(path); err == nil && string(existing) == body {
					_ = env.chmod(path, modeWrapperExec)
					continue
				}
				if err := backupAndWrite(env, path, []byte(body), modeWrapperExec); err != nil {
					return restoreTouched(fmt.Errorf("write %s: %w", path, err))
				}
				touched = append(touched, path)
			}
			for _, wrapper := range defaultToolWrappers {
				if desiredSet[wrapper] {
					continue
				}
				path := filepath.Join(env.wrapperDir, wrapper)
				if _, err := env.stat(path); err == nil {
					if _, err := backupCurrentToBak(env, path); err != nil {
						return restoreTouched(fmt.Errorf("backup stale wrapper %s: %w", path, err))
					}
					if err := env.removeFile(path); err != nil && !errors.Is(err, os.ErrNotExist) {
						return restoreTouched(fmt.Errorf("remove stale wrapper %s: %w", path, err))
					}
					touched = append(touched, path)
				} else if !errors.Is(err, os.ErrNotExist) {
					return restoreTouched(fmt.Errorf("stat stale wrapper %s: %w", path, err))
				}
			}
			return len(touched) > 0, nil
		},
		undo: func(_ context.Context, env *installEnv) error {
			var errs []error
			for i := len(touched) - 1; i >= 0; i-- {
				path := touched[i]
				if err := restoreBackup(env, path); err != nil {
					errs = append(errs, err)
				}
			}
			return errors.Join(errs...)
		},
	}
}

func wrapperNamesForEntries(entries []toolsListEntry) []string {
	out := make([]string, 0, len(entries))
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		wrapper := "plk-" + entry.name
		if seen[wrapper] {
			continue
		}
		seen[wrapper] = true
		out = append(out, wrapper)
	}
	return out
}

// renderToolWrapper emits a per-tool wrapper that does the outer sudo so
// the operator just types `plk-claude foo` instead of `sudo plk-launch claude foo`.
// `-n` (non-interactive) makes the wrapper fail fast if the sudoers rule
// does not match instead of hanging on a password prompt — the rule we
// install is NOPASSWD-scoped so the legitimate case never prompts.
func renderToolWrapper(env *installEnv, tool string) string {
	return strings.Join([]string{
		"#!/bin/bash",
		"# Managed by `pipelock contain install`. Edits are clobbered on next install.",
		"exec sudo -n -u " + env.agentUserName + " " + filepath.Join(env.wrapperDir, "plk-launch") + " " + tool + ` "$@"`,
		"",
	}, "\n")
}

// ---------------------------------------------------------------------------
// Step 19: write wrapper inventory (so verify probe 4 can enumerate)
// ---------------------------------------------------------------------------

type wrapperInventory struct {
	Wrappers []string `json:"wrappers"`
}

func stepWriteWrapperInventory() step {
	return step{
		name: "write-wrapper-inventory",
		desc: "record wrapper inventory in /etc/pipelock/contain/wrappers.json",
		apply: func(_ context.Context, env *installEnv) (bool, error) {
			// Parent dir must be traversable by pipelock-agent (shared with
			// tools.list). The file itself is pipelock-agent-readable so verify
			// probe 4 can enumerate wrappers under unprivileged invocation.
			if err := env.mkdirAll(filepath.Dir(env.wrapperInvPath), modeDirTraversable); err != nil {
				return false, fmt.Errorf("mkdir %s: %w", filepath.Dir(env.wrapperInvPath), err)
			}
			if err := env.chmod(filepath.Dir(env.wrapperInvPath), modeDirTraversable); err != nil {
				return false, fmt.Errorf("chmod %s: %w", filepath.Dir(env.wrapperInvPath), err)
			}
			entries, err := readToolsList(env)
			if err != nil {
				return false, fmt.Errorf("read tools.list: %w", err)
			}
			desired := wrapperNamesForEntries(entries)
			data, err := env.readFile(env.wrapperInvPath)
			if err != nil {
				if !errors.Is(err, os.ErrNotExist) {
					return false, fmt.Errorf("read wrapper inventory: %w", err)
				}
				out, err := marshalWrapperInventory(wrapperInventory{Wrappers: desired})
				if err != nil {
					return false, err
				}
				if err := backupAndWrite(env, env.wrapperInvPath, out, modeAllowListReadable); err != nil {
					return false, err
				}
				return true, nil
			}
			var inv wrapperInventory
			if err := json.Unmarshal(data, &inv); err != nil {
				return false, fmt.Errorf("parse wrapper inventory: %w", err)
			}
			if stringSlicesEqual(inv.Wrappers, desired) {
				return false, nil
			}
			out, err := marshalWrapperInventory(wrapperInventory{Wrappers: desired})
			if err != nil {
				return false, err
			}
			if err := backupAndWrite(env, env.wrapperInvPath, out, modeAllowListReadable); err != nil {
				return false, err
			}
			return true, nil
		},
		undo: func(_ context.Context, env *installEnv) error {
			return restoreBackup(env, env.wrapperInvPath)
		},
	}
}

func stringSlicesEqual(a, b []string) bool {
	return slices.Equal(a, b)
}

func marshalWrapperInventory(inv wrapperInventory) ([]byte, error) {
	data, err := json.MarshalIndent(inv, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal wrapper inventory: %w", err)
	}
	return append(data, '\n'), nil
}

// ---------------------------------------------------------------------------
// Step 20: sudoers entry
// ---------------------------------------------------------------------------

func stepInstallSudoers() step {
	return step{
		name: "install-sudoers",
		desc: "write /etc/sudoers.d/50-pipelock-agent (validated with visudo -c)",
		apply: func(ctx context.Context, env *installEnv) (bool, error) {
			body := renderSudoers(env)
			if existing, err := env.readFile(env.sudoersPath); err == nil && string(existing) == body {
				_ = env.chmod(env.sudoersPath, modeSudoers)
				return false, nil
			}
			if err := backupAndWrite(env, env.sudoersPath, []byte(body), modeSudoers); err != nil {
				return false, err
			}
			if err := runOrErr(ctx, env, "visudo", "-cf", env.sudoersPath); err != nil {
				// Roll back inside the step so a malformed sudoers never
				// ends up loaded. The orchestrator would also undo, but
				// removing the bad file ourselves is cheaper and clearer.
				_ = restoreBackup(env, env.sudoersPath)
				return false, fmt.Errorf("visudo rejected new sudoers: %w", err)
			}
			return true, nil
		},
		undo: func(_ context.Context, env *installEnv) error {
			return restoreBackup(env, env.sudoersPath)
		},
	}
}

// renderSudoers builds the sudoers entry. Scoped to the launcher path so
// the operator can run plk-* wrappers without prompting, but the rule does
// NOT grant general-purpose sudo to pipelock-agent.
func renderSudoers(env *installEnv) string {
	launcher := filepath.Join(env.wrapperDir, "plk-launch")
	return fmt.Sprintf(
		"# Managed by `pipelock contain install`. Do not edit by hand.\n%s ALL=(%s) NOPASSWD: %s *\n",
		env.operatorUser, env.agentUserName, launcher,
	)
}
