// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cli/contain/workspacediff"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	posturepkg "github.com/luckyPipewrench/pipelock/internal/posture"
	"github.com/luckyPipewrench/pipelock/internal/posturebinding"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	defaultContainConfigPath = "/etc/pipelock/pipelock.yaml"
	defaultContainPostureDir = "/var/lib/pipelock/contain/posture"
	containRunPrivilegeProbe = "agent_privilege_escape_denied"

	// defaultWorkspaceDiffCapBytes is the per-file content-digest cap for the
	// post-session workspace change statement. A regular file at or
	// under this size gets a sha256 digest; a larger one is recorded as
	// oversize with no digest, never partially hashed. This is evidence, not
	// backup: no file content is ever stored.
	defaultWorkspaceDiffCapBytes = 10 * 1024 * 1024
)

type containRunOptions struct {
	configFile            string
	port                  int
	postureOutput         string
	dryRun                bool
	workspaceDiffCapBytes int64
}

type containRunEnv struct {
	probe       *probeEnv
	launch      func(context.Context, *probeEnv, []string, io.Reader, io.Writer, io.Writer) error
	emitPosture func(cfg *config.Config, privKey ed25519.PrivateKey, outputDir string, env *probeEnv, args []string) (postureEmission, error)
	// loadConfig loads the ONE config snapshot reused for both posture
	// capsule emission and workspace-statement signing key resolution (H2).
	// Defaults to config.Load; overridable in tests that stub emitPosture
	// and never intend to touch a real config file on disk.
	loadConfig func(configFile string) (*config.Config, error)
}

type postureEmission struct {
	path          string
	capsuleSHA256 string
}

func defaultContainRunEnv() containRunEnv {
	return containRunEnv{
		probe:       defaultProbeEnv(),
		launch:      launchContainedAgent,
		emitPosture: emitContainRunPosture,
		loadConfig:  func(configFile string) (*config.Config, error) { return config.Load(filepath.Clean(configFile)) },
	}
}

func runCmd() *cobra.Command {
	opts := containRunOptions{
		configFile:            defaultContainConfigPath,
		port:                  defaultProxyPort,
		postureOutput:         defaultContainPostureDir,
		workspaceDiffCapBytes: defaultWorkspaceDiffCapBytes,
	}

	cmd := &cobra.Command{
		Use:   "run [flags] -- <tool> [args...]",
		Short: "Verify containment, then launch a registered agent tool",
		Long: `Verify the installed host containment boundary before starting an agent.

The command runs the same containment probes as verify, adds a privilege-escape
canary, emits a signed posture capsule, then launches the requested registered
tool through plk-launch as the contained pipelock-agent user.

Must be run as root. The launched tool reads its own environment and credentials;
Pipelock does not read or store agent secrets.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("usage: pipelock contain run -- <tool> [args...]")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validatePort(opts.port); err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			if !containRunSupported() {
				return cliutil.ExitCodeError(cliutil.ExitConfig, errors.New("contain run is supported only on Linux"))
			}
			if !isRoot() {
				return cliutil.ExitCodeError(cliutil.ExitConfig, errors.New("contain run must be run as root (use sudo)"))
			}
			env := defaultContainRunEnv()
			env.probe.port = opts.port
			return runContainRun(cmd.Context(), cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr(), env, opts, args)
		},
	}

	cmd.Flags().StringVarP(&opts.configFile, "config", "c", opts.configFile, "pipelock config file for the signed posture capsule")
	cmd.Flags().IntVar(&opts.port, "port", opts.port, "pipelock listen port to probe on loopback")
	cmd.Flags().StringVar(&opts.postureOutput, "posture-output", opts.postureOutput, "directory for the signed contain-run posture capsule")
	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "run preflight and print the session contract, then exit without emitting a posture capsule or launching")
	cmd.Flags().Int64Var(&opts.workspaceDiffCapBytes, "workspace-diff-cap-bytes", opts.workspaceDiffCapBytes, "per-file content-digest cap for the post-session workspace change statement; larger files are recorded oversize with no digest")

	return cmd
}

func runContainRun(
	ctx context.Context,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
	env containRunEnv,
	opts containRunOptions,
	args []string,
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if env.probe == nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, errors.New("contain run preflight environment is missing"))
	}
	if env.launch == nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, errors.New("contain run launcher is unavailable on this platform"))
	}
	if env.emitPosture == nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, errors.New("contain run posture emitter is unavailable"))
	}
	if len(args) == 0 {
		return cliutil.ExitCodeError(cliutil.ExitConfig, errors.New("usage: pipelock contain run -- <tool> [args...]"))
	}
	tool := args[0]
	if !addToolNamePattern.MatchString(tool) {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("invalid tool name %q (must match %s)", tool, containToolNameRegex))
	}

	// Read the workspace inventory ONCE, before preflight, so the workspace probe
	// checks readability and expiry of every recorded grant in the same pass, and
	// the contract and the expiry gate below derive from the same read the launch
	// enforces. A grant the agent cannot actually read, or one past its expiry,
	// fails preflight (fail closed) rather than launching against a stale record.
	inv, err := loadWorkspaceInventoryFrom(env.probe.readFile, env.probe.workspaceInvPath)
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("read workspace inventory: %w", err))
	}
	// Only the grants governing THIS agent user gate this launch; another
	// contained user's expired grant must not refuse it, and its paths must not
	// be probed as though this agent could read them.
	grants := grantsForAgent(inv.Workspaces, env.probe.agentUserName)
	env.probe.workspaceGrants = grants

	_, _ = fmt.Fprintln(stdout, "pipelock contain run: verifying containment preflight")
	entries, err := containRunPreflight(ctx, stdout, env.probe, tool)
	if err != nil {
		return err
	}

	// Resolve the posture proof path this run writes, and thread it into the
	// contained launch env so an in-child emitter binds the exact capsule rather
	// than fall back to the default path and grade containment UNKNOWN. The child
	// starts with its cwd set to the agent home, so relative --posture-output
	// values must become absolute before they are hashed into launch evidence.
	proofPath, err := containRunPostureProofPath(opts.postureOutput)
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, err)
	}
	env.probe.postureProofPath = proofPath

	contract := buildSessionContract(env.probe, tool, entries, grants, proofPath)
	// The contract is the operator's review surface. If it cannot be written
	// (closed pipe, failed writer) nobody saw the boundary, so refuse to go on
	// rather than emit a capsule and launch unreviewed (fail closed).
	if err := renderSessionContract(stdout, contract); err != nil {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("write session contract: %w", err))
	}

	// Fail CLOSED on an expired grant: the recorded window has passed while the
	// ACL is still live, so refuse the launch until the operator re-grants or
	// revokes. Dry-runs use this same gate so their outcome cannot claim a launch
	// is possible when a real launch would refuse it. Expiry gates the launch; it
	// does not remove the ACL.
	expired, err := expiredWorkspaceGrants(grants, containRunNow(env.probe))
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, err)
	}
	if len(expired) > 0 {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf(
			"refusing to launch: %d workspace grant(s) have expired: %s; re-grant with `pipelock contain grant-workspace` or remove with `pipelock contain revoke-workspace`",
			len(expired), strings.Join(expired, ", ")))
	}
	if opts.dryRun {
		return nil
	}
	// Session-start manifest of every granted workspace, taken before the
	// posture capsule is emitted and before launch, so it reflects the
	// workspace exactly as granted at the moment this session begins. A
	// failure here must not abort the launch: docs/contain-cli.md promises
	// the workspace change statement never blocks launch on its own
	// (the same contract the missing-signing-key path already honors), so
	// this warns and proceeds with the statement unavailable for this
	// session rather than refusing containment the operator otherwise
	// qualifies for.
	beforeSnapshots, snapErr := snapshotWorkspaces(grants, opts.workspaceDiffCapBytes)
	if snapErr != nil {
		beforeSnapshots = nil
		_, _ = fmt.Fprintf(stdout, "  [WARN] workspace change statement will be unavailable: %v\n", snapErr)
		_, _ = fmt.Fprintf(stdout, "%s reason=%q\n", workspaceStatementUnavailableLine, snapErr.Error())
	}

	// Resolve the workspace-statement signing key BEFORE launch, from the
	// SAME config read the posture capsule about to be emitted uses, and
	// reuse this exact key after launch. Loading it again after the agent
	// exits would let an operator's mid-session key rotation sign the
	// statement with a key the posture capsule launched under was never
	// bound to. A failure here is reported once, up front, rather than
	// silently discovered after the agent has already run.
	// Load config ONCE here and reuse this exact snapshot for both the
	// posture capsule emission below and the workspace-statement signing key
	// resolution: loading it twice would let an operator's key rotation
	// between the two loads sign the statement with a key the capsule this
	// session launched under was never bound to (H2).
	if env.loadConfig == nil {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, errors.New("internal: containRunEnv.loadConfig is not set"))
	}
	runCfg, runCfgErr := env.loadConfig(opts.configFile)
	if runCfgErr != nil {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("loading config: %w", runCfgErr))
	}

	workspaceSigningKey, workspaceSigningKeyErr := resolveWorkspaceStatementSigningKey(runCfg)
	if len(grants) > 0 && workspaceSigningKeyErr != nil {
		_, _ = fmt.Fprintf(stdout, "  [WARN] workspace change statement will be unavailable: %v\n", workspaceSigningKeyErr)
		_, _ = fmt.Fprintf(stdout, "%s reason=%q\n", workspaceStatementUnavailableLine, workspaceSigningKeyErr.Error())
	}

	// Thread the SAME already-loaded private key into posture emission
	// (posturepkg.Options.SigningKey) whenever it resolved successfully, so
	// the capsule never triggers a SECOND, independent read of the signing
	// key file: that second read is exactly the race H2 closed for the
	// config snapshot but left open for the key itself, since
	// posturepkg.Emit would otherwise call its own resolveSigningKey against
	// cfg.FlightRecorder.SigningKeyPath a second time. When the key failed
	// to load above, pass nil and let Emit attempt its own resolution (the
	// existing missing-key fallback path, unchanged).
	var capsuleSigningKey ed25519.PrivateKey
	if workspaceSigningKeyErr == nil {
		capsuleSigningKey = workspaceSigningKey
	}
	posture, err := env.emitPosture(runCfg, capsuleSigningKey, opts.postureOutput, env.probe, args)
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("emit contain-run posture capsule: %w", err))
	}
	_, _ = fmt.Fprintf(stdout, "  [PASS] signed posture capsule: %s\n", posture.path)
	warnCustomPostureOutput(stderr, opts.postureOutput, proofPath)
	_, _ = fmt.Fprintf(stdout, "pipelock contain run: launching %s as %s\n", tool, env.probe.agentUserName)

	launchErr := env.launch(ctx, env.probe, args, stdin, stdout, stderr)

	// Session-end workspace change statement, bound to the posture capsule
	// this exact session emitted, regardless of whether the launched tool
	// exited cleanly: a crashed or refused launch still gets an honest
	// statement of what the workspace looked like, rather than none at all.
	// Skipped entirely (no line at all) when there were no granted
	// workspaces; already-reported-unavailable when the key could not be
	// loaded before launch.
	if len(beforeSnapshots) > 0 && workspaceSigningKeyErr == nil {
		stmtPath, incomplete, incompleteReason, boundaryCheck, stmtErr := emitContainRunWorkspaceStatement(opts, env.probe, beforeSnapshots, grants, posture.path, posture.capsuleSHA256, workspaceSigningKey)
		switch {
		case stmtErr != nil:
			_, _ = fmt.Fprintf(stderr, "pipelock contain run: workspace change statement failed: %v\n", stmtErr)
			_, _ = fmt.Fprintf(stdout, "%s reason=%q\n", workspaceStatementUnavailableLine, stmtErr.Error())
		case incomplete:
			// The statement was signed and written successfully, but its
			// CONTENT says the diff could not fully observe the workspace
			// (a budget cap or an unreadable/mount-excluded path). That is
			// never a [PASS]: an operator scanning for [PASS]/[FAIL] lines
			// must not read a partial observation as a clean result (M5).
			_, _ = fmt.Fprintf(stdout, "  [WARN] signed workspace change statement is INCOMPLETE: %s\n", stmtPath)
			_, _ = fmt.Fprintf(stdout, "%s reason=%q path=%s boundary_check=%s\n", workspaceStatementIncompleteLine, incompleteReason, stmtPath, boundaryCheck)
		default:
			_, _ = fmt.Fprintf(stdout, "  [PASS] signed workspace change statement: %s\n", stmtPath)
			_, _ = fmt.Fprintf(stdout, "%s path=%s boundary_check=%s\n", workspaceStatementWrittenLine, stmtPath, boundaryCheck)
		}
	}

	if launchErr != nil {
		return launchErr
	}
	return nil
}

// workspaceStatementUnavailableLine and workspaceStatementWrittenLine are a
// stable, single-line, grep-able outcome contract for the workspace change
// statement, independent of the surrounding human-readable prose, so an
// operator script can key on "did this session's evidence get written"
// without parsing free text.
const (
	workspaceStatementUnavailableLine = "workspace_change_statement=unavailable"
	workspaceStatementWrittenLine     = "workspace_change_statement=written"
	workspaceStatementIncompleteLine  = "workspace_change_statement=incomplete"
)

// resolveWorkspaceStatementSigningKey loads the SAME signing key the posture
// capsule uses (flight_recorder.signing_key_path from configFile), read once
// before launch so a key rotation during the launched session cannot change
// which key ends up signing the statement.
func resolveWorkspaceStatementSigningKey(cfg *config.Config) (ed25519.PrivateKey, error) {
	keyPath := filepath.Clean(cfg.FlightRecorder.SigningKeyPath)
	if keyPath == "." || cfg.FlightRecorder.SigningKeyPath == "" {
		return nil, errors.New("flight_recorder.signing_key_path is required to sign the workspace change statement")
	}
	privKey, err := signing.LoadPrivateKeyFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("load signing key: %w", err)
	}
	return privKey, nil
}

// snapshotWorkspaces records the current state of every granted workspace
// path, keyed by path, using the SAME grant list the session contract and
// the expiry gate already derived from.
func snapshotWorkspaces(grants []workspaceGrant, capBytes int64) (map[string]workspacediff.Manifest, error) {
	out := make(map[string]workspacediff.Manifest, len(grants))
	for _, g := range grants {
		if _, ok := out[g.Path]; ok {
			continue
		}
		m, err := workspacediff.Snapshot(g.Path, capBytes, workspacediff.DefaultBudget())
		if err != nil {
			return nil, fmt.Errorf("snapshot %s: %w", g.Path, err)
		}
		out[g.Path] = m
	}
	return out, nil
}

// emitContainRunWorkspaceStatement diffs each granted workspace against its
// session-start snapshot and signs the result with privKey (resolved BEFORE
// launch by the caller), bound to this session via the posture capsule's own
// sha256 digest.
func emitContainRunWorkspaceStatement(
	opts containRunOptions,
	env *probeEnv,
	before map[string]workspacediff.Manifest,
	grants []workspaceGrant,
	posturePath string,
	capsuleSHA256 string,
	privKey ed25519.PrivateKey,
) (path string, incomplete bool, incompleteReason string, boundaryCheck workspacediff.BoundaryCheck, err error) {
	statements := make([]workspacediff.Statement, 0, len(grants))
	seen := make(map[string]struct{}, len(grants))
	now := containRunNow(env)
	var incompleteReasons []string
	for _, g := range grants {
		if _, ok := seen[g.Path]; ok {
			continue
		}
		seen[g.Path] = struct{}{}
		beforeSnap, ok := before[g.Path]
		if !ok {
			return "", false, "", "", fmt.Errorf("missing session-start snapshot for %s", g.Path)
		}
		afterSnap, snapErr := workspacediff.Snapshot(g.Path, opts.workspaceDiffCapBytes, workspacediff.DefaultBudget())
		if snapErr != nil {
			return "", false, "", "", fmt.Errorf("snapshot %s at session end: %w", g.Path, snapErr)
		}
		st, diffErr := workspacediff.Diff(beforeSnap, afterSnap, now)
		if diffErr != nil {
			return "", false, "", "", fmt.Errorf("diff %s: %w", g.Path, diffErr)
		}
		if st.BoundaryCheck == workspacediff.BoundaryCheckDeviceOnly {
			boundaryCheck = workspacediff.BoundaryCheckDeviceOnly
		} else if boundaryCheck == "" {
			boundaryCheck = workspacediff.BoundaryCheckMountID
		}
		if st.Incomplete {
			incompleteReasons = append(incompleteReasons, fmt.Sprintf("%s: %s", g.Path, st.IncompleteReason))
		}
		statements = append(statements, st)
	}

	signed, err := workspacediff.Sign(statements, capsuleSHA256, privKey)
	if err != nil {
		return "", false, "", "", err
	}
	path, err = workspacediff.WriteJSON(filepath.Dir(posturePath), signed)
	if err != nil {
		return "", false, "", "", err
	}
	if len(incompleteReasons) > 0 {
		return path, true, strings.Join(incompleteReasons, "; "), boundaryCheck, nil
	}
	return path, false, "", boundaryCheck, nil
}

// containRunNow returns the probe environment's clock, defaulting to time.Now
// so production callers need not wire it.
func containRunNow(env *probeEnv) time.Time {
	if env.now != nil {
		return env.now()
	}
	return time.Now()
}

// sessionContract is the set of boundaries `contain run` is about to grant the
// agent, rendered for the operator before launch. Every field is derived from
// the SAME preflight state the launch itself uses (the same probe environment,
// the single tools.list read from preflight, the single workspace-inventory
// read), so the printed contract can never describe a boundary different from
// the one that is enforced.
type sessionContract struct {
	Tool            string
	AgentUser       string
	ProxyURL        string
	ProxyPort       int
	PostureCapsule  string
	RegisteredTools []string
	Workspaces      []contractWorkspace
	// PrivateTmp reports whether the agent's /tmp is isolated from the operator.
	// contain run preflight proves the transient-service canary before this
	// contract is rendered, so this field is never true without that evidence.
	PrivateTmp bool
}

type contractWorkspace struct {
	Path    string
	Mode    string
	Owner   string
	Created string
	Expires string
	Status  string
}

// buildSessionContract assembles the contract from preflight state. tools are
// the entries preflight already parsed and the launcher's allow-list relies on;
// grants are the single workspace-inventory read; proofPath is the exact capsule
// destination threaded into the launch environment.
func buildSessionContract(env *probeEnv, tool string, tools []toolsListEntry, grants []workspaceGrant, proofPath string) sessionContract {
	names := make([]string, 0, len(tools))
	for _, e := range tools {
		names = append(names, e.name)
	}
	now := containRunNow(env)
	workspaces := make([]contractWorkspace, 0, len(grants))
	for _, g := range grants {
		workspaces = append(workspaces, contractWorkspace{
			Path:    g.Path,
			Mode:    valueOrDash(g.Mode),
			Owner:   valueOrDash(g.Owner),
			Created: valueOrDash(g.Created),
			Expires: grantExpiryLabel(g),
			Status:  g.grantStatus(now),
		})
	}
	return sessionContract{
		Tool:            tool,
		AgentUser:       env.agentUserName,
		ProxyURL:        proxyURLFor(env.port),
		ProxyPort:       env.port,
		PostureCapsule:  proofPath,
		RegisteredTools: names,
		Workspaces:      workspaces,
		PrivateTmp:      true,
	}
}

// firstErrWriter records the first write error so a multi-line render can
// report whether the whole block reached the operator.
type firstErrWriter struct {
	w   io.Writer
	err error
}

func (f *firstErrWriter) Write(p []byte) (int, error) {
	if f.err != nil {
		return 0, f.err
	}
	n, err := f.w.Write(p)
	if err != nil {
		f.err = err
	}
	return n, err
}

// renderSessionContract prints the contract as an operator-facing block. Pure
// over the struct so tests assert exact text. It returns the first write error
// so a caller can refuse to launch a boundary the operator never saw.
func renderSessionContract(w io.Writer, c sessionContract) error {
	out := &firstErrWriter{w: w}
	_, _ = fmt.Fprintf(out, "pipelock contain run: session contract for %s\n", c.Tool)
	_, _ = fmt.Fprintf(out, "  agent user:       %s\n", c.AgentUser)
	_, _ = fmt.Fprintf(out, "  proxy egress:     %s (loopback proxy only; direct egress denied by nftables)\n", c.ProxyURL)
	_, _ = fmt.Fprintf(out, "  posture capsule:  %s\n", c.PostureCapsule)
	if c.PrivateTmp {
		_, _ = fmt.Fprintln(out, "  agent temp dirs:  /tmp and /var/tmp private (isolated from the operator)")
	} else {
		_, _ = fmt.Fprintln(out, "  agent temp dirs:  /tmp and /var/tmp shared with the operator (not private)")
	}
	if len(c.RegisteredTools) == 0 {
		_, _ = fmt.Fprintln(out, "  registered tools: (none)")
	} else {
		_, _ = fmt.Fprintf(out, "  registered tools: %s\n", strings.Join(c.RegisteredTools, ", "))
	}
	if len(c.Workspaces) == 0 {
		_, _ = fmt.Fprintln(out, "  workspaces:       (none granted)")
	} else {
		_, _ = fmt.Fprintln(out, "  workspaces:")
		for _, w := range c.Workspaces {
			_, _ = fmt.Fprintf(out, "    %s  %s  owner=%s  created=%s  expires=%s  [%s]\n",
				w.Path, w.Mode, w.Owner, w.Created, w.Expires, w.Status)
		}
	}
	return out.err
}

func containRunPostureProofPath(postureOutput string) (string, error) {
	proofPath := filepath.Join(filepath.Clean(postureOutput), posturepkg.ProofFilename)
	if filepath.IsAbs(proofPath) {
		return proofPath, nil
	}
	abs, err := filepath.Abs(proofPath)
	if err != nil {
		return "", fmt.Errorf("resolve posture proof path: %w", err)
	}
	return abs, nil
}

// warnCustomPostureOutput tells the operator that a non-default --posture-output
// is only read automatically by an emitter running in the contained child this
// command launches. A separately-running proxy/runtime (e.g. the systemd
// pipelock service) reads the default proof path and will grade containment
// UNKNOWN for this capsule unless PIPELOCK_POSTURE_PROOF is set in its own
// environment.
func warnCustomPostureOutput(stderr io.Writer, postureOutput, posturePath string) {
	if filepath.Clean(postureOutput) == defaultContainPostureDir {
		return
	}
	_, _ = fmt.Fprintf(stderr,
		"  [WARN] --posture-output is not the default (%s). The tool launched here binds this\n"+
			"         capsule automatically, but a separately-running pipelock proxy/runtime reads\n"+
			"         %s. Set %s=%s in that service's environment for it to bind this capsule.\n",
		defaultContainPostureDir, posturebinding.DefaultContainRunProofPath,
		posturebinding.RuntimeProofEnv, posturePath)
}

// containRunPreflight runs every containment probe, the privilege-escape
// canary, and the requested-tool registration check. It returns the parsed
// tools.list entries it read for the registration check so the caller renders
// the session contract from the SAME read the launch path relies on, never a
// second, possibly-divergent read.
func containRunPreflight(ctx context.Context, out io.Writer, env *probeEnv, tool string) ([]toolsListEntry, error) {
	for _, p := range probesForEnv(env) {
		status, detail := p.fn(ctx, env)
		writeTextLine(out, p, status, detail)
		if status != statusPass {
			return nil, cliutil.ExitCodeError(cliutil.ExitGeneral,
				fmt.Errorf("containment preflight failed at probe %d (%s): %s: %s", p.n, p.name, status, detail))
		}
	}

	// Published numbers are a contract operators and dashboards key off, so a
	// run-only check must never reuse a verify probe number. This comment used
	// to be the only thing holding that invariant and it did not hold it: a
	// verify probe was added at 18 while this file had already published 18.
	// TestContainRunProbeNumbersDoNotCollideWithVerify now fails when the two
	// sets overlap, so a new probe on either side cannot silently take a number
	// the other already publishes.
	status, detail := probeAgentPrivilegeEscapeDenied(ctx, env)
	writeTextLine(out, probe{n: 17, name: containRunPrivilegeProbe, desc: "pipelock-agent cannot sudo back out"}, status, detail)
	if status != statusPass {
		return nil, cliutil.ExitCodeError(cliutil.ExitGeneral,
			fmt.Errorf("containment preflight failed at %s: %s: %s", containRunPrivilegeProbe, status, detail))
	}

	entries, status, detail := probeRequestedToolRegistered(env, tool)
	writeTextLine(out, probe{n: 18, name: "requested_tool_registered", desc: "requested tool is registered in tools.list"}, status, detail)
	if status != statusPass {
		return nil, cliutil.ExitCodeError(cliutil.ExitGeneral,
			fmt.Errorf("containment preflight failed at requested_tool_registered: %s: %s", status, detail))
	}
	return entries, nil
}

func probeAgentPrivilegeEscapeDenied(ctx context.Context, env *probeEnv) (string, string) {
	out, code, err := env.runCmd(ctx, "sudo", "-n", "-u", env.agentUserName, "--", "sudo", "-n", "true")
	if err != nil {
		return statusFail, fmt.Sprintf("sudo privilege-escape canary could not run: %v", err)
	}
	if isSudoUserMissing(out) {
		return statusFail, fmt.Sprintf("%s user not present; install containment model first", env.agentUserName)
	}
	if code == 0 {
		return statusFail, fmt.Sprintf("%s can run sudo non-interactively; privilege escape is possible", env.agentUserName)
	}
	return statusPass, fmt.Sprintf("sudo escape denied (exit=%d): %s", code, oneLine(out))
}

// probeRequestedToolRegistered confirms the requested tool is present in the
// runtime allow-list and returns the parsed entries so the caller can render
// them in the session contract without a second read of tools.list.
func probeRequestedToolRegistered(env *probeEnv, tool string) ([]toolsListEntry, string, string) {
	data, err := env.readFile(env.toolsListPath)
	if err != nil {
		return nil, statusFail, fmt.Sprintf("read %s: %v", env.toolsListPath, err)
	}
	entries, err := parseToolsList(data)
	if err != nil {
		return nil, statusFail, fmt.Sprintf("parse %s: %v", env.toolsListPath, err)
	}
	for _, entry := range entries {
		if entry.name == tool {
			return entries, statusPass, fmt.Sprintf("%s is registered", tool)
		}
	}
	return entries, statusFail, fmt.Sprintf("%s is not registered; run `pipelock contain add-tool %s` first", tool, tool)
}

// parseAgentGIDs converts the agent's group-id strings (primary plus
// supplementary, as returned by user.GroupIds) into the uint32 set for
// syscall.Credential.Groups. The primary gid is always included first so the
// resulting setgroups(2) call can never leave the launched process holding the
// caller's (root's) supplementary groups. Duplicates are dropped; relative
// order is otherwise preserved. Root group membership and non-numeric ids fail
// closed.
func parseAgentGIDs(ids []string, primary uint32) ([]uint32, error) {
	if primary == 0 {
		return nil, errors.New("primary group id 0 is not allowed for contained launch")
	}
	out := []uint32{primary}
	seen := map[uint32]struct{}{primary: {}}
	for _, s := range ids {
		v, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid group id %q: %w", s, err)
		}
		g := uint32(v)
		if g == 0 {
			return nil, errors.New("supplementary group id 0 is not allowed for contained launch")
		}
		if _, ok := seen[g]; ok {
			continue
		}
		seen[g] = struct{}{}
		out = append(out, g)
	}
	return out, nil
}

func emitContainRunPosture(cfg *config.Config, privKey ed25519.PrivateKey, outputDir string, env *probeEnv, args []string) (postureEmission, error) {
	launchEvidence, err := containRunLaunchEvidence(env, args)
	if err != nil {
		return postureEmission{}, fmt.Errorf("build launch evidence: %w", err)
	}
	containmentEvidence, err := containRunContainmentEvidence(env, launchEvidence.TargetUID)
	if err != nil {
		return postureEmission{}, fmt.Errorf("build containment evidence: %w", err)
	}
	capsule, err := posturepkg.Emit(cfg, posturepkg.Options{
		ContainLaunch: &launchEvidence,
		Containment:   &containmentEvidence,
		SigningKey:    privKey,
	})
	if err != nil {
		return postureEmission{}, err
	}
	path, capsuleBytes, err := posturepkg.WriteProofJSONWithBytes(outputDir, capsule)
	if err != nil {
		return postureEmission{}, err
	}
	sum := sha256.Sum256(capsuleBytes)
	return postureEmission{path: path, capsuleSHA256: hex.EncodeToString(sum[:])}, nil
}

func containRunLaunchEvidence(env *probeEnv, args []string) (posturepkg.ContainLaunchEvidence, error) {
	if env == nil {
		return posturepkg.ContainLaunchEvidence{}, errors.New("probe environment is missing")
	}
	if len(args) == 0 {
		return posturepkg.ContainLaunchEvidence{}, errors.New("launch args are missing")
	}
	u, err := env.lookupUser(env.agentUserName)
	if err != nil {
		return posturepkg.ContainLaunchEvidence{}, fmt.Errorf("lookup %s: %w", env.agentUserName, err)
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return posturepkg.ContainLaunchEvidence{}, fmt.Errorf("parse uid for %s: %w", env.agentUserName, err)
	}
	if uid == 0 {
		return posturepkg.ContainLaunchEvidence{}, fmt.Errorf("%s resolves to uid 0; refusing contained launch", env.agentUserName)
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return posturepkg.ContainLaunchEvidence{}, fmt.Errorf("parse gid for %s: %w", env.agentUserName, err)
	}
	groupIDs, err := groupIDsForEnv(env, u)
	if err != nil {
		return posturepkg.ContainLaunchEvidence{}, fmt.Errorf("resolve groups for %s: %w", env.agentUserName, err)
	}
	groups, err := parseAgentGIDs(groupIDs, uint32(gid))
	if err != nil {
		return posturepkg.ContainLaunchEvidence{}, fmt.Errorf("group ids for %s: %w", env.agentUserName, err)
	}
	homeDir, err := cleanContainedAgentHomeDir(env.agentUserName, u.HomeDir)
	if err != nil {
		return posturepkg.ContainLaunchEvidence{}, err
	}

	launchEnv := containLaunchEnv(env.agentUserName, homeDir, env.port, env.postureProofPath)
	envVars := make([]string, 0, len(launchEnv))
	for _, entry := range launchEnv {
		name, _, ok := strings.Cut(entry, "=")
		if !ok {
			return posturepkg.ContainLaunchEvidence{}, fmt.Errorf("malformed launch env entry %q", entry)
		}
		envVars = append(envVars, name)
	}
	argvHash, err := stringSliceSHA256(args)
	if err != nil {
		return posturepkg.ContainLaunchEvidence{}, fmt.Errorf("hash argv: %w", err)
	}
	envHash, err := stringSliceSHA256(launchEnv)
	if err != nil {
		return posturepkg.ContainLaunchEvidence{}, fmt.Errorf("hash env: %w", err)
	}

	return posturepkg.ContainLaunchEvidence{
		Launcher:     defaultLaunchScript,
		AgentUser:    env.agentUserName,
		TargetUID:    strconv.FormatUint(uid, 10),
		TargetGID:    strconv.FormatUint(gid, 10),
		TargetGroups: groupIDStrings(groups),
		Tool:         args[0],
		Argc:         len(args),
		ArgvSHA256:   argvHash,
		CWD:          homeDir,
		ProxyPort:    env.port,
		EnvVars:      envVars,
		EnvSHA256:    envHash,
	}, nil
}

func containRunContainmentEvidence(env *probeEnv, targetUID string) (posturepkg.ContainmentEvidence, error) {
	if env == nil {
		return posturepkg.ContainmentEvidence{}, errors.New("probe environment is missing")
	}
	nftStatus, nftDetail := probeNFTContainment(context.Background(), env)
	egressStatus, egressDetail := probeCCAgentEgressDenied(context.Background(), env)
	if nftStatus == statusPass && egressStatus == statusPass {
		ruleHash, err := containmentRuleHash(env)
		if err != nil {
			return posturepkg.ContainmentEvidence{}, err
		}
		return posturepkg.ContainmentEvidence{
			Mode:                     posturepkg.ContainmentModeKernelNFTOwnerMatch,
			BoundaryVerified:         true,
			ProbeRefusedDirectEgress: true,
			KernelRuleHash:           ruleHash,
			TargetUID:                targetUID,
		}, nil
	}
	if nftStatus != statusPass {
		return posturepkg.ContainmentEvidence{}, fmt.Errorf("nft boundary probe did not pass: %s: %s", nftStatus, nftDetail)
	}
	return posturepkg.ContainmentEvidence{}, fmt.Errorf("direct-egress probe did not pass: %s: %s", egressStatus, egressDetail)
}

func containmentRuleHash(env *probeEnv) (string, error) {
	if env.nftRulesPath == "" {
		return "", errors.New("nftables rules path is required for kernel containment evidence")
	}
	data, err := env.readFile(env.nftRulesPath)
	if err != nil {
		return "", fmt.Errorf("read nftables rules file %s: %w", env.nftRulesPath, err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func groupIDsForEnv(env *probeEnv, u *user.User) ([]string, error) {
	if env != nil && env.groupIDs != nil {
		return env.groupIDs(u)
	}
	return realGroupIDs(u)
}

func groupIDStrings(groups []uint32) []string {
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		out = append(out, strconv.FormatUint(uint64(g), 10))
	}
	return out
}

func cleanContainedAgentHomeDir(agentUserName, homeDir string) (string, error) {
	clean := filepath.Clean(homeDir)
	if homeDir == "" || clean == "." || !filepath.IsAbs(clean) {
		return "", fmt.Errorf("%s home directory %q is not absolute; refusing contained launch", agentUserName, homeDir)
	}
	return clean, nil
}

func stringSliceSHA256(values []string) (string, error) {
	data, err := json.Marshal(values)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
