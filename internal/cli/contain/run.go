// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
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

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	posturepkg "github.com/luckyPipewrench/pipelock/internal/posture"
)

const (
	defaultContainConfigPath = "/etc/pipelock/pipelock.yaml"
	defaultContainPostureDir = "/var/lib/pipelock/contain/posture"
	containRunPrivilegeProbe = "agent_privilege_escape_denied"
)

type containRunOptions struct {
	configFile    string
	port          int
	postureOutput string
}

type containRunEnv struct {
	probe       *probeEnv
	launch      func(context.Context, *probeEnv, []string, io.Reader, io.Writer, io.Writer) error
	emitPosture func(configFile, outputDir string, env *probeEnv, args []string) (string, error)
}

func defaultContainRunEnv() containRunEnv {
	return containRunEnv{
		probe:       defaultProbeEnv(),
		launch:      launchContainedAgent,
		emitPosture: emitContainRunPosture,
	}
}

func runCmd() *cobra.Command {
	opts := containRunOptions{
		configFile:    defaultContainConfigPath,
		port:          defaultProxyPort,
		postureOutput: defaultContainPostureDir,
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

	_, _ = fmt.Fprintln(stdout, "pipelock contain run: verifying containment preflight")
	if err := containRunPreflight(ctx, stdout, env.probe, tool); err != nil {
		return err
	}

	posturePath, err := env.emitPosture(opts.configFile, opts.postureOutput, env.probe, args)
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("emit contain-run posture capsule: %w", err))
	}
	_, _ = fmt.Fprintf(stdout, "  [PASS] signed posture capsule: %s\n", posturePath)
	_, _ = fmt.Fprintf(stdout, "pipelock contain run: launching %s as %s\n", tool, env.probe.agentUserName)

	if err := env.launch(ctx, env.probe, args, stdin, stdout, stderr); err != nil {
		return err
	}
	return nil
}

func containRunPreflight(ctx context.Context, out io.Writer, env *probeEnv, tool string) error {
	for _, p := range probesForEnv(env) {
		status, detail := p.fn(ctx, env)
		writeTextLine(out, p, status, detail)
		if status != statusPass {
			return cliutil.ExitCodeError(cliutil.ExitGeneral,
				fmt.Errorf("containment preflight failed at probe %d (%s): %s: %s", p.n, p.name, status, detail))
		}
	}

	// Numbered above the verify probe range (max 13, the conditional
	// workspace_access probe) so these run-only checks never collide with a
	// verify probe number operators may key off.
	status, detail := probeAgentPrivilegeEscapeDenied(ctx, env)
	writeTextLine(out, probe{n: 14, name: containRunPrivilegeProbe, desc: "pipelock-agent cannot sudo back out"}, status, detail)
	if status != statusPass {
		return cliutil.ExitCodeError(cliutil.ExitGeneral,
			fmt.Errorf("containment preflight failed at %s: %s: %s", containRunPrivilegeProbe, status, detail))
	}

	status, detail = probeRequestedToolRegistered(env, tool)
	writeTextLine(out, probe{n: 15, name: "requested_tool_registered", desc: "requested tool is registered in tools.list"}, status, detail)
	if status != statusPass {
		return cliutil.ExitCodeError(cliutil.ExitGeneral,
			fmt.Errorf("containment preflight failed at requested_tool_registered: %s: %s", status, detail))
	}
	return nil
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

func probeRequestedToolRegistered(env *probeEnv, tool string) (string, string) {
	data, err := env.readFile(env.toolsListPath)
	if err != nil {
		return statusFail, fmt.Sprintf("read %s: %v", env.toolsListPath, err)
	}
	entries, err := parseToolsList(data)
	if err != nil {
		return statusFail, fmt.Sprintf("parse %s: %v", env.toolsListPath, err)
	}
	for _, entry := range entries {
		if entry.name == tool {
			return statusPass, fmt.Sprintf("%s is registered", tool)
		}
	}
	return statusFail, fmt.Sprintf("%s is not registered; run `pipelock contain add-tool %s` first", tool, tool)
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

func emitContainRunPosture(configFile, outputDir string, env *probeEnv, args []string) (string, error) {
	cfg, err := config.Load(filepath.Clean(configFile))
	if err != nil {
		return "", fmt.Errorf("loading config: %w", err)
	}
	launchEvidence, err := containRunLaunchEvidence(env, args)
	if err != nil {
		return "", fmt.Errorf("build launch evidence: %w", err)
	}
	containmentEvidence, err := containRunContainmentEvidence(env, launchEvidence.TargetUID)
	if err != nil {
		return "", fmt.Errorf("build containment evidence: %w", err)
	}
	capsule, err := posturepkg.Emit(cfg, posturepkg.Options{
		ContainLaunch: &launchEvidence,
		Containment:   &containmentEvidence,
	})
	if err != nil {
		return "", err
	}
	path, err := posturepkg.WriteProofJSON(outputDir, capsule)
	if err != nil {
		return "", err
	}
	return path, nil
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

	launchEnv := containLaunchEnv(env.agentUserName, homeDir, env.port)
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
