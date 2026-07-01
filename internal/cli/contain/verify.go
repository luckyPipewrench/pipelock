// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

// Probe environment defaults. These match the layout produced by
// `pipelock contain install`. Operators who installed the model
// elsewhere can override via flags.
const (
	defaultProxyPort    = 8888
	defaultProxyUser    = "pipelock-proxy"
	defaultAgentUser    = "pipelock-agent"
	defaultWrapperDir   = "/usr/local/bin"
	defaultLaunchScript = "/usr/local/bin/plk-launch"
	defaultCABundlePath = "/etc/pipelock/combined-ca.pem"
	defaultServiceName  = "pipelock.service"
	defaultNFTTable     = "pipelock_containment"
	defaultNFTChain     = "output_filter"

	probeDialTimeout = 2 * time.Second

	// curl flags shared between the egress canary and the operator
	// reachability probe. Connect timeout is intentionally lower than
	// max time so a slow handshake still returns within probe budget.
	curlConnectTimeout = "3"
	curlMaxTime        = "5"
	defaultCurlPath    = "/usr/bin/curl"
	curlPath           = defaultCurlPath
	canaryURL          = "https://example.com/"

	// Probe status values. Strings (not an enum type) so JSON
	// serialization is identity and tests can compare cheaply.
	statusPass = "pass"
	statusFail = "fail"
	statusSkip = "skip"

	// Internal: cap on stdout/stderr we keep from a subprocess so a
	// runaway command can't blow the runner's heap.
	maxCmdOutputBytes = 64 << 10
)

// expectedNoProxy is the exact NO_PROXY value the plk-launch wrapper must
// set per the 2026-05-04 decision in the runbook's open questions
// (cluster traffic flows through Pipelock, so NO_PROXY is limited to
// loopback). Any deviation is a policy regression.
const expectedNoProxy = "NO_PROXY=" + contractNoProxy

// defaultToolWrappers is the fallback wrapper list used when the inventory
// file has not been written yet.
var defaultToolWrappers = []string{"plk-claude", "plk-codex", "plk-gemini", "plk-playwright"}

// runCommand is the function shape used by probes that shell out.
// Factored as a type so tests can inject canned outputs without
// spawning a real process.
//
// Contract:
//   - On a process that ran (even with a non-zero exit), returns
//     stdout+stderr, the exit code, and a nil error.
//   - On context cancellation or executable-not-found, returns
//     whatever output was captured, an exit code of -1, and the wrap
//     error from exec.
type runCommand func(ctx context.Context, name string, args ...string) (output string, exitCode int, err error)

// dialFunc is the dialer signature probe 6 uses. Same shape as
// net.Dialer.DialContext + a timeout.
type dialFunc func(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error)

// lookupUserFunc is the os/user.Lookup signature, factored so tests can
// substitute a deterministic lookup.
type lookupUserFunc func(name string) (*user.User, error)

type groupIDsFunc func(*user.User) ([]string, error)

// probeEnv carries the inputs every probe needs. Everything is
// addressable from outside the package so tests can populate it
// directly without going through the cobra layer.
type probeEnv struct {
	port               int
	operatorUser       string
	proxyUserName      string
	agentUserName      string
	wrapperDir         string
	toolWrappers       []string
	caBundlePath       string
	launchPath         string
	nftTable           string
	nftChain           string
	nftRulesPath       string
	nftMainPath        string
	nftPersistUnitPath string
	nftPath            string
	serviceName        string
	curlPath           string
	pinPath            string
	wrapperInvPath     string
	toolsListPath      string
	workspacePaths     []string

	runCmd     runCommand
	dialCtx    dialFunc
	lookupUser lookupUserFunc
	groupIDs   groupIDsFunc
	stat       func(path string) (os.FileInfo, error)
	readFile   func(path string) ([]byte, error)
	selfPath   func() (string, error)
	hashFile   func(path string) (string, error)
}

// defaultProbeEnv returns the production environment. The operator user
// is derived from $SUDO_USER (set by sudo to the invoking user) when
// present; otherwise probe 9 runs curl as the current process user
// directly. See probe 9 implementation for the runtime branch.
func defaultProbeEnv() *probeEnv {
	platform := detectContainPlatform(os.ReadFile, os.Stat, exec.LookPath)
	return &probeEnv{
		port:               defaultProxyPort,
		operatorUser:       os.Getenv("SUDO_USER"),
		proxyUserName:      defaultProxyUser,
		agentUserName:      defaultAgentUser,
		wrapperDir:         defaultWrapperDir,
		toolWrappers:       append([]string(nil), defaultToolWrappers...),
		caBundlePath:       defaultCABundlePath,
		launchPath:         defaultLaunchScript,
		nftTable:           defaultNFTTable,
		nftChain:           defaultNFTChain,
		nftRulesPath:       defaultNFTRulesPath,
		nftPersistUnitPath: defaultNFTPersistUnitPath,
		nftPath:            platform.nftPath,
		serviceName:        defaultServiceName,
		curlPath:           platform.curlPath,
		pinPath:            defaultIntegrityPin,
		wrapperInvPath:     defaultWrapperInvPath,
		toolsListPath:      defaultToolsListPath,
		runCmd:             realRunCommand,
		dialCtx:            realDial,
		lookupUser:         user.Lookup,
		groupIDs:           realGroupIDs,
		stat:               os.Stat,
		readFile:           os.ReadFile,
		selfPath:           os.Executable,
		hashFile:           sha256HexOfFile,
	}
}

func realGroupIDs(u *user.User) ([]string, error) {
	return u.GroupIds()
}

// realRunCommand executes name+args under ctx, captures merged stdout
// and stderr (bounded), and returns the process exit code. An
// ExitError is treated as a successful invocation with a non-zero
// exit code - only failure to start the binary returns a non-nil
// error.
func realRunCommand(ctx context.Context, name string, args ...string) (string, int, error) {
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // G204: name comes from probe definitions (compile-time string literals or package consts), never user input.
	buf := newCappedBuffer(maxCmdOutputBytes)
	cmd.Stdout = buf
	cmd.Stderr = buf
	runErr := cmd.Run()

	out := buf.String()

	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		return out, exitErr.ExitCode(), nil
	}
	if runErr != nil {
		return out, -1, runErr
	}
	return out, 0, nil
}

// cappedBuffer captures the first N bytes written and silently
// drops the rest. Every Write reports the full input length back to
// the caller so a chatty subprocess is not backpressured; the
// runner just stops accumulating once the cap is hit. This bounds
// memory at probe-runner level even if the target command produces
// gigabytes of output.
type cappedBuffer struct {
	buf bytes.Buffer
	rem int
}

func newCappedBuffer(capBytes int) *cappedBuffer {
	return &cappedBuffer{rem: capBytes}
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if c.rem > 0 {
		n := len(p)
		if n > c.rem {
			n = c.rem
		}
		_, _ = c.buf.Write(p[:n])
		c.rem -= n
	}
	return len(p), nil
}

func (c *cappedBuffer) String() string { return c.buf.String() }

// realDial dials network+address with a fixed timeout, honoring ctx
// cancellation. Tests inject a deterministic dialer.
func realDial(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	return d.DialContext(ctx, network, address)
}

// probe is one verification step. Probes are walked in slice order;
// reordering is a contract change (operators may key off probe numbers
// in dashboards).
type probe struct {
	n    int
	name string
	desc string
	fn   func(ctx context.Context, env *probeEnv) (status, detail string)
}

func allProbes() []probe {
	return []probe{
		{1, "system_users_exist", "system users exist", probeSystemUsers},
		{2, "pipelock_systemd_unit", "pipelock systemd unit running as pipelock-proxy", probeSystemdUnit},
		{3, "nftables_containment_ruleset", "nftables containment ruleset present", probeNFTContainment},
		{4, "wrapper_scripts_installed", "wrapper scripts installed", probeWrapperScripts},
		{5, "ca_bundle_present", "pipelock CA bundle readable", probeCABundle},
		{6, "pipelock_listening_loopback", "pipelock listening on loopback", probeLoopbackListen},
		{7, "no_proxy_env_correct", "NO_PROXY in plk-launch matches policy", probeNoProxyEnv},
		{8, "cc_agent_egress_denied", "pipelock-agent cannot reach the internet directly", probeCCAgentEgressDenied},
		{9, "operator_egress_reachable", "operator user can still reach the internet", probeOperatorEgress},
		{10, "binary_integrity_pin", "installed pipelock binary matches TOFU pin", probeBinaryIntegrity},
		{11, "cc_launch_allow_list_enforced", "plk-launch rejects tools missing from the allow-list", probeCCLaunchAllowList},
		{12, "listed_tool_targets_resolvable", "tools.list entries resolve for pipelock-agent", probeListedToolTargets},
	}
}

func probesForEnv(env *probeEnv) []probe {
	probes := allProbes()
	if len(env.workspacePaths) > 0 {
		probes = append(probes, probe{13, "workspace_access", "pipelock-agent can read configured workspace paths", probeWorkspaceAccess})
	}
	return probes
}

func probeWorkspaceAccess(ctx context.Context, env *probeEnv) (string, string) {
	var bad []string
	for _, path := range env.workspacePaths {
		clean, err := filepath.Abs(filepath.Clean(path))
		if err != nil {
			bad = append(bad, fmt.Sprintf("%s resolve: %v", path, err))
			continue
		}
		info, err := env.stat(clean)
		if err != nil {
			bad = append(bad, fmt.Sprintf("%s stat: %v", clean, err))
			continue
		}
		args := []string{"-n", "-u", env.agentUserName, "--", "test", "-r", clean}
		if info.IsDir() {
			args = []string{"-n", "-u", env.agentUserName, "--", "test", "-r", clean, "-a", "-x", clean}
		}
		out, code, err := env.runCmd(ctx, "sudo", args...)
		if err != nil {
			bad = append(bad, fmt.Sprintf("%s check failed: %v", clean, err))
			continue
		}
		if isSudoUserMissing(out) {
			return statusSkip, "pipelock-agent user missing (install never ran)"
		}
		if isSudoRefusal(out) {
			return statusSkip, "sudo -n refused (no NOPASSWD rule for operator -> pipelock-agent)"
		}
		if code != 0 {
			bad = append(bad, fmt.Sprintf("%s not readable/traversable by %s: %s", clean, env.agentUserName, oneLine(out)))
		}
	}
	if len(bad) > 0 {
		return statusFail, strings.Join(bad, "; ")
	}
	return statusPass, fmt.Sprintf("%d workspace path(s) readable by %s", len(env.workspacePaths), env.agentUserName)
}

func probeListedToolTargets(_ context.Context, env *probeEnv) (string, string) {
	data, err := env.readFile(env.toolsListPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return statusSkip, fmt.Sprintf("tools.list missing at %s (install never ran)", env.toolsListPath)
		}
		return statusFail, fmt.Sprintf("read %s: %v", env.toolsListPath, err)
	}
	entries, err := parseToolsList(data)
	if err != nil {
		return statusFail, fmt.Sprintf("parse %s: %v", env.toolsListPath, err)
	}
	if len(entries) == 0 {
		return statusFail, fmt.Sprintf("%s has no tool entries", env.toolsListPath)
	}

	agentPath := agentExecPath(env.agentUserName)
	var bad []string
	for _, entry := range entries {
		target := entry.target
		if target == "" {
			var ok bool
			target, ok = resolveToolInPath(env, entry.name, agentPath)
			if !ok {
				bad = append(bad, fmt.Sprintf("%s not found in pipelock-agent PATH", entry.name))
				continue
			}
		}
		if !filepath.IsAbs(target) {
			bad = append(bad, fmt.Sprintf("%s target %q is not absolute", entry.name, target))
			continue
		}
		info, err := env.stat(target)
		if err != nil {
			bad = append(bad, fmt.Sprintf("%s target %s: %v", entry.name, target, err))
			continue
		}
		if info.IsDir() {
			bad = append(bad, fmt.Sprintf("%s target %s is a directory", entry.name, target))
			continue
		}
		if info.Mode().Perm()&0o111 == 0 {
			bad = append(bad, fmt.Sprintf("%s target %s is not executable", entry.name, target))
		}
	}
	if len(bad) > 0 {
		return statusFail, strings.Join(bad, "; ")
	}
	return statusPass, fmt.Sprintf("%d allow-listed tool target(s) resolvable via %s", len(entries), agentPath)
}

func agentExecPath(agentUserName string) string {
	return "/home/" + agentUserName + "/.local/bin:/usr/local/bin:/usr/bin:/bin"
}

func resolveToolInPath(env *probeEnv, name, pathList string) (string, bool) {
	for _, dir := range filepath.SplitList(pathList) {
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

// probeCCLaunchAllowList runs `plk-launch <something-not-installed>` as
// pipelock-agent and asserts the script exits 5 - "tool not in allow-list".
// This exercises the full read path: sudoers grants no-password to
// plk-launch, /etc/pipelock is directory-traversable for pipelock-agent,
// /etc/pipelock/contain is traversable, /etc/pipelock/contain/tools.list
// is readable, and the bash script's allow-list lookup is intact.
//
// We use a sentinel tool name (random + obviously not a real tool) so
// that even on a system where the operator's `pipelock contain add-tool`
// invocations accidentally collide with real binaries, this probe still
// exercises the denial branch.
//
// Exit code mapping (matches install.go renderLaunchWrapper):
//   - 0  unexpected - the sentinel was somehow accepted and executed
//   - 1  sudo refused (NOPASSWD rule missing) → skip
//   - 3  tool-name regex rejected - sentinel chosen wrong
//   - 4  tools.list unreadable - fail, this breaks the launcher boundary
//   - 5  tool not in allow-list - PASS
//   - 6  in allow-list but PATH lookup failed - unexpected
func probeCCLaunchAllowList(ctx context.Context, env *probeEnv) (string, string) {
	// Sentinel must satisfy containToolNameRegex (max 31 chars) so plk-launch
	// reaches the allow-list rejection path (exit 5) instead of the up-front
	// name regex (exit 3). "not-a-real-tool" suffix preserves operator intent.
	const sentinelTool = "pipelock-probe-sentinel-tool"

	out, code, err := env.runCmd(ctx, "sudo", "-n", "-u", env.agentUserName, "--",
		env.launchPath, sentinelTool)
	if err != nil {
		return statusSkip, fmt.Sprintf("plk-launch invocation failed: %v", err)
	}
	if isSudoUserMissing(out) {
		return statusSkip, "pipelock-agent user missing (install never ran)"
	}
	if isSudoRefusal(out) {
		return statusSkip, "sudo -n refused (no NOPASSWD rule for operator -> pipelock-agent)"
	}
	if isSudoTargetCommandMissing(out) {
		return statusSkip, fmt.Sprintf("plk-launch missing at %s (install never ran)", env.launchPath)
	}

	switch code {
	case 5:
		return statusPass, "allow-list correctly rejected sentinel tool"
	case 4:
		return statusFail, fmt.Sprintf("tools.list unreadable by pipelock-agent (exit 4): %s", oneLine(out))
	case 0:
		return statusFail, fmt.Sprintf("sentinel tool %q was unexpectedly allowed; allow-list bypass", sentinelTool)
	default:
		// Anything else is unexpected. Report the exit code + first
		// stderr line so the operator can map it back to the wrapper's
		// exit-code table.
		return statusFail, fmt.Sprintf("plk-launch exit %d (expected 5): %s", code, oneLine(out))
	}
}

// probeBinaryIntegrity reads the integrity pin written at install time and
// compares it against the SHA-256 of the currently-running binary.
// Skipped when the pin file is missing (install never happened) or
// unreadable to this user (run as root to verify). Failure means either
// the binary was swapped after install OR a different pipelock binary is
// being used to run verify than the one that was installed.
func probeBinaryIntegrity(_ context.Context, env *probeEnv) (string, string) {
	data, err := env.readFile(env.pinPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return statusSkip, fmt.Sprintf("no pin at %s (install never ran or skipped)", env.pinPath)
		}
		return statusSkip, fmt.Sprintf("read %s: %v (rerun as root)", env.pinPath, err)
	}
	pinned := strings.TrimSpace(string(data))
	if pinned == "" {
		return statusFail, fmt.Sprintf("%s is empty (corrupted pin)", env.pinPath)
	}
	if _, err := hex.DecodeString(pinned); err != nil || len(pinned) != sha256HexLen {
		return statusFail, fmt.Sprintf("%s contains malformed SHA-256 pin (length %d)", env.pinPath, len(pinned))
	}

	self, err := env.selfPath()
	if err != nil {
		return statusFail, fmt.Sprintf("resolve self path: %v", err)
	}
	got, err := env.hashFile(self)
	if err != nil {
		return statusFail, fmt.Sprintf("hash %s: %v", self, err)
	}
	if got != pinned {
		// Truncate for readability; full hashes are 64 chars.
		return statusFail, fmt.Sprintf("binary hash mismatch: pin=%s got=%s (binary swapped after install or different binary running verify)",
			shortHash(pinned), shortHash(got))
	}
	return statusPass, fmt.Sprintf("binary hash %s matches pin", shortHash(pinned))
}

const sha256HexLen = 64

func shortHash(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12] + "…"
}

// probeRecord is one JSON record per probe in --json output.
type probeRecord struct {
	Probe  int    `json:"probe"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// aggregateRecord is the trailing JSON record summarizing the run.
type aggregateRecord struct {
	Aggregate aggregateBody `json:"aggregate"`
}

type aggregateBody struct {
	Pass     int `json:"pass"`
	Fail     int `json:"fail"`
	Skip     int `json:"skip"`
	Total    int `json:"total"`
	ExitCode int `json:"exit_code"`
}

// verifyOpts collects all flag-derived state for runVerify.
type verifyOpts struct {
	jsonOutput      bool
	enforcementOnly bool
	port            int
	workspacePaths  []string
}

func verifyCmd() *cobra.Command {
	var opts verifyOpts

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Run read-only probes against the containment model",
		Long: `Run twelve read-only probes to verify the workstation containment model
is installed correctly and the boundary is intact.

Probes inspect system users, the pipelock systemd unit, nftables rules,
wrapper scripts, the CA bundle, the pipelock loopback bind, the NO_PROXY
policy, run two egress canaries (pipelock-agent must NOT reach the internet
directly; the operator user must still reach the internet), verify the
installed binary matches the TOFU integrity pin written at install
time, and exercise plk-launch end-to-end with a sentinel tool to confirm
the allow-list enforcement path actually fires. Pass --workspace to also
verify that pipelock-agent can read/traverse real project directories.
Pass --enforcement-only when another process owns the proxy lifecycle;
that mode verifies the kernel/user/wrapper controls while skipping proxy
liveness probes before making plk wrappers the default entry point.

verify never mutates state. Probes that require root visibility
(nft list ruleset) record skip when run unprivileged.

Exit codes:
  0  All probes passed.
  1  At least one probe failed (containment is broken or partially installed).
  2  Verification incomplete (one or more probes skipped, curl/sudo missing,
     context cancelled).`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validatePort(opts.port); err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			env := defaultProbeEnv()
			env.port = opts.port
			env.workspacePaths = append([]string(nil), opts.workspacePaths...)
			return runVerify(cmd, env, opts)
		},
	}

	cmd.Flags().BoolVar(&opts.jsonOutput, "json", false, "emit newline-delimited JSON instead of text")
	cmd.Flags().BoolVar(&opts.enforcementOnly, "enforcement-only", false, "skip service and loopback listener liveness probes")
	cmd.Flags().IntVar(&opts.port, "port", defaultProxyPort, "pipelock listen port to probe on loopback")
	cmd.Flags().StringArrayVar(&opts.workspacePaths, "workspace", nil, "workspace path that pipelock-agent must be able to read/traverse (repeatable)")

	return cmd
}

func validatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid --port %d (must be 1-65535)", port)
	}
	return nil
}

// runVerify walks every probe in order, prints per-probe output in
// either text or JSON mode, and returns an ExitError carrying the
// aggregate exit code.
func runVerify(cmd *cobra.Command, env *probeEnv, opts verifyOpts) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	w := cmd.OutOrStdout()
	enc := json.NewEncoder(w)

	if !opts.jsonOutput {
		header := "pipelock contain verify"
		if opts.enforcementOnly {
			header += " --enforcement-only"
		}
		_, _ = fmt.Fprintln(w, header)
	}

	probes := probesForEnv(env)
	if opts.enforcementOnly {
		probes = enforcementProbes(probes)
	}
	var passN, failN, skipN int

	for _, p := range probes {
		status, detail := p.fn(ctx, env)
		switch status {
		case statusPass:
			passN++
		case statusFail:
			failN++
		case statusSkip:
			skipN++
		default:
			// A probe returned something unexpected. Coerce to fail
			// and carry the value forward so we don't silently drop it.
			failN++
			detail = fmt.Sprintf("invalid status %q (detail: %s)", status, detail)
			status = statusFail
		}

		if opts.jsonOutput {
			if err := enc.Encode(probeRecord{
				Probe:  p.n,
				Name:   p.name,
				Status: status,
				Detail: detail,
			}); err != nil {
				return fmt.Errorf("encoding probe %d JSON: %w", p.n, err)
			}
			continue
		}

		writeTextLine(w, p, status, detail)
	}

	exitCode := cliutil.ExitOK
	switch {
	case failN > 0:
		exitCode = cliutil.ExitGeneral
	case skipN > 0:
		exitCode = cliutil.ExitConfig
	}

	if opts.jsonOutput {
		if err := enc.Encode(aggregateRecord{Aggregate: aggregateBody{
			Pass:     passN,
			Fail:     failN,
			Skip:     skipN,
			Total:    len(probes),
			ExitCode: exitCode,
		}}); err != nil {
			return fmt.Errorf("encoding aggregate JSON: %w", err)
		}
	} else {
		_, _ = fmt.Fprintf(w, "Result: %d PASS / %d FAIL / %d SKIP — exit %d\n", passN, failN, skipN, exitCode)
	}

	if exitCode == cliutil.ExitOK {
		return nil
	}
	if failN > 0 {
		return cliutil.ExitCodeError(exitCode, fmt.Errorf("%d probe(s) failed", failN))
	}
	return cliutil.ExitCodeError(exitCode, fmt.Errorf("%d probe(s) skipped; verification incomplete", skipN))
}

func enforcementProbes(probes []probe) []probe {
	skip := map[string]struct{}{
		"pipelock_systemd_unit":       {},
		"pipelock_listening_loopback": {},
	}
	filtered := make([]probe, 0, len(probes))
	for _, p := range probes {
		if _, ok := skip[p.name]; ok {
			continue
		}
		filtered = append(filtered, p)
	}
	return filtered
}

// writeTextLine renders one probe outcome in text mode.
func writeTextLine(w io.Writer, p probe, status, detail string) {
	tag := "[PASS]"
	switch status {
	case statusFail:
		tag = "[FAIL]"
	case statusSkip:
		tag = "[SKIP]"
	}

	line := fmt.Sprintf("  %s probe %d: %s", tag, p.n, p.desc)
	if status != statusPass && detail != "" {
		line += " (" + detail + ")"
	} else if status == statusPass && detail != "" {
		line += " — " + detail
	}
	_, _ = fmt.Fprintln(w, line)
}

// ---------------------------------------------------------------------------
// Probe 1: system_users_exist
// ---------------------------------------------------------------------------

func probeSystemUsers(_ context.Context, env *probeEnv) (string, string) {
	proxy, perr := env.lookupUser(env.proxyUserName)
	agent, aerr := env.lookupUser(env.agentUserName)

	switch {
	case perr != nil && aerr != nil:
		return statusFail, fmt.Sprintf("neither %s nor %s exist", env.proxyUserName, env.agentUserName)
	case perr != nil:
		return statusFail, fmt.Sprintf("%s missing: %v", env.proxyUserName, perr)
	case aerr != nil:
		return statusFail, fmt.Sprintf("%s missing: %v", env.agentUserName, aerr)
	}

	return statusPass, fmt.Sprintf("%s uid=%s, %s uid=%s",
		env.proxyUserName, proxy.Uid, env.agentUserName, agent.Uid)
}

// ---------------------------------------------------------------------------
// Probe 2: pipelock_systemd_unit
// ---------------------------------------------------------------------------

func probeSystemdUnit(ctx context.Context, env *probeEnv) (string, string) {
	out, code, err := env.runCmd(ctx, "systemctl", "show", env.serviceName,
		"--property=ActiveState,SubState,User,Type",
	)
	if err != nil {
		return statusSkip, fmt.Sprintf("systemctl unavailable: %v", err)
	}
	if code != 0 {
		return statusFail, fmt.Sprintf("systemctl exit=%d: %s", code, oneLine(out))
	}

	fields := parseSystemdShow(out)
	active := fields["ActiveState"]
	sub := fields["SubState"]
	svcUser := fields["User"]

	if svcUser != env.proxyUserName {
		return statusFail, fmt.Sprintf("ActiveState=%s SubState=%s User=%q (want User=%s)",
			active, sub, svcUser, env.proxyUserName)
	}
	if active != "active" || sub != "running" {
		return statusFail, fmt.Sprintf("ActiveState=%s SubState=%s User=%s (want active/running)",
			active, sub, svcUser)
	}
	return statusPass, fmt.Sprintf("ActiveState=%s SubState=%s User=%s", active, sub, svcUser)
}

// parseSystemdShow parses `systemctl show --property=...` key=value
// output into a map. Empty lines and lines without an '=' are ignored.
func parseSystemdShow(out string) map[string]string {
	fields := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		fields[k] = v
	}
	return fields
}

// ---------------------------------------------------------------------------
// Probe 3: nftables_containment_ruleset
// ---------------------------------------------------------------------------

func probeNFTContainment(ctx context.Context, env *probeEnv) (string, string) {
	out, code, err := env.runCmd(ctx, probeNFTExecutable(env), "list", "table", "inet", env.nftTable)
	if err != nil {
		return statusSkip, fmt.Sprintf("nft unavailable: %v", err)
	}
	if code != 0 {
		low := strings.ToLower(out)
		if strings.Contains(low, "operation not permitted") || strings.Contains(low, "permission denied") {
			return statusSkip, "nft list table requires root; rerun as root"
		}
		if strings.Contains(low, "no such file") || strings.Contains(low, "does not exist") {
			return statusFail, fmt.Sprintf("table inet %s not loaded", env.nftTable)
		}
		return statusFail, fmt.Sprintf("nft exit=%d: %s", code, oneLine(out))
	}

	if !strings.Contains(out, "chain "+env.nftChain) {
		return statusFail, fmt.Sprintf("chain %s missing from table", env.nftChain)
	}

	current, err := containmentUIDsFromProbeEnv(env)
	if err != nil {
		return statusFail, err.Error()
	}
	if current.operatorKnown && !chainHasSkuidAcceptForUID(out, env.nftChain, current.operatorUID) {
		return statusFail, fmt.Sprintf("chain present but operator uid %d accept rule missing", current.operatorUID)
	}
	if !chainHasSkuidAcceptForUID(out, env.nftChain, current.proxyUID) {
		return statusFail, fmt.Sprintf("chain present but proxy uid %d accept rule missing", current.proxyUID)
	}
	if !chainHasAgentCatchAllDrop(out, env.nftChain, current.agentUID) {
		return statusFail, fmt.Sprintf("chain present but current agent uid %d catch-all skuid-drop rule missing", current.agentUID)
	}
	if !chainHasAgentProxyLoopbackAllowBeforeDrop(out, env.nftChain, current.agentUID, env.port) {
		return statusFail, fmt.Sprintf("chain present but current agent uid %d loopback allow for 127.0.0.1:%d is missing or appears after the agent catch-all drop", current.agentUID, env.port)
	}
	if !chainHasAgentDNSDropBeforeCatchAll(out, env.nftChain, current.agentUID, "udp") {
		return statusFail, fmt.Sprintf("chain present but current agent uid %d udp/53 DNS drop rule missing or appears after the agent catch-all drop", current.agentUID)
	}
	if !chainHasAgentDNSDropBeforeCatchAll(out, env.nftChain, current.agentUID, "tcp") {
		return statusFail, fmt.Sprintf("chain present but current agent uid %d tcp/53 DNS drop rule missing or appears after the agent catch-all drop", current.agentUID)
	}
	if chainHasUnsafeVerdictBeforeAgentDrop(out, env.nftChain, current, env.port) {
		return statusFail, "chain contains unexpected verdict before agent drop"
	}
	if env.nftPersistUnitPath != "" && env.nftRulesPath != "" {
		if err := verifyNFTPersistence(env); err != nil {
			return statusFail, err.Error()
		}
	}
	return statusPass, fmt.Sprintf("table inet %s has chain %s with current agent uid %d skuid drop rule, proxy-only loopback allow, direct-DNS drops, and persistence unit",
		env.nftTable, env.nftChain, current.agentUID)
}

type containmentUIDs struct {
	operatorUID   int
	operatorKnown bool
	proxyUID      int
	agentUID      int
}

func containmentUIDsFromProbeEnv(env *probeEnv) (containmentUIDs, error) {
	proxyUID, err := lookupUID(env.lookupUser, env.proxyUserName)
	if err != nil {
		return containmentUIDs{}, fmt.Errorf("lookup proxy uid %s: %w", env.proxyUserName, err)
	}
	if proxyUID == 0 {
		return containmentUIDs{}, fmt.Errorf("%s resolves to uid 0; containment proxy user must be non-root", env.proxyUserName)
	}
	agentUID, err := lookupUID(env.lookupUser, env.agentUserName)
	if err != nil {
		return containmentUIDs{}, fmt.Errorf("lookup agent uid %s: %w", env.agentUserName, err)
	}
	if agentUID == 0 {
		return containmentUIDs{}, fmt.Errorf("%s resolves to uid 0; contained agent user must be non-root", env.agentUserName)
	}

	current := containmentUIDs{proxyUID: proxyUID, agentUID: agentUID}
	if proxyUID == agentUID {
		return containmentUIDs{}, fmt.Errorf("%s and %s both resolve to uid %d; containment users must be distinct", env.proxyUserName, env.agentUserName, agentUID)
	}
	if env.nftRulesPath == "" {
		return current, nil
	}
	data, err := env.readFile(env.nftRulesPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return current, nil
		}
		return containmentUIDs{}, fmt.Errorf("read nftables rules file %s: %w", env.nftRulesPath, err)
	}
	header, ok, err := parseNFTRulesHeaderUIDs(data)
	if err != nil {
		return containmentUIDs{}, fmt.Errorf("parse nftables rules file %s: %w", env.nftRulesPath, err)
	}
	if !ok {
		return current, nil
	}
	if header.proxyUID != proxyUID {
		return containmentUIDs{}, fmt.Errorf("nftables rules file proxy uid %d does not match current %s uid %d", header.proxyUID, env.proxyUserName, proxyUID)
	}
	if header.agentUID != agentUID {
		return containmentUIDs{}, fmt.Errorf("nftables rules file agent uid %d does not match current %s uid %d", header.agentUID, env.agentUserName, agentUID)
	}
	if header.operatorUID == agentUID {
		return containmentUIDs{}, fmt.Errorf("nftables rules file operator uid %d matches current %s uid; contained agent must not be allow-listed", header.operatorUID, env.agentUserName)
	}
	current.operatorUID = header.operatorUID
	current.operatorKnown = true
	return current, nil
}

func lookupUID(lookup lookupUserFunc, name string) (int, error) {
	u, err := lookup(name)
	if err != nil {
		return 0, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, fmt.Errorf("parse uid: %w", err)
	}
	return uid, nil
}

type nftRulesHeaderUIDs struct {
	operatorUID int
	proxyUID    int
	agentUID    int
}

func parseNFTRulesHeaderUIDs(data []byte) (nftRulesHeaderUIDs, bool, error) {
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if !strings.HasPrefix(line, "#") || !strings.Contains(line, "operator=") {
			continue
		}
		fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(line, "#")))
		values := map[string]int{}
		for _, field := range fields {
			key, value, ok := strings.Cut(field, "=")
			if !ok {
				continue
			}
			switch key {
			case "operator", "pipelock-proxy", "pipelock-agent":
				uid, err := strconv.Atoi(value)
				if err != nil {
					return nftRulesHeaderUIDs{}, true, fmt.Errorf("%s uid %q: %w", key, value, err)
				}
				values[key] = uid
			}
		}
		operatorUID, hasOperator := values["operator"]
		proxyUID, hasProxy := values["pipelock-proxy"]
		agentUID, hasAgent := values["pipelock-agent"]
		if !hasOperator || !hasProxy || !hasAgent {
			return nftRulesHeaderUIDs{}, true, errors.New("managed uid header missing operator, pipelock-proxy, or pipelock-agent uid")
		}
		return nftRulesHeaderUIDs{operatorUID: operatorUID, proxyUID: proxyUID, agentUID: agentUID}, true, nil
	}
	return nftRulesHeaderUIDs{}, false, nil
}

func verifyNFTPersistence(env *probeEnv) error {
	data, err := env.readFile(env.nftPersistUnitPath)
	if err != nil {
		return fmt.Errorf("read nftables persistence unit %s: %w", env.nftPersistUnitPath, err)
	}
	body := string(data)
	if !execStartLineContains(body, env.nftRulesPath) {
		return fmt.Errorf("%s missing ExecStart for %s", env.nftPersistUnitPath, env.nftRulesPath)
	}
	return nil
}

func execStartLineContains(body, needle string) bool {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ExecStart=") && strings.Contains(line, needle) {
			return true
		}
	}
	return false
}

func probeNFTExecutable(env *probeEnv) string {
	if env != nil && env.nftPath != "" {
		return env.nftPath
	}
	return "nft"
}

func chainHasAgentCatchAllDrop(out, chainName string, uid int) bool {
	return chainHasLine(out, chainName, func(line string) bool {
		return lineHasTerminalSkuidVerdict(line, uid, "drop")
	})
}

func chainHasSkuidAcceptForUID(out, chainName string, uid int) bool {
	return chainHasLine(out, chainName, func(line string) bool {
		return lineHasTerminalSkuidVerdict(line, uid, "accept")
	})
}

func chainHasAgentProxyLoopbackAllowBeforeDrop(out, chainName string, agentUID, port int) bool {
	return chainHasLineBeforeAgentDrop(out, chainName, agentUID, func(line string) bool {
		return lineHasAgentProxyLoopbackAllow(line, agentUID, port)
	})
}

func lineHasAgentProxyLoopbackAllow(line string, agentUID, port int) bool {
	return lineHasSkuid(line, agentUID) &&
		lineHasIPDAddr(line, "127.0.0.1") &&
		lineHasToken(line, "tcp") &&
		lineHasDPort(line, port) &&
		lineHasToken(line, "accept")
}

func chainHasAgentDNSDropBeforeCatchAll(out, chainName string, agentUID int, protocol string) bool {
	return chainHasLineBeforeAgentDrop(out, chainName, agentUID, func(line string) bool {
		return lineHasSkuidProtocolDPortVerdict(line, agentUID, protocol, 53, "drop")
	})
}

func chainHasUnsafeVerdictBeforeAgentDrop(out, chainName string, uids containmentUIDs, proxyPort int) bool {
	return chainHasLineBeforeAgentDrop(out, chainName, uids.agentUID, func(line string) bool {
		// Before the agent catch-all drop, only the managed operator/proxy
		// accepts, the agent's proxy loopback allow, and DNS drops are safe.
		// Any other terminal/control-flow verdict can bypass containment under
		// the base-chain "policy accept" default.
		if !lineHasAnyToken(line, "accept", "return", "jump", "goto", "queue") {
			return false
		}
		if uids.operatorKnown && lineHasTerminalSkuidVerdict(line, uids.operatorUID, "accept") {
			return false
		}
		if lineHasTerminalSkuidVerdict(line, uids.proxyUID, "accept") {
			return false
		}
		if lineHasAgentProxyLoopbackAllow(line, uids.agentUID, proxyPort) {
			return false
		}
		if lineHasSkuidProtocolDPortVerdict(line, uids.agentUID, "udp", 53, "drop") ||
			lineHasSkuidProtocolDPortVerdict(line, uids.agentUID, "tcp", 53, "drop") {
			return false
		}
		if uid, ok := terminalSkuidUIDVerdict(line, "accept"); ok && uid != uids.agentUID {
			return false
		}
		return true
	})
}

func terminalSkuidUIDVerdict(line, verdict string) (int, bool) {
	fields := strings.Fields(line)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] != "skuid" {
			continue
		}
		uid, err := strconv.Atoi(fields[i+1])
		if err != nil {
			continue
		}
		verdictAt := indexTokenAfter(fields, verdict, i+2)
		if verdictAt != -1 && fieldsAreNFTBookkeeping(fields[i+2:verdictAt]) {
			return uid, true
		}
	}
	return 0, false
}

func lineHasSkuid(line string, uid int) bool {
	want := strconv.Itoa(uid)
	fields := strings.Fields(line)
	for i, field := range fields {
		if field == "skuid" && i+1 < len(fields) && fields[i+1] == want {
			return true
		}
	}
	return false
}

func lineHasTerminalSkuidVerdict(line string, uid int, verdict string) bool {
	fields := strings.Fields(line)
	uidText := strconv.Itoa(uid)
	skuidAt := indexSkuidUID(fields, uidText)
	if skuidAt == -1 {
		return false
	}
	verdictAt := indexTokenAfter(fields, verdict, skuidAt+1)
	if verdictAt == -1 {
		return false
	}
	return fieldsAreNFTBookkeeping(fields[skuidAt+1 : verdictAt])
}

func lineHasSkuidProtocolDPortVerdict(line string, uid int, protocol string, port int, verdict string) bool {
	fields := strings.Fields(line)
	skuidAt := indexSkuidUID(fields, strconv.Itoa(uid))
	if skuidAt == -1 || skuidAt+3 >= len(fields) {
		return false
	}
	if fields[skuidAt+1] != protocol || fields[skuidAt+2] != "dport" || fields[skuidAt+3] != strconv.Itoa(port) {
		return false
	}
	verdictAt := indexTokenAfter(fields, verdict, skuidAt+4)
	if verdictAt == -1 {
		return false
	}
	return fieldsAreNFTBookkeeping(fields[skuidAt+4 : verdictAt])
}

func indexSkuidUID(fields []string, uidText string) int {
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "skuid" && fields[i+1] == uidText {
			return i + 1
		}
	}
	return -1
}

func indexTokenAfter(fields []string, want string, start int) int {
	for i := start; i < len(fields); i++ {
		if fields[i] == want {
			return i
		}
	}
	return -1
}

func fieldsAreNFTBookkeeping(fields []string) bool {
	inPrefix := false
	seenCounter := false
	expectCount := false
	for _, field := range fields {
		if inPrefix {
			if strings.HasSuffix(field, `"`) {
				inPrefix = false
			}
			continue
		}
		if expectCount {
			// `nft list` renders an inline counter as
			// "counter packets <n> bytes <n>"; consume the numeric
			// argument that follows the packets/bytes keyword.
			expectCount = false
			if _, err := strconv.Atoi(field); err == nil {
				continue
			}
			return false
		}
		switch field {
		case "counter":
			seenCounter = true
		case "log":
			continue
		case "packets", "bytes":
			if !seenCounter {
				return false
			}
			expectCount = true
		case "prefix":
			inPrefix = true
		default:
			return false
		}
	}
	return !inPrefix && !expectCount
}

func lineHasIPDAddr(line, addr string) bool {
	fields := strings.Fields(line)
	for i := 0; i+2 < len(fields); i++ {
		if fields[i] == "ip" && fields[i+1] == "daddr" && fields[i+2] == addr {
			return true
		}
	}
	return false
}

func lineHasDPort(line string, port int) bool {
	want := strconv.Itoa(port)
	fields := strings.Fields(line)
	for i, field := range fields {
		if field == "dport" && i+1 < len(fields) && fields[i+1] == want {
			return true
		}
	}
	return false
}

func lineHasToken(line, want string) bool {
	for _, field := range strings.Fields(line) {
		if field == want {
			return true
		}
	}
	return false
}

func lineHasAnyToken(line string, wants ...string) bool {
	for _, field := range strings.Fields(line) {
		for _, want := range wants {
			if field == want {
				return true
			}
		}
	}
	return false
}

func chainHasLineBeforeAgentDrop(out, chainName string, agentUID int, match func(string) bool) bool {
	inChain := false
	depth := 0
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if !inChain && (strings.HasPrefix(line, "chain "+chainName+" ") || line == "chain "+chainName+"{") {
			inChain = true
		}
		if !inChain {
			continue
		}
		if strings.Contains(line, "{") {
			depth += strings.Count(line, "{")
		}
		if lineHasTerminalSkuidVerdict(line, agentUID, "drop") {
			return false
		}
		if match(line) {
			return true
		}
		if strings.Contains(line, "}") {
			depth -= strings.Count(line, "}")
			if depth <= 0 {
				inChain = false
				depth = 0
			}
		}
	}
	return false
}

func chainHasLine(out, chainName string, match func(string) bool) bool {
	inChain := false
	depth := 0
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if !inChain && (strings.HasPrefix(line, "chain "+chainName+" ") || line == "chain "+chainName+"{") {
			inChain = true
		}
		if !inChain {
			continue
		}
		if strings.Contains(line, "{") {
			depth += strings.Count(line, "{")
		}
		if match(line) {
			return true
		}
		if strings.Contains(line, "}") {
			depth -= strings.Count(line, "}")
			if depth <= 0 {
				inChain = false
				depth = 0
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Probe 4: wrapper_scripts_installed
// ---------------------------------------------------------------------------

func probeWrapperScripts(_ context.Context, env *probeEnv) (string, string) {
	info, err := os.Stat(filepath.Clean(env.launchPath))
	if err != nil {
		return statusFail, fmt.Sprintf("%s missing: %v", env.launchPath, err)
	}
	mode := info.Mode().Perm()
	if mode != 0o755 {
		return statusFail, fmt.Sprintf("%s has perm 0o%03o, want 0o755", env.launchPath, mode)
	}

	metaPath := filepath.Join(env.wrapperDir, "plk")
	info, err = os.Stat(filepath.Clean(metaPath))
	if err != nil {
		return statusFail, fmt.Sprintf("%s missing: %v", metaPath, err)
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return statusFail, fmt.Sprintf("%s is not a non-empty executable wrapper file", metaPath)
	}
	mode = info.Mode().Perm()
	if mode != 0o755 {
		return statusFail, fmt.Sprintf("%s has perm 0o%03o, want 0o755", metaPath, mode)
	}

	wrappers, err := wrappersForVerify(env)
	if err != nil {
		return statusFail, err.Error()
	}
	var foundNames []string
	for _, name := range wrappers {
		if strings.TrimSpace(name) == "" {
			return statusFail, "wrapper inventory contains empty wrapper name"
		}
		p := filepath.Join(env.wrapperDir, name)
		info, err := os.Stat(filepath.Clean(p))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return statusFail, fmt.Sprintf("%s stat failed: %v", p, err)
		}
		if !info.Mode().IsRegular() || info.Size() == 0 {
			return statusFail, fmt.Sprintf("%s is not a non-empty executable wrapper file", p)
		}
		mode := info.Mode().Perm()
		if mode != 0o755 {
			return statusFail, fmt.Sprintf("%s has perm 0o%03o, want 0o755", p, mode)
		}
		foundNames = append(foundNames, name)
	}
	if len(foundNames) == 0 {
		return statusFail, fmt.Sprintf("no tool wrappers found in %s (expected one of %v)",
			env.wrapperDir, wrappers)
	}
	return statusPass, fmt.Sprintf("plk + plk-launch + %d tool wrapper(s): %s",
		len(foundNames), strings.Join(foundNames, ","))
}

func wrappersForVerify(env *probeEnv) ([]string, error) {
	if env.wrapperInvPath == "" {
		return append([]string(nil), env.toolWrappers...), nil
	}
	data, err := env.readFile(env.wrapperInvPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return append([]string(nil), env.toolWrappers...), nil
		}
		return nil, fmt.Errorf("read wrapper inventory %s: %w", env.wrapperInvPath, err)
	}
	var inv wrapperInventory
	if err := json.Unmarshal(data, &inv); err != nil {
		return nil, fmt.Errorf("parse wrapper inventory %s: %w", env.wrapperInvPath, err)
	}
	if len(inv.Wrappers) == 0 {
		return nil, fmt.Errorf("wrapper inventory %s is empty", env.wrapperInvPath)
	}
	return append([]string(nil), inv.Wrappers...), nil
}

// ---------------------------------------------------------------------------
// Probe 5: ca_bundle_present
// ---------------------------------------------------------------------------

func probeCABundle(_ context.Context, env *probeEnv) (string, string) {
	data, err := os.ReadFile(filepath.Clean(env.caBundlePath))
	if err != nil {
		return statusFail, fmt.Sprintf("read %s: %v", env.caBundlePath, err)
	}

	count, pipelockCN, parseErr := scanPipelockCertCN(data)
	if parseErr != nil {
		return statusFail, fmt.Sprintf("parse %s: %v", env.caBundlePath, parseErr)
	}
	if count == 0 {
		return statusFail, fmt.Sprintf("%s parsed 0 certificates", env.caBundlePath)
	}
	if pipelockCN == "" {
		return statusFail, fmt.Sprintf("%s has %d cert(s); none match Pipelock", env.caBundlePath, count)
	}
	return statusPass, fmt.Sprintf("%d certs in bundle; pipelock CA CN=%s", count, pipelockCN)
}

// scanPipelockCertCN walks a PEM blob and returns the total cert
// count and the CN of the first certificate whose subject CN
// contains "pipelock" (case-insensitive).
func scanPipelockCertCN(data []byte) (int, string, error) {
	var count int
	var pipelockCN string
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return count, pipelockCN, fmt.Errorf("certificate %d: %w", count+1, err)
		}
		count++
		if pipelockCN == "" && strings.Contains(strings.ToLower(cert.Subject.CommonName), "pipelock") {
			pipelockCN = cert.Subject.CommonName
		}
	}
	return count, pipelockCN, nil
}

// ---------------------------------------------------------------------------
// Probe 6: pipelock_listening_loopback
// ---------------------------------------------------------------------------

func probeLoopbackListen(ctx context.Context, env *probeEnv) (string, string) {
	addr := net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", env.port))
	start := time.Now()
	conn, err := env.dialCtx(ctx, "tcp", addr, probeDialTimeout)
	if err != nil {
		return statusFail, fmt.Sprintf("dial %s: %v", addr, err)
	}
	elapsed := time.Since(start)
	_ = conn.Close()
	return statusPass, fmt.Sprintf("%s accepted TCP within %s", addr, formatDialDuration(elapsed))
}

// formatDialDuration renders an elapsed dial time at millisecond
// resolution, special-casing sub-millisecond results so they don't
// appear as a misleading "0s".
func formatDialDuration(d time.Duration) string {
	if d < time.Millisecond {
		return "<1ms"
	}
	return d.Round(time.Millisecond).String()
}

// ---------------------------------------------------------------------------
// Probe 7: no_proxy_env_correct
// ---------------------------------------------------------------------------

func probeNoProxyEnv(_ context.Context, env *probeEnv) (string, string) {
	data, err := os.ReadFile(filepath.Clean(env.launchPath))
	if err != nil {
		return statusFail, fmt.Sprintf("read %s: %v", env.launchPath, err)
	}
	actual := extractNoProxy(data)
	if actual == "" {
		return statusFail, fmt.Sprintf("NO_PROXY assignment not found in %s", env.launchPath)
	}
	if actual != expectedNoProxy {
		return statusFail, fmt.Sprintf("NO_PROXY value differs from policy: %q (want %q)", actual, expectedNoProxy)
	}
	return statusPass, expectedNoProxy
}

// extractNoProxy finds the first NO_PROXY=<value> assignment in the
// wrapper script and returns the full assignment string up to the
// first whitespace or shell line continuation. Returns "" if no
// assignment is present.
func extractNoProxy(data []byte) string {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, field := range strings.Fields(line) {
			field = strings.TrimSuffix(field, "\\")
			if strings.HasPrefix(field, "NO_PROXY=") {
				return field
			}
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Probe 8: cc_agent_egress_denied
// ---------------------------------------------------------------------------

func curlNoProxyArgsFor(curl string) []string {
	if curl == "" {
		curl = defaultCurlPath
	}
	return []string{
		curl,
		"--connect-timeout", curlConnectTimeout,
		"--max-time", curlMaxTime,
		"--noproxy", "*",
		"-sS",
		"-o", "/dev/null",
		"-w", "%{http_code}",
		canaryURL,
	}
}

func probeCCAgentEgressDenied(ctx context.Context, env *probeEnv) (string, string) {
	curlArgs := curlNoProxyArgsFor(env.curlPath)
	curlPath := curlArgs[0]
	args := append([]string{"-n", "-u", env.agentUserName, "--"}, curlArgs...)
	out, code, err := env.runCmd(ctx, "sudo", args...)
	if err != nil {
		return statusSkip, fmt.Sprintf("sudo/curl unavailable: %v", err)
	}
	if isSudoRefusal(out) {
		return statusSkip, "sudo refused without password; configure NOPASSWD entry to enable canary"
	}
	if isSudoUserMissing(out) {
		return statusSkip, fmt.Sprintf("%s user not present; install containment model first", env.agentUserName)
	}
	if isSudoTargetCommandMissing(out) {
		return statusSkip, fmt.Sprintf("sudo could not execute %s; install curl to enable canary", curlPath)
	}
	if code == 0 {
		return statusFail, fmt.Sprintf("unexpected curl success: HTTP %s from example.com", oneLine(out))
	}
	return statusPass, fmt.Sprintf("curl blocked (exit=%d) — containment enforced", code)
}

// ---------------------------------------------------------------------------
// Probe 9: operator_egress_reachable
// ---------------------------------------------------------------------------

func probeOperatorEgress(ctx context.Context, env *probeEnv) (string, string) {
	var out string
	var code int
	var err error

	if env.operatorUser == "" {
		curlArgs := curlNoProxyArgsFor(env.curlPath)
		out, code, err = env.runCmd(ctx, curlArgs[0], curlArgs[1:]...)
	} else {
		args := append([]string{"-n", "-u", env.operatorUser, "--"}, curlNoProxyArgsFor(env.curlPath)...)
		out, code, err = env.runCmd(ctx, "sudo", args...)
	}

	if err != nil {
		return statusSkip, fmt.Sprintf("curl unavailable: %v", err)
	}
	if isSudoRefusal(out) {
		return statusSkip, "sudo refused without password; rerun curl manually as operator"
	}
	if isSudoUserMissing(out) {
		return statusSkip, fmt.Sprintf("%s user not present", env.operatorUser)
	}
	if isSudoTargetCommandMissing(out) {
		return statusSkip, "curl not executable for operator canary"
	}
	if code != 0 {
		return statusFail, fmt.Sprintf("operator curl failed (exit=%d): %s", code, oneLine(out))
	}
	// Probe 9 contract is "any 2xx/3xx HTTP". Curl with -w '%{http_code}'
	// exits 0 even on 4xx/5xx, so we must inspect the printed status
	// code instead of trusting curl's exit code alone. A captive portal
	// or carrier intercept returning a synthetic 4xx would otherwise
	// look like "operator reachable". realRunCommand merges stdout and
	// stderr, so benign sudo/PAM/libnss warnings can land in front of
	// curl's HTTP code; take the trailing whitespace-separated token
	// since `-w '%{http_code}'` writes the code last with no newline.
	fields := strings.Fields(oneLine(out))
	if len(fields) == 0 {
		return statusFail, "operator curl produced no output"
	}
	httpCodeStr := fields[len(fields)-1]
	httpCode, parseErr := strconv.Atoi(httpCodeStr)
	if parseErr != nil {
		return statusFail, fmt.Sprintf("operator returned unparseable HTTP code: %q", httpCodeStr)
	}
	if httpCode < 200 || httpCode >= 400 {
		return statusFail, fmt.Sprintf("operator returned non-2xx/3xx HTTP %d", httpCode)
	}
	return statusPass, fmt.Sprintf("HTTP %d from example.com", httpCode)
}

// isSudoRefusal scans subprocess output for the well-known sudo
// failure modes that indicate no NOPASSWD entry, not a curl-level
// failure. Used by probes 8 and 9 to disambiguate skip vs fail.
func isSudoRefusal(out string) bool {
	low := strings.ToLower(out)
	switch {
	case strings.Contains(low, "password is required"),
		strings.Contains(low, "may not run"),
		strings.Contains(low, "not allowed to execute"),
		strings.Contains(low, "no tty present"):
		return true
	}
	return false
}

// isSudoUserMissing detects sudo's "unknown user" failure mode. If the
// target user (pipelock-agent or the operator) does not exist on the system,
// sudo exits non-zero before invoking the target command. Probes 8
// and 9 must treat this as skip rather than fail, otherwise an
// uninstalled containment model would falsely report PASS on the
// canary.
func isSudoUserMissing(out string) bool {
	return strings.Contains(strings.ToLower(out), "unknown user")
}

func isSudoTargetCommandMissing(out string) bool {
	low := strings.ToLower(out)
	return strings.Contains(low, "command not found") ||
		strings.Contains(low, "no such file or directory")
}

// oneLine trims trailing whitespace and collapses internal newlines so
// detail lines don't break text output.
func oneLine(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}
