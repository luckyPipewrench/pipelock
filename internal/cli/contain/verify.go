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
	"math"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

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

	probeDialTimeout        = 2 * time.Second
	readinessTimeout        = 5 * time.Second
	installReadinessTimeout = 30 * time.Second
	readinessInterval       = 100 * time.Millisecond

	// curl flags shared between the egress canary and the operator
	// reachability probe. Connect timeout is intentionally lower than
	// max time so a slow handshake still returns within probe budget.
	curlConnectTimeout = "3"
	curlMaxTime        = "5"
	defaultCurlPath    = "/usr/bin/curl"
	curlPath           = defaultCurlPath
	canaryURL          = "https://example.com/"

	// Probe 8 uses a DNS-free, non-routable TEST-NET-1 address on a normally
	// unused port. This forces the probe packet through the managed catch-all
	// agent DROP rule and removes DNS/TLS as alternate causes of failure. The
	// curl's own time_connect measurement provides probe-specific evidence of
	// whether this canary established TCP; the UID-wide DROP counter only
	// corroborates a dial that did not complete.
	directEgressCanaryURL       = "http://192.0.2.1:9/"
	directCurlConnectTimeout    = "1"
	directCurlMaxTime           = "2"
	directCurlTimeConnectPrefix = "PLK_TIME_CONNECT="
	directCurlWriteOut          = "\n" + directCurlTimeConnectPrefix + "%{time_connect}\n%{http_code}"

	// Probe status values. Strings (not an enum type) so JSON
	// serialization is identity and tests can compare cheaply.
	statusPass    = "pass"
	statusFail    = "fail"
	statusSkip    = "skip"
	statusUnknown = "unknown"

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

type waitFunc func(ctx context.Context, duration time.Duration) error

// lookupUserFunc is the os/user.Lookup signature, factored so tests can
// substitute a deterministic lookup.
type lookupUserFunc func(name string) (*user.User, error)

type groupIDsFunc func(*user.User) ([]string, error)

// dropCounterFunc reads the total packet count for the managed nftables DROP
// rules that apply to the contained agent user.
type dropCounterFunc func(ctx context.Context, env *probeEnv) (uint64, error)

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
	readinessTimeout   time.Duration
	curlPath           string
	pinPath            string
	wrapperInvPath     string
	toolsListPath      string
	workspacePaths     []string
	pipelockTarget     string
	verifyRunningImage bool
	// postureProofPath is the resolved path the current `contain run` writes its
	// signed posture capsule to. It is exported into the contained launch env as
	// PIPELOCK_POSTURE_PROOF so an in-child emitter binds the exact capsule this
	// run produced, even when --posture-output points off the default path.
	postureProofPath string

	runCmd      runCommand
	dropCounter dropCounterFunc
	dialCtx     dialFunc
	wait        waitFunc
	lookupUser  lookupUserFunc
	groupIDs    groupIDsFunc
	stat        func(path string) (os.FileInfo, error)
	readFile    func(path string) ([]byte, error)
	readLink    func(path string) (string, error)
	selfPath    func() (string, error)
	hashFile    func(path string) (string, error)
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
		pipelockTarget:     defaultPipelockTarget,
		verifyRunningImage: true,
		runCmd:             realRunCommand,
		dropCounter:        readContainmentDropCounter,
		dialCtx:            realDial,
		wait:               waitForReadiness,
		lookupUser:         user.Lookup,
		groupIDs:           realGroupIDs,
		stat:               os.Stat,
		readFile:           os.ReadFile,
		readLink:           os.Readlink,
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

// errorTrackingWriter preserves the first output error even when a text
// renderer intentionally ignores individual fmt write results. Command drivers
// check Err after each logical record so a broken output stream can never be
// reported as a successful verification.
type errorTrackingWriter struct {
	w   io.Writer
	err error
}

// Write forwards p while recording the first error or short write.
func (w *errorTrackingWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	n, err := w.w.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	if err != nil {
		w.err = err
	}
	return n, err
}

// Err returns the first write failure observed by Write.
func (w *errorTrackingWriter) Err() error {
	return w.err
}

// realDial dials network+address with a fixed timeout, honoring ctx
// cancellation. Tests inject a deterministic dialer.
func realDial(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	return d.DialContext(ctx, network, address)
}

func waitForReadiness(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
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
		{10, "binary_integrity_pin", "deployed and running pipelock binary match TOFU pin", probeBinaryIntegrity},
		{11, "cc_launch_allow_list_enforced", "plk-launch rejects tools missing from the allow-list", probeCCLaunchAllowList},
		{12, "listed_tool_targets_resolvable", "tools.list entries resolve for pipelock-agent", probeListedToolTargets},
	}
}

func probesForEnv(env *probeEnv) []probe {
	probes := allProbes()
	if !env.verifyRunningImage {
		for i := range probes {
			if probes[i].name == "binary_integrity_pin" {
				probes[i].desc = "deployed pipelock binary matches TOFU pin; running-service image is not verified"
				break
			}
		}
	}
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

// probeListedToolTargets verifies each configured wrapper target exists and is
// executable from the contained agent's user context.
func probeListedToolTargets(ctx context.Context, env *probeEnv) (string, string) {
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
			continue
		}

		out, code, runErr := env.runCmd(ctx, "sudo", "-n", "-u", env.agentUserName, "--", "test", "-x", target)
		if runErr != nil {
			return statusSkip, fmt.Sprintf("could not verify %s as %s: %v", target, env.agentUserName, runErr)
		}
		if isSudoUserMissing(out) {
			return statusSkip, fmt.Sprintf("%s user missing (install never ran)", env.agentUserName)
		}
		if isSudoRefusal(out) {
			return statusSkip, fmt.Sprintf("sudo -n refused agent-context executable check for %s", target)
		}
		if code != 0 {
			bad = append(bad, fmt.Sprintf("%s target %s is not executable/traversable by %s: %s",
				entry.name, target, env.agentUserName, oneLine(out)))
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
// normally confirms all three identities agree: the deployed install path, the
// effective systemd ExecStart path, and the executable mapped by the service's
// current MainPID. In enforcement-only mode it checks the deployed path and pin
// only, and reports that running-service image verification was not performed.
// Running-image checks skip when the needed host state is unavailable to the
// caller (for example, /proc access requires root).
//
// This is still trust-on-first-use drift detection. It does not survive an
// attacker able to rewrite the binary, pin, unit, and running process as root.
func probeBinaryIntegrity(ctx context.Context, env *probeEnv) (string, string) {
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
	// Install writes a lowercase hex digest and hashFile returns lowercase, so an
	// uppercase pin can never match. Rejecting it as malformed here tells the
	// operator the pin itself is wrong; letting it through reports a hash
	// mismatch, which reads as a swapped binary and sends them hunting a
	// compromise that did not happen.
	if _, err := hex.DecodeString(pinned); err != nil || len(pinned) != sha256HexLen ||
		pinned != strings.ToLower(pinned) {
		return statusFail, fmt.Sprintf("%s contains malformed SHA-256 pin (length %d)", env.pinPath, len(pinned))
	}

	target := filepath.Clean(env.pipelockTarget)
	got, err := env.hashFile(target)
	if err != nil {
		return statusFail, fmt.Sprintf("hash deployed binary %s: %v", target, err)
	}
	if got != pinned {
		// Truncate for readability; full hashes are 64 chars.
		return statusFail, fmt.Sprintf("binary hash mismatch: pin=%s got=%s (deployed binary swapped after install)",
			shortHash(pinned), shortHash(got))
	}
	if !env.verifyRunningImage {
		return statusPass, fmt.Sprintf("deployed %s (running service image not verified)", binaryIntegrityDetail(env, target, pinned))
	}

	// The installed pathname alone is not the running service identity. An
	// atomic upgrade can replace and re-pin the file while the old executable
	// remains mapped by the current service process until restart.
	execStart, code, err := env.runCmd(ctx, "systemctl", "show", env.serviceName, "--property=ExecStart", "--value")
	if err != nil {
		return statusSkip, fmt.Sprintf("systemctl unavailable for running binary verification: %v", err)
	}
	if code != 0 {
		return statusFail, fmt.Sprintf("systemctl exit=%d while reading ExecStart: %s", code, oneLine(execStart))
	}

	execPath, err := systemdExecStartPath(execStart)
	if err != nil {
		return statusFail, fmt.Sprintf("parse effective ExecStart: %v", err)
	}
	if filepath.Clean(execPath) != target {
		return statusFail, fmt.Sprintf("effective ExecStart path %s does not match deployed binary %s", oneLine(execPath), oneLine(target))
	}

	mainPID, code, err := env.runCmd(ctx, "systemctl", "show", env.serviceName, "--property=MainPID", "--value")
	if err != nil {
		return statusSkip, fmt.Sprintf("systemctl unavailable for running binary verification: %v", err)
	}
	if code != 0 {
		return statusFail, fmt.Sprintf("systemctl exit=%d while reading MainPID: %s", code, oneLine(mainPID))
	}

	pid, err := systemdMainPID(strings.TrimSpace(mainPID))
	if err != nil {
		return statusFail, fmt.Sprintf("parse service MainPID: %v", err)
	}
	procExe := serviceProcessExePath(pid)
	runningPath, err := env.readLink(procExe)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return statusSkip, fmt.Sprintf("read running service image %s: %v (rerun as root)", procExe, err)
		}
		return statusFail, fmt.Sprintf("read running service image %s: %v", procExe, err)
	}

	targetInfo, err := env.stat(target)
	if err != nil {
		return statusFail, fmt.Sprintf("stat deployed binary %s: %v", target, err)
	}
	runningInfo, err := env.stat(procExe)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return statusSkip, fmt.Sprintf("stat running service image %s: %v (rerun as root)", procExe, err)
		}
		return statusFail, fmt.Sprintf("stat running service image %s: %v", procExe, err)
	}
	if !os.SameFile(targetInfo, runningInfo) {
		return statusFail, fmt.Sprintf("running service image %s differs from deployed binary %s", oneLine(runningPath), oneLine(target))
	}

	runningHash, err := env.hashFile(procExe)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return statusSkip, fmt.Sprintf("hash running service image %s: %v (rerun as root)", procExe, err)
		}
		return statusFail, fmt.Sprintf("hash running service image %s: %v", procExe, err)
	}
	if runningHash != pinned {
		return statusFail, fmt.Sprintf("running service image hash mismatch: pin=%s got=%s", shortHash(pinned), shortHash(runningHash))
	}

	return statusPass, fmt.Sprintf("deployed and running service %s", binaryIntegrityDetail(env, target, pinned))
}

func binaryIntegrityDetail(env *probeEnv, target, pinned string) string {
	detail := fmt.Sprintf("binary hash %s matches pin", shortHash(pinned))
	if self, err := env.selfPath(); err == nil && filepath.Clean(self) != target {
		self = filepath.Clean(self)
		targetInfo, targetErr := env.stat(target)
		selfInfo, selfErr := env.stat(self)
		switch {
		case targetErr != nil || selfErr != nil:
			// Identity is unknown, not different. Saying the binaries differ here
			// would assert something unverified, which is the failure this probe
			// exists to stop making.
			detail += fmt.Sprintf(" (note: could not compare invoking binary %s with deployed binary %s)", self, target)
		case !os.SameFile(targetInfo, selfInfo):
			detail += fmt.Sprintf(" (note: invoking binary %s differs from deployed binary %s)", self, target)
		}
	}
	return detail
}

// systemdExecStartPath extracts the one executable path from systemctl show's
// stable ExecStart representation. Pipelock's managed service is Type=simple
// with exactly one command; accepting multiple commands here would leave its
// running program ambiguous.
func systemdExecStartPath(raw string) (string, error) {
	var paths []string
	for _, segment := range strings.Split(raw, ";") {
		segment = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(segment), "{"))
		if !strings.HasPrefix(segment, "path=") {
			continue
		}
		path := strings.TrimPrefix(segment, "path=")
		if path == "" || !filepath.IsAbs(path) {
			return "", fmt.Errorf("invalid executable path %q", path)
		}
		paths = append(paths, path)
	}
	if len(paths) == 0 {
		return "", fmt.Errorf("no executable path in %q", raw)
	}
	if len(paths) != 1 {
		return "", fmt.Errorf("expected one executable path, found %d", len(paths))
	}
	return paths[0], nil
}

func systemdMainPID(raw string) (int, error) {
	if raw == "" {
		return 0, errors.New("missing MainPID")
	}
	pid, err := strconv.Atoi(raw)
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("invalid MainPID %q", raw)
	}
	return pid, nil
}

func serviceProcessExePath(pid int) string {
	return filepath.Join("/proc", strconv.Itoa(pid), "exe")
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
	Unknown  int `json:"unknown,omitempty"`
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
deployed and running service binaries match the TOFU integrity pin written at
install time, and exercise plk-launch end-to-end with a sentinel tool to confirm
the allow-list enforcement path actually fires. Pass --workspace to also
verify that pipelock-agent can read/traverse real project directories.
Pass --enforcement-only when another process owns the proxy lifecycle;
that mode verifies the kernel/user/wrapper controls and the pinned file at the
deployed path, while skipping proxy liveness and running-service-image checks.

verify never mutates state. Probes that require root visibility
(nft list ruleset) record skip when run unprivileged.

Exit codes:
  0  All probes passed.
  1  At least one probe failed (containment is broken or partially installed).
  2  Verification incomplete (one or more probes skipped or inconclusive,
     curl/sudo missing, context cancelled).`,
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
	cmd.Flags().BoolVar(&opts.enforcementOnly, "enforcement-only", false, "skip service, loopback, and running-service-image checks")
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
	// Mode policy is per invocation. Callers can share a probe environment in
	// tests and embedders, so never toggle a field on their environment while a
	// verification is running.
	runEnv := *env
	if opts.enforcementOnly {
		runEnv.verifyRunningImage = false
	}

	w := cmd.OutOrStdout()
	var textWriter *errorTrackingWriter
	if !opts.jsonOutput {
		textWriter = &errorTrackingWriter{w: w}
		w = textWriter
	}
	enc := json.NewEncoder(w)

	if !opts.jsonOutput {
		header := "pipelock contain verify"
		if opts.enforcementOnly {
			header += " --enforcement-only"
		}
		_, _ = fmt.Fprintln(w, header)
		if err := textWriter.Err(); err != nil {
			return fmt.Errorf("writing verify header: %w", err)
		}
	}

	probes := probesForEnv(&runEnv)
	if opts.enforcementOnly {
		probes = enforcementProbes(probes)
	}
	var passN, failN, skipN, unknownN int

	for _, p := range probes {
		status, detail := p.fn(ctx, &runEnv)
		switch status {
		case statusPass:
			passN++
		case statusFail:
			failN++
		case statusSkip:
			skipN++
		case statusUnknown:
			unknownN++
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
		if err := textWriter.Err(); err != nil {
			return fmt.Errorf("writing probe %d text: %w", p.n, err)
		}
	}

	exitCode := cliutil.ExitOK
	switch {
	case failN > 0:
		exitCode = cliutil.ExitGeneral
	case skipN > 0 || unknownN > 0:
		exitCode = cliutil.ExitConfig
	}

	if opts.jsonOutput {
		if err := enc.Encode(aggregateRecord{Aggregate: aggregateBody{
			Pass:     passN,
			Fail:     failN,
			Skip:     skipN,
			Unknown:  unknownN,
			Total:    len(probes),
			ExitCode: exitCode,
		}}); err != nil {
			return fmt.Errorf("encoding aggregate JSON: %w", err)
		}
	} else {
		if unknownN > 0 {
			_, _ = fmt.Fprintf(w, "Result: %d PASS / %d FAIL / %d SKIP / %d UNKNOWN — exit %d\n", passN, failN, skipN, unknownN, exitCode)
		} else {
			_, _ = fmt.Fprintf(w, "Result: %d PASS / %d FAIL / %d SKIP — exit %d\n", passN, failN, skipN, exitCode)
		}
		if err := textWriter.Err(); err != nil {
			return fmt.Errorf("writing verify aggregate: %w", err)
		}
	}

	if exitCode == cliutil.ExitOK {
		return nil
	}
	if failN > 0 {
		return cliutil.ExitCodeError(exitCode, fmt.Errorf("%d probe(s) failed", failN))
	}
	if unknownN > 0 {
		return cliutil.ExitCodeError(exitCode, fmt.Errorf("%d probe(s) inconclusive; verification incomplete", unknownN))
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
	case statusUnknown:
		tag = "[UNKNOWN]"
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

// probeNFTContainment verifies the installed nftables boundary structure,
// ordering, UID ownership, and persistence wiring.
func probeNFTContainment(ctx context.Context, env *probeEnv) (string, string) {
	out, code, err := env.runCmd(ctx, probeNFTExecutable(env), "-n", "-a", "list", "chain", "inet", env.nftTable, env.nftChain)
	if err != nil {
		return statusSkip, fmt.Sprintf("nft unavailable: %v", err)
	}
	if code != 0 {
		low := strings.ToLower(out)
		if strings.Contains(low, "operation not permitted") || strings.Contains(low, "permission denied") {
			return statusSkip, "nft list chain requires root; rerun as root"
		}
		if strings.Contains(low, "no such file") || strings.Contains(low, "does not exist") {
			return statusFail, fmt.Sprintf("chain %s missing or not loaded from table inet %s", env.nftChain, env.nftTable)
		}
		return statusFail, fmt.Sprintf("nft exit=%d: %s", code, oneLine(out))
	}

	lines, err := attributedNFTChainLines(out, env.nftChain)
	if err != nil {
		return statusFail, err.Error()
	}

	current, err := containmentUIDsFromProbeEnv(env)
	if err != nil {
		return statusFail, err.Error()
	}
	if current.operatorKnown && !chainLinesHaveSkuidAcceptForUID(lines, current.operatorUID) {
		return statusFail, fmt.Sprintf("chain present but operator uid %d accept rule missing", current.operatorUID)
	}
	if !chainLinesHaveSkuidAcceptForUID(lines, current.proxyUID) {
		return statusFail, fmt.Sprintf("chain present but proxy uid %d accept rule missing", current.proxyUID)
	}
	if !chainLinesHaveAgentCatchAllDrop(lines, current.agentUID) {
		return statusFail, fmt.Sprintf("chain present but current agent uid %d catch-all skuid-drop rule missing", current.agentUID)
	}
	if !chainLinesHaveAgentProxyLoopbackAllowBeforeDrop(lines, current.agentUID, env.port) {
		return statusFail, fmt.Sprintf("chain present but current agent uid %d loopback allow for 127.0.0.1:%d is missing or appears after the agent catch-all drop", current.agentUID, env.port)
	}
	if !chainLinesHaveAgentDNSDropBeforeCatchAll(lines, current.agentUID, "udp") {
		return statusFail, fmt.Sprintf("chain present but current agent uid %d udp/53 DNS drop rule missing or appears after the agent catch-all drop", current.agentUID)
	}
	if !chainLinesHaveAgentDNSDropBeforeCatchAll(lines, current.agentUID, "tcp") {
		return statusFail, fmt.Sprintf("chain present but current agent uid %d tcp/53 DNS drop rule missing or appears after the agent catch-all drop", current.agentUID)
	}
	if chainLinesHaveUnsafeVerdictBeforeAgentDrop(lines, current, env.port) {
		return statusFail, "chain contains unexpected verdict before agent drop"
	}
	if !nftChainLinesHaveManagedOutputBaseChain(lines) {
		return statusFail, fmt.Sprintf("chain %s is not the managed output base chain (want type filter hook output priority filter/0 policy accept)", env.nftChain)
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

func chainLinesHaveAgentCatchAllDrop(lines []string, uid int) bool {
	return chainLinesHaveLine(lines, func(line string) bool {
		return lineHasTerminalSkuidVerdict(line, uid, "drop")
	})
}

func chainLinesHaveSkuidAcceptForUID(lines []string, uid int) bool {
	return chainLinesHaveLine(lines, func(line string) bool {
		return lineHasTerminalSkuidVerdict(line, uid, "accept")
	})
}

func chainLinesHaveAgentProxyLoopbackAllowBeforeDrop(lines []string, agentUID, port int) bool {
	return chainLinesHaveLineBeforeAgentDrop(lines, agentUID, func(line string) bool {
		return lineHasAgentProxyLoopbackAllow(line, agentUID, port)
	})
}

func lineHasAgentProxyLoopbackAllow(line string, agentUID, port int) bool {
	fields := nftLineFields(line)
	want := []string{
		"meta", "skuid", strconv.Itoa(agentUID),
		"ip", "daddr", "127.0.0.1",
		"tcp", "dport", strconv.Itoa(port),
		"accept",
	}
	if len(fields) < len(want) {
		return false
	}
	for i, field := range want {
		if fields[i] != field {
			return false
		}
	}
	return nftRuleTailIsCommentOnly(fields[len(want):])
}

func chainLinesHaveAgentDNSDropBeforeCatchAll(lines []string, agentUID int, protocol string) bool {
	return chainLinesHaveLineBeforeAgentDrop(lines, agentUID, func(line string) bool {
		return lineHasSkuidProtocolDPortVerdict(line, agentUID, protocol, 53, "drop")
	})
}

func chainLinesHaveUnsafeVerdictBeforeAgentDrop(lines []string, uids containmentUIDs, proxyPort int) bool {
	return chainLinesHaveLineBeforeAgentDrop(lines, uids.agentUID, func(line string) bool {
		// Before the agent catch-all drop, only the managed operator/proxy
		// accepts, the agent's proxy loopback allow, and DNS drops are safe.
		// Any other terminal/control-flow verdict can bypass containment under
		// the base-chain "policy accept" default or intercept the direct canary
		// before it reaches the counter used for attribution.
		if !lineHasAnyToken(line, "accept", "drop", "reject", "return", "jump", "goto", "queue") {
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
		for _, verdict := range []string{"accept", "drop", "reject"} {
			if uid, ok := terminalSkuidUIDVerdict(line, verdict); ok && uid != uids.agentUID {
				return false
			}
		}
		return true
	})
}

// terminalSkuidUIDVerdict extracts the UID from an exact skuid verdict rule.
func terminalSkuidUIDVerdict(line, verdict string) (int, bool) {
	fields := nftLineFields(line)
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

// lineHasTerminalSkuidVerdict matches an exact UID with a terminal verdict.
func lineHasTerminalSkuidVerdict(line string, uid int, verdict string) bool {
	fields := nftLineFields(line)
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

// lineHasSkuidProtocolDPortVerdict matches the canonical UID/protocol/port rule.
func lineHasSkuidProtocolDPortVerdict(line string, uid int, protocol string, port int, verdict string) bool {
	fields := nftLineFields(line)
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

// fieldsAreNFTBookkeeping accepts only counter and log tokens between the
// managed rule's UID predicate and DROP verdict.
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
			if _, err := strconv.ParseUint(field, 10, 64); err == nil {
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

func nftRuleTailIsCommentOnly(fields []string) bool {
	if len(fields) == 0 {
		return true
	}
	return len(fields) == 2 && fields[0] == "comment" && strings.HasPrefix(fields[1], `"`) && strings.HasSuffix(fields[1], `"`)
}

// lineHasAnyToken finds any requested unquoted nft syntax token.
func lineHasAnyToken(line string, wants ...string) bool {
	for _, field := range nftLineFields(line) {
		for _, want := range wants {
			if field == want {
				return true
			}
		}
	}
	return false
}

// nftLineFields tokenizes one nft list-output line without treating whitespace
// or verdict-looking words inside quoted strings as rule syntax. A trailing
// "# handle N" annotation is a comment and is omitted. This is intentionally a
// small list-output tokenizer, not a general nft parser: the verifier only
// needs stable tokens for the canonical rules renderNFTRules emits.
func nftLineFields(line string) []string {
	fields := make([]string, 0, 16)
	var field strings.Builder
	inQuote := false
	escaped := false
	flush := func() {
		if field.Len() == 0 {
			return
		}
		fields = append(fields, field.String())
		field.Reset()
	}

	for _, r := range line {
		if inQuote {
			field.WriteRune(r)
			switch {
			case escaped:
				escaped = false
			case r == '\\':
				escaped = true
			case r == '"':
				inQuote = false
			}
			continue
		}

		switch r {
		case '#':
			flush()
			return fields
		case '"':
			inQuote = true
			field.WriteRune(r)
		case ' ', '\t', '\r', '\n', '\v', '\f':
			flush()
		default:
			field.WriteRune(r)
		}
	}
	flush()
	return fields
}

// nftLineBraceDelta counts structural braces while ignoring braces inside
// quoted comments/log prefixes and trailing "# handle N" annotations.
func nftLineBraceDelta(line string) int {
	delta := 0
	inQuote := false
	escaped := false
	for _, r := range line {
		if inQuote {
			switch {
			case escaped:
				escaped = false
			case r == '\\':
				escaped = true
			case r == '"':
				inQuote = false
			}
			continue
		}
		switch r {
		case '#':
			return delta
		case '"':
			inQuote = true
		case '{':
			delta++
		case '}':
			delta--
		}
	}
	return delta
}

// nftLineHasBalancedQuotes rejects malformed list output before chain traversal.
// Without this check, an unterminated quoted comment could hide the target
// chain's closing brace and make rules in a later chain look attributable to it.
func nftLineHasBalancedQuotes(line string) bool {
	inQuote := false
	escaped := false
	for _, r := range line {
		if inQuote {
			switch {
			case escaped:
				escaped = false
			case r == '\\':
				escaped = true
			case r == '"':
				inQuote = false
			}
			continue
		}
		switch r {
		case '#':
			return true
		case '"':
			inQuote = true
		}
	}
	return !inQuote
}

// isNFTChainDeclaration reports whether line declares exactly chainName.
func isNFTChainDeclaration(line, chainName string) bool {
	if !nftLineHasBalancedQuotes(line) {
		return false
	}
	fields := nftLineFields(line)
	if len(fields) == 3 {
		return fields[0] == "chain" && fields[1] == chainName && fields[2] == "{"
	}
	// Retain support for compact synthetic listings used by older tests while
	// requiring an exact name rather than a prefix match.
	return line == "chain "+chainName+"{"
}

// outputHasNFTChainDeclaration finds an exact chain declaration in nft output.
func outputHasNFTChainDeclaration(out, chainName string) bool {
	for _, raw := range strings.Split(out, "\n") {
		if isNFTChainDeclaration(strings.TrimSpace(raw), chainName) {
			return true
		}
	}
	return false
}

// attributedNFTChainLines accepts only output from an exact
// `nft list chain inet <table> <chain>` query. The command itself attributes
// the following rules to the requested chain; this parser rejects ambiguous
// table-wide output that includes a different chain and never searches later
// chains for missing evidence.
func attributedNFTChainLines(out, chainName string) ([]string, error) {
	var lines []string
	declared := false
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "table ") || line == "}" {
			continue
		}
		if strings.HasPrefix(line, "chain ") {
			if !isNFTChainDeclaration(line, chainName) {
				return nil, fmt.Errorf("nft output is not positively attributed to chain %s", chainName)
			}
			if declared {
				return nil, fmt.Errorf("nft output declares chain %s more than once", chainName)
			}
			declared = true
			continue
		}
		if !declared {
			return nil, fmt.Errorf("nft output for chain %s has rule content before the chain declaration", chainName)
		}
		if !nftLineHasBalancedQuotes(line) {
			return nil, fmt.Errorf("nft output for chain %s contains malformed quoted rule content", chainName)
		}
		lines = append(lines, line)
	}
	if !declared {
		return nil, fmt.Errorf("chain %s missing from nft output", chainName)
	}
	return lines, nil
}

// chainLinesHaveLine applies match only to nft lines already attributed by an
// exact list-chain command. A malformed line fails closed by not matching.
func chainLinesHaveLine(lines []string, match func(string) bool) bool {
	for _, line := range lines {
		if !nftLineHasBalancedQuotes(line) {
			return false
		}
		if match(line) {
			return true
		}
	}
	return false
}

// chainLinesHaveLineBeforeAgentDrop applies match only before the managed
// agent DROP in nft lines already attributed to the exact live chain.
func chainLinesHaveLineBeforeAgentDrop(lines []string, agentUID int, match func(string) bool) bool {
	for _, line := range lines {
		if !nftLineHasBalancedQuotes(line) {
			return false
		}
		if lineHasTerminalSkuidVerdict(line, agentUID, "drop") {
			return false
		}
		if match(line) {
			return true
		}
	}
	return false
}

// chainHasLineBeforeAgentDrop applies match only before the managed agent DROP.
func chainHasLineBeforeAgentDrop(out, chainName string, agentUID int, match func(string) bool) bool {
	lines, err := attributedNFTChainLines(out, chainName)
	if err != nil {
		return false
	}
	return chainLinesHaveLineBeforeAgentDrop(lines, agentUID, match)
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
	timeout := env.readinessTimeout
	if timeout <= 0 {
		timeout = readinessTimeout
	}
	readyCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	maxAttempts := int(timeout/readinessInterval) + 1
	const serviceStatePollEvery = 5
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		conn, err := env.dialCtx(readyCtx, "tcp", addr, min(probeDialTimeout, readinessInterval))
		if err == nil {
			elapsed := time.Since(start)
			_ = conn.Close()
			return statusPass, fmt.Sprintf("%s accepted TCP within %s", addr, formatDialDuration(elapsed))
		}
		lastErr = err

		if attempt%serviceStatePollEvery == 0 || attempt == maxAttempts-1 {
			out, code, showErr := env.runCmd(readyCtx, "systemctl", "show", env.serviceName,
				"--property=ActiveState,SubState",
			)
			if showErr == nil && code == 0 {
				fields := parseSystemdShow(out)
				if fields["ActiveState"] != systemctlActive || fields["SubState"] != "running" {
					return statusFail, fmt.Sprintf("dial %s: %v; service exited before readiness (ActiveState=%s SubState=%s)",
						addr, err, fields["ActiveState"], fields["SubState"])
				}
			}
		}
		if attempt == maxAttempts-1 {
			break
		}
		if err := env.wait(readyCtx, readinessInterval); err != nil {
			break
		}
	}
	return statusFail, fmt.Sprintf("dial %s: service did not become ready within %s (last error: %v)", addr, timeout, lastErr)
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

// curlDirectCanaryArgsFor builds the bounded DNS-free direct-egress probe.
func curlDirectCanaryArgsFor(curl string) []string {
	if curl == "" {
		curl = defaultCurlPath
	}
	return []string{
		curl,
		"--connect-timeout", directCurlConnectTimeout,
		"--max-time", directCurlMaxTime,
		"--noproxy", "*",
		"-sS",
		"-o", "/dev/null",
		"-w", directCurlWriteOut,
		directEgressCanaryURL,
	}
}

// readContainmentDropCounter reads the packet counter on the single managed
// catch-all DROP rule for the current contained-agent UID. Probe 8 uses a
// literal IP and therefore must reach this rule rather than either DNS rule.
func readContainmentDropCounter(ctx context.Context, env *probeEnv) (uint64, error) {
	current, err := containmentUIDsFromProbeEnv(env)
	if err != nil {
		return 0, err
	}
	out, code, err := env.runCmd(ctx, probeNFTExecutable(env), "-n", "-a", "list", "chain", "inet", env.nftTable, env.nftChain)
	if err != nil {
		return 0, fmt.Errorf("list nft chain: %w", err)
	}
	if code != 0 {
		return 0, fmt.Errorf("list nft chain exit=%d: %s", code, oneLine(out))
	}
	lines, err := attributedNFTChainLines(out, env.nftChain)
	if err != nil {
		return 0, err
	}
	if !nftChainLinesHaveManagedOutputBaseChain(lines) {
		return 0, fmt.Errorf("chain %s is not the managed output base chain (want type filter hook output priority filter/0 policy accept)", env.nftChain)
	}
	if chainLinesHaveUnsafeVerdictBeforeAgentDrop(lines, current, env.port) {
		return 0, fmt.Errorf("chain %s has an unexpected verdict before managed catch-all DROP; direct-canary attribution is unsafe", env.nftChain)
	}
	return managedContainmentDropPacketCountFromLines(lines, env.nftChain, current.agentUID)
}

// chainHasManagedOutputBaseChain confirms the requested chain is attached to
// the local-output hook with the declaration renderNFTRules installs. nft may
// print the standard "filter" priority symbolically or as its numeric value 0.
// Without this check, a regular/unhooked lookalike chain could provide a benign
// counter that the direct-canary packet never traverses.
func chainHasManagedOutputBaseChain(out, chainName string) bool {
	lines, err := attributedNFTChainLines(out, chainName)
	if err != nil {
		return false
	}
	return nftChainLinesHaveManagedOutputBaseChain(lines)
}

func nftChainLinesHaveManagedOutputBaseChain(lines []string) bool {
	return chainLinesHaveLine(lines, func(line string) bool {
		fields := nftLineFields(strings.ReplaceAll(line, ";", " "))
		if len(fields) != 8 {
			return false
		}
		return fields[0] == "type" &&
			fields[1] == "filter" &&
			fields[2] == "hook" &&
			fields[3] == "output" &&
			fields[4] == "priority" &&
			(fields[5] == "filter" || fields[5] == "0") &&
			fields[6] == "policy" &&
			fields[7] == "accept"
	})
}

// managedContainmentDropPacketCount extracts the packet count from exactly one
// canonical managed agent catch-all DROP rule in the requested chain. Duplicate
// lookalikes, wrong-chain rules, DNS counters, and rules with extra predicates
// are rejected rather than accepted as attribution evidence.
func managedContainmentDropPacketCount(out, chainName string, agentUID int) (uint64, error) {
	lines, err := attributedNFTChainLines(out, chainName)
	if err != nil {
		return 0, err
	}
	return managedContainmentDropPacketCountFromLines(lines, chainName, agentUID)
}

func managedContainmentDropPacketCountFromLines(lines []string, chainName string, agentUID int) (uint64, error) {
	var packets uint64
	var parseErr error
	matched := 0
	for _, line := range lines {
		if !nftLineHasBalancedQuotes(line) {
			parseErr = fmt.Errorf("managed catch-all DROP rule has malformed quoted rule content: %s", oneLine(line))
			break
		}
		if !strings.Contains(line, `log prefix "`+nftLogPrefix(EgressClassNotRoutingThroughPipelock)+` "`) {
			continue
		}

		fields := nftLineFields(line)
		uidAt := indexSkuidUID(fields, strconv.Itoa(agentUID))
		// renderNFTRules emits the catch-all expression as the complete
		// `meta skuid <uid>` predicate. Requiring it at the start rejects a
		// destination/interface/etc. predicate placed before skuid; such a
		// lookalike would not necessarily see the direct-canary packet.
		if uidAt != 2 || fields[0] != "meta" || fields[1] != "skuid" {
			continue
		}
		dropAt := indexTokenAfter(fields, "drop", uidAt+1)
		if dropAt == -1 || uidAt+1 >= dropAt || fields[uidAt+1] != "counter" {
			continue
		}
		packetsAt := -1
		for i := uidAt + 1; i+2 < dropAt; i++ {
			if fields[i] == "counter" && fields[i+1] == "packets" {
				if packetsAt != -1 {
					parseErr = fmt.Errorf("managed catch-all DROP rule has multiple packet counters: %s", oneLine(line))
					break
				}
				packetsAt = i + 2
			}
		}
		if parseErr != nil {
			break
		}
		if packetsAt == -1 {
			parseErr = fmt.Errorf("managed catch-all DROP rule has no expanded packet counter: %s", oneLine(line))
			break
		}
		parsed, err := strconv.ParseUint(fields[packetsAt], 10, 64)
		if err != nil {
			parseErr = fmt.Errorf("parse managed catch-all DROP packet counter %q: %w", fields[packetsAt], err)
			break
		}
		if !fieldsAreNFTBookkeeping(fields[uidAt+1 : dropAt]) {
			continue
		}
		packets = parsed
		matched++
	}
	if parseErr != nil {
		return 0, parseErr
	}
	if matched == 0 {
		return 0, fmt.Errorf("no managed catch-all DROP packet counter found in chain %s for agent uid %d", chainName, agentUID)
	}
	if matched != 1 {
		return 0, fmt.Errorf("found %d managed catch-all DROP packet counters in chain %s for agent uid %d; want exactly one", matched, chainName, agentUID)
	}
	return packets, nil
}

// probeCCAgentEgressDenied verifies that curl's probe-specific time_connect
// reports no completed TCP dial and that the exact managed catch-all DROP
// counter also increased. The counter is UID-wide corroboration only: it cannot
// turn a completed or unattributable canary dial into PASS.
func probeCCAgentEgressDenied(ctx context.Context, env *probeEnv) (string, string) {
	var before uint64
	var beforeErr error
	if env.dropCounter != nil {
		before, beforeErr = env.dropCounter(ctx, env)
	}
	curlArgs := curlDirectCanaryArgsFor(env.curlPath)
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
		return statusFail, fmt.Sprintf("unexpected curl success: HTTP %s from direct canary %s", oneLine(out), directEgressCanaryURL)
	}
	dialCompletion := parseDirectCurlDialCompletion(out)
	outcome, after, afterErr := classifyDirectEgressAttribution(code, dialCompletion, env.dropCounter != nil, before, beforeErr, func() (uint64, error) {
		return env.dropCounter(ctx, env)
	})
	switch outcome {
	case egressAttrFailPostConnect:
		return statusFail, fmt.Sprintf("CONTAINMENT HOLE: direct egress reached the network before curl failed (exit=%d): %s", code, oneLine(out))
	case egressAttrUnknownDialCompletion:
		return statusUnknown, fmt.Sprintf("curl failed (exit=%d), but probe-specific time_connect was missing or unparseable; refusing to claim containment", code)
	case egressAttrUnknownNoCounter:
		return statusUnknown, fmt.Sprintf("curl failed (exit=%d), but no DROP counter reader is available; containment attribution is inconclusive", code)
	case egressAttrUnknownBeforeErr:
		return statusUnknown, fmt.Sprintf("curl failed (exit=%d), but containment attribution is inconclusive: read DROP counter before probe: %v", code, beforeErr)
	case egressAttrUnknownAfterErr:
		return statusUnknown, fmt.Sprintf("curl failed (exit=%d), but containment attribution is inconclusive: read DROP counter after probe: %v", code, afterErr)
	case egressAttrUnknownNoDelta:
		return statusUnknown, fmt.Sprintf("curl failed (exit=%d), but managed DROP counter did not increase (%d -> %d); failure may be unrelated to containment", code, before, after)
	case egressAttrUnknownUnexpectedExit:
		return statusUnknown, fmt.Sprintf("curl failed with unexpected exit=%d despite a counter delta; the DNS-free HTTP canary expected a connect refusal or timeout", code)
	case egressAttrPass:
		return statusPass, fmt.Sprintf("curl dial did not complete (exit=%d, time_connect=0); managed DROP counter increased (%d -> %d) — containment enforced", code, before, after)
	default:
		// Fail closed: an unhandled attribution outcome (e.g. a future enum
		// value) must never fall through to PASS.
		return statusUnknown, fmt.Sprintf("unexpected direct-egress attribution outcome %d (exit=%d); refusing to claim containment", outcome, code)
	}
}

// egressAttribution is the transport-neutral verdict of the shared direct-egress
// counter-attribution decision tree. Callers map it to their own result type.
type egressAttribution int

const (
	egressAttrFailPostConnect       egressAttribution = iota // connection established -> containment hole
	egressAttrUnknownDialCompletion                          // probe-specific dial completion is missing/unparseable
	egressAttrUnknownNoCounter                               // no DROP counter reader available
	egressAttrUnknownBeforeErr                               // reading the counter before the probe failed
	egressAttrUnknownAfterErr                                // reading the counter after the probe failed
	egressAttrUnknownNoDelta                                 // counter did not increase -> unattributable
	egressAttrUnknownUnexpectedExit                          // counter delta but a non-dial-blocked exit
	egressAttrPass                                           // dial-blocked exit AND positive counter delta
)

// classifyDirectEgressAttribution is the SINGLE source of truth for the
// direct-egress containment verdict on a NON-ZERO canary exit, shared by
// `contain verify` (probeCCAgentEgressDenied) and `contain doctor`
// (checkRawEgressBlocked) so the two can never silently disagree about whether
// containment held. Callers handle skip cases and the code==0 unexpected-success
// case first, then map the returned attribution to their own result type and
// wording. Branch order is security-critical: probe-specific evidence that the
// dial completed, or an independently post-connect exit, is a containment hole
// regardless of the counter. Missing probe-specific timing stays UNKNOWN. PASS
// requires a dial that did not complete, a dial-blocked exit, and a positive
// managed DROP-counter delta. readAfter is invoked lazily so completed,
// post-connect, unknown-timing, and no-counter paths perform no counter read.
func classifyDirectEgressAttribution(code int, dialCompletion directDialCompletion, hasCounter bool, before uint64, beforeErr error, readAfter func() (uint64, error)) (outcome egressAttribution, after uint64, afterErr error) {
	if dialCompletion == directDialCompleted {
		return egressAttrFailPostConnect, 0, nil
	}
	if isPostConnectCurlExit(code) {
		return egressAttrFailPostConnect, 0, nil
	}
	if dialCompletion != directDialNotCompleted {
		return egressAttrUnknownDialCompletion, 0, nil
	}
	if !hasCounter {
		return egressAttrUnknownNoCounter, 0, nil
	}
	after, afterErr = readAfter()
	if beforeErr != nil {
		return egressAttrUnknownBeforeErr, after, afterErr
	}
	if afterErr != nil {
		return egressAttrUnknownAfterErr, after, afterErr
	}
	if after <= before {
		return egressAttrUnknownNoDelta, after, afterErr
	}
	if !isDirectEgressBlockedCurlExit(code) {
		return egressAttrUnknownUnexpectedExit, after, afterErr
	}
	return egressAttrPass, after, afterErr
}

// directDialCompletion is curl's probe-specific account of whether its TCP
// connection completed. Unknown is deliberately distinct from not-completed:
// missing or malformed write-out evidence can never support PASS.
type directDialCompletion int

const (
	directDialUnknown directDialCompletion = iota
	directDialNotCompleted
	directDialCompleted
)

// parseDirectCurlDialCompletion reads curl's stable time_connect sentinel.
// strconv.ParseFloat is locale-independent, and curl's write-out variables use
// a dot decimal separator. Exactly zero means TCP never connected; any finite
// positive value means the direct dial escaped containment.
func parseDirectCurlDialCompletion(out string) directDialCompletion {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, directCurlTimeConnectPrefix) {
			continue
		}
		raw := strings.TrimSpace(strings.TrimPrefix(line, directCurlTimeConnectPrefix))
		value, err := strconv.ParseFloat(raw, 64)
		if err != nil || value < 0 || math.IsNaN(value) || math.IsInf(value, 0) {
			return directDialUnknown
		}
		if value == 0 {
			return directDialNotCompleted
		}
		return directDialCompleted
	}
	return directDialUnknown
}

// isDirectEgressBlockedCurlExit identifies dial outcomes consistent with either
// an explicit rejection (7) or a silently dropped SYN that times out (28).
// Exit 28 is a generic curl timeout, so the caller separately requires this
// canary's time_connect to be exactly zero before either exit can support PASS.
// The UID-wide managed DROP-counter delta then corroborates that no-dial result;
// it is never treated as probe attribution on its own.
func isDirectEgressBlockedCurlExit(code int) bool {
	return code == 7 || code == 28
}

// isPostConnectCurlExit identifies curl failures that require a connection to
// have progressed beyond the outbound dial. These are containment failures even
// if unrelated same-UID traffic also increments the managed DROP counter.
func isPostConnectCurlExit(code int) bool {
	switch code {
	// Server/protocol responses or completed transfer setup.
	case 8, 16, 18, 21, 22, 23, 25, 30, 31, 33, 36, 38, 39, 47,
		52, 61, 63, 64, 67, 68, 69, 70, 71, 72, 73, 74, 78, 79,
		84, 85, 86, 87, 88, 92, 94, 95, 96:
		return true
	// TLS peer/handshake evidence or network I/O after connect.
	case 35, 51, 55, 56, 60, 80, 83, 90, 91, 97:
		return true
	default:
		return false
	}
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

// oneLine trims and collapses whitespace, and removes control/format runes so
// subprocess output cannot inject terminal escapes or bidirectional formatting
// into text-mode evidence.
func oneLine(s string) string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r) || unicode.In(r, unicode.Cf)
	})
	return strings.Join(fields, " ")
}
