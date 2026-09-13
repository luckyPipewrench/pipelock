// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const systemdRunPath = "systemd-run"

var (
	privateTmpCanaryRoot = isRoot
	privateTmpCreateTemp = os.CreateTemp
	privateTmpVersion    = func(ctx context.Context) (string, error) {
		out, err := exec.CommandContext(ctx, systemdRunPath, "--version").Output()
		return string(out), err
	}
)

// privateTmpSystemdRunArgs returns the transient-service invocation used for
// every contained-agent launch. A systemd service, rather than a scope, is
// required because PrivateTmp creates the service's private mount namespace.
// plk-launch remains the final process so the existing allow-list and
// env-clearing contract still apply inside that namespace.
func privateTmpSystemdRunArgs(uid, gid uint32, groups []uint32, homeDir string, launchEnv, command []string, interactive bool) []string {
	args := []string{
		"--wait",
		"--collect",
		"--service-type=exec",
		"--expand-environment=no",
		"--property=PrivateTmp=true",
		"--uid=" + strconv.FormatUint(uint64(uid), 10),
		"--gid=" + strconv.FormatUint(uint64(gid), 10),
		"--working-directory=" + homeDir,
	}
	if supplementary := supplementaryGroupIDs(groups, gid); len(supplementary) > 0 {
		args = append(args, "--property=SupplementaryGroups="+strings.Join(supplementary, " "))
	}
	for _, entry := range launchEnv {
		args = append(args, "--setenv="+entry)
	}
	if interactive {
		args = append(args, "--pty")
	} else {
		args = append(args, "--pipe")
	}
	args = append(args, "--")
	return append(args, command...)
}

func supplementaryGroupIDs(groups []uint32, primary uint32) []string {
	ids := make([]string, 0, len(groups))
	seen := make(map[uint32]struct{}, len(groups))
	for _, group := range groups {
		if group == primary {
			continue
		}
		if _, ok := seen[group]; ok {
			continue
		}
		seen[group] = struct{}{}
		ids = append(ids, strconv.FormatUint(uint64(group), 10))
	}
	return ids
}

func containedAgentPrivateTmpCommand(opts containedAgentCommandOptions) (*exec.Cmd, *bytes.Buffer) {
	command := append([]string{defaultLaunchScript}, opts.args...)
	launchEnv := containLaunchEnv(opts.agentUserName, opts.homeDir, opts.proxyPort, opts.postureProofPath)
	cmd := exec.CommandContext(opts.ctx, systemdRunPath)
	cmd.Args = append([]string{systemdRunPath}, privateTmpSystemdRunArgs(opts.uid, opts.gid, opts.groups, opts.homeDir, launchEnv, command, isTerminalReader(opts.stdin))...)
	cmd.Stdin = opts.stdin
	cmd.Stdout = opts.stdout
	statusOutput := &bytes.Buffer{}
	cmd.Stderr = io.MultiWriter(opts.stderr, statusOutput)
	return cmd, statusOutput
}

// systemdMainSignal extracts the transient service's signal result from
// systemd-run --wait output. systemd itself treats several terminating signals
// as clean for non-oneshot services, so the wrapper's process status alone is
// insufficient to preserve the contained tool's shell-compatible exit code.
func systemdMainSignal(output string) (syscall.Signal, bool) {
	for _, line := range strings.Split(output, "\n") {
		if !strings.Contains(line, "code=killed") && !strings.Contains(line, "code=dumped") {
			continue
		}
		const marker = "status="
		idx := strings.Index(line, marker)
		if idx < 0 {
			continue
		}
		name := strings.TrimSpace(line[idx+len(marker):])
		parts := strings.SplitN(name, "/", 2)
		if len(parts) == 2 {
			name = parts[1]
		}
		name = strings.TrimPrefix(name, "SIG")
		for signal := syscall.Signal(1); signal < 65; signal++ {
			if strings.TrimPrefix(unix.SignalName(signal), "SIG") == name {
				return signal, true
			}
		}
	}
	return 0, false
}

// probePrivateTmp proves that systemd creates a private mount namespace for a
// contained-agent-shaped transient service. The host canaries are deliberately
// in /tmp and /var/tmp, so a pass directly proves both paths are isolated. We
// create and remove the canaries within this probe; verification leaves no
// durable state.
func probePrivateTmp(ctx context.Context, env *probeEnv) (string, string) {
	if env.privateTmpProbe != nil {
		return env.privateTmpProbe(ctx, env)
	}
	if !privateTmpCanaryRoot() {
		return statusSkip, "private temporary-directory canary requires root to start a transient systemd service"
	}
	versionOutput, versionErr := privateTmpVersion(ctx)
	if versionErr != nil {
		return statusFail, fmt.Sprintf("check systemd version for private temporary directories: %v", versionErr)
	}
	fields := strings.Fields(versionOutput)
	if len(fields) < 2 {
		return statusFail, fmt.Sprintf("check systemd version for private temporary directories: unrecognized output %q", oneLine(versionOutput))
	}
	version, err := strconv.Atoi(fields[1])
	if err != nil || version < 254 {
		return statusFail, fmt.Sprintf("private temporary directories require systemd 254 or newer (found %q)", fields[1])
	}
	// Create the canary in /tmp explicitly, never os.CreateTemp's "" default:
	// the default honors $TMPDIR, which sudo can preserve, and would place the
	// canary outside /tmp. PrivateTmp isolates /tmp and /var/tmp specifically,
	// so the canary must live in the directory whose isolation this probe
	// claims to prove, matching the hardcoded /var/tmp sibling below.
	tmpCanary, err := privateTmpCreateTemp("/tmp", "pipelock-contain-private-tmp-")
	if err != nil {
		return statusFail, fmt.Sprintf("create operator /tmp canary: %v", err)
	}
	tmpCanaryPath := tmpCanary.Name()
	defer func() { _ = os.Remove(tmpCanaryPath) }()
	if err := tmpCanary.Close(); err != nil {
		return statusFail, fmt.Sprintf("close operator /tmp canary: %v", err)
	}
	varTmpCanary, err := privateTmpCreateTemp("/var/tmp", "pipelock-contain-private-tmp-")
	if err != nil {
		return statusFail, fmt.Sprintf("create operator /var/tmp canary: %v", err)
	}
	varTmpCanaryPath := varTmpCanary.Name()
	defer func() { _ = os.Remove(varTmpCanaryPath) }()
	if err := varTmpCanary.Close(); err != nil {
		return statusFail, fmt.Sprintf("close operator /var/tmp canary: %v", err)
	}

	args, err := privateTmpSystemdRunArgsForAgent(env, []string{"/usr/bin/test", "!", "-e", tmpCanaryPath, "-a", "!", "-e", varTmpCanaryPath})
	if err != nil {
		return statusFail, fmt.Sprintf("prepare private temporary-directory canary: %v", err)
	}
	out, code, err := env.runCmd(ctx, systemdRunPath, args...)
	if err != nil {
		return statusFail, fmt.Sprintf("private temporary-directory canary could not start: %v", err)
	}
	if code != 0 {
		return statusFail, fmt.Sprintf("agent transient service could see an operator temporary canary (exit=%d): %s", code, oneLine(out))
	}
	return statusPass, "agent transient service cannot see operator /tmp or /var/tmp canaries"
}

func privateTmpSystemdRunArgsForAgent(env *probeEnv, command []string) ([]string, error) {
	u, err := env.lookupUser(env.agentUserName)
	if err != nil {
		return nil, fmt.Errorf("lookup %s: %w", env.agentUserName, err)
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("parse uid for %s: %w", env.agentUserName, err)
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("parse gid for %s: %w", env.agentUserName, err)
	}
	groupIDs, err := groupIDsForEnv(env, u)
	if err != nil {
		return nil, fmt.Errorf("resolve groups for %s: %w", env.agentUserName, err)
	}
	groups, err := parseAgentGIDs(groupIDs, uint32(gid))
	if err != nil {
		return nil, fmt.Errorf("group ids for %s: %w", env.agentUserName, err)
	}
	return privateTmpSystemdRunArgs(uint32(uid), uint32(gid), groups, u.HomeDir, nil, command, false), nil
}

func isTerminalReader(reader any) bool {
	file, ok := reader.(*os.File)
	if !ok {
		return false
	}
	_, err := unix.IoctlGetTermios(int(file.Fd()), unix.TCGETS)
	return err == nil
}
