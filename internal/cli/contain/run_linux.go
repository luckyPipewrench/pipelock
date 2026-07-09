// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

func isRoot() bool {
	return os.Geteuid() == 0
}

func containRunSupported() bool {
	return true
}

var runContainedAgentCommand = func(cmd *exec.Cmd) error {
	return cmd.Run()
}

func launchContainedAgent(
	ctx context.Context,
	env *probeEnv,
	args []string,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
) error {
	u, err := env.lookupUser(env.agentUserName)
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("lookup %s: %w", env.agentUserName, err))
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("parse uid for %s: %w", env.agentUserName, err))
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("parse gid for %s: %w", env.agentUserName, err))
	}
	if uid == 0 || gid == 0 {
		// A launcher whose whole job is containment must never drop into the
		// root uid/gid. If the agent account is misconfigured as root, refuse
		// fail-closed instead of launching the tool unconstrained.
		return cliutil.ExitCodeError(cliutil.ExitConfig,
			fmt.Errorf("%s resolves to uid %d gid %d; refusing to launch a contained tool as root", env.agentUserName, uid, gid))
	}
	homeDir, err := cleanContainedAgentHomeDir(env.agentUserName, u.HomeDir)
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, err)
	}
	if filepath.Clean(env.launchPath) != defaultLaunchScript {
		return cliutil.ExitCodeError(cliutil.ExitConfig,
			fmt.Errorf("contain run launcher path %q does not match expected %s", env.launchPath, defaultLaunchScript))
	}
	// Resolve the agent's own group set so the child matches what
	// `sudo -u <agent>` grants via initgroups. Without an explicit setgroups
	// the child would inherit the launcher's (root's) supplementary groups.
	groupIDs, err := groupIDsForEnv(env, u)
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("resolve groups for %s: %w", env.agentUserName, err))
	}
	groups, err := parseAgentGIDs(groupIDs, uint32(gid))
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("group ids for %s: %w", env.agentUserName, err))
	}

	cmd := containedAgentCommand(containedAgentCommandOptions{
		ctx:              ctx,
		agentUserName:    env.agentUserName,
		homeDir:          homeDir,
		proxyPort:        env.port,
		postureProofPath: env.postureProofPath,
		uid:              uint32(uid),
		gid:              uint32(gid),
		groups:           groups,
		args:             args,
		stdin:            stdin,
		stdout:           stdout,
		stderr:           stderr,
	})

	if err := runContainedAgentCommand(cmd); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
				signal := status.Signal()
				return cliutil.ExitCodeError(128+int(signal), fmt.Errorf("contained agent terminated by signal %s", signal))
			}
			exitCode := exitErr.ExitCode()
			if exitCode < 0 {
				return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("contained agent exited without status: %w", err))
			}
			return cliutil.ExitCodeError(exitCode, fmt.Errorf("contained agent exited with status %d", exitCode))
		}
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("launch contained agent via %s: %w", defaultLaunchScript, err))
	}
	return nil
}

type containedAgentCommandOptions struct {
	ctx              context.Context
	agentUserName    string
	homeDir          string
	proxyPort        int
	postureProofPath string
	uid              uint32
	gid              uint32
	groups           []uint32
	args             []string
	stdin            io.Reader
	stdout           io.Writer
	stderr           io.Writer
}

func containedAgentCommand(opts containedAgentCommandOptions) *exec.Cmd {
	cmd := exec.CommandContext(opts.ctx, defaultLaunchScript)
	cmd.Args = append([]string{defaultLaunchScript}, opts.args...)
	cmd.Stdin = opts.stdin
	cmd.Stdout = opts.stdout
	cmd.Stderr = opts.stderr
	cmd.Dir = opts.homeDir
	cmd.Env = containLaunchEnv(opts.agentUserName, opts.homeDir, opts.proxyPort, opts.postureProofPath)
	cmd.SysProcAttr = agentSysProcAttr(opts.uid, opts.gid, opts.groups)
	return cmd
}

// agentSysProcAttr builds the credential the contained tool launches under.
// NoSetGroups stays false (the zero value) so the kernel runs setgroups(2) and
// the child drops the launcher's (root's) supplementary groups instead of
// inheriting them; groups carries the agent's own group set (primary plus
// supplementary), matching what `sudo -u <agent>` grants via initgroups.
// Pdeathsig terminates the contained tool if this launcher dies.
func agentSysProcAttr(uid, gid uint32, groups []uint32) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:    uid,
			Gid:    gid,
			Groups: groups,
		},
		Pdeathsig: syscall.SIGTERM,
	}
}
