// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !js

package playground

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

// --------------------------------------------------------------------------
// Self-managed (in-VM) containment.
//
// The host-install path (`containVerifier` in the live command) gates a session
// on `pipelock contain verify`, which assumes an operator ran
// `pipelock contain install` on the host. The per-visitor-microVM deployment
// (Fly.io) sets the kernel owner-match egress rule itself in the VM boot
// entrypoint, so `pipelock contain install` never runs and `pipelock contain
// verify` is not applicable.
//
// This file provides the install-AGNOSTIC start gate for that model: it does not
// trust any installer; it empirically confirms, before the agent runs, that the
// contained agent uid's direct egress is actually dropped. It is the start-time
// counterpart to the cryptographic HostContainmentWitness produced at finalize
// (buildHostContainmentWitness / Enforced), and uses the SAME differential
// methodology so the two cannot diverge: the operator reaches a host-local
// control target while the contained agent is blocked from that same target and
// from the real direct-egress suite, then the same contained uid is denied local
// platform/device/namespace escape surfaces. Because only the source uid differs
// for network probes, a network block is attributable to the kernel owner-match
// rule, not to an unroutable or down target.
//
// Fail-closed: any non-blocked agent probe, a control target the operator cannot
// reach (broken probe), missing root, or an unknown agent user is an error, and
// the caller must refuse to start the session.
// --------------------------------------------------------------------------

// ErrInVMContainmentNotProven signals that the install-agnostic start gate could
// not prove the contained agent uid's direct egress is dropped, so a session
// claiming containment must not begin.
var ErrInVMContainmentNotProven = errors.New(
	"playground: in-VM containment not proven: the contained agent uid's egress/local escape surfaces are not blocked; " +
		"refusing to start (set the nft owner-match egress rule in the deployment, e.g. the microVM boot entrypoint)")

// evalStartContainment is the pure decision over a start-gate probe set: it
// returns nil ONLY when the operator reached the control target (proving the
// probe can see "open"), the contained agent was explicitly BLOCKED from that
// same control target (the differential that isolates the kernel owner-match
// drop, and the negative proof that the agent cannot reach arbitrary loopback),
// every real direct-egress probe was explicitly blocked, and every local escape
// probe was explicitly blocked or unavailable. Open=false alone is not enough:
// a connection-refused result is reachable-but-closed, not containment. Empty
// direct or local suites fail closed so a vacuous pass is impossible. It mirrors
// HostContainmentWitness.Enforced minus the proxy-port contract (no proxy exists
// yet at start-gate time).
func evalStartContainment(operatorControl, agentControl ProbeResult, agentDirect, agentLocal []ProbeResult) error {
	if !operatorControl.Open || operatorControl.Blocked {
		return fmt.Errorf("%w: operator could not reach the control target %q (probe mechanism unreliable)",
			ErrInVMContainmentNotProven, operatorControl.Target)
	}
	if agentControl.Open || !agentControl.Blocked {
		return fmt.Errorf("%w: contained agent reached non-proxy loopback target %q (%s)",
			ErrInVMContainmentNotProven, agentControl.Target, agentControl.Detail)
	}
	if len(agentDirect) == 0 {
		return fmt.Errorf("%w: no direct-egress probes ran", ErrInVMContainmentNotProven)
	}
	for _, p := range agentDirect {
		if p.Open || !p.Blocked {
			return fmt.Errorf("%w: contained agent reached direct-egress target %q (%s)",
				ErrInVMContainmentNotProven, p.Target, p.Detail)
		}
	}
	if len(agentLocal) == 0 {
		return fmt.Errorf("%w: no local escape probes ran", ErrInVMContainmentNotProven)
	}
	for _, p := range agentLocal {
		if p.Open || !p.Blocked {
			return fmt.Errorf("%w: contained agent reached local escape target %q (%s)",
				ErrInVMContainmentNotProven, p.Target, p.Detail)
		}
	}
	return nil
}

// VerifyInVMContainment empirically confirms the contained agent uid's direct
// egress is dropped, WITHOUT depending on `pipelock contain install` /
// `pipelock contain verify`. It is the start gate for the self-managed
// (in-VM/Fly) containment model where the deployment sets the nft owner-match
// rule itself.
//
// It requires root (the contained probe drops to the agent uid, a privileged
// operation), confirms the agent user exists, stands up a host-local control
// listener, probes it as the operator (must connect), then probes the SAME
// control target plus the real direct-egress suite as the contained agent uid
// (every one must be blocked), and probes local escape surfaces as the contained
// agent uid (every one must be blocked or unavailable). Returns
// ErrInVMContainmentNotProven (wrapped) on any failure so the caller fails
// closed.
//
// toyAgentBin is the probe binary (the live command's --toyagent-bin); it is the
// same binary the finalize-time HostContainmentWitness uses, so the start gate
// and the signed proof exercise an identical probe path.
func VerifyInVMContainment(ctx context.Context, toyAgentBin, agentUser string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("%w: requires root to drop the probe to the agent uid (euid=%d)",
			ErrInVMContainmentNotProven, os.Geteuid())
	}
	if strings.TrimSpace(toyAgentBin) == "" {
		return fmt.Errorf("%w: no probe binary configured (set --toyagent-bin)", ErrInVMContainmentNotProven)
	}

	ctrlLn, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("%w: control listener: %w", ErrInVMContainmentNotProven, err)
	}
	defer func() { _ = ctrlLn.Close() }()
	go func() {
		for {
			c, acceptErr := ctrlLn.Accept()
			if acceptErr != nil {
				return
			}
			_ = c.Close()
		}
	}()
	ctrlTarget := ctrlLn.Addr().String()

	// Operator probe of the control target (current process is the operator):
	// proves the probe can detect a reachable target.
	operatorControl := ProbeDirectEgress(ctx, ctrlTarget)

	// Contained-agent probes, in order: the control target (must be blocked) then
	// the real direct-egress suite (all must be blocked).
	agentTargets := append([]string{ctrlTarget}, DirectEgressTargets()...)
	agentProbes, err := spawnAgentEgressProbe(ctx, toyAgentBin, agentUser, agentTargets)
	if err != nil {
		return fmt.Errorf("%w: contained agent probe: %w", ErrInVMContainmentNotProven, err)
	}
	localProbes, err := spawnAgentLocalEscapeProbe(ctx, toyAgentBin, agentUser)
	if err != nil {
		return fmt.Errorf("%w: contained agent local escape probe: %w", ErrInVMContainmentNotProven, err)
	}

	return evalStartContainment(operatorControl, agentProbes[0], agentProbes[1:], localProbes)
}

// spawnAgentEgressProbe runs toyAgentBin in --probe-targets mode dropped to the
// contained agent user (uid-scoped) and returns the parsed, order-validated
// results. Requires root (the uid drop is privileged). This is the single shared
// agent-uid probe spawn used by both the start gate (VerifyInVMContainment) and
// the finalize witness (LiveRun.runEgressProbe), so the two cannot diverge.
func spawnAgentEgressProbe(ctx context.Context, toyAgentBin, agentUser string, targets []string) ([]ProbeResult, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("contained egress probe requires root (euid=%d)", os.Geteuid())
	}
	args := []string{"--probe-targets", strings.Join(targets, ",")}
	cmd := exec.CommandContext(ctx, toyAgentBin, args...)
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin"}
	if err := configureContainedCommand(cmd, agentUser); err != nil {
		return nil, fmt.Errorf("configure contained egress probe: %w", err)
	}

	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("egress probe exec: %w", err)
	}
	return decodeProbeResults(stdout.Bytes(), targets)
}

// spawnAgentLocalEscapeProbe runs toyAgentBin in --probe-local-targets mode
// dropped to the contained agent user and returns the parsed, order-validated
// results. It exercises non-network escape surfaces from the same uid as the
// live agent before the VM serves traffic.
func spawnAgentLocalEscapeProbe(ctx context.Context, toyAgentBin, agentUser string) ([]ProbeResult, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("contained local escape probe requires root (euid=%d)", os.Geteuid())
	}
	targets := LocalEscapeTargets()
	args := []string{"--probe-local-targets", strings.Join(targets, ",")}
	cmd := exec.CommandContext(ctx, toyAgentBin, args...)
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin"}
	if err := configureContainedCommand(cmd, agentUser); err != nil {
		return nil, fmt.Errorf("configure contained local escape probe: %w", err)
	}

	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("local escape probe exec: %w", err)
	}
	return decodeProbeResults(stdout.Bytes(), targets)
}
