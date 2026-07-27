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
	"os/user"
	"strconv"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/cli/contain"
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
// This file provides the installer-independent start gate for that model. It
// requires the deployment to load the same canonical ruleset shape emitted by
// Pipelock, then empirically confirms before the agent runs that the contained
// agent uid's direct egress is actually dropped. It is the start-time
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

// ErrInVMContainmentNotProven signals that the installer-independent start gate could
// not prove the contained agent uid's direct egress is dropped, so a session
// claiming containment must not begin.
var ErrInVMContainmentNotProven = errors.New(
	"playground: in-VM containment not proven: the contained agent uid's egress/local escape surfaces are not blocked; " +
		"refusing to start (set the nft owner-match egress rule in the deployment, e.g. the microVM boot entrypoint)")

// InVMContainmentHook adapts the installer-independent containment gate to
// the deterministic demo's ContainmentHook seam. It is intended for hosts whose
// deployment manages the kernel boundary itself instead of using the exact
// stock `pipelock contain install` ruleset.
type InVMContainmentHook struct {
	ToyAgentBin string
	AgentUser   string
}

// NewInVMContainmentHook creates a containment hook that proves the boundary
// with the supplied toy-agent probe binary.
func NewInVMContainmentHook(toyAgentBin string) *InVMContainmentHook {
	return &InVMContainmentHook{ToyAgentBin: toyAgentBin}
}

// Setup proves the configured contained uid cannot escape through direct
// network or local platform surfaces. It does not trust installer state.
func (h *InVMContainmentHook) Setup(ctx context.Context, opts DemoOpts) error {
	agentUser := h.AgentUser
	if agentUser == "" {
		agentUser = defaultContainedAgentUser
	}
	return VerifyInVMContainment(ctx, h.ToyAgentBin, agentUser, opts.ProxyPort)
}

// Teardown is a no-op because the deployment owns the persistent containment
// boundary and the probe creates no lasting firewall state.
func (h *InVMContainmentHook) Teardown(_ string) error {
	return nil
}

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
	deniedLocal := 0
	for _, p := range agentLocal {
		if p.Open || (!p.Blocked && !p.Absent) {
			return fmt.Errorf("%w: local escape target %q was open or could not be proven denied/absent (%s)",
				ErrInVMContainmentNotProven, p.Target, p.Detail)
		}
		if p.Blocked {
			deniedLocal++
		}
	}
	if deniedLocal == 0 {
		return fmt.Errorf("%w: local escape suite contained only absent surfaces and proved no enforced denial", ErrInVMContainmentNotProven)
	}
	return nil
}

// VerifyInVMContainment confirms the canonical live nft ruleset and empirically
// proves the contained agent uid's direct egress is dropped, WITHOUT depending
// on `pipelock contain install` / `pipelock contain verify`. It is the start gate for the self-managed
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
func VerifyInVMContainment(ctx context.Context, toyAgentBin, agentUser string, proxyPort int) error {
	return VerifyInVMContainmentWithUIDs(ctx, toyAgentBin, agentUser, proxyPort, 0, 0)
}

// VerifyInVMContainmentWithUIDs verifies a deployment whose operator and proxy
// processes use explicitly configured UIDs.
func VerifyInVMContainmentWithUIDs(ctx context.Context, toyAgentBin, agentUser string, proxyPort, operatorUID, proxyUID int) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("%w: requires root to drop the probe to the agent uid (euid=%d)",
			ErrInVMContainmentNotProven, os.Geteuid())
	}
	if strings.TrimSpace(toyAgentBin) == "" {
		return fmt.Errorf("%w: no probe binary configured (set --toyagent-bin)", ErrInVMContainmentNotProven)
	}
	if proxyPort < 1 || proxyPort > 65535 {
		return fmt.Errorf("%w: proxy port must be 1-65535", ErrInVMContainmentNotProven)
	}
	if agentUser == "" {
		agentUser = defaultContainedAgentUser
	}
	agent, err := user.Lookup(agentUser)
	if err != nil {
		return fmt.Errorf("%w: lookup agent user %q: %w", ErrInVMContainmentNotProven, agentUser, err)
	}
	agentUID, err := strconv.Atoi(agent.Uid)
	if err != nil || agentUID <= 0 {
		return fmt.Errorf("%w: invalid agent uid %q", ErrInVMContainmentNotProven, agent.Uid)
	}
	if operatorUID < 0 || proxyUID < 0 {
		return fmt.Errorf("%w: operator and proxy UIDs must be non-negative", ErrInVMContainmentNotProven)
	}
	if err := contain.VerifySelfManagedNFTRules(ctx, operatorUID, proxyUID, agentUID, proxyPort); err != nil {
		return fmt.Errorf("%w: %w", ErrInVMContainmentNotProven, err)
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
	proxyLn, err := (&net.ListenConfig{}).Listen(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort))
	if err != nil {
		return fmt.Errorf("%w: proxy contract listener: %w", ErrInVMContainmentNotProven, err)
	}
	defer func() { _ = proxyLn.Close() }()
	go acceptProbeConnections(proxyLn)

	// Probe the control target in-process as the operator. Never execute the
	// configured helper binary with root credentials; only contained-agent
	// probes cross the subprocess boundary and they always drop privileges.
	operatorControl := ProbeDirectEgress(ctx, ctrlTarget)

	// Contained-agent probes, in order: the permitted proxy target (must be open),
	// the different loopback control target (must be blocked), then the exact
	// DirectEgressTargets suite (all must be blocked). decodeProbeResults enforces
	// this count and order before these index-based partitions are reachable.
	proxyTarget := proxyLn.Addr().String()
	agentTargets := append([]string{proxyTarget, ctrlTarget}, DirectEgressTargets()...)
	agentProbes, err := spawnAgentEgressProbe(ctx, toyAgentBin, agentUser, agentTargets)
	if err != nil {
		return fmt.Errorf("%w: contained agent probe: %w", ErrInVMContainmentNotProven, err)
	}
	if len(agentProbes) != len(agentTargets) {
		return fmt.Errorf("%w: contained agent probe returned %d results, want %d",
			ErrInVMContainmentNotProven, len(agentProbes), len(agentTargets))
	}
	localProbes, err := spawnAgentLocalEscapeProbe(ctx, toyAgentBin, agentUser)
	if err != nil {
		return fmt.Errorf("%w: contained agent local escape probe: %w", ErrInVMContainmentNotProven, err)
	}

	if err := evalProxyStartContract(proxyTarget, agentProbes[0]); err != nil {
		return err
	}
	return evalStartContainment(operatorControl, agentProbes[1], agentProbes[2:], localProbes)
}

func acceptProbeConnections(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_ = conn.Close()
	}
}

func evalProxyStartContract(target string, probe ProbeResult) error {
	if probe.Target != target || !probe.Open || probe.Blocked {
		return fmt.Errorf("%w: contained agent could not reach configured proxy target %q (%s)", ErrInVMContainmentNotProven, target, probe.Detail)
	}
	return nil
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
	return spawnEgressProbe(ctx, toyAgentBin, agentUser, targets)
}

func spawnEgressProbe(ctx context.Context, toyAgentBin, agentUser string, targets []string) ([]ProbeResult, error) {
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
