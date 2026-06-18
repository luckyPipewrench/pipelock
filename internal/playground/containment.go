// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"time"
)

// --------------------------------------------------------------------------
// Egress probe: attempt a direct (no-proxy) TCP connection to a target and
// classify it as Open (connected), Blocked (kernel/network denial), or
// ambiguous/reachable failure (for example connection refused).
// --------------------------------------------------------------------------

// ProbeResult holds the outcome of a single direct-egress probe. It is
// serialized into the signed HostContainmentWitness, so its JSON shape is part
// of the evidence model: the field tags must stay stable for SignedBytes
// determinism.
type ProbeResult struct {
	// Target is the host:port that was probed.
	Target string `json:"target"`
	// Open is true when the probe connected successfully (egress is NOT blocked).
	Open bool `json:"open"`
	// Blocked is true only when the probe failed in a way consistent with a
	// kernel/network egress denial. Reachable-but-closed targets (connection
	// refused) are NOT blocked: they prove packets escaped far enough to get a
	// response.
	Blocked bool `json:"blocked"`
	// Detail is a human-readable classification (e.g. "connected", "connection refused").
	Detail string `json:"detail"`
}

// probeTimeout is the per-target TCP dial timeout for egress probes. Short
// enough to keep the self-test fast, long enough that a real connection on
// loopback or LAN completes.
const probeTimeout = 2 * time.Second

const defaultContainedAgentUser = "pipelock-agent"

// ProbeDirectEgress attempts a direct (proxy-less) TCP connection to target
// (host:port). It classifies connected targets as Open, timeout/no-route/
// permission failures as Blocked, and reachable-but-closed or ambiguous
// failures as neither. The probe uses an
// explicit nil-Proxy transport so HTTP_PROXY / HTTPS_PROXY env vars are
// NOT consulted -- this is testing the raw network path, not the mediated one.
func ProbeDirectEgress(ctx context.Context, target string) ProbeResult {
	dialer := &net.Dialer{Timeout: probeTimeout}

	dialCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	conn, err := dialer.DialContext(dialCtx, "tcp", target)
	if err != nil {
		blocked := isEgressBlockError(err)
		return ProbeResult{
			Target:  target,
			Open:    false,
			Blocked: blocked,
			Detail:  probeErrorDetail(err, blocked),
		}
	}
	_ = conn.Close()
	return ProbeResult{
		Target:  target,
		Open:    true,
		Blocked: false,
		Detail:  "connected",
	}
}

func isEgressBlockError(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	if errors.Is(err, os.ErrPermission) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "network is unreachable") ||
		strings.Contains(msg, "no route to host") ||
		strings.Contains(msg, "host is down") ||
		strings.Contains(msg, "operation not permitted") ||
		strings.Contains(msg, "permission denied") ||
		strings.Contains(msg, "administratively prohibited")
}

func probeErrorDetail(err error, blocked bool) string {
	if strings.Contains(strings.ToLower(err.Error()), "connection refused") {
		return fmt.Sprintf("reachable: connection refused: %v", err)
	}
	if blocked {
		return fmt.Sprintf("blocked: %v", err)
	}
	return fmt.Sprintf("not blocked: %v", err)
}

// --------------------------------------------------------------------------
// Target suites: the two categories of egress targets the demo probes.
// --------------------------------------------------------------------------

// DirectEgressTargets returns the direct-egress containment suite: addresses
// the kernel must block when containment is active. These are the "known-bad"
// routes that a contained agent should never reach directly.
//
// Each entry is a host:port suitable for a TCP dial. Targets are chosen so that
// under containment the dial fails with a kernel/network DENIAL (timeout, no
// route, permission) -- not a client-side malformed-address error. An IPv6
// link-local literal without a %zone (e.g. [fe80::1]:443) is deliberately NOT
// used: it fails with EINVAL ("invalid argument") before any packet leaves the
// host, which is a malformed dial, not an egress block, so it can never honestly
// prove containment on any host. The list covers the categories from the
// playground spec:
//   - Cloud metadata IP (169.254.169.254:80)
//   - RFC-1918 private IP (10.0.0.1:443)
//   - Public DNS resolvers (8.8.8.8:53, 1.1.1.1:853 DoT)
//   - Public HTTPS endpoint (93.184.216.34:443 -- example.com's IP)
func DirectEgressTargets() []string {
	return []string{
		"169.254.169.254:80", // cloud metadata
		"10.0.0.1:443",       // RFC-1918 private
		"8.8.8.8:53",         // public DNS (Google)
		"1.1.1.1:853",        // public DNS over TLS (Cloudflare)
		"93.184.216.34:443",  // public HTTPS (example.com)
	}
}

// MediatedProxyPolicyTargets returns the mediated-proxy-policy suite: request
// patterns that must be blocked by the proxy's policy engine (DLP, domain
// blocklist, SSRF) even when traffic is routed through the proxy. These are
// tested as URL patterns during the live run, not as raw TCP targets.
func MediatedProxyPolicyTargets() []string {
	return []string{
		"http://intake.lab.test/redirect-to-forbidden",
		"http://169.254.169.254/latest/meta-data/",
		"http://[::1]:8080/",
		"http://metadata.google.internal/computeMetadata/v1/",
		"ftp://intake.lab.test/data",
		"http://10.0.0.1:8080/internal-api",
	}
}

// --------------------------------------------------------------------------
// Self-test: probe all known-bad routes and report whether containment holds.
// --------------------------------------------------------------------------

// SelfTestResult holds the aggregate result of probing all known-bad routes.
type SelfTestResult struct {
	// Probes contains one result per target.
	Probes []ProbeResult
	// AllBlocked is true ONLY when every single known-bad route was explicitly
	// classified as blocked. Any open, refused, or ambiguous route means
	// containment is not proven and the contained demo must abort.
	AllBlocked bool
}

// RunContainmentSelfTest probes every target in the provided list via direct
// (no-proxy) TCP and returns the aggregate result. AllBlocked is true ONLY
// if EVERY target failed with an egress-block classification. Any connected
// route, connection-refused response, or ambiguous failure means containment is
// not proven.
//
// This diagnostic helper is useful for checking a target list from the current
// process's network position. The split-proof live demo's production
// containment gate is buildHostContainmentWitness, which drops the probe
// subprocess to the contained agent user before probing.
func RunContainmentSelfTest(ctx context.Context, targets []string) SelfTestResult {
	probes := make([]ProbeResult, 0, len(targets))
	allBlocked := true

	for _, t := range targets {
		p := ProbeDirectEgress(ctx, t)
		probes = append(probes, p)
		if !p.Blocked {
			allBlocked = false
		}
	}

	return SelfTestResult{
		Probes:     probes,
		AllBlocked: allBlocked,
	}
}

// --------------------------------------------------------------------------
// ErrContainmentSelfTestFailed is returned when the per-run containment
// self-test detects open routes, meaning containment is not fully enforced.
// --------------------------------------------------------------------------

// ErrContainmentSelfTestFailed signals that the per-run self-test found at
// least one known-bad route is reachable, so the contained demo cannot proceed
// honestly.
var ErrContainmentSelfTestFailed = errors.New(
	"playground: containment self-test failed: at least one known-bad route is reachable; " +
		"contained demo cannot proceed (direct egress is not fully blocked)")

// --------------------------------------------------------------------------
// RealContainmentHook: integrates with the shipped `pipelock contain` mechanism.
// --------------------------------------------------------------------------

// RealContainmentHook implements ContainmentHook by delegating to the
// shipped `pipelock contain` mechanism for kernel-level agent containment.
//
// HOST-VERIFICATION-PENDING: Setup and Teardown require root privileges and
// a working `pipelock contain install` + nftables setup. They return
// descriptive errors when privileges or tooling are unavailable. The actual
// kernel-blocks-egress property is verified ONLY on a privileged host, not
// in CI. Unit tests skip the end-to-end test with a clear message.
type RealContainmentHook struct {
	// PipelockBin is the path to the pipelock binary used for containment.
	// When empty, "pipelock" is resolved via PATH.
	PipelockBin string

	// AgentUser is the contained agent username.
	// When empty, defaults to "pipelock-agent".
	AgentUser string
}

// NewRealContainmentHook creates a RealContainmentHook with the given
// pipelock binary path. Pass "" to resolve "pipelock" via PATH.
func NewRealContainmentHook(pipelockBin string) *RealContainmentHook {
	return &RealContainmentHook{
		PipelockBin: pipelockBin,
	}
}

// Setup prepares kernel containment: verifies privileges, verifies
// `pipelock contain` is installed, and confirms the contained agent user exists.
//
// HOST-VERIFICATION-PENDING: this method only succeeds on a privileged
// host with `pipelock contain` installed. It returns a descriptive error
// when the prerequisites are not met.
func (h *RealContainmentHook) Setup(ctx context.Context, opts DemoOpts) error {
	// --- Privilege check ---
	if os.Geteuid() != 0 {
		return fmt.Errorf("containment setup requires root privileges (euid=%d); "+
			"run with sudo or as root", os.Geteuid())
	}

	// --- Resolve pipelock binary ---
	bin := h.PipelockBin
	if bin == "" {
		bin = "pipelock"
	}
	resolvedBin, err := exec.LookPath(bin)
	if err != nil {
		return fmt.Errorf("containment setup: pipelock binary %q not found: %w", bin, err)
	}

	agentUser := h.AgentUser
	if agentUser == "" {
		agentUser = defaultContainedAgentUser
	}
	if _, err := user.Lookup(agentUser); err != nil {
		return fmt.Errorf("containment setup: contained agent user %q not found: %w", agentUser, err)
	}

	// --- Verify containment is installed (pipelock contain verify) ---
	verifyCmd := exec.CommandContext(ctx, resolvedBin, "contain", "verify")
	verifyOut, verifyErr := verifyCmd.CombinedOutput()
	if verifyErr != nil {
		return fmt.Errorf("containment setup: 'pipelock contain verify' failed "+
			"(containment may not be installed): %w\noutput: %s", verifyErr, verifyOut)
	}

	return nil
}

// Teardown cleans up containment state for the run directory. On a real host,
// this would remove nft chains and stop agent processes. The teardown is
// best-effort: errors are returned but should not prevent cleanup of other
// resources.
//
// HOST-VERIFICATION-PENDING: actual nft cleanup requires root.
func (h *RealContainmentHook) Teardown(runDir string) error {
	// The shipped containment model's nft chains are persistent (they survive
	// across runs). Per-run teardown only needs to clean up agent processes
	// if any were started. The playground demo's toy agent is ephemeral
	// (exec.CommandContext with the run's context), so it is already dead by
	// the time teardown runs.
	//
	// Future: if the playground ever starts long-lived contained processes,
	// kill them here.
	_ = runDir // reserved for future per-run state cleanup
	return nil
}

// --------------------------------------------------------------------------
// requirePrivilegedHost is a test helper that skips tests requiring root
// and a working containment setup.
// --------------------------------------------------------------------------

// ContainmentAvailable checks whether `pipelock contain verify` can be run
// successfully. Used by tests to gate host-only containment tests.
func ContainmentAvailable() bool {
	// Quick check: is pipelock in PATH?
	_, err := exec.LookPath("pipelock")
	if err != nil {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "pipelock", "contain", "verify")
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

// --------------------------------------------------------------------------
// Production containment gate.
//
// RunContainmentSelfTest remains a diagnostic helper: it probes from the
// caller's process, which is not representative of UID-scoped containment when
// the caller is root. The live demo's production gate is the signed
// HostContainmentWitness built by LiveRun.buildHostContainmentWitness: that path
// first proves an operator-vs-agent control differential, then requires the
// contained agent user to block the exact DirectEgressTargets suite.
// --------------------------------------------------------------------------
