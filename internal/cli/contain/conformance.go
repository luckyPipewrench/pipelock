// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"fmt"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

// This file is the ONLY exported surface the containment-conformance
// artifact under sdk/conformance/ depends on. It deliberately exposes the
// minimum needed to drive the egress-containment probes (probe 8 / probe 9)
// against canned command and DROP-counter readers, with NO access to the real
// sudo/curl/nft execution path and NO leak of the unexported probe/probeEnv
// internals.
//
// DESIGN NOTE (why this shape):
//   - The probe registry, probeEnv, and probeRecord types are unexported and
//     must stay that way (they carry real-execution seams — sudo argv builders,
//     a live dialer, os.Stat/ReadFile, the binary-integrity hasher). Exporting
//     them would widen the production attack surface for one test artifact.
//   - The conformance artifact only needs to prove the DIRECT-EGRESS probes:
//     probe 8 (pipelock-agent must NOT reach the internet directly) and
//     probe 9 (the operator must still reach the internet). Those two probes
//     depend solely on the injected command and DROP-counter readers plus the
//     agent/operator usernames — none of the filesystem/dialer/hasher seams.
//   - So we export exactly one options struct (ConformanceEnv) carrying those
//     two narrow readers, and one driver (RunContainmentConformance) returning
//     exported result records plus the same aggregate exit code runVerify would
//     produce for these probes. The sdk/conformance test imports this, drives it
//     from JSON fixtures, and asserts per-probe status + exit code. This mirrors
//     how sdk/conformance/conformance_test.go already imports internal packages.

// ConformanceRunCommand is the canned command-runner the conformance harness
// injects. It has the same shape as the production runCommand seam: given the
// executable name and its argv, it returns merged stdout/stderr, the process
// exit code, and a non-nil error ONLY when the binary could not be started.
// Fixtures map a (name, argv) invocation to a canned (stdout, exitCode).
type ConformanceRunCommand func(ctx context.Context, name string, args ...string) (stdout string, exitCode int, err error)

// ConformanceDropCounter is the canned managed nftables DROP-counter reader
// used by the offline conformance harness. Probe 8 reads it immediately before
// and after the canned curl invocation.
type ConformanceDropCounter func(ctx context.Context) (uint64, error)

// ConformanceEnv carries the minimal inputs the egress-containment probes need.
// It is an options struct (not a long parameter list) so future conformance
// knobs are added as fields, never as new positional arguments.
type ConformanceEnv struct {
	// RunCommand is the canned runner. Required; a nil runner fails closed
	// (RunContainmentConformance returns an error rather than silently
	// passing, matching pipelock's fail-closed default).
	RunCommand ConformanceRunCommand

	// DropCounter is required for probe 8 to return PASS. A nil reader or a
	// non-increasing sequence produces UNKNOWN/exit 2, matching live verify.
	DropCounter ConformanceDropCounter

	// AgentUser is the unprivileged agent account probe 8 must prove is
	// blocked from direct egress. Defaults to the production agent user when
	// empty so fixtures need not restate it.
	AgentUser string

	// OperatorUser is the account probe 9 proves can still reach the
	// internet. When empty, probe 9 invokes curl directly (the production
	// behaviour when $SUDO_USER is unset).
	OperatorUser string

	// NFTChainText, when non-empty, is the literal `nft -n -a list chain inet
	// <table> <chain>` output text that probe 8's DROP-counter attribution
	// parses through the SAME chain-text recognizer `contain verify` (probe 3,
	// probeNFTContainment) uses: attributedNFTChainLines,
	// agentUIDBareAcceptBeforeDrop, chainLinesHaveUnsafeVerdictBeforeAgentDrop,
	// and managedContainmentDropPacketCountFromLines. This is the input a
	// fixture uses to exercise the structural agent-UID-accept-before-drop
	// containment hole, which DropCounter's pre-baked uint64 sequence cannot
	// reach at all. Setting NFTChainText together with DropCounter is
	// rejected as ambiguous.
	NFTChainText string

	// AgentUID and ProxyUID are the contained-agent and pipelock-proxy UIDs
	// the chain-text recognizer matches against. Both are REQUIRED and must
	// be distinct when NFTChainText is set; there is no safe default UID to
	// assume for a security recognizer, so a zero value fails closed at load.
	AgentUID int
	ProxyUID int

	// OperatorUID is the managed operator UID the recognizer treats as a safe
	// pre-drop accept. Optional; zero means "no managed operator UID
	// recorded" (matching a missing header in production), which is a normal,
	// not degraded, input and must not be confused with UID 0 (root).
	OperatorUID int

	// ProxyPort is the loopback port the recognizer's agent-proxy-loopback-
	// allow check uses. Defaults to the production proxy port (8888) when
	// zero.
	ProxyPort int
}

// ConformanceProbeResult is one exported per-probe outcome. Status is one of
// the canonical "pass" / "fail" / "skip" / "unknown" strings verify emits.
type ConformanceProbeResult struct {
	Probe  int    `json:"probe"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// Exported status constants so the conformance artifact can assert against
// them without re-declaring the unexported originals.
const (
	ConformanceStatusPass    = statusPass
	ConformanceStatusFail    = statusFail
	ConformanceStatusSkip    = statusSkip
	ConformanceStatusUnknown = statusUnknown
)

// Exit codes mirror the verify command's aggregate contract:
//
//	0  every driven probe passed,
//	1  at least one probe FAILED (containment is broken),
//	2  no failures but at least one probe SKIPPED or UNKNOWN (incomplete).
//
// These are re-exported from cliutil so callers (and the gate script) do not
// have to import cliutil just to read the numbers.
//
// conformanceExitInvalid (misconfigured harness, e.g. a nil runner) shares the
// numeric value of ConformanceExitSkip because both are config-class, non-zero,
// fail-closed outcomes. They are disambiguated by the error return, NOT the exit
// code: the invalid path returns a non-nil error, whereas a genuine skip returns
// a nil error. Callers that must tell them apart check the error.
const (
	ConformanceExitOK      = cliutil.ExitOK
	ConformanceExitFail    = cliutil.ExitGeneral
	ConformanceExitSkip    = cliutil.ExitConfig
	conformanceExitInvalid = cliutil.ExitConfig
)

// RunContainmentConformance drives the direct-egress containment probes
// (probe 8: pipelock-agent egress denied; probe 9: operator egress reachable)
// against the injected command runner in env, and returns the per-probe
// results plus the aggregate exit code.
//
// The aggregate exit code follows the same fail > incomplete > pass precedence
// the real `contain verify` driver uses (runVerify): a single FAIL yields exit 1
// regardless of how many probes passed, while SKIP/UNKNOWN without a failure
// yields exit 2. This is the property the must-fail "leaky-egress" fixture
// exercises.
//
// A nil runner (misconfigured fixture) fails closed: the function returns a
// non-nil error and the invalid exit code, never a silent pass.
func RunContainmentConformance(ctx context.Context, env ConformanceEnv) ([]ConformanceProbeResult, int, error) {
	if env.RunCommand == nil {
		return nil, conformanceExitInvalid, fmt.Errorf("conformance: RunCommand runner is required")
	}
	if env.NFTChainText != "" {
		if env.DropCounter != nil {
			return nil, conformanceExitInvalid, fmt.Errorf("conformance: NFTChainText and DropCounter are mutually exclusive fixture inputs (ambiguous)")
		}
		if env.AgentUID <= 0 || env.ProxyUID <= 0 {
			return nil, conformanceExitInvalid, fmt.Errorf("conformance: NFTChainText requires positive AgentUID and ProxyUID")
		}
		if env.AgentUID == env.ProxyUID {
			return nil, conformanceExitInvalid, fmt.Errorf("conformance: AgentUID and ProxyUID must be distinct")
		}
		// Zero keeps its documented meaning (unknown operator, default port);
		// any other value must be a real UID or a real port, or the
		// recognizer would report a conformance result for an input that
		// cannot describe a host.
		if env.OperatorUID < 0 {
			return nil, conformanceExitInvalid, fmt.Errorf("conformance: OperatorUID must be zero (unknown) or positive")
		}
		// The operator, proxy and agent are distinct system identities in any
		// real installation. Aliasing the operator to either of the others
		// describes a host that cannot exist, and the recognizer then reads
		// the operator's own accept as an agent bypass, so the fixture fails
		// with a containment-hole message that misdescribes the cause.
		// Reject the alias here instead, where the reason is visible.
		if env.OperatorUID != 0 && (env.OperatorUID == env.AgentUID || env.OperatorUID == env.ProxyUID) {
			return nil, conformanceExitInvalid, fmt.Errorf("conformance: OperatorUID must be distinct from AgentUID and ProxyUID")
		}
		if env.ProxyPort != 0 {
			if err := validatePort(env.ProxyPort); err != nil {
				return nil, conformanceExitInvalid, fmt.Errorf("conformance: ProxyPort: %w", err)
			}
		}
	}
	if ctx == nil {
		ctx = context.Background()
	}

	// Build the unexported probeEnv from the exported inputs. Only the fields
	// probes 8 and 9 consult are populated; everything else stays zero so a
	// fixture cannot reach a filesystem/dialer/hasher path by accident.
	internalEnv := &probeEnv{
		agentUserName: env.AgentUser,
		operatorUser:  env.OperatorUser,
		runCmd:        runCommand(env.RunCommand),
	}
	switch {
	case env.NFTChainText != "":
		// Feed the chain-text recognizer used by probe 3
		// (probeNFTContainment) and production's readContainmentDropCounter,
		// rather than reimplementing it, so this artifact can never drift
		// from what `contain verify` actually checks.
		proxyPort := env.ProxyPort
		if proxyPort == 0 {
			proxyPort = defaultProxyPort
		}
		uids := containmentUIDs{
			proxyUID:      env.ProxyUID,
			agentUID:      env.AgentUID,
			operatorUID:   env.OperatorUID,
			operatorKnown: env.OperatorUID != 0,
		}
		chainText := env.NFTChainText
		internalEnv.dropCounter = func(context.Context, *probeEnv) (uint64, error) {
			return conformanceChainDropCounter(chainText, uids, proxyPort)
		}
	case env.DropCounter != nil:
		internalEnv.dropCounter = func(ctx context.Context, _ *probeEnv) (uint64, error) {
			return env.DropCounter(ctx)
		}
	}
	if internalEnv.agentUserName == "" {
		internalEnv.agentUserName = defaultAgentUser
	}

	// The two direct-egress probes, in registry order (8 then 9).
	egressProbes := []probe{
		{8, "cc_agent_egress_denied", "pipelock-agent cannot reach the internet directly", probeCCAgentEgressDenied},
		{9, "operator_egress_reachable", "operator user can still reach the internet", probeOperatorEgress},
	}

	results := make([]ConformanceProbeResult, 0, len(egressProbes))
	var passN, failN, skipN, unknownN int
	for _, p := range egressProbes {
		status, detail := p.fn(ctx, internalEnv)
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
			// Unknown status coerces to fail and carries the value forward,
			// exactly as runVerify does. A probe must never vanish silently.
			failN++
			detail = fmt.Sprintf("invalid status %q (detail: %s)", status, detail)
			status = statusFail
		}
		results = append(results, ConformanceProbeResult{
			Probe:  p.n,
			Name:   p.name,
			Status: status,
			Detail: detail,
		})
	}

	exitCode := ConformanceExitOK
	switch {
	case failN > 0:
		exitCode = ConformanceExitFail
	case skipN > 0 || unknownN > 0:
		exitCode = ConformanceExitSkip
	}
	return results, exitCode, nil
}

// conformanceChainDropCounter feeds fixture-supplied chain text and UIDs to
// containmentDropCounterFromChainText, the same recognizer production's
// readContainmentDropCounter uses after its live `nft list chain` round trip.
func conformanceChainDropCounter(chainText string, uids containmentUIDs, proxyPort int) (uint64, error) {
	return containmentDropCounterFromChainText(chainText, defaultNFTChain, uids, proxyPort)
}
