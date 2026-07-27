// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"time"
)

// HostContainmentWitness is the orchestrator-signed attestation that, for one
// specific run, the host's kernel containment blocked the contained agent
// (running as AgentUID) from reaching egress targets and local escape surfaces,
// while the operator could reach the control target.
//
// It is the split-proof counterpart to the collector Witness: where the
// collector witness attests what the lab collector observed for the MEDIATED
// path, this witness attests the host-enforced containment property. The two are
// orthogonal and are proven where each is actually enforced -- the proxy scans
// mediated traffic; the kernel owner-match rule blocks direct egress; process
// and host hardening block local platform/device/namespace escape surfaces.
//
// The honesty hinges on a DIFFERENTIAL: ControlTarget is a host-local listener
// that is genuinely reachable absent containment. The operator probe of it must
// be Open and the contained-agent probe of the SAME target must be explicitly
// Blocked.
// Because only the source uid differs between the two probes, a block can only
// be attributed to the kernel owner-match rule -- never to an unroutable or
// down target (the weakness of probing a single reserved IP).
//
// It is signed by the orchestrator key (the run's trust root, the same key that
// signs the launch manifest) and is intrinsically bound to
// (RunNonce, LaunchManifestHash) so it cannot be replayed against another run.
//
// INVARIANT: no map-typed fields. SignedBytes determinism depends on
// struct-declaration-order JSON marshaling, which is only stable for structs.
type HostContainmentWitness struct {
	RunNonce           string `json:"run_nonce"`
	LaunchManifestHash string `json:"launch_manifest_hash"`
	// ProbeSuiteVersion identifies the exact target-suite semantics. Empty is
	// the legacy v1 suite so previously signed witnesses retain identical bytes.
	ProbeSuiteVersion string `json:"probe_suite_version,omitempty"`

	AgentUser string `json:"agent_user"`
	AgentUID  int    `json:"agent_uid"`

	// ControlTarget is the host-local listener used for the differential proof.
	ControlTarget string `json:"control_target"`
	// ControlOperatorProbe is the operator's probe of ControlTarget. It MUST be
	// Open: it proves the probe mechanism can detect a reachable target, so a
	// "blocked" result elsewhere is meaningful and not a broken probe.
	ControlOperatorProbe ProbeResult `json:"control_operator_probe"`
	// ControlAgentProbe is the contained agent's probe of the SAME ControlTarget.
	// It MUST be explicitly blocked (Open=false, Blocked=true). Together with
	// ControlOperatorProbe being Open, this is the differential that isolates
	// the kernel owner-match drop. Because ControlTarget is a NON-proxy loopback
	// port, this blocked probe is also the negative proof that the contained
	// agent cannot reach arbitrary loopback services -- only the proxy.
	ControlAgentProbe ProbeResult `json:"control_agent_probe"`

	// ProxyTarget is the contained agent's SOLE permitted egress: the playground
	// in-process proxy on a fixed reserved loopback port. The kernel owner-match
	// rule allows the agent uid to reach EXACTLY this host:port and nothing else.
	// It is recorded and signed so the bundle attests the precise port contract,
	// closing the gap where a random proxy port could not align with the
	// single-port owner-match allow rule.
	ProxyTarget string `json:"proxy_target"`
	// ProxyAgentProbe is the contained agent's probe of ProxyTarget. It MUST be
	// Open: the agent CAN reach its one allowed egress. Paired with
	// ControlAgentProbe (a DIFFERENT loopback port) being Blocked, this proves the
	// agent reaches exactly the proxy and nothing else on loopback. It also
	// catches an operator port mismatch -- the playground proxy bound to a port
	// the nft rule does not allow leaves this probe Blocked, which fails the run
	// closed instead of silently breaking the demo.
	ProxyAgentProbe ProbeResult `json:"proxy_agent_probe"`

	// AgentProbes are the contained agent's probes of the real direct-egress
	// target suite (cloud metadata, RFC-1918, public DNS, public HTTPS). Every
	// one MUST be explicitly blocked (Open=false, Blocked=true); any open,
	// refused, or ambiguous route means containment is not proven.
	AgentProbes []ProbeResult `json:"agent_probes"`

	// LocalAgentProbes are the contained agent's probes of local, non-network
	// escape surfaces (platform control sockets, raw device nodes, and
	// capability-gated local privilege operations). Every one MUST be explicitly
	// blocked or unavailable. These probes cover paths that never traverse the
	// HTTP proxy, so destination-control receipts alone cannot prove them.
	LocalAgentProbes []ProbeResult `json:"local_agent_probes"`

	ProbedAt time.Time `json:"probed_at"`

	Signature string `json:"signature,omitempty"`
}

// SignedBytes returns the canonical JSON of the witness with the Signature field
// cleared. These are the exact bytes the orchestrator signs and a verifier
// checks. Deterministic via struct declaration order (no maps).
func (w HostContainmentWitness) SignedBytes() []byte {
	w.Signature = ""
	b, _ := json.Marshal(w)
	return b
}

// DirectSuiteProven reports whether AgentProbes covers the exact
// DirectEgressTargets suite, in order. This prevents a witness from proving a
// weaker statement by signing one easy blocked route while omitting the harder
// categories.
func (w HostContainmentWitness) DirectSuiteProven() bool {
	expected, ok := expectedProbeTargets(w.ProbeSuiteVersion, legacyDirectEgressTargets, DirectEgressTargets)
	if !ok {
		return false
	}
	if len(w.AgentProbes) != len(expected) {
		return false
	}
	for i, target := range expected {
		if w.AgentProbes[i].Target != target {
			return false
		}
	}
	return true
}

// LocalEscapeSuiteProven reports whether LocalAgentProbes covers the exact
// LocalEscapeTargets suite, in order. This prevents a witness from omitting a
// known local surface (for example the Fly control socket or raw block device)
// while still claiming host containment.
func (w HostContainmentWitness) LocalEscapeSuiteProven() bool {
	expected, ok := expectedProbeTargets(w.ProbeSuiteVersion, legacyLocalEscapeTargets, LocalEscapeTargets)
	if !ok {
		return false
	}
	if len(w.LocalAgentProbes) != len(expected) {
		return false
	}
	for i, target := range expected {
		if w.LocalAgentProbes[i].Target != target {
			return false
		}
	}
	return true
}

func expectedProbeTargets(version string, legacy, current func() []string) ([]string, bool) {
	switch version {
	case "":
		return legacy(), true
	case currentContainmentProbeSuite:
		return current(), true
	default:
		return nil, false
	}
}

// AllAgentBlocked reports whether every contained-agent probe -- the control
// target probe, every direct-egress probe, and every local escape probe present
// in the witness -- was explicitly classified as blocked. Open=false alone is
// not enough for direct egress: a connection-refused response is
// reachable-but-closed, not containment. It requires at least one real
// direct-egress probe and at least one local escape probe so empty suites cannot
// pass vacuously. Enforced additionally requires exact target suites.
func (w HostContainmentWitness) AllAgentBlocked() bool {
	if len(w.AgentProbes) == 0 || len(w.LocalAgentProbes) == 0 {
		return false
	}
	if w.ControlAgentProbe.Open || !w.ControlAgentProbe.Blocked {
		return false
	}
	for _, p := range w.AgentProbes {
		if p.Open || !p.Blocked {
			return false
		}
	}
	deniedLocal := 0
	for _, p := range w.LocalAgentProbes {
		if p.Blocked && p.Absent {
			return false
		}
		if p.Open || (!p.Blocked && !p.Absent) {
			return false
		}
		if p.Blocked {
			deniedLocal++
		}
	}
	return deniedLocal > 0
}

// LocalProbeCounts separates enforced denials from surfaces absent on this
// host so public renderers do not overstate absence as a kernel block.
func (w HostContainmentWitness) LocalProbeCounts() (denied, absent int) {
	for _, probe := range w.LocalAgentProbes {
		if probe.Blocked && probe.Absent {
			continue
		}
		if probe.Blocked {
			denied++
		}
		if probe.Absent {
			absent++
		}
	}
	return denied, absent
}

// DifferentialProven reports whether the control differential holds: the SAME
// host-local target is reachable for the operator and blocked for the contained
// agent. This is what makes the block attributable to containment rather than to
// an unroutable or down target.
func (w HostContainmentWitness) DifferentialProven() bool {
	if !isIPv4LoopbackHostPort(w.ControlTarget) {
		return false
	}
	if w.ControlOperatorProbe.Target != w.ControlTarget || w.ControlAgentProbe.Target != w.ControlTarget {
		return false
	}
	return w.ControlOperatorProbe.Open && !w.ControlOperatorProbe.Blocked &&
		!w.ControlAgentProbe.Open && w.ControlAgentProbe.Blocked
}

// ProxyContractProven reports whether the contained agent's SOLE permitted
// egress is the playground proxy and nothing else on loopback: ProxyTarget is
// set, distinct from the (blocked) ControlTarget, and the agent's own probe of
// it is Open. Paired with DifferentialProven (the same-uid differential that
// isolates the kernel owner-match) and ControlAgentProbe being blocked, this is
// the port contract: the agent reaches exactly the proxy port, a different
// loopback port it does not. It also fails closed on an operator port mismatch
// (playground proxy bound to a port the nft rule does not allow) -- that leaves
// ProxyAgentProbe blocked, so this returns false and the run does not verify.
func (w HostContainmentWitness) ProxyContractProven() bool {
	if !isIPv4LoopbackHostPort(w.ProxyTarget) || w.ProxyTarget == w.ControlTarget {
		return false
	}
	return w.ProxyAgentProbe.Target == w.ProxyTarget && w.ProxyAgentProbe.Open && !w.ProxyAgentProbe.Blocked
}

func isIPv4LoopbackHostPort(target string) bool {
	addrPort, err := netip.ParseAddrPort(target)
	if err != nil {
		return false
	}
	if !addrPort.Addr().Is4() || !addrPort.Addr().IsLoopback() {
		return false
	}
	return addrPort.Port() != 0
}

// Enforced is the fail-closed gate: containment is proven for this run ONLY when
// the differential holds, the agent reaches exactly its proxy port (and a
// different loopback port is blocked), the exact direct-egress and local escape
// suites were probed, and every contained-agent probe was explicitly blocked.
// Any open, refused, or ambiguous agent route, a missing or substituted target,
// a missing/unreachable control target, a proxy the agent cannot reach (or a
// proxy/control collision), or an empty probe suite fails closed.
func (w HostContainmentWitness) Enforced() bool {
	return w.DifferentialProven() && w.ProxyContractProven() &&
		w.DirectSuiteProven() && w.LocalEscapeSuiteProven() && w.AllAgentBlocked()
}

// SignHostContainmentWitness signs w with the orchestrator private key over its
// canonical (signature-excluded) bytes and returns a copy with the hex Signature
// set.
func SignHostContainmentWitness(priv ed25519.PrivateKey, w HostContainmentWitness) HostContainmentWitness {
	sig := ed25519.Sign(priv, w.SignedBytes())
	w.Signature = hex.EncodeToString(sig)
	return w
}

// VerifyHostContainmentWitness reports whether w carries a valid ed25519
// signature under the given orchestrator public key (hex-encoded). It rejects
// malformed or wrong-length keys and signatures (fail closed).
func VerifyHostContainmentWitness(orchestratorPubHex string, w HostContainmentWitness) bool {
	pub, err := hex.DecodeString(orchestratorPubHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := hex.DecodeString(w.Signature)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), w.SignedBytes(), sig)
}

// HostContainmentBindsRun reports whether w is intrinsically bound to the given
// run nonce and launch-manifest hash. A witness from one run does NOT satisfy
// this for another run, which is what makes it non-replayable.
func HostContainmentBindsRun(w HostContainmentWitness, nonce, manifestHash string) bool {
	return w.RunNonce == nonce && w.LaunchManifestHash == manifestHash
}
