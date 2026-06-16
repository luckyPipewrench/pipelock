// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"time"
)

// HostContainmentWitness is the orchestrator-signed attestation that, for one
// specific run, the host's kernel containment blocked the contained agent
// (running as AgentUID) from reaching egress targets while the operator could.
//
// It is the split-proof counterpart to the collector Witness: where the
// collector witness attests what the lab collector observed for the MEDIATED
// path, this witness attests the ENFORCED-direct-egress property. The two are
// orthogonal and are proven where each is actually enforced -- the proxy
// scans mediated traffic; the kernel owner-match rule blocks direct egress.
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
	// the kernel owner-match drop.
	ControlAgentProbe ProbeResult `json:"control_agent_probe"`

	// AgentProbes are the contained agent's probes of the real direct-egress
	// target suite (cloud metadata, RFC-1918, public DNS, public HTTPS). Every
	// one MUST be explicitly blocked (Open=false, Blocked=true); any open,
	// refused, or ambiguous route means containment is not proven.
	AgentProbes []ProbeResult `json:"agent_probes"`

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
	expected := DirectEgressTargets()
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

// AllAgentBlocked reports whether every contained-agent probe -- the control
// target probe AND every direct-egress probe present in the witness -- was
// explicitly classified as blocked. Open=false alone is not enough: a
// connection-refused response is reachable-but-closed, not containment. It
// requires at least one real direct-egress probe so an empty suite cannot pass
// vacuously. Enforced additionally requires DirectSuiteProven.
func (w HostContainmentWitness) AllAgentBlocked() bool {
	if len(w.AgentProbes) == 0 {
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
	return true
}

// DifferentialProven reports whether the control differential holds: the SAME
// host-local target is reachable for the operator and blocked for the contained
// agent. This is what makes the block attributable to containment rather than to
// an unroutable or down target.
func (w HostContainmentWitness) DifferentialProven() bool {
	if w.ControlTarget == "" {
		return false
	}
	if w.ControlOperatorProbe.Target != w.ControlTarget || w.ControlAgentProbe.Target != w.ControlTarget {
		return false
	}
	return w.ControlOperatorProbe.Open && !w.ControlAgentProbe.Open && w.ControlAgentProbe.Blocked
}

// Enforced is the fail-closed gate: containment is proven for this run ONLY when
// the differential holds, the exact direct-egress suite was probed, and every
// contained-agent probe was explicitly blocked. Any open, refused, or ambiguous
// agent route, a missing or substituted target, a missing/unreachable control
// target, or an empty probe suite fails closed.
func (w HostContainmentWitness) Enforced() bool {
	return w.DifferentialProven() && w.DirectSuiteProven() && w.AllAgentBlocked()
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
