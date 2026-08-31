// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import "time"

// EvidenceClass is the honesty label every on-screen/report claim carries.
type EvidenceClass string

const (
	ClassPipelockDecision EvidenceClass = "pipelock_decision"
	ClassCollectorWitness EvidenceClass = "collector_witness"
	ClassHostContainment  EvidenceClass = "host_containment"
	ClassNarration        EvidenceClass = "narration"
)

// LaunchManifest is signed BEFORE the agent starts and pins the whole run.
type LaunchManifest struct {
	RunNonce              string    `json:"run_nonce"`
	ScenarioID            string    `json:"scenario_id"`
	CanaryID              string    `json:"canary_id"`
	PipelockPubKey        string    `json:"pipelock_pubkey"`
	CollectorPubKey       string    `json:"collector_pubkey"`
	PolicyHash            string    `json:"policy_hash"`
	CollectorConfigDigest string    `json:"collector_config_digest"`
	TargetHost            string    `json:"target_host"`
	StartedAt             time.Time `json:"started_at"`
	// Contained pins, in the signed manifest, whether this run produced a
	// host-containment witness. When true, VerifyRun additionally requires the
	// host-containment checks to be present and pass. Because the manifest is
	// signed under the orchestrator key, an attacker cannot flip this to skip
	// the containment checks without invalidating the manifest signature.
	Contained bool `json:"contained"`
	// AgentKind records which agent drove the run: AgentKindModel for the real
	// model-backed subprocess, empty (or AgentKindDeterministic) for the scripted
	// IntentAgent. A free model does not reproduce the scripted safe-GET +
	// body_dlp beats, so a model run verifies under an honest model-mode predicate
	// (containment + zero-leak + a signed decision trail) instead of the strict
	// deterministic one. Covered by the manifest signature, so it cannot be
	// flipped to dodge the stricter check.
	AgentKind string `json:"agent_kind,omitempty"`
	// DelegationID and ImageDigest bind delegated manifests to the root-signed
	// session authorization. They remain absent from legacy manifests so the
	// legacy canonical signed bytes stay byte-identical.
	DelegationID string `json:"delegation_id,omitempty"`
	ImageDigest  string `json:"image_digest,omitempty"`
	Signature    string `json:"signature,omitempty"`
}

// Agent kinds recorded in LaunchManifest.AgentKind. Empty is treated as
// deterministic for backward compatibility with manifests signed before the
// field existed.
const (
	AgentKindModel         = "model"
	AgentKindDeterministic = "deterministic"
)
