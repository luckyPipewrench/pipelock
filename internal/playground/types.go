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
	Signature             string    `json:"signature,omitempty"`
}
