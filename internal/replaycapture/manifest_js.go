// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build js

package replaycapture

const ManifestSchemaVersion = "pipelock.replay_manifest.v0"

type Manifest struct {
	SchemaVersion    string        `json:"schema_version"`
	ScenarioID       string        `json:"scenario_id"`
	Title            string        `json:"title"`
	Category         string        `json:"category"`
	BenchCaseID      string        `json:"bench_case_id"`
	Transport        string        `json:"transport"`
	DestinationClass string        `json:"destination_class"`
	DecisiveVerdict  string        `json:"decisive_verdict"`
	DecisiveLayer    string        `json:"decisive_layer,omitempty"`
	Without          string        `json:"without"`
	With             string        `json:"with"`
	RedactedShape    string        `json:"redacted_shape,omitempty"`
	PipelockVersion  string        `json:"pipelock_version"`
	PolicyHash       string        `json:"policy_hash"`
	SignerKey        string        `json:"signer_key"`
	CapturedAt       string        `json:"captured_at"`
	Packet           PacketBinding `json:"packet"`
	Receipts         []ReceiptView `json:"receipts"`
	VerifierCommand  string        `json:"verifier_command"`
	CompletenessNote string        `json:"completeness_note"`
}

type PacketBinding struct {
	Path         string `json:"path"`
	SHA256       string `json:"sha256"`
	RootHash     string `json:"root_hash"`
	ReceiptCount int    `json:"receipt_count"`
	FinalSeq     int    `json:"final_seq"`
}

type ReceiptView struct {
	ChainSeq       int    `json:"chain_seq"`
	ActionID       string `json:"action_id"`
	ActionType     string `json:"action_type"`
	Verdict        string `json:"verdict"`
	Transport      string `json:"transport,omitempty"`
	Method         string `json:"method,omitempty"`
	Layer          string `json:"layer,omitempty"`
	Pattern        string `json:"pattern,omitempty"`
	Severity       string `json:"severity,omitempty"`
	TargetRedacted string `json:"target_redacted,omitempty"`
}
