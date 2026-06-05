// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package replaycapture

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// ManifestSchemaVersion is the locked replay-manifest identifier. The manifest
// is UI-playback metadata that BINDS to an Audit Packet; it is presentation
// glue, not evidence. The evidence is the signed receipt chain in the packet.
const ManifestSchemaVersion = "pipelock.replay_manifest.v0"

const artifactManifestName = "manifest.json"

// completenessNote is the exact, approved honesty language. Every public
// surface that renders a manifest must show it verbatim: the signed artifact is
// the receipt chain of DECISIONS, not the transcript, and a verified chain does
// not prove completeness.
const completenessNote = "A verified chain proves the included mediated decisions were signed by the " +
	"mediator and untampered. It does NOT prove session completeness, that no event was missed, that the " +
	"agent was sandboxed, or that traffic could not bypass Pipelock. The prompts and responses shown are " +
	"unsigned playback metadata; only the receipt chain of decisions is signed."

// Manifest is the UI-playback metadata bound to one Audit Packet.
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

// PacketBinding ties the manifest to a specific packet by hash, root, and count.
type PacketBinding struct {
	Path         string `json:"path"`
	SHA256       string `json:"sha256"`
	RootHash     string `json:"root_hash"`
	ReceiptCount int    `json:"receipt_count"`
	FinalSeq     int    `json:"final_seq"`
}

// ReceiptView is the per-receipt display row for the timeline stepper, derived
// entirely from the signed receipt (honest, no invented fields).
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

// BuildManifest constructs a replay manifest binding the captured scenario to
// its assembled packet. packetBytes is the exact packet.json content (so the
// bound sha256 matches the published file).
func BuildManifest(cs *CapturedScenario, res *AssembleResult, packetBytes []byte, pipelockVersion string) Manifest {
	s := cs.Scenario
	decisive := decisiveReceiptAR(cs.Receipts, s.ExpectedVerdict)
	decisiveLayer := ""
	if decisive != nil {
		decisiveLayer = decisive.Layer
	}

	views := make([]ReceiptView, 0, len(cs.Receipts))
	for _, r := range cs.Receipts {
		ar := r.ActionRecord
		views = append(views, ReceiptView{
			ChainSeq:       boundedInt(ar.ChainSeq),
			ActionID:       ar.ActionID,
			ActionType:     string(ar.ActionType),
			Verdict:        ar.Verdict,
			Transport:      ar.Transport,
			Method:         ar.Method,
			Layer:          ar.Layer,
			Pattern:        ar.Pattern,
			Severity:       ar.Severity,
			TargetRedacted: ar.Target,
		})
	}

	sum := sha256.Sum256(packetBytes)

	return Manifest{
		SchemaVersion:    ManifestSchemaVersion,
		ScenarioID:       s.ID,
		Title:            s.Title,
		Category:         s.Category,
		BenchCaseID:      s.BenchCaseID,
		Transport:        s.Transport,
		DestinationClass: s.DestinationClass,
		DecisiveVerdict:  decisiveVerdict(cs),
		DecisiveLayer:    decisiveLayer,
		Without:          s.Without,
		With:             s.With,
		RedactedShape:    s.RedactedShape,
		PipelockVersion:  pipelockVersion,
		PolicyHash:       cs.PolicyHash,
		SignerKey:        cs.SignerKeyHex,
		CapturedAt:       res.Packet.Run.StartedAt,
		Packet: PacketBinding{
			Path:         artifactPacketName,
			SHA256:       hex.EncodeToString(sum[:]),
			RootHash:     cs.RootHash,
			ReceiptCount: cs.ReceiptCount,
			FinalSeq:     boundedInt(cs.FinalSeq),
		},
		Receipts:         views,
		VerifierCommand:  fmt.Sprintf("pipelock-verifier audit-packet . --key %s", cs.SignerKeyHex),
		CompletenessNote: completenessNote,
	}
}

// WriteManifest renders the manifest as manifest.json in the packet directory.
func WriteManifest(packetDir string, m Manifest) error {
	data, err := marshalIndentNoEscape(m)
	if err != nil {
		return fmt.Errorf("marshaling manifest: %w", err)
	}
	if err := os.WriteFile(filepath.Join(packetDir, artifactManifestName), data, filePerm); err != nil {
		return fmt.Errorf("writing manifest: %w", err)
	}
	return nil
}
