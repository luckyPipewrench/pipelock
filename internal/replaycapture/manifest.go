// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !js

package replaycapture

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

const artifactManifestName = "manifest.json"

// completenessNote is the exact, approved honesty language. Every public
// surface that renders a manifest must show it verbatim: the signed artifact is
// the receipt chain of DECISIONS, not the transcript, and a verified chain does
// not prove completeness.
const completenessNote = "A verified chain proves the included mediated decisions were signed by the " +
	"mediator and untampered. It does NOT prove session completeness, that no event was missed, that the " +
	"agent was sandboxed, or that traffic could not bypass Pipelock. The prompts and responses shown are " +
	"unsigned playback metadata; only the receipt chain of decisions is signed."

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
