// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// Bundle is the offline-verifiable view model the playground demo viewer
// renders. It is produced from a completed run directory by GenerateBundle.
//
// The honesty contract is the split between scripted narrative and real proof:
//   - Beats, Chat, and Agent carry the SCRIPTED, deterministic narrative for a
//     scenario. They are authored, not derived: a run directory cannot produce
//     human dialogue. They make the demo legible and repeatable.
//   - Decisions, Checks, and Verifier carry REAL data lifted from the signed
//     run artifacts (the receipt chain, the collector witness, the
//     host-containment witness, and the offline VerifyRun result). These are
//     the cryptographic facts a viewer can independently check; nothing here is
//     invented.
//
// JSON field names match the viewer's expected keys exactly (including the
// camelCase totalBeats/tagKind), so the generated bundle is a drop-in for the
// hand-authored sample the viewer shipped with.
type Bundle struct {
	Mode       string           `json:"mode"`
	RunID      string           `json:"run_id"`
	TotalBeats int              `json:"totalBeats"`
	Beats      []string         `json:"beats"`
	Chat       []BundleChatTurn `json:"chat"`
	Agent      []BundleAgentAct `json:"agent"`
	Decisions  []BundleDecision `json:"decisions"`
	Checks     []string         `json:"checks"`
	Verifier   BundleVerifier   `json:"verifier"`
}

// BundleChatTurn is one scripted chat line (user or agent) pinned to a beat.
type BundleChatTurn struct {
	Beat    int    `json:"beat"`
	Role    string `json:"role"`
	Tag     string `json:"tag"`
	TagKind string `json:"tagKind"`
	HTML    string `json:"html"`
}

// BundleAgentAct is one scripted agent action pinned to a beat. The Line field
// is hydrated with the real request target from the run's receipts.
type BundleAgentAct struct {
	Beat  int    `json:"beat"`
	Kind  string `json:"kind"`
	TS    string `json:"ts"`
	Act   string `json:"act"`
	Title string `json:"title"`
	Line  string `json:"line"`
	Note  string `json:"note"`
}

// BundleDecision is one mediator/witness decision rendered in the proof column.
// It is a union over the four decision classes (pipelock_decision allow/block,
// host_containment, collector_witness); fields not relevant to a given class are
// omitted. Every value here is derived from a signed run artifact.
type BundleDecision struct {
	Beat     int      `json:"beat"`
	Class    string   `json:"class"`
	Color    string   `json:"color"`
	Verdict  string   `json:"verdict,omitempty"`
	Pop      bool     `json:"pop,omitempty"`
	Banner   string   `json:"banner,omitempty"`
	Target   string   `json:"target,omitempty"`
	Meta     string   `json:"meta,omitempty"`
	Headline string   `json:"headline,omitempty"`
	Body     string   `json:"body,omitempty"`
	Signer   string   `json:"signer,omitempty"`
	Key      string   `json:"key,omitempty"`
	Envelope []string `json:"envelope,omitempty"`
}

// BundleVerifier is the "verify this yourself" block. Key and Command are the
// real published orchestrator key and the exact offline verify invocation.
type BundleVerifier struct {
	Status      string `json:"status"`
	Key         string `json:"key"`
	Fingerprint string `json:"fingerprint"`
	Command     string `json:"command"`
}

// Decision-column colors (match the viewer palette). Centralized so the
// generator and any future renderer agree on one source of truth.
const (
	bundleColorAllow      = "#00e5a0"
	bundleColorBlock      = "#ef4444"
	bundleColorContain    = "#f59e0b"
	bundleColorWitness    = "#38bdf8"
	bundleSignerPipelock  = "pipelock"
	bundleSignerOrch      = "orchestrator"
	bundleSignerCollector = "collector"
)

var (
	verifyRunForBundle           = VerifyRun
	extractReceiptsForBundle     = receipt.ExtractReceipts
	loadBundleArtifactsForBundle = loadBundleArtifacts
)

// GenerateBundle reads a completed playground run directory and produces a
// Bundle: the scripted narrative for the run's scenario, hydrated with the real
// signed proof (receipt chain, witnesses, offline verify result).
//
// orchestratorPubHex is the run's trust-root public key — the same key passed to
// `verify --orchestrator-key`. It is used both to run the offline verification
// (so Checks reflects a real pass) and to render the verifier block.
//
// It fails closed: a missing or malformed artifact, an unsupported scenario, or
// a run whose offline verification does not pass returns an error rather than a
// bundle that overstates what was proven.
func GenerateBundle(runDir, orchestratorPubHex string) (Bundle, error) {
	cleanDir := filepath.Clean(runDir)

	// Offline-verify first: a bundle must never claim more than the run proves.
	rep, err := verifyRunForBundle(cleanDir, orchestratorPubHex)
	if err != nil {
		return Bundle{}, fmt.Errorf("verify run: %w", err)
	}
	if !rep.OK {
		return Bundle{}, fmt.Errorf("run did not verify; refusing to generate a bundle that overstates proof (failed checks: %s)", failedCheckNames(rep))
	}

	lm, err := loadLaunchManifest(cleanDir)
	if err != nil {
		return Bundle{}, err
	}

	narr, ok := bundleNarratives[lm.ScenarioID]
	if !ok {
		return Bundle{}, fmt.Errorf("no bundle narrative for scenario %q", lm.ScenarioID)
	}

	receipts, err := extractReceiptsForBundle(filepath.Join(cleanDir, packetSubdir, "evidence.jsonl"))
	if err != nil {
		return Bundle{}, fmt.Errorf("extract receipts: %w", err)
	}

	// The host-containment witness exists only for contained runs; for
	// uncontained runs hcw is nil and the containment decision is omitted.
	witness, hcw, err := loadBundleArtifactsForBundle(cleanDir, lm.Contained)
	if err != nil {
		return Bundle{}, err
	}

	return Bundle{
		Mode:       "replay",
		RunID:      lm.RunNonce,
		TotalBeats: len(narr.beats),
		Beats:      append([]string{}, narr.beats...),
		Chat:       append([]BundleChatTurn{}, narr.chat...),
		Agent:      hydrateAgentActs(narr, receipts, hcw),
		Decisions:  buildDecisions(narr, receipts, rep, witness, hcw),
		Checks:     checkNames(rep),
		Verifier:   buildVerifier(cleanDir, orchestratorPubHex),
	}, nil
}

// loadLaunchManifest reads and unmarshals the signed launch manifest. The
// signature is already checked by VerifyRun before this is called.
func loadLaunchManifest(cleanDir string) (LaunchManifest, error) {
	data, err := os.ReadFile(filepath.Clean(filepath.Join(cleanDir, launchManifestFile)))
	if err != nil {
		return LaunchManifest{}, fmt.Errorf("read launch manifest: %w", err)
	}
	var lm LaunchManifest
	if err := json.Unmarshal(data, &lm); err != nil {
		return LaunchManifest{}, fmt.Errorf("parse launch manifest: %w", err)
	}
	return lm, nil
}

func checkNames(rep VerifyReport) []string {
	names := make([]string, 0, len(rep.Checks))
	for _, c := range rep.Checks {
		names = append(names, c.Name)
	}
	return names
}

func failedCheckNames(rep VerifyReport) string {
	var failed []string
	for _, c := range rep.Checks {
		if !c.OK {
			failed = append(failed, c.Name)
		}
	}
	if len(failed) == 0 {
		return "(none reported; required check missing)"
	}
	return strings.Join(failed, ", ")
}

// shortKey renders an ed25519 public key hex as a compact ed25519:abcd…ef label
// for the proof column, matching the viewer's display convention.
func shortKey(hexKey string) string {
	if len(hexKey) <= 6 {
		return "ed25519:" + hexKey
	}
	return "ed25519:" + hexKey[:4] + "…" + hexKey[len(hexKey)-2:]
}
