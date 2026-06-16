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

const bundleTSLayout = "15:04:05"

// hydrateAgentActs copies the scripted agent action cards and fills the request
// line + timestamp of the allow and block acts from the real receipts, and the
// bypass act from the host-containment witness (contained runs only), so the
// agent column shows what the agent actually requested rather than a placeholder.
func hydrateAgentActs(narr scenarioNarrative, receipts []receipt.Receipt, hcw *HostContainmentWitness) []BundleAgentAct {
	allowR, hasAllow := findReceipt(receipts, liveDemoAllowedVerdict, "")
	blockR, hasBlock := findReceipt(receipts, liveDemoExpectedVerdict, liveDemoExpectedBlockLayer)

	out := make([]BundleAgentAct, 0, len(narr.agent))
	for _, a := range narr.agent {
		switch {
		case a.Beat == narr.allowBeat && hasAllow:
			ar := allowR.ActionRecord
			a.Line = requestLine(ar)
			a.TS = ar.Timestamp.Format(bundleTSLayout)
		case a.Beat == narr.blockBeat && hasBlock:
			ar := blockR.ActionRecord
			a.Line = requestLine(ar)
			a.TS = ar.Timestamp.Format(bundleTSLayout)
		case a.Beat == narr.containDecision.beat-1 && hcw != nil && len(hcw.AgentProbes) > 0:
			// The bypass attempt (beat just before the containment decision):
			// show a real blocked direct-egress target from the witness.
			a.Line = "connect() → " + hcw.AgentProbes[0].Target + " · direct egress, bypassing the proxy"
			a.TS = hcw.ProbedAt.Format(bundleTSLayout)
		}
		out = append(out, a)
	}
	return out
}

func requestLine(ar receipt.ActionRecord) string {
	method := ar.Method
	if method == "" {
		method = "REQ"
	}
	return method + " " + ar.Target
}

// findReceipt returns the first receipt whose normalized verdict matches and,
// when layer is non-empty, whose layer also matches.
func findReceipt(receipts []receipt.Receipt, verdict, layer string) (receipt.Receipt, bool) {
	for _, r := range receipts {
		ar := r.ActionRecord
		if receipt.NormalizeVerdict(ar.Verdict) != verdict {
			continue
		}
		if layer != "" && ar.Layer != layer {
			continue
		}
		return r, true
	}
	return receipt.Receipt{}, false
}

// buildDecisions assembles the proof-column decisions in beat order, injecting
// real data from the receipts, the collector witness, and (for contained runs)
// the host-containment witness. The scripted framing comes from narr. When hcw
// is nil (uncontained run) the host-containment decision is omitted.
func buildDecisions(narr scenarioNarrative, receipts []receipt.Receipt, rep VerifyReport, witness Witness, hcw *HostContainmentWitness) []BundleDecision {
	var decisions []BundleDecision

	// --- ALLOW (mediated) ---
	if allowR, ok := findReceipt(receipts, liveDemoAllowedVerdict, ""); ok {
		ar := allowR.ActionRecord
		decisions = append(decisions, BundleDecision{
			Beat:    narr.allowDecision.beat,
			Class:   string(ClassPipelockDecision),
			Color:   narr.allowDecision.color,
			Verdict: "ALLOW",
			Target:  requestLine(ar),
			Meta:    fmt.Sprintf("verdict=allow · transport=%s", ar.Transport),
			Signer:  bundleSignerPipelock,
			Key:     shortKey(allowR.SignerKey),
		})
	}

	// --- BLOCK (mediated, with the signed receipt envelope) ---
	if blockR, ok := findReceipt(receipts, liveDemoExpectedVerdict, liveDemoExpectedBlockLayer); ok {
		ar := blockR.ActionRecord
		meta := fmt.Sprintf("verdict=block · layer=%s", ar.Layer)
		if ar.Pattern != "" {
			meta += " · " + ar.Pattern
		}
		decisions = append(decisions, BundleDecision{
			Beat:     narr.blockDecision.beat,
			Class:    string(ClassPipelockDecision),
			Color:    narr.blockDecision.color,
			Verdict:  "BLOCKED",
			Pop:      true,
			Banner:   narr.blockDecision.banner,
			Target:   requestLine(ar),
			Meta:     meta,
			Signer:   bundleSignerPipelock,
			Key:      shortKey(blockR.SignerKey),
			Envelope: receiptEnvelopeLines(blockR),
		})
	}

	// --- HOST CONTAINMENT (contained runs only) ---
	if hcw != nil {
		decisions = append(decisions, BundleDecision{
			Beat:     narr.containDecision.beat,
			Class:    string(ClassHostContainment),
			Color:    narr.containDecision.color,
			Headline: narr.containDecision.headline,
			Body: fmt.Sprintf("%d direct-egress routes blocked for the contained agent; the same control target stayed reachable for the operator.",
				len(hcw.AgentProbes)),
			Meta:   "owner-match drop · enforced by the host kernel",
			Signer: bundleSignerOrch,
			Key:    shortKey(rep.OrchestratorKey),
		})
	}

	// --- COLLECTOR WITNESS ---
	decisions = append(decisions, BundleDecision{
		Beat:     narr.witnessDecision.beat,
		Class:    string(ClassCollectorWitness),
		Color:    narr.witnessDecision.color,
		Headline: fmt.Sprintf("canary observed = %d", witness.ObservedCount),
		Body:     "The lab target signs its own statement: nothing arrived over the run window.",
		Meta:     fmt.Sprintf("observations=%d · binds=%s", witness.ObservedCount, shortNonce(witness.RunNonce)),
		Signer:   bundleSignerCollector,
		Key:      shortKey(rep.CollectorKey),
	})

	return decisions
}

// receiptEnvelopeLines renders the signed receipt as indented JSON split into
// lines, matching the viewer's expandable-envelope format. This is the real
// signed artifact, not a sample — the same bytes a verifier checks.
func receiptEnvelopeLines(r receipt.Receipt) []string {
	b, _ := json.MarshalIndent(r, "", "  ")
	return strings.Split(string(b), "\n")
}

func buildVerifier(cleanDir, orchestratorPubHex string) BundleVerifier {
	return BundleVerifier{
		Status:      "verified offline against the published orchestrator key",
		Key:         orchestratorPubHex,
		Fingerprint: shortKey(orchestratorPubHex),
		Command: fmt.Sprintf("pipelock-playground-demo verify %s --orchestrator-key %s",
			cleanDir, orchestratorPubHex),
	}
}

// loadBundleArtifacts loads the collector witness (always) and, for contained
// runs, the host-containment witness. It fails closed if either required
// artifact is missing or malformed.
func loadBundleArtifacts(cleanDir string, contained bool) (Witness, *HostContainmentWitness, error) {
	witness, err := loadWitness(cleanDir)
	if err != nil {
		return Witness{}, nil, err
	}
	if !contained {
		return witness, nil, nil
	}
	hcw, err := loadHostContainmentWitness(cleanDir)
	if err != nil {
		return Witness{}, nil, err
	}
	return witness, &hcw, nil
}

func loadWitness(cleanDir string) (Witness, error) {
	data, err := os.ReadFile(filepath.Clean(filepath.Join(cleanDir, witnessFile)))
	if err != nil {
		return Witness{}, fmt.Errorf("read witness: %w", err)
	}
	var w Witness
	if err := json.Unmarshal(data, &w); err != nil {
		return Witness{}, fmt.Errorf("parse witness: %w", err)
	}
	return w, nil
}

func loadHostContainmentWitness(cleanDir string) (HostContainmentWitness, error) {
	data, err := os.ReadFile(filepath.Clean(filepath.Join(cleanDir, hostContainmentWitnessFile)))
	if err != nil {
		return HostContainmentWitness{}, fmt.Errorf("read host-containment witness: %w", err)
	}
	var hcw HostContainmentWitness
	if err := json.Unmarshal(data, &hcw); err != nil {
		return HostContainmentWitness{}, fmt.Errorf("parse host-containment witness: %w", err)
	}
	return hcw, nil
}

// shortNonce trims a run nonce for compact display while keeping it recognizable.
func shortNonce(nonce string) string {
	if len(nonce) <= 12 {
		return nonce
	}
	return nonce[:12] + "…"
}
