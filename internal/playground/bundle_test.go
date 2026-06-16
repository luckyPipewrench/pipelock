// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground_test

import (
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/playground"
)

// TestGenerateBundle_LiveDemo_RealData drives a real uncontained live-demo run
// and asserts the generated bundle carries the run's REAL signed proof, not
// placeholders. This is the end-to-end anchor for the generator.
func TestGenerateBundle_LiveDemo_RealData(t *testing.T) {
	if testing.Short() {
		t.Skip("builds binaries and boots a real proxy")
	}
	runDir := t.TempDir()
	rep, err := playground.RunDemo(t.Context(), io.Discard, playground.DemoOpts{
		ScenarioID: playground.LiveDemoScenarioID,
		RunDir:     runDir,
	})
	if err != nil {
		t.Fatalf("RunDemo: %v", err)
	}
	if !rep.OK {
		t.Fatalf("run did not verify: %+v", rep.Checks)
	}

	b, err := playground.GenerateBundle(runDir, rep.OrchestratorKey)
	if err != nil {
		t.Fatalf("GenerateBundle: %v", err)
	}

	if b.RunID != rep.RunNonce {
		t.Errorf("run_id=%q want %q", b.RunID, rep.RunNonce)
	}
	if b.TotalBeats != len(b.Beats) || b.TotalBeats == 0 {
		t.Errorf("totalBeats=%d beats=%d", b.TotalBeats, len(b.Beats))
	}
	// Verifier block carries the real trust-root key, not a placeholder.
	if b.Verifier.Key != rep.OrchestratorKey {
		t.Errorf("verifier key=%q want %q", b.Verifier.Key, rep.OrchestratorKey)
	}
	if strings.Contains(b.Verifier.Key, "sample") || strings.Contains(b.Verifier.Command, "./demo-run") {
		t.Errorf("verifier still looks like the placeholder sample: %+v", b.Verifier)
	}

	// Uncontained run: allow, block, collector witness; no host-containment.
	var hasAllow, hasBlock, hasWitness, hasContain bool
	for _, d := range b.Decisions {
		switch {
		case d.Verdict == "ALLOW":
			hasAllow = true
		case d.Verdict == "BLOCKED":
			hasBlock = true
			if len(d.Envelope) == 0 {
				t.Error("block decision must carry the real signed receipt envelope")
			}
		case d.Class == "collector_witness":
			hasWitness = true
		case d.Class == "host_containment":
			hasContain = true
		}
	}
	if !hasAllow || !hasBlock || !hasWitness {
		t.Errorf("missing decisions: allow=%v block=%v witness=%v", hasAllow, hasBlock, hasWitness)
	}
	if hasContain {
		t.Error("uncontained run must not emit a host-containment decision")
	}

	// Checks reflect the real verify report.
	if len(b.Checks) != len(rep.Checks) {
		t.Errorf("checks=%d want %d", len(b.Checks), len(rep.Checks))
	}
}

// TestGenerateBundle_FailsClosed_OnTamper proves the generator refuses to emit a
// bundle for a run that no longer verifies (one flipped witness byte).
func TestGenerateBundle_FailsClosed_OnTamper(t *testing.T) {
	if testing.Short() {
		t.Skip("builds binaries and boots a real proxy")
	}
	runDir := t.TempDir()
	rep, err := playground.RunDemo(t.Context(), io.Discard, playground.DemoOpts{
		ScenarioID: playground.LiveDemoScenarioID,
		RunDir:     runDir,
	})
	if err != nil || !rep.OK {
		t.Fatalf("RunDemo: err=%v ok=%v", err, rep.OK)
	}

	flipByteInFile(t, filepath.Join(runDir, "witness.json"))

	if _, err := playground.GenerateBundle(runDir, rep.OrchestratorKey); err == nil {
		t.Fatal("GenerateBundle must fail closed when the run no longer verifies")
	}
}

// TestGenerateBundle_NoNarrativeForScenario proves the generator fails closed for
// a verified run whose scenario has no authored bundle narrative.
func TestGenerateBundle_NoNarrativeForScenario(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a real packet via the capture engine")
	}
	// buildRunDir produces a verifying run for the url-blocked scenario, which
	// has no bundle narrative.
	dir, orchPubHex, _ := buildRunDir(t, false)
	_, err := playground.GenerateBundle(dir, orchPubHex)
	if err == nil || !strings.Contains(err.Error(), "no bundle narrative") {
		t.Fatalf("want no-narrative error, got %v", err)
	}
}

// TestGenerateBundle_BadOrchestratorKey fails closed on a key that cannot verify.
func TestGenerateBundle_BadOrchestratorKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Empty dir: verify fails to even load the manifest, so generation aborts.
	if _, err := playground.GenerateBundle(dir, strings.Repeat("0", 64)); err == nil {
		t.Fatal("GenerateBundle must fail closed when the run cannot be verified")
	}
}
