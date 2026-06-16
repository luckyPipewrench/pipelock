// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/playground"
	"github.com/luckyPipewrench/pipelock/internal/replaycapture"
)

// verifyCanaryValue builds the synthetic canary at runtime to satisfy gosec G101.
const verifyCanaryValue = "AKIA" + "IOSFODNN7EXAMPLE"

// testGenKey returns a fresh ed25519 keypair, failing the test on error.
func testGenKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genKey: %v", err)
	}
	return pub, priv
}

// goodRunDir constructs a fully-valid run directory end-to-end in a temp dir:
//
//  1. Generate orchestrator + collector key pairs.
//  2. Run a real in-process capture via replaycapture.NewEngine to produce
//     a genuine evidence file + pipelock pubkey.
//  3. AssembleFromEvidence into <dir>/packet.
//  4. Build + sign a LaunchManifest pinning pipelock + collector pubkeys + a run nonce.
//  5. Run red-case calibration.
//  6. Open a collector run, attach the red-case, seal + sign a witness.
//  7. Write launch-manifest.json and witness.json.
//
// Returns (dir, orchestratorPubHex).
func goodRunDir(t *testing.T) (string, string) {
	t.Helper()

	// 1. Generate keys.
	orchPub, orchPriv := testGenKey(t)
	colPub, colPriv := testGenKey(t)

	// 2. Capture real evidence via the replaycapture engine.
	engineDir := t.TempDir()
	engine, err := replaycapture.NewEngine(engineDir)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	scenarios := replaycapture.DefaultScenarios()
	var exfilScenario replaycapture.Scenario
	for _, s := range scenarios {
		if s.ID == "secret-exfil-url-blocked" {
			exfilScenario = s
			break
		}
	}
	if exfilScenario.ID == "" {
		t.Fatal("secret-exfil-url-blocked scenario not found")
	}

	captured, err := engine.Capture(exfilScenario)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}

	// 3. Assemble evidence into a packet. AssembleFromEvidence creates
	//    <outDir>/<scenarioID>/ as the packet dir. We use a staging dir and
	//    then rename it to <runDir>/packet so the run-dir layout matches
	//    VerifyRun's expectation.
	runDir := t.TempDir()
	stageDir := t.TempDir()
	generatedAt := time.Now().UTC()
	result, err := playground.AssembleFromEvidence(
		captured.EvidenceFile,
		engine.PublicKeyHex(),
		stageDir,
		generatedAt,
	)
	if err != nil {
		t.Fatalf("AssembleFromEvidence: %v", err)
	}
	// Move the actual packet dir to <runDir>/packet.
	packetDst := filepath.Join(runDir, "packet")
	if err := os.Rename(result.PacketDir, packetDst); err != nil {
		t.Fatalf("rename packet dir: %v", err)
	}

	// 4. Build + sign a LaunchManifest.
	nonce := "verify-test-nonce"
	lm := playground.LaunchManifest{
		RunNonce:        nonce,
		ScenarioID:      exfilScenario.ID,
		CanaryID:        "aws_canary",
		PipelockPubKey:  engine.PublicKeyHex(),
		CollectorPubKey: hex.EncodeToString(colPub),
		PolicyHash:      captured.PolicyHash,
		TargetHost:      "exfil.target.test",
		StartedAt:       time.Now().UTC(),
	}
	lm = playground.SignLaunchManifest(orchPriv, lm)

	// 5. Run red-case calibration.
	ctx := context.Background()
	redCase, redWitness, err := playground.RunRedCaseCalibrationWithWitness(ctx, colPriv, "aws_canary", verifyCanaryValue)
	if err != nil {
		t.Fatalf("RunRedCaseCalibration: %v", err)
	}

	// 6. Open collector run, attach red-case, seal + sign witness.
	collector := playground.NewCollector("aws_canary", verifyCanaryValue)
	if err := collector.OpenRun(nonce, lm.Hash()); err != nil {
		t.Fatalf("OpenRun: %v", err)
	}
	if err := collector.AttachRedCase(nonce, redCase); err != nil {
		t.Fatalf("AttachRedCase: %v", err)
	}

	const drainWindow = 200 * time.Millisecond
	witness, err := collector.SealAndSign(nonce, colPriv, drainWindow)
	if err != nil {
		t.Fatalf("SealAndSign: %v", err)
	}

	// 7. Write launch-manifest.json and witness.json.
	lmBytes, err := json.Marshal(lm)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "launch-manifest.json"), lmBytes, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	wBytes, err := json.Marshal(witness)
	if err != nil {
		t.Fatalf("marshal witness: %v", err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "witness.json"), wBytes, 0o600); err != nil {
		t.Fatalf("write witness: %v", err)
	}
	redBytes, err := json.Marshal(redWitness)
	if err != nil {
		t.Fatalf("marshal red witness: %v", err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "red-witness.json"), redBytes, 0o600); err != nil {
		t.Fatalf("write red witness: %v", err)
	}

	return runDir, hex.EncodeToString(orchPub)
}

// mustFailVerify builds a good run dir, applies a mutation, and asserts that
// VerifyRun returns OK==false (or an error) -- never OK==true.
func mustFailVerify(t *testing.T, mutate func(dir string)) {
	t.Helper()
	dir, orchPubHex := goodRunDir(t)
	mutate(dir)
	rep, err := playground.VerifyRun(dir, orchPubHex)
	if err != nil {
		// An error is also acceptable -- the verify failed closed.
		return
	}
	if rep.OK {
		t.Fatalf("verify must fail closed after mutation, but got OK=true: %+v", rep)
	}
}

func TestVerify_AllGood_Passes(t *testing.T) {
	t.Parallel()
	dir, orchPubHex := goodRunDir(t)
	rep, err := playground.VerifyRun(dir, orchPubHex)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		for _, c := range rep.Checks {
			if !c.OK {
				t.Logf("FAILED CHECK: %s — %s", c.Name, c.Reason)
			}
		}
		t.Fatalf("good run must pass: OK=false")
	}
	// Every check must have passed. 8 required checks in the full chain.
	const expectedChecks = 8
	if len(rep.Checks) < expectedChecks {
		t.Fatalf("expected at least %d checks, got %d", expectedChecks, len(rep.Checks))
	}
	for _, c := range rep.Checks {
		if !c.OK {
			t.Fatalf("check %q failed: %s", c.Name, c.Reason)
		}
	}
}

func TestVerify_TamperedWitnessByte_FailsClosed(t *testing.T) {
	t.Parallel()
	mustFailVerify(t, func(dir string) {
		flipByteInFile(t, filepath.Join(dir, "witness.json"), "signature")
	})
}

func TestVerify_SwappedWitnessFromOtherRun_FailsClosed(t *testing.T) {
	t.Parallel()
	mustFailVerify(t, func(dir string) {
		// Build a second, independent good run and swap its witness in.
		otherDir, _ := goodRunDir(t)
		otherWitness, err := os.ReadFile(filepath.Clean(filepath.Join(otherDir, "witness.json")))
		if err != nil {
			t.Fatalf("read other witness: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "witness.json"), otherWitness, 0o600); err != nil {
			t.Fatalf("overwrite witness: %v", err)
		}
	})
}

func TestVerify_StrippedRedCase_FailsClosed(t *testing.T) {
	t.Parallel()
	mustFailVerify(t, func(dir string) {
		// Remove the red_case_result from the witness JSON. This also
		// breaks the witness signature, which is fine -- still must fail.
		path := filepath.Clean(filepath.Join(dir, "witness.json"))
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read witness: %v", err)
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatalf("unmarshal witness: %v", err)
		}
		delete(m, "red_case_result")
		out, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("marshal witness: %v", err)
		}
		if err := os.WriteFile(path, out, 0o600); err != nil {
			t.Fatalf("write witness: %v", err)
		}
	})
}

func TestVerify_MissingRedWitnessArtifact_FailsClosed(t *testing.T) {
	t.Parallel()
	mustFailVerify(t, func(dir string) {
		if err := os.Remove(filepath.Join(dir, "red-witness.json")); err != nil {
			t.Fatalf("remove red witness: %v", err)
		}
	})
}

func TestVerify_SignedCollectorLeak_FailsClosed(t *testing.T) {
	t.Parallel()
	dir, orchPubHex := goodRunDirWithSignedCollectorLeak(t)
	rep, err := playground.VerifyRun(dir, orchPubHex)
	if err != nil {
		return
	}
	if rep.OK {
		t.Fatalf("signed collector leak must fail verification, got OK=true: %+v", rep)
	}
	found := false
	for _, c := range rep.Checks {
		if c.Name == "live-demo-semantics" && !c.OK {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected failed live-demo-semantics check, got %+v", rep.Checks)
	}
}

func TestVerify_EditedManifestNonce_FailsClosed(t *testing.T) {
	t.Parallel()
	mustFailVerify(t, func(dir string) {
		path := filepath.Clean(filepath.Join(dir, "launch-manifest.json"))
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read manifest: %v", err)
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatalf("unmarshal manifest: %v", err)
		}
		m["run_nonce"] = json.RawMessage(`"tampered-nonce"`)
		out, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("marshal manifest: %v", err)
		}
		if err := os.WriteFile(path, out, 0o600); err != nil {
			t.Fatalf("write manifest: %v", err)
		}
	})
}

func TestVerify_BrokenReceiptChain_FailsClosed(t *testing.T) {
	t.Parallel()
	mustFailVerify(t, func(dir string) {
		// Corrupt a byte in the receipt signature inside the evidence JSONL
		// to break the chain verification.
		evidencePath := findEvidenceFile(t, filepath.Join(dir, "packet"))
		flipByteInFile(t, evidencePath, "signature")
	})
}

func TestVerify_TamperedManifestSig_FailsClosed(t *testing.T) {
	t.Parallel()
	mustFailVerify(t, func(dir string) {
		flipByteInFile(t, filepath.Join(dir, "launch-manifest.json"), "signature")
	})
}

// TestVerify_EmptyPinnedPipelockKey_FailsClosed is a regression test for the
// TOFU fail-open: if the manifest pins an empty PipelockPubKey, VerifyPacketDir
// falls back to the packet's self-declared signer key, accepting any
// self-consistent self-signed packet. The fix gates on a valid pinned key
// BEFORE calling VerifyPacketDir.
func TestVerify_EmptyPinnedPipelockKey_FailsClosed(t *testing.T) {
	t.Parallel()
	empty := ""
	dir, orchPubHex := goodRunDirWithPinnedKeyOverride(t, &empty, nil)
	rep, err := playground.VerifyRun(dir, orchPubHex)
	if err != nil {
		return // error = fail closed, acceptable
	}
	if rep.OK {
		t.Fatalf("empty PipelockPubKey must fail closed, got OK=true: %+v", rep)
	}
	// Confirm the specific check that caught it.
	found := false
	for _, c := range rep.Checks {
		if c.Name == "pinned-pipelock-key" && !c.OK {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected failed pinned-pipelock-key check, got checks: %+v", rep.Checks)
	}
}

// TestVerify_EmptyPinnedCollectorKey_FailsClosed is the analogous test for an
// empty CollectorPubKey.
func TestVerify_EmptyPinnedCollectorKey_FailsClosed(t *testing.T) {
	t.Parallel()
	empty := ""
	dir, orchPubHex := goodRunDirWithPinnedKeyOverride(t, nil, &empty)
	rep, err := playground.VerifyRun(dir, orchPubHex)
	if err != nil {
		return // error = fail closed, acceptable
	}
	if rep.OK {
		t.Fatalf("empty CollectorPubKey must fail closed, got OK=true: %+v", rep)
	}
	// Confirm the specific check that caught it.
	found := false
	for _, c := range rep.Checks {
		if c.Name == "pinned-collector-key" && !c.OK {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected failed pinned-collector-key check, got checks: %+v", rep.Checks)
	}
}

// goodRunDirWithPinnedKeyOverride is like goodRunDir but allows overriding the
// PipelockPubKey and/or CollectorPubKey in the signed manifest. The manifest
// is properly re-signed by the orchestrator, so step 1 passes.
func goodRunDirWithPinnedKeyOverride(t *testing.T, pipelockKeyOverride, collectorKeyOverride *string) (string, string) {
	t.Helper()

	orchPub, orchPriv := testGenKey(t)
	colPub, colPriv := testGenKey(t)

	engineDir := t.TempDir()
	engine, err := replaycapture.NewEngine(engineDir)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	scenarios := replaycapture.DefaultScenarios()
	var exfilScenario replaycapture.Scenario
	for _, s := range scenarios {
		if s.ID == "secret-exfil-url-blocked" {
			exfilScenario = s
			break
		}
	}
	if exfilScenario.ID == "" {
		t.Fatal("secret-exfil-url-blocked scenario not found")
	}

	captured, err := engine.Capture(exfilScenario)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}

	runDir := t.TempDir()
	stageDir := t.TempDir()
	result, err := playground.AssembleFromEvidence(
		captured.EvidenceFile, engine.PublicKeyHex(), stageDir, time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("AssembleFromEvidence: %v", err)
	}
	if err := os.Rename(result.PacketDir, filepath.Join(runDir, "packet")); err != nil {
		t.Fatalf("rename: %v", err)
	}

	// Build the manifest with overridable keys.
	pipelockKey := engine.PublicKeyHex()
	if pipelockKeyOverride != nil {
		pipelockKey = *pipelockKeyOverride
	}
	collectorKey := hex.EncodeToString(colPub)
	if collectorKeyOverride != nil {
		collectorKey = *collectorKeyOverride
	}

	nonce := "verify-test-nonce"
	lm := playground.LaunchManifest{
		RunNonce:        nonce,
		ScenarioID:      exfilScenario.ID,
		CanaryID:        "aws_canary",
		PipelockPubKey:  pipelockKey,
		CollectorPubKey: collectorKey,
		PolicyHash:      captured.PolicyHash,
		TargetHost:      "exfil.target.test",
		StartedAt:       time.Now().UTC(),
	}
	lm = playground.SignLaunchManifest(orchPriv, lm)

	ctx := context.Background()
	redCase, redWitness, err := playground.RunRedCaseCalibrationWithWitness(ctx, colPriv, "aws_canary", verifyCanaryValue)
	if err != nil {
		t.Fatalf("RunRedCaseCalibration: %v", err)
	}

	collector := playground.NewCollector("aws_canary", verifyCanaryValue)
	if err := collector.OpenRun(nonce, lm.Hash()); err != nil {
		t.Fatalf("OpenRun: %v", err)
	}
	if err := collector.AttachRedCase(nonce, redCase); err != nil {
		t.Fatalf("AttachRedCase: %v", err)
	}
	witness, err := collector.SealAndSign(nonce, colPriv, 200*time.Millisecond)
	if err != nil {
		t.Fatalf("SealAndSign: %v", err)
	}

	lmBytes, err := json.Marshal(lm)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "launch-manifest.json"), lmBytes, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	wBytes, err := json.Marshal(witness)
	if err != nil {
		t.Fatalf("marshal witness: %v", err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "witness.json"), wBytes, 0o600); err != nil {
		t.Fatalf("write witness: %v", err)
	}
	redBytes, err := json.Marshal(redWitness)
	if err != nil {
		t.Fatalf("marshal red witness: %v", err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "red-witness.json"), redBytes, 0o600); err != nil {
		t.Fatalf("write red witness: %v", err)
	}

	return runDir, hex.EncodeToString(orchPub)
}

func goodRunDirWithSignedCollectorLeak(t *testing.T) (string, string) {
	t.Helper()

	orchPub, orchPriv := testGenKey(t)
	colPub, colPriv := testGenKey(t)

	engineDir := t.TempDir()
	engine, err := replaycapture.NewEngine(engineDir)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	var exfilScenario replaycapture.Scenario
	for _, s := range replaycapture.DefaultScenarios() {
		if s.ID == "secret-exfil-url-blocked" {
			exfilScenario = s
			break
		}
	}
	if exfilScenario.ID == "" {
		t.Fatal("secret-exfil-url-blocked scenario not found")
	}

	captured, err := engine.Capture(exfilScenario)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}

	runDir := t.TempDir()
	stageDir := t.TempDir()
	result, err := playground.AssembleFromEvidence(
		captured.EvidenceFile,
		engine.PublicKeyHex(),
		stageDir,
		time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("AssembleFromEvidence: %v", err)
	}
	if err := os.Rename(result.PacketDir, filepath.Join(runDir, "packet")); err != nil {
		t.Fatalf("rename packet dir: %v", err)
	}

	nonce := "verify-test-nonce"
	lm := playground.LaunchManifest{
		RunNonce:        nonce,
		ScenarioID:      exfilScenario.ID,
		CanaryID:        "aws_canary",
		PipelockPubKey:  engine.PublicKeyHex(),
		CollectorPubKey: hex.EncodeToString(colPub),
		PolicyHash:      captured.PolicyHash,
		TargetHost:      "exfil.target.test",
		StartedAt:       time.Now().UTC(),
	}
	lm = playground.SignLaunchManifest(orchPriv, lm)

	redCase, redWitness, err := playground.RunRedCaseCalibrationWithWitness(t.Context(), colPriv, lm.CanaryID, verifyCanaryValue)
	if err != nil {
		t.Fatalf("RunRedCaseCalibrationWithWitness: %v", err)
	}

	collector := playground.NewCollector(lm.CanaryID, verifyCanaryValue)
	if err := collector.OpenRun(lm.RunNonce, lm.Hash()); err != nil {
		t.Fatalf("OpenRun: %v", err)
	}
	if err := collector.AttachRedCase(lm.RunNonce, redCase); err != nil {
		t.Fatalf("AttachRedCase: %v", err)
	}

	srv := httptest.NewServer(collector.Handler())
	defer srv.Close()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/?run="+lm.RunNonce, strings.NewReader("field="+verifyCanaryValue))
	if err != nil {
		t.Fatalf("build leak request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post leak to collector: %v", err)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		_ = resp.Body.Close()
		t.Fatalf("post leak to collector returned HTTP %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	witness, err := collector.SealAndSign(lm.RunNonce, colPriv, 200*time.Millisecond)
	if err != nil {
		t.Fatalf("SealAndSign: %v", err)
	}

	lmBytes, err := json.Marshal(lm)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "launch-manifest.json"), lmBytes, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	wBytes, err := json.Marshal(witness)
	if err != nil {
		t.Fatalf("marshal witness: %v", err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "witness.json"), wBytes, 0o600); err != nil {
		t.Fatalf("write witness: %v", err)
	}
	redBytes, err := json.Marshal(redWitness)
	if err != nil {
		t.Fatalf("marshal red witness: %v", err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "red-witness.json"), redBytes, 0o600); err != nil {
		t.Fatalf("write red witness: %v", err)
	}

	return runDir, hex.EncodeToString(orchPub)
}

// --- helpers ---

// flipByteInFile reads a JSON file, finds the first occurrence of fieldHint in
// the raw bytes, and flips a byte near it to corrupt the data.
func flipByteInFile(t *testing.T, path, fieldHint string) {
	t.Helper()
	cleanPath := filepath.Clean(path)
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		t.Fatalf("flipByteInFile read %s: %v", path, err)
	}
	// Find the field hint in the raw JSON bytes.
	needle := []byte(`"` + fieldHint + `":"`)
	idx := bytesIndex(data, needle)
	if idx < 0 {
		// Try with a space after the colon.
		needle = []byte(`"` + fieldHint + `": "`)
		idx = bytesIndex(data, needle)
	}
	if idx < 0 {
		t.Fatalf("flipByteInFile: field %q not found in %s", fieldHint, path)
	}
	// Flip a byte in the VALUE (past the opening quote of the value).
	target := idx + len(needle) + 2
	if target >= len(data) {
		target = idx + len(needle)
	}
	data[target] ^= 0x01
	if err := os.WriteFile(cleanPath, data, 0o600); err != nil {
		t.Fatalf("flipByteInFile write %s: %v", cleanPath, err)
	}
}

// bytesIndex returns the index of needle in data, or -1 if not found.
func bytesIndex(data, needle []byte) int {
	for i := 0; i <= len(data)-len(needle); i++ {
		match := true
		for j := range needle {
			if data[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// findEvidenceFile locates the evidence JSONL inside a packet dir.
func findEvidenceFile(t *testing.T, packetDir string) string {
	t.Helper()
	path := filepath.Join(packetDir, "evidence.jsonl")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("evidence file not found: %v", err)
	}
	return path
}
