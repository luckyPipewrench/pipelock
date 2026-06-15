// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/internal/replaycapture"
)

// Check is one step of the verify trust chain.
type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
}

// VerifyReport is the all-or-nothing result of VerifyRun.
type VerifyReport struct {
	OK            bool    `json:"ok"`
	Checks        []Check `json:"checks"`
	ObservedCount int     `json:"observed_count"` // reported, NOT a pass/fail gate
	RunNonce      string  `json:"run_nonce"`
	CollectorKey  string  `json:"collector_key"`
	PipelockKey   string  `json:"pipelock_key"`
}

// Run directory layout (produced by the demo runner, consumed by VerifyRun):
//
//	<rundir>/
//	  packet/                # the Audit Packet dir (packet.json, evidence.jsonl, manifest.json)
//	  launch-manifest.json   # signed LaunchManifest (JSON)
//	  witness.json           # signed Witness (JSON)
const (
	packetSubdir          = "packet"
	launchManifestFile    = "launch-manifest.json"
	witnessFile           = "witness.json"
	checkManifestSig      = "launch-manifest-signature"
	checkPinnedPipelock   = "pinned-pipelock-key"
	checkAuditPacket      = "audit-packet-chain"
	checkPinnedCollector  = "pinned-collector-key"
	checkWitnessSig       = "collector-witness-signature"
	checkWitnessBinding   = "witness-binds-run"
	checkRedCaseCalibrate = "red-case-calibration"
)

// requiredChecks is the full set of check names that must all appear and pass
// for a run to be considered verified. finalize uses this to enforce that the
// entire chain ran -- a future early-return that forgets to append a Check
// cannot silently produce OK=true.
var requiredChecks = []string{
	checkManifestSig,
	checkPinnedPipelock,
	checkAuditPacket,
	checkPinnedCollector,
	checkWitnessSig,
	checkWitnessBinding,
	checkRedCaseCalibrate,
}

// VerifyRun performs the all-or-nothing offline verification of a playground
// demo run directory. The trust root is the single orchestratorPubHex key; all
// other keys (pipelock, collector) are taken from the verified manifest, NOT
// trusted blindly from the witness or packet.
//
// The five-step chain:
//  1. Verify the signed launch manifest under the orchestrator pubkey.
//  2. Verify the Audit Packet (receipt chain + totals) under the pipelock
//     pubkey that the manifest pins.
//  3. Verify the collector witness signature under the collector pubkey the
//     manifest pins.
//  4. Verify the witness binds the run (nonce + manifest hash).
//  5. Verify the red-case calibration is present and genuine.
//
// OK = logical AND of all checks. Any single failure => OK=false with a
// specific reason. Missing/malformed files fail closed (no panic).
func VerifyRun(dir, orchestratorPubHex string) (VerifyReport, error) {
	rep := VerifyReport{}
	cleanDir := filepath.Clean(dir)

	// --- Load files (fail closed on missing/malformed) ---

	lmBytes, err := os.ReadFile(filepath.Clean(filepath.Join(cleanDir, launchManifestFile)))
	if err != nil {
		rep.Checks = append(rep.Checks, Check{
			Name:   checkManifestSig,
			OK:     false,
			Reason: fmt.Sprintf("cannot read launch-manifest.json: %v", err),
		})
		return finalize(rep), nil
	}
	var lm LaunchManifest
	if err := json.Unmarshal(lmBytes, &lm); err != nil {
		rep.Checks = append(rep.Checks, Check{
			Name:   checkManifestSig,
			OK:     false,
			Reason: fmt.Sprintf("malformed launch-manifest.json: %v", err),
		})
		return finalize(rep), nil
	}

	wBytes, err := os.ReadFile(filepath.Clean(filepath.Join(cleanDir, witnessFile)))
	if err != nil {
		rep.Checks = append(rep.Checks, Check{
			Name:   checkManifestSig,
			OK:     true,
			Reason: "loaded (verification deferred to step 1)",
		}, Check{
			Name:   checkWitnessSig,
			OK:     false,
			Reason: fmt.Sprintf("cannot read witness.json: %v", err),
		})
		return finalize(rep), nil
	}
	var witness Witness
	if err := json.Unmarshal(wBytes, &witness); err != nil {
		rep.Checks = append(rep.Checks, Check{
			Name:   checkManifestSig,
			OK:     true,
			Reason: "loaded (verification deferred to step 1)",
		}, Check{
			Name:   checkWitnessSig,
			OK:     false,
			Reason: fmt.Sprintf("malformed witness.json: %v", err),
		})
		return finalize(rep), nil
	}

	// --- Step 1: Verify launch manifest signature under orchestrator key ---

	orchPub, err := hex.DecodeString(orchestratorPubHex)
	if err != nil || len(orchPub) != ed25519.PublicKeySize {
		rep.Checks = append(rep.Checks, Check{
			Name:   checkManifestSig,
			OK:     false,
			Reason: "invalid orchestrator public key",
		})
		return finalize(rep), nil
	}
	if !VerifyLaunchManifest(ed25519.PublicKey(orchPub), lm) {
		rep.Checks = append(rep.Checks, Check{
			Name:   checkManifestSig,
			OK:     false,
			Reason: "launch manifest signature invalid under orchestrator key",
		})
		return finalize(rep), nil
	}
	rep.Checks = append(rep.Checks, Check{
		Name: checkManifestSig,
		OK:   true,
	})
	rep.RunNonce = lm.RunNonce
	rep.PipelockKey = lm.PipelockPubKey
	rep.CollectorKey = lm.CollectorPubKey

	// --- Pinned pipelock key gate (before step 2) ---
	// Without this gate, an empty PipelockPubKey causes VerifyPacketDir to
	// fall back to the packet's self-declared signer key, which makes the
	// audit-packet check trust-on-first-use (fail-open). We require the
	// manifest to pin a real ed25519 public key.
	if pipeKeyBytes, pipeErr := hex.DecodeString(lm.PipelockPubKey); pipeErr != nil || len(pipeKeyBytes) != ed25519.PublicKeySize {
		rep.Checks = append(rep.Checks, Check{
			Name:   checkPinnedPipelock,
			OK:     false,
			Reason: "manifest pins no valid pipelock public key",
		})
		return finalize(rep), nil
	}
	rep.Checks = append(rep.Checks, Check{
		Name: checkPinnedPipelock,
		OK:   true,
	})

	// --- Step 2: Verify Audit Packet under the pipelock key the manifest pins ---

	packetDir := filepath.Join(cleanDir, packetSubdir)
	if err := replaycapture.VerifyPacketDir(packetDir, lm.PipelockPubKey); err != nil {
		rep.Checks = append(rep.Checks, Check{
			Name:   checkAuditPacket,
			OK:     false,
			Reason: fmt.Sprintf("audit packet verification failed: %v", err),
		})
		return finalize(rep), nil
	}
	rep.Checks = append(rep.Checks, Check{
		Name: checkAuditPacket,
		OK:   true,
	})

	// --- Pinned collector key gate (before step 3) ---
	// Belt-and-suspenders: VerifyWitness also rejects empty/short keys, but
	// an explicit gate here documents the trust-chain intent and is robust
	// to future refactoring of VerifyWitness.
	if colKeyBytes, colErr := hex.DecodeString(lm.CollectorPubKey); colErr != nil || len(colKeyBytes) != ed25519.PublicKeySize {
		rep.Checks = append(rep.Checks, Check{
			Name:   checkPinnedCollector,
			OK:     false,
			Reason: "manifest pins no valid collector public key",
		})
		return finalize(rep), nil
	}
	rep.Checks = append(rep.Checks, Check{
		Name: checkPinnedCollector,
		OK:   true,
	})

	// --- Step 3: Verify witness signature under the collector key the manifest pins ---

	if !VerifyWitness(lm.CollectorPubKey, witness) {
		rep.Checks = append(rep.Checks, Check{
			Name:   checkWitnessSig,
			OK:     false,
			Reason: "witness signature invalid under manifest's collector key",
		})
		return finalize(rep), nil
	}
	rep.Checks = append(rep.Checks, Check{
		Name: checkWitnessSig,
		OK:   true,
	})

	// --- Step 4: Verify witness binds this run (nonce + manifest hash) ---

	if !WitnessBindsRun(witness, lm.RunNonce, lm.Hash()) {
		rep.Checks = append(rep.Checks, Check{
			Name:   checkWitnessBinding,
			OK:     false,
			Reason: fmt.Sprintf("witness nonce=%q manifestHash=%q does not match manifest nonce=%q hash=%q", witness.RunNonce, witness.LaunchManifestHash, lm.RunNonce, lm.Hash()),
		})
		return finalize(rep), nil
	}
	rep.Checks = append(rep.Checks, Check{
		Name: checkWitnessBinding,
		OK:   true,
	})

	// --- Step 5: Verify red-case calibration is present and genuine ---

	rc := witness.RedCaseResult
	if rc == nil {
		rep.Checks = append(rep.Checks, Check{
			Name:   checkRedCaseCalibrate,
			OK:     false,
			Reason: "red-case result missing from witness",
		})
		return finalize(rep), nil
	}
	var redReasons []string
	if !rc.WitnessWentRed {
		redReasons = append(redReasons, "WitnessWentRed is false")
	}
	if rc.ObservedCount < 1 {
		redReasons = append(redReasons, fmt.Sprintf("ObservedCount=%d (want >= 1)", rc.ObservedCount))
	}
	if rc.CollectorPubKey != lm.CollectorPubKey {
		redReasons = append(redReasons, fmt.Sprintf("CollectorPubKey mismatch: red=%q manifest=%q", rc.CollectorPubKey, lm.CollectorPubKey))
	}
	if rc.RedWitnessDigest == "" {
		redReasons = append(redReasons, "RedWitnessDigest is empty")
	}
	if len(redReasons) > 0 {
		rep.Checks = append(rep.Checks, Check{
			Name:   checkRedCaseCalibrate,
			OK:     false,
			Reason: fmt.Sprintf("red-case check failed: %v", redReasons),
		})
		return finalize(rep), nil
	}
	rep.Checks = append(rep.Checks, Check{
		Name: checkRedCaseCalibrate,
		OK:   true,
	})

	rep.ObservedCount = witness.ObservedCount
	return finalize(rep), nil
}

// finalize computes the top-level OK. It is affirmative: OK=true requires
// that every entry in requiredChecks appeared AND none failed. An empty
// Checks slice, a missing check name, or any failed check all produce
// OK=false. This invariant means a future early-return that forgets to
// append a Check cannot silently produce OK=true.
func finalize(rep VerifyReport) VerifyReport {
	if len(rep.Checks) == 0 {
		rep.OK = false
		return rep
	}

	present := make(map[string]bool, len(rep.Checks))
	allPassed := true
	for _, c := range rep.Checks {
		present[c.Name] = true
		if !c.OK {
			allPassed = false
		}
	}

	// Every required check must be present.
	for _, name := range requiredChecks {
		if !present[name] {
			allPassed = false
			break
		}
	}

	rep.OK = allPassed
	return rep
}
