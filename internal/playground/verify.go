// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
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
	// OrchestratorKey is the trust-root key the run was verified against. It is
	// the key callers must pass to `verify --orchestrator-key`; it is NOT the
	// Pipelock or collector key. Echoed from the VerifyRun argument so the
	// report (and any printed verify command) carries the correct key.
	OrchestratorKey string `json:"orchestrator_key"`
}

// Run directory layout (produced by the demo runner, consumed by VerifyRun):
//
//	<rundir>/
//	  packet/                # the Audit Packet dir (packet.json, evidence.jsonl, manifest.json)
//	  launch-manifest.json   # signed LaunchManifest (JSON)
//	  witness.json           # signed Witness (JSON)
const (
	packetSubdir               = "packet"
	launchManifestFile         = "launch-manifest.json"
	witnessFile                = "witness.json"
	redWitnessFile             = "red-witness.json"
	hostContainmentWitnessFile = "host-containment-witness.json"
	verifyInstructionsFile     = "VERIFY.txt"
	checkManifestSig           = "launch-manifest-signature"
	checkPinnedPipelock        = "pinned-pipelock-key"
	checkAuditPacket           = "audit-packet-chain"
	checkPinnedCollector       = "pinned-collector-key"
	checkWitnessSig            = "collector-witness-signature"
	checkWitnessBinding        = "witness-binds-run"
	checkRedCaseCalibrate      = "red-case-calibration"
	checkLiveSemantics         = "live-demo-semantics"
	checkHostContainSig        = "host-containment-witness-signature"
	checkHostContainBinding    = "host-containment-binds-run"
	checkHostContainEnforced   = "host-containment-enforced"

	maxBundleMembers       = 64
	maxBundleMemberBytes   = 16 << 20
	maxBundleExpandedBytes = 32 << 20
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
	checkLiveSemantics,
}

// containmentChecks are the additional checks required when the signed manifest
// declares Contained=true. They are appended to requiredChecks for contained
// runs so a contained run cannot be verified without a valid, run-bound,
// enforced host-containment witness.
var containmentChecks = []string{
	checkHostContainSig,
	checkHostContainBinding,
	checkHostContainEnforced,
}

// RunArtifacts is the in-memory form of a sealed playground run. It mirrors the
// files inside a run directory and inside the downloadable tar.gz bundle.
type RunArtifacts struct {
	LaunchManifest         []byte
	Witness                []byte
	RedWitness             []byte
	HostContainmentWitness []byte
	PacketJSON             []byte
	PacketEvidenceJSONL    []byte
	PacketManifestJSON     []byte
}

// VerifyPublishedBundleBytes verifies the raw playground bundle served by
// /api/live/bundle (os="") against the compiled published orchestrator key. It
// never accepts a trust root from the bundle itself.
func VerifyPublishedBundleBytes(bundle []byte) (VerifyReport, error) {
	artifacts, err := ExtractRunArtifactsFromBundle(bundle)
	if err != nil {
		rep := VerifyReport{OrchestratorKey: PublishedOrchestratorPubKeyHex}
		rep.Checks = append(rep.Checks, Check{
			Name:   checkManifestSig,
			OK:     false,
			Reason: fmt.Sprintf("cannot read session bundle: %v", err),
		})
		return finalize(rep, requiredChecks), nil
	}
	return VerifyRunArtifacts(artifacts, PublishedOrchestratorPubKeyHex)
}

// ExtractRunArtifactsFromBundle unpacks the deterministic downloadable
// playground tar.gz into the same in-memory artifact struct VerifyRunArtifacts
// consumes. Only the documented files under pipelock-session/ are retained.
func ExtractRunArtifactsFromBundle(bundle []byte) (RunArtifacts, error) {
	gr, err := gzip.NewReader(bytes.NewReader(bundle))
	if err != nil {
		return RunArtifacts{}, fmt.Errorf("read gzip: %w", err)
	}
	defer func() { _ = gr.Close() }()

	var artifacts RunArtifacts
	seen := make(map[string]bool, len(archiveArtifacts))
	expanded := &io.LimitedReader{R: gr, N: maxBundleExpandedBytes + 1}
	tr := tar.NewReader(expanded)
	members := 0
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return RunArtifacts{}, fmt.Errorf("read tar: %w", err)
		}
		members++
		if members > maxBundleMembers {
			return RunArtifacts{}, fmt.Errorf("bundle has too many members")
		}
		if expanded.N <= 0 {
			return RunArtifacts{}, fmt.Errorf("bundle expanded size exceeds %d bytes", maxBundleExpandedBytes)
		}
		name, retain, err := bundleArtifactName(hdr.Name, hdr.Typeflag)
		if err != nil {
			return RunArtifacts{}, err
		}
		if !retain {
			continue
		}
		if seen[name] {
			return RunArtifacts{}, fmt.Errorf("duplicate bundle artifact %s", name)
		}
		seen[name] = true
		if hdr.Size < 0 || hdr.Size > maxBundleMemberBytes {
			return RunArtifacts{}, fmt.Errorf("bundle artifact %s is too large", name)
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxBundleMemberBytes+1))
		if err != nil {
			return RunArtifacts{}, fmt.Errorf("read bundle file %s: %w", name, err)
		}
		if len(data) > maxBundleMemberBytes {
			return RunArtifacts{}, fmt.Errorf("bundle artifact %s is too large", name)
		}
		switch name {
		case launchManifestFile:
			artifacts.LaunchManifest = data
		case witnessFile:
			artifacts.Witness = data
		case redWitnessFile:
			artifacts.RedWitness = data
		case hostContainmentWitnessFile:
			artifacts.HostContainmentWitness = data
		case filepath.ToSlash(filepath.Join(packetSubdir, packetJSONFile)):
			artifacts.PacketJSON = data
		case filepath.ToSlash(filepath.Join(packetSubdir, packetEvidenceFile)):
			artifacts.PacketEvidenceJSONL = data
		case filepath.ToSlash(filepath.Join(packetSubdir, packetManifestFile)):
			artifacts.PacketManifestJSON = data
		}
	}
	return artifacts, nil
}

func bundleArtifactName(raw string, typeflag byte) (name string, retain bool, err error) {
	clean, err := cleanBundleMemberName(raw)
	if err != nil {
		return "", false, err
	}
	if typeflag != tar.TypeReg {
		return "", false, nil
	}
	name, ok := strings.CutPrefix(clean, downloadArchivePrefix+"/")
	if !ok {
		return "", false, fmt.Errorf("unexpected bundle member %s", raw)
	}
	switch name {
	case verifyInstructionsFile:
		return name, false, nil
	case launchManifestFile,
		witnessFile,
		redWitnessFile,
		hostContainmentWitnessFile,
		path.Join(packetSubdir, packetJSONFile),
		path.Join(packetSubdir, packetEvidenceFile),
		path.Join(packetSubdir, packetManifestFile):
		return name, true, nil
	default:
		return "", false, fmt.Errorf("unexpected bundle artifact %s", name)
	}
}

func cleanBundleMemberName(raw string) (string, error) {
	if raw == "" || strings.Contains(raw, "\x00") || strings.Contains(raw, "\\") || strings.HasPrefix(raw, "/") {
		return "", fmt.Errorf("unsafe bundle member name %q", raw)
	}
	name := filepath.ToSlash(raw)
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("unsafe bundle member name %q", raw)
		}
	}
	if clean := path.Clean(name); clean != name {
		return "", fmt.Errorf("unsafe bundle member name %q", raw)
	}
	return name, nil
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
	cleanDir := filepath.Clean(dir)
	var artifacts RunArtifacts
	var err error
	if artifacts.LaunchManifest, err = readRunArtifact(cleanDir, launchManifestFile); err != nil {
		return VerifyReport{OrchestratorKey: orchestratorPubHex}, err
	}
	if artifacts.Witness, err = readRunArtifact(cleanDir, witnessFile); err != nil {
		return VerifyReport{OrchestratorKey: orchestratorPubHex}, err
	}
	if artifacts.RedWitness, err = readRunArtifact(cleanDir, redWitnessFile); err != nil {
		return VerifyReport{OrchestratorKey: orchestratorPubHex}, err
	}
	if artifacts.HostContainmentWitness, err = readRunArtifact(cleanDir, hostContainmentWitnessFile); err != nil {
		return VerifyReport{OrchestratorKey: orchestratorPubHex}, err
	}
	if artifacts.PacketJSON, err = readRunArtifact(cleanDir, filepath.Join(packetSubdir, packetJSONFile)); err != nil {
		return VerifyReport{OrchestratorKey: orchestratorPubHex}, err
	}
	if artifacts.PacketEvidenceJSONL, err = readRunArtifact(cleanDir, filepath.Join(packetSubdir, packetEvidenceFile)); err != nil {
		return VerifyReport{OrchestratorKey: orchestratorPubHex}, err
	}
	if artifacts.PacketManifestJSON, err = readRunArtifact(cleanDir, filepath.Join(packetSubdir, packetManifestFile)); err != nil {
		return VerifyReport{OrchestratorKey: orchestratorPubHex}, err
	}
	return VerifyRunArtifacts(artifacts, orchestratorPubHex)
}

func readRunArtifact(cleanDir, name string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Clean(filepath.Join(cleanDir, name)))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("cannot read %s: %w", name, err)
	}
	return data, nil
}

// VerifyRunArtifacts performs the all-or-nothing offline verification of a
// playground demo run from in-memory bytes. This is the shared verifier used by
// the browser/WASM path.
func VerifyRunArtifacts(artifacts RunArtifacts, orchestratorPubHex string) (VerifyReport, error) {
	rep := VerifyReport{OrchestratorKey: orchestratorPubHex}

	// required is the base check set until the manifest reveals whether this was
	// a contained run, at which point the containment checks are appended.
	required := requiredChecks

	// --- Load files (fail closed on missing/malformed) ---

	if len(artifacts.LaunchManifest) == 0 {
		rep.Checks = append(rep.Checks, Check{
			Name:   checkManifestSig,
			OK:     false,
			Reason: "missing launch-manifest.json",
		})
		return finalize(rep, required), nil
	}
	var lm LaunchManifest
	if err := unmarshalStrictArtifact(launchManifestFile, artifacts.LaunchManifest, &lm); err != nil {
		rep.Checks = append(rep.Checks, Check{
			Name:   checkManifestSig,
			OK:     false,
			Reason: fmt.Sprintf("malformed launch-manifest.json: %v", err),
		})
		return finalize(rep, required), nil
	}
	// A contained run additionally requires the host-containment checks. The
	// flag is read from the (not-yet-signature-verified) manifest, but it is
	// covered by the manifest signature: any tamper -- flipping Contained to
	// false to skip the checks, or to true on an uncontained run -- breaks the
	// signature and fails step 1 below, so this can only fail closed.
	if lm.Contained {
		required = append(append([]string{}, requiredChecks...), containmentChecks...)
	}

	if len(artifacts.Witness) == 0 {
		rep.Checks = append(rep.Checks, Check{
			Name:   checkWitnessSig,
			OK:     false,
			Reason: "missing witness.json",
		})
		return finalize(rep, required), nil
	}
	var witness Witness
	if err := unmarshalStrictArtifact(witnessFile, artifacts.Witness, &witness); err != nil {
		rep.Checks = append(rep.Checks, Check{
			Name:   checkWitnessSig,
			OK:     false,
			Reason: fmt.Sprintf("malformed witness.json: %v", err),
		})
		return finalize(rep, required), nil
	}

	// --- Step 1: Verify launch manifest signature under orchestrator key ---

	orchPub, err := hex.DecodeString(orchestratorPubHex)
	if err != nil || len(orchPub) != ed25519.PublicKeySize {
		rep.Checks = append(rep.Checks, Check{
			Name:   checkManifestSig,
			OK:     false,
			Reason: "invalid orchestrator public key",
		})
		return finalize(rep, required), nil
	}
	if !VerifyLaunchManifest(ed25519.PublicKey(orchPub), lm) {
		rep.Checks = append(rep.Checks, Check{
			Name:   checkManifestSig,
			OK:     false,
			Reason: "launch manifest signature invalid under orchestrator key",
		})
		return finalize(rep, required), nil
	}
	rep.Checks = append(rep.Checks, Check{
		Name: checkManifestSig,
		OK:   true,
	})
	rep.RunNonce = lm.RunNonce
	rep.PipelockKey = lm.PipelockPubKey
	rep.CollectorKey = lm.CollectorPubKey

	// --- Pinned pipelock key gate (before step 2) ---
	// Without this gate, an empty PipelockPubKey causes packet verification to
	// fall back to the packet's self-declared signer key, which makes the
	// audit-packet check trust-on-first-use (fail-open). We require the
	// manifest to pin a real ed25519 public key.
	if pipeKeyBytes, pipeErr := hex.DecodeString(lm.PipelockPubKey); pipeErr != nil || len(pipeKeyBytes) != ed25519.PublicKeySize {
		rep.Checks = append(rep.Checks, Check{
			Name:   checkPinnedPipelock,
			OK:     false,
			Reason: "manifest pins no valid pipelock public key",
		})
		return finalize(rep, required), nil
	}
	rep.Checks = append(rep.Checks, Check{
		Name: checkPinnedPipelock,
		OK:   true,
	})

	// --- Step 2: Verify Audit Packet under the pipelock key the manifest pins ---

	if err := replaycapture.VerifyPacketBytes(artifacts.PacketJSON, artifacts.PacketEvidenceJSONL, lm.PipelockPubKey); err != nil {
		rep.Checks = append(rep.Checks, Check{
			Name:   checkAuditPacket,
			OK:     false,
			Reason: fmt.Sprintf("audit packet verification failed: %v", err),
		})
		return finalize(rep, required), nil
	}
	rep.Checks = append(rep.Checks, Check{
		Name: checkAuditPacket,
		OK:   true,
	})

	// --- Pinned collector key gate (before witness verification) ---
	// Belt-and-suspenders: VerifyWitness also rejects empty/short keys, but
	// an explicit gate here documents the trust-chain intent and is robust
	// to future refactoring of VerifyWitness.
	if colKeyBytes, colErr := hex.DecodeString(lm.CollectorPubKey); colErr != nil || len(colKeyBytes) != ed25519.PublicKeySize {
		rep.Checks = append(rep.Checks, Check{
			Name:   checkPinnedCollector,
			OK:     false,
			Reason: "manifest pins no valid collector public key",
		})
		return finalize(rep, required), nil
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
		return finalize(rep, required), nil
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
		return finalize(rep, required), nil
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
		return finalize(rep, required), nil
	}
	redWitness, redReasons := verifyRedWitnessArtifactBytes(artifacts.RedWitness, lm, rc)
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
	if redWitness.CanaryID != "" && redWitness.CanaryID != lm.CanaryID {
		redReasons = append(redReasons, fmt.Sprintf("red witness canary_id=%q manifest=%q", redWitness.CanaryID, lm.CanaryID))
	}
	if len(redReasons) > 0 {
		rep.Checks = append(rep.Checks, Check{
			Name:   checkRedCaseCalibrate,
			OK:     false,
			Reason: fmt.Sprintf("red-case check failed: %v", redReasons),
		})
		return finalize(rep, required), nil
	}
	rep.Checks = append(rep.Checks, Check{
		Name: checkRedCaseCalibrate,
		OK:   true,
	})

	// --- Step 6: Verify the signed artifacts prove the live demo semantics ---

	if err := verifyLiveDemoSemanticsBytes(artifacts.PacketManifestJSON, artifacts.PacketEvidenceJSONL, lm, witness); err != nil {
		rep.Checks = append(rep.Checks, Check{
			Name:   checkLiveSemantics,
			OK:     false,
			Reason: err.Error(),
		})
		return finalize(rep, required), nil
	}
	rep.Checks = append(rep.Checks, Check{
		Name: checkLiveSemantics,
		OK:   true,
	})

	// --- Step 7: Host-containment witness (contained runs only) ---
	// Split-proof: the steps above prove the proxy's mediated allow/block
	// decision; this proves the kernel owner-match drop from the contained
	// network position. Required only when the signed manifest says Contained.
	if lm.Contained {
		verifyHostContainmentBytes(artifacts.HostContainmentWitness, lm, orchestratorPubHex, &rep)
	}

	rep.ObservedCount = witness.ObservedCount
	return finalize(rep, required), nil
}

func verifyHostContainmentBytes(data []byte, lm LaunchManifest, orchestratorPubHex string, rep *VerifyReport) {
	if len(data) == 0 {
		rep.Checks = append(rep.Checks, Check{
			Name:   checkHostContainSig,
			OK:     false,
			Reason: fmt.Sprintf("missing %s", hostContainmentWitnessFile),
		})
		return
	}
	verifyHostContainmentData(data, lm, orchestratorPubHex, rep)
}

func verifyHostContainmentData(data []byte, lm LaunchManifest, orchestratorPubHex string, rep *VerifyReport) {
	var hcw HostContainmentWitness
	if err := unmarshalStrictArtifact(hostContainmentWitnessFile, data, &hcw); err != nil {
		rep.Checks = append(rep.Checks, Check{
			Name:   checkHostContainSig,
			OK:     false,
			Reason: fmt.Sprintf("malformed %s: %v", hostContainmentWitnessFile, err),
		})
		return
	}

	// Signature under the orchestrator key (the run's trust root).
	if !VerifyHostContainmentWitness(orchestratorPubHex, hcw) {
		rep.Checks = append(rep.Checks, Check{
			Name:   checkHostContainSig,
			OK:     false,
			Reason: "host-containment witness signature invalid under orchestrator key",
		})
		return
	}
	rep.Checks = append(rep.Checks, Check{Name: checkHostContainSig, OK: true})

	// Binding to this exact run (nonce + manifest hash) -- non-replayable.
	if !HostContainmentBindsRun(hcw, lm.RunNonce, lm.Hash()) {
		rep.Checks = append(rep.Checks, Check{
			Name:   checkHostContainBinding,
			OK:     false,
			Reason: fmt.Sprintf("witness nonce=%q manifestHash=%q does not match manifest nonce=%q hash=%q", hcw.RunNonce, hcw.LaunchManifestHash, lm.RunNonce, lm.Hash()),
		})
		return
	}
	rep.Checks = append(rep.Checks, Check{Name: checkHostContainBinding, OK: true})

	// Enforcement: the differential holds (operator reaches the control target,
	// the contained agent does not) AND every contained-agent probe was blocked.
	if !hcw.Enforced() {
		rep.Checks = append(rep.Checks, Check{
			Name:   checkHostContainEnforced,
			OK:     false,
			Reason: hostContainmentEnforcedReason(hcw),
		})
		return
	}
	rep.Checks = append(rep.Checks, Check{Name: checkHostContainEnforced, OK: true})
}

func hostContainmentEnforcedReason(hcw HostContainmentWitness) string {
	if hcw.ProxyTarget == "" || hcw.ProxyAgentProbe.Target == "" {
		return "host-containment witness uses an older format without proxy-contract proof; regenerate the bundle with this release"
	}
	if len(hcw.LocalAgentProbes) == 0 {
		return "host-containment witness uses an older format without local escape probes; regenerate the bundle with this release"
	}
	return "host-containment not proven: differential failed, proxy contract missing/substituted, target suite missing/substituted, local escape suite missing/substituted, or a contained-agent route/surface was open"
}

func verifyRedWitnessArtifactBytes(data []byte, lm LaunchManifest, rc *RedCaseResult) (Witness, []string) {
	if len(data) == 0 {
		return Witness{}, []string{fmt.Sprintf("missing %s", redWitnessFile)}
	}
	return verifyRedWitnessArtifactData(data, lm, rc, nil)
}

func verifyRedWitnessArtifactData(data []byte, lm LaunchManifest, rc *RedCaseResult, reasons []string) (Witness, []string) {
	var red Witness
	if err := unmarshalStrictArtifact(redWitnessFile, data, &red); err != nil {
		return Witness{}, []string{fmt.Sprintf("malformed %s: %v", redWitnessFile, err)}
	}
	if !VerifyWitness(lm.CollectorPubKey, red) {
		reasons = append(reasons, "red witness signature invalid under manifest's collector key")
	}
	if red.ObservedCount < 1 {
		reasons = append(reasons, fmt.Sprintf("red witness ObservedCount=%d (want >= 1)", red.ObservedCount))
	}
	if red.RunNonce != calibrationNoncePrefix+lm.CanaryID {
		reasons = append(reasons, fmt.Sprintf("red witness nonce=%q (want %q)", red.RunNonce, calibrationNoncePrefix+lm.CanaryID))
	}
	sum := sha256.Sum256(red.SignedBytes())
	if got := hex.EncodeToString(sum[:]); got != rc.RedWitnessDigest {
		reasons = append(reasons, fmt.Sprintf("red witness digest=%q summary=%q", got, rc.RedWitnessDigest))
	}
	if red.RedCaseResult != nil {
		reasons = append(reasons, "red witness must not recursively carry a red-case result")
	}
	return red, reasons
}

func verifyLiveDemoSemanticsBytes(manifestJSON, evidenceJSONL []byte, lm LaunchManifest, witness Witness) error {
	if len(manifestJSON) == 0 {
		return fmt.Errorf("missing packet manifest")
	}
	var replayManifest replaycapture.Manifest
	if err := unmarshalStrictArtifact(packetManifestFile, manifestJSON, &replayManifest); err != nil {
		return fmt.Errorf("malformed packet manifest: %w", err)
	}
	if err := verifyLiveDemoManifest(replayManifest, lm); err != nil {
		return err
	}

	receipts, err := receipt.ExtractReceiptsBytes(evidenceJSONL)
	if err != nil {
		return fmt.Errorf("extract packet receipts for semantic check: %w", err)
	}
	return verifyLiveDemoReceipts(receipts, lm, witness)
}

func verifyLiveDemoManifest(replayManifest replaycapture.Manifest, lm LaunchManifest) error {
	if replayManifest.ScenarioID != lm.ScenarioID {
		return fmt.Errorf("packet scenario_id=%q does not match launch manifest scenario_id=%q", replayManifest.ScenarioID, lm.ScenarioID)
	}
	if replayManifest.PolicyHash != lm.PolicyHash {
		return fmt.Errorf("packet policy_hash=%q does not match launch manifest policy_hash=%q", replayManifest.PolicyHash, lm.PolicyHash)
	}
	return nil
}

func verifyLiveDemoReceipts(receipts []receipt.Receipt, lm LaunchManifest, witness Witness) error {
	decisionReceipts := liveDemoDecisionReceipts(receipts)
	// A real model-backed run does not reproduce the scripted safe-GET + body_dlp
	// beats, so it verifies under the honest model-mode predicate instead of the
	// strict deterministic one. AgentKind is covered by the manifest signature, so
	// it cannot be flipped to dodge the stricter check.
	if lm.AgentKind == AgentKindModel {
		if lm.ScenarioID != LiveDemoScenarioID {
			return fmt.Errorf("unsupported model-mode scenario %q", lm.ScenarioID)
		}
		return verifyModelLiveContained(decisionReceipts, witness)
	}

	switch lm.ScenarioID {
	case LiveDemoScenarioID:
		return verifyBodyExfilLiveDemo(decisionReceipts, witness)
	case "secret-exfil-url-blocked":
		return verifyURLExfilReplayCompatible(decisionReceipts, witness)
	default:
		return fmt.Errorf("unsupported playground verify scenario %q", lm.ScenarioID)
	}
}

func liveDemoDecisionReceipts(receipts []receipt.Receipt) []receipt.Receipt {
	out := make([]receipt.Receipt, 0, len(receipts))
	for _, r := range receipts {
		if r.ActionRecord.SessionControl != nil {
			continue
		}
		out = append(out, r)
	}
	return out
}

// verifyModelLiveContained is the honest predicate for a real model-backed run.
// A free, uninstructed model does not reliably reproduce the scripted safe-GET +
// body_dlp beats, so this deliberately does NOT claim "the secret was caught in a
// scan". The model bundle attests only what signed artifacts independently prove:
// nothing reached the collector, and the firewall produced a signed decision
// trail. Containment itself (the agent could reach only the proxy) is proven
// separately by the host-containment checks, which are required for a contained
// run. Each of those facts rides on a signature that binds this run, so none is
// gameable; the claim is intentionally narrower than the deterministic one.
func verifyModelLiveContained(receipts []receipt.Receipt, witness Witness) error {
	if witness.ObservedCount != 0 || witness.TotalCount != 0 {
		return fmt.Errorf("collector observed=%d total=%d; a clean live run must not reach the collector", witness.ObservedCount, witness.TotalCount)
	}
	if len(receipts) == 0 {
		return fmt.Errorf("no signed decision receipts in the run; nothing to attest")
	}
	return nil
}

func verifyBodyExfilLiveDemo(receipts []receipt.Receipt, witness Witness) error {
	if witness.ObservedCount != 0 || witness.TotalCount != 0 {
		return fmt.Errorf("collector observed=%d total=%d; blocked live exfil must not reach the collector", witness.ObservedCount, witness.TotalCount)
	}

	hasAllow := false
	hasBodyBlock := false
	for _, r := range receipts {
		ar := r.ActionRecord
		verdict := receipt.NormalizeVerdict(ar.Verdict)
		if verdict == liveDemoAllowedVerdict {
			hasAllow = true
		}
		if verdict == liveDemoExpectedVerdict && ar.Layer == liveDemoExpectedBlockLayer {
			hasBodyBlock = true
		}
	}
	var missing []string
	if !hasAllow {
		missing = append(missing, "allow receipt")
	}
	if !hasBodyBlock {
		missing = append(missing, "body_dlp block receipt")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required live-demo receipt semantics: %s", strings.Join(missing, ", "))
	}
	return nil
}

func verifyURLExfilReplayCompatible(receipts []receipt.Receipt, witness Witness) error {
	if witness.ObservedCount != 0 {
		return fmt.Errorf("collector observed=%d; blocked exfil must observe 0", witness.ObservedCount)
	}
	for _, r := range receipts {
		ar := r.ActionRecord
		if receipt.NormalizeVerdict(ar.Verdict) == liveDemoExpectedVerdict && ar.Layer == "core_dlp" {
			return nil
		}
	}
	return fmt.Errorf("missing core_dlp block receipt")
}

// finalize computes the top-level OK. It is affirmative: OK=true requires
// that every entry in required appeared AND none failed. An empty Checks slice,
// a missing check name, or any failed check all produce OK=false. This
// invariant means a future early-return that forgets to append a Check cannot
// silently produce OK=true. The required set is computed by VerifyRun and
// includes the containment checks for contained runs.
func finalize(rep VerifyReport, required []string) VerifyReport {
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
	for _, name := range required {
		if !present[name] {
			allPassed = false
			break
		}
	}

	rep.OK = allPassed
	return rep
}
