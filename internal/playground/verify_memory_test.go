// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/playground"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/replaycapture"
	auditpacket "github.com/luckyPipewrench/pipelock/sdk/audit-packet"
)

func TestVerifyRunArtifacts_InMemory(t *testing.T) {
	t.Parallel()
	fixture := newVerifyMemoryFixture(t)

	tests := []struct {
		name      string
		artifacts playground.RunArtifacts
		key       string
		wantOK    bool
	}{
		{
			name:      "valid bundle artifacts",
			artifacts: fixture.artifacts,
			key:       fixture.orchestratorPubHex,
			wantOK:    true,
		},
		{
			name:      "wrong orchestrator key fails closed",
			artifacts: fixture.artifacts,
			key:       strings.Repeat("00", ed25519.PublicKeySize),
			wantOK:    false,
		},
		{
			name:      "missing orchestrator key fails closed",
			artifacts: fixture.artifacts,
			key:       "",
			wantOK:    false,
		},
		{
			name:      "corrupt one witness byte fails closed",
			artifacts: corruptWitnessByte(fixture.artifacts),
			key:       fixture.orchestratorPubHex,
			wantOK:    false,
		},
		{
			name:      "missing pinned pipelock key fails closed",
			artifacts: fixtureWithMissingPipelockKey(t, fixture),
			key:       fixture.orchestratorPubHex,
			wantOK:    false,
		},
		{
			name:      "packet evidence path mismatch fails closed",
			artifacts: fixtureWithPacketEvidencePath(t, fixture, "other-evidence.jsonl"),
			key:       fixture.orchestratorPubHex,
			wantOK:    false,
		},
		{
			name: "truncated manifest fails closed",
			artifacts: playground.RunArtifacts{
				LaunchManifest: []byte(`{"run_nonce"`),
			},
			key:    fixture.orchestratorPubHex,
			wantOK: false,
		},
		{
			name:      "garbage input fails closed",
			artifacts: playground.RunArtifacts{LaunchManifest: []byte("not json")},
			key:       fixture.orchestratorPubHex,
			wantOK:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rep, err := playground.VerifyRunArtifacts(tc.artifacts, tc.key)
			if err != nil {
				t.Fatalf("VerifyRunArtifacts returned unexpected error: %v", err)
			}
			if rep.OK != tc.wantOK {
				t.Fatalf("OK = %t, want %t; checks=%+v", rep.OK, tc.wantOK, rep.Checks)
			}
		})
	}
}

func TestExtractRunArtifactsFromBundle_InMemory(t *testing.T) {
	t.Parallel()
	fixture := newVerifyMemoryFixture(t)
	runDir := writeRunArtifactsFromMemory(t, fixture.artifacts)
	bundle, err := playground.ArchiveRunForDownload(runDir, fixture.orchestratorPubHex)
	if err != nil {
		t.Fatalf("ArchiveRunForDownload: %v", err)
	}
	artifacts, err := playground.ExtractRunArtifactsFromBundle(bundle)
	if err != nil {
		t.Fatalf("ExtractRunArtifactsFromBundle: %v", err)
	}
	rep, err := playground.VerifyRunArtifacts(artifacts, fixture.orchestratorPubHex)
	if err != nil {
		t.Fatalf("VerifyRunArtifacts: %v", err)
	}
	if !rep.OK {
		t.Fatalf("bundle artifacts did not verify: %+v", rep.Checks)
	}
}

func TestVerifyPublishedBundleBytes_RejectsUnpublishedSigner(t *testing.T) {
	t.Parallel()

	bundle, _ := realBundleForMemoryVerify(t)
	rep, err := playground.VerifyPublishedBundleBytes(bundle)
	if err != nil {
		t.Fatalf("VerifyPublishedBundleBytes: %v", err)
	}
	if rep.OK {
		t.Fatalf("bundle signed by an unpublished orchestrator key verified: %+v", rep)
	}
	if rep.OrchestratorKey != playground.PublishedOrchestratorPubKeyHex {
		t.Fatalf("OrchestratorKey = %q, want published key", rep.OrchestratorKey)
	}
}

func TestVerifyRunArtifacts_MissingWitnessDoesNotReportUncheckedManifestPass(t *testing.T) {
	t.Parallel()

	fixture := newVerifyMemoryFixture(t)
	artifacts := fixture.artifacts
	artifacts.Witness = nil
	rep, err := playground.VerifyRunArtifacts(artifacts, fixture.orchestratorPubHex)
	if err != nil {
		t.Fatalf("VerifyRunArtifacts: %v", err)
	}
	if rep.OK {
		t.Fatalf("missing witness verified: %+v", rep)
	}
	for _, check := range rep.Checks {
		if check.Name == "launch-manifest-signature" {
			t.Fatalf("reported manifest signature check before reading witness: %+v", rep.Checks)
		}
	}
}

func TestExtractRunArtifactsFromBundle_RejectsAmbiguousOrUnsafeMembers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		entries []bundleEntry
	}{
		{
			name: "duplicate artifact",
			entries: []bundleEntry{
				{name: "pipelock-session/launch-manifest.json", data: []byte(`{}`)},
				{name: "pipelock-session/launch-manifest.json", data: []byte(`{}`)},
			},
		},
		{
			name:    "path traversal artifact",
			entries: []bundleEntry{{name: "pipelock-session/../pipelock-session/launch-manifest.json", data: []byte(`{}`)}},
		},
		{
			name:    "backslash traversal artifact",
			entries: []bundleEntry{{name: `pipelock-session\launch-manifest.json`, data: []byte(`{}`)}},
		},
		{
			name:    "unknown artifact under prefix",
			entries: []bundleEntry{{name: "pipelock-session/extra.json", data: []byte(`{}`)}},
		},
		{
			name:    "artifact outside prefix",
			entries: []bundleEntry{{name: "launch-manifest.json", data: []byte(`{}`)}},
		},
		{
			name:    "huge declared member",
			entries: []bundleEntry{{name: "pipelock-session/launch-manifest.json", declaredSize: 17 << 20}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := playground.ExtractRunArtifactsFromBundle(makeBundle(t, tc.entries)); err == nil {
				t.Fatal("ExtractRunArtifactsFromBundle returned nil error for unsafe bundle")
			}
		})
	}
}

func TestVerifyRunArtifacts_RealBundleValidAndTamperInvalid(t *testing.T) {
	t.Parallel()

	bundle, orchestratorPubHex := realBundleForMemoryVerify(t)
	artifacts, err := playground.ExtractRunArtifactsFromBundle(bundle)
	if err != nil {
		t.Fatalf("ExtractRunArtifactsFromBundle: %v", err)
	}

	rep, err := playground.VerifyRunArtifacts(artifacts, orchestratorPubHex)
	if err != nil {
		t.Fatalf("VerifyRunArtifacts valid bundle: %v", err)
	}
	if !rep.OK {
		t.Fatalf("valid bundle did not verify: %+v", rep.Checks)
	}
	if rep.ObservedCount != 0 {
		t.Fatalf("ObservedCount = %d, want 0", rep.ObservedCount)
	}
	for _, check := range rep.Checks {
		if !check.OK {
			t.Fatalf("check %q failed on valid bundle: %s", check.Name, check.Reason)
		}
	}

	tampered := artifacts
	tampered.PacketEvidenceJSONL = append([]byte(nil), artifacts.PacketEvidenceJSONL...)
	if len(tampered.PacketEvidenceJSONL) == 0 {
		t.Fatal("valid bundle has empty packet evidence")
	}
	tampered.PacketEvidenceJSONL[len(tampered.PacketEvidenceJSONL)/2] ^= 0x01

	tamperRep, err := playground.VerifyRunArtifacts(tampered, orchestratorPubHex)
	if err != nil {
		t.Fatalf("VerifyRunArtifacts tampered bundle: %v", err)
	}
	if tamperRep.OK {
		t.Fatalf("tampered bundle verified: %+v", tamperRep.Checks)
	}
}

func realBundleForMemoryVerify(t *testing.T) ([]byte, string) {
	t.Helper()
	orchPub, orchPriv := testKeyPair(t)
	pipePub, pipePriv := testKeyPair(t)
	colPub, colPriv := testKeyPair(t)

	const (
		runNonce   = "0123456789abcdef0123456789abcdef"
		canaryID   = "aws_canary"
		policyHash = "policy-real-bundle-hash"
		scenarioID = "secret-exfil-url-blocked"
	)
	now := time.Unix(1_700_000_123, 0).UTC()
	rec := signReceipt(t, pipePriv, receipt.ActionRecord{
		Version:         receipt.ActionRecordVersion,
		ActionID:        "act-real-bundle-core-dlp",
		ActionType:      receipt.ActionWrite,
		Principal:       "pipelock-lab",
		Actor:           "lab-agent",
		Timestamp:       now,
		Target:          "https://collector.example.com/collect",
		SideEffectClass: receipt.SideEffectExternalWrite,
		Reversibility:   receipt.ReversibilityUnknown,
		PolicyHash:      policyHash,
		Verdict:         "block",
		Transport:       "http",
		Method:          "POST",
		Layer:           "core_dlp",
		Pattern:         "request body contains secret",
		ChainPrevHash:   receipt.GenesisHash,
		ChainSeq:        0,
		RunNonce:        runNonce,
	})

	evidenceDir := filepath.Join(t.TempDir(), scenarioID)
	if err := os.MkdirAll(evidenceDir, 0o750); err != nil {
		t.Fatalf("mkdir evidence dir: %v", err)
	}
	evidenceFile := filepath.Join(evidenceDir, "evidence.jsonl")
	if err := os.WriteFile(evidenceFile, mustMarshalReceiptLine(t, rec), 0o600); err != nil {
		t.Fatalf("write evidence: %v", err)
	}

	stageDir := t.TempDir()
	result, err := playground.AssembleFromEvidence(evidenceFile, hex.EncodeToString(pipePub), stageDir, now)
	if err != nil {
		t.Fatalf("AssembleFromEvidence: %v", err)
	}
	runDir := t.TempDir()
	if err := os.Rename(result.PacketDir, filepath.Join(runDir, "packet")); err != nil {
		t.Fatalf("rename packet dir: %v", err)
	}

	lm := playground.SignLaunchManifest(orchPriv, playground.LaunchManifest{
		RunNonce:        runNonce,
		ScenarioID:      scenarioID,
		CanaryID:        canaryID,
		PipelockPubKey:  hex.EncodeToString(pipePub),
		CollectorPubKey: hex.EncodeToString(colPub),
		PolicyHash:      policyHash,
		TargetHost:      "intake.lab.test",
		StartedAt:       now,
	})
	redWitness := signWitness(t, colPriv, playground.Witness{
		RunNonce:           "redcase-calib-" + canaryID,
		CanaryID:           canaryID,
		ObservedCount:      1,
		TotalCount:         1,
		RequestLogDigest:   strings.Repeat("c", 64),
		RunClosedAt:        now,
		DrainDeadline:      now.Add(time.Second),
		LaunchManifestHash: "redcase",
	})
	witness := signWitness(t, colPriv, playground.Witness{
		RunNonce:           runNonce,
		CanaryID:           canaryID,
		ObservedCount:      0,
		TotalCount:         0,
		RequestLogDigest:   strings.Repeat("d", 64),
		RunClosedAt:        now,
		DrainDeadline:      now.Add(time.Second),
		LaunchManifestHash: lm.Hash(),
		RedCaseResult: &playground.RedCaseResult{
			WitnessWentRed:   true,
			ObservedCount:    1,
			At:               now,
			CollectorPubKey:  hex.EncodeToString(colPub),
			RedWitnessDigest: sha256Hex(redWitness.SignedBytes()),
		},
	})

	files := map[string][]byte{
		"launch-manifest.json": mustJSON(t, lm),
		"witness.json":         mustJSON(t, witness),
		"red-witness.json":     mustJSON(t, redWitness),
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(runDir, name), data, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	bundle, err := playground.ArchiveRunForDownload(runDir, hex.EncodeToString(orchPub))
	if err != nil {
		t.Fatalf("ArchiveRunForDownload: %v", err)
	}
	return bundle, hex.EncodeToString(orchPub)
}

func TestVerifyPublishedBundleBytes_FailsClosedOnGarbage(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		bundle []byte
	}{
		{name: "garbage", bundle: []byte("not a gzip bundle")},
		{name: "truncated gzip", bundle: []byte{0x1f, 0x8b, 0x08}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rep, err := playground.VerifyPublishedBundleBytes(tc.bundle)
			if err != nil {
				t.Fatalf("VerifyPublishedBundleBytes returned unexpected error: %v", err)
			}
			if rep.OK {
				t.Fatalf("garbage bundle verified: %+v", rep)
			}
		})
	}
}

type verifyMemoryFixture struct {
	artifacts          playground.RunArtifacts
	orchestratorPubHex string
	orchestratorPriv   ed25519.PrivateKey
	launchManifest     playground.LaunchManifest
}

type bundleEntry struct {
	name         string
	data         []byte
	declaredSize int64
}

func newVerifyMemoryFixture(t *testing.T) verifyMemoryFixture {
	t.Helper()
	orchPub, orchPriv := testKeyPair(t)
	pipePub, pipePriv := testKeyPair(t)
	colPub, colPriv := testKeyPair(t)

	const (
		runNonce   = "verify-memory-run"
		canaryID   = "aws_canary"
		policyHash = "policy-test-hash"
		scenarioID = "secret-exfil-url-blocked"
	)
	now := time.Unix(1_700_000_000, 0).UTC()
	rec := signReceipt(t, pipePriv, receipt.ActionRecord{
		Version:         receipt.ActionRecordVersion,
		ActionID:        "act-block-core-dlp",
		ActionType:      receipt.ActionWrite,
		Timestamp:       now,
		Target:          "http://intake.lab.test/collect",
		SideEffectClass: receipt.SideEffectExternalWrite,
		Reversibility:   receipt.ReversibilityUnknown,
		PolicyHash:      policyHash,
		Verdict:         "block",
		Transport:       "http",
		Method:          "POST",
		Layer:           "core_dlp",
		Pattern:         "request body contains secret",
		ChainPrevHash:   receipt.GenesisHash,
		ChainSeq:        0,
		RunNonce:        runNonce,
	})
	chain := receipt.VerifyChain([]receipt.Receipt{rec}, hex.EncodeToString(pipePub))
	if !chain.Valid {
		t.Fatalf("test receipt chain invalid: %s", chain.Error)
	}
	evidenceJSONL := mustMarshalReceiptLine(t, rec)
	packetJSON := mustJSON(t, auditpacket.Packet{
		SchemaVersion: auditpacket.SchemaVersion,
		PacketID:      "ap-verify-memory",
		GeneratedAt:   now.Format(time.RFC3339),
		Run: auditpacket.Run{
			Provider:      auditpacket.ProviderLocal,
			AgentIdentity: "pipelock-lab-agent",
			StartedAt:     now.Format(time.RFC3339),
			CompletedAt:   now.Format(time.RFC3339),
		},
		Policy: auditpacket.Policy{PolicyHashes: []string{policyHash}},
		Summary: auditpacket.Summary{
			ReceiptCount:   1,
			Totals:         auditpacket.Totals{Block: 1},
			Transports:     map[string]int{"http": 1},
			Layers:         map[string]int{"core_dlp": 1},
			DomainsTouched: []string{"intake.lab.test"},
		},
		Verifier: auditpacket.Verifier{
			Verdict:      auditpacket.VerdictValid,
			Trusted:      true,
			ReceiptCount: 1,
			RootHash:     chain.RootHash,
			FinalSeq:     0,
			SignerKey:    hex.EncodeToString(pipePub),
			OutputFile:   "verifier.txt",
		},
		Posture: auditpacket.Posture{
			EnforcementMode:        "synthetic_lab",
			RunnerOS:               "linux",
			RawSocketStatus:        auditpacket.StatusUnknown,
			DockerSocketStatus:     auditpacket.StatusUnknown,
			DNSUDPStatus:           auditpacket.StatusUnknown,
			BrowserProxyStatus:     auditpacket.StatusUnknown,
			WebsocketFrameScanning: auditpacket.WebsocketFrameScanningOff,
			UnsupportedPaths:       []string{},
		},
		Artifacts: auditpacket.Artifacts{
			Packet:   "packet.json",
			Evidence: "evidence.jsonl",
			Verifier: "verifier.txt",
		},
	})
	packetManifestJSON := mustJSON(t, replaycapture.Manifest{
		SchemaVersion: replaycapture.ManifestSchemaVersion,
		ScenarioID:    scenarioID,
		PolicyHash:    policyHash,
		SignerKey:     hex.EncodeToString(pipePub),
		Packet: replaycapture.PacketBinding{
			Path:         "packet.json",
			RootHash:     chain.RootHash,
			ReceiptCount: 1,
			FinalSeq:     0,
		},
	})

	lm := playground.SignLaunchManifest(orchPriv, playground.LaunchManifest{
		RunNonce:        runNonce,
		ScenarioID:      scenarioID,
		CanaryID:        canaryID,
		PipelockPubKey:  hex.EncodeToString(pipePub),
		CollectorPubKey: hex.EncodeToString(colPub),
		PolicyHash:      policyHash,
		TargetHost:      "intake.lab.test",
		StartedAt:       now,
	})
	redWitness := signWitness(t, colPriv, playground.Witness{
		RunNonce:           "redcase-calib-" + canaryID,
		CanaryID:           canaryID,
		ObservedCount:      1,
		TotalCount:         1,
		RequestLogDigest:   strings.Repeat("a", 64),
		RunClosedAt:        now,
		DrainDeadline:      now.Add(time.Second),
		LaunchManifestHash: "redcase",
	})
	redSum := sha256Hex(redWitness.SignedBytes())
	witness := signWitness(t, colPriv, playground.Witness{
		RunNonce:           runNonce,
		CanaryID:           canaryID,
		ObservedCount:      0,
		TotalCount:         0,
		RequestLogDigest:   strings.Repeat("b", 64),
		RunClosedAt:        now,
		DrainDeadline:      now.Add(time.Second),
		LaunchManifestHash: lm.Hash(),
		RedCaseResult: &playground.RedCaseResult{
			WitnessWentRed:   true,
			ObservedCount:    1,
			At:               now,
			CollectorPubKey:  hex.EncodeToString(colPub),
			RedWitnessDigest: redSum,
		},
	})

	return verifyMemoryFixture{
		artifacts: playground.RunArtifacts{
			LaunchManifest:      mustJSON(t, lm),
			Witness:             mustJSON(t, witness),
			RedWitness:          mustJSON(t, redWitness),
			PacketJSON:          packetJSON,
			PacketEvidenceJSONL: evidenceJSONL,
			PacketManifestJSON:  packetManifestJSON,
		},
		orchestratorPubHex: hex.EncodeToString(orchPub),
		orchestratorPriv:   orchPriv,
		launchManifest:     lm,
	}
}

func fixtureWithMissingPipelockKey(t *testing.T, fixture verifyMemoryFixture) playground.RunArtifacts {
	t.Helper()
	lm := fixture.launchManifest
	lm.PipelockPubKey = ""
	lm = playground.SignLaunchManifest(fixture.orchestratorPriv, lm)
	artifacts := fixture.artifacts
	artifacts.LaunchManifest = mustJSON(t, lm)
	return artifacts
}

func fixtureWithPacketEvidencePath(t *testing.T, fixture verifyMemoryFixture, evidencePath string) playground.RunArtifacts {
	t.Helper()
	var pkt auditpacket.Packet
	if err := json.Unmarshal(fixture.artifacts.PacketJSON, &pkt); err != nil {
		t.Fatalf("unmarshal packet fixture: %v", err)
	}
	pkt.Artifacts.Evidence = evidencePath
	artifacts := fixture.artifacts
	artifacts.PacketJSON = mustJSON(t, pkt)
	return artifacts
}

func corruptWitnessByte(artifacts playground.RunArtifacts) playground.RunArtifacts {
	out := artifacts
	out.Witness = append([]byte(nil), artifacts.Witness...)
	if len(out.Witness) > 10 {
		out.Witness[len(out.Witness)/2] ^= 0x01
	}
	return out
}

func writeRunArtifactsFromMemory(t *testing.T, artifacts playground.RunArtifacts) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string][]byte{
		"launch-manifest.json":  artifacts.LaunchManifest,
		"witness.json":          artifacts.Witness,
		"red-witness.json":      artifacts.RedWitness,
		"packet/packet.json":    artifacts.PacketJSON,
		"packet/evidence.jsonl": artifacts.PacketEvidenceJSONL,
		"packet/manifest.json":  artifacts.PacketManifestJSON,
	}
	for name, data := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	return dir
}

func testKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

func signReceipt(t *testing.T, priv ed25519.PrivateKey, ar receipt.ActionRecord) receipt.Receipt {
	t.Helper()
	rec, err := receipt.Sign(ar, priv)
	if err != nil {
		t.Fatalf("receipt.Sign: %v", err)
	}
	return rec
}

func signWitness(t *testing.T, priv ed25519.PrivateKey, w playground.Witness) playground.Witness {
	t.Helper()
	w.Signature = hex.EncodeToString(ed25519.Sign(priv, w.SignedBytes()))
	return w
}

func mustMarshalReceiptLine(t *testing.T, rec receipt.Receipt) []byte {
	t.Helper()
	data, err := receipt.Marshal(rec)
	if err != nil {
		t.Fatalf("receipt.Marshal: %v", err)
	}
	return append(data, '\n')
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return data
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func makeBundle(t *testing.T, entries []bundleEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, entry := range entries {
		size := int64(len(entry.data))
		if entry.declaredSize > 0 {
			size = entry.declaredSize
		}
		if err := tw.WriteHeader(&tar.Header{Name: entry.name, Mode: 0o600, Size: size}); err != nil {
			t.Fatalf("WriteHeader: %v", err)
		}
		if len(entry.data) > 0 {
			if _, err := tw.Write(entry.data); err != nil {
				t.Fatalf("Write: %v", err)
			}
		}
		if entry.declaredSize > 0 {
			break
		}
	}
	if err := tw.Close(); err != nil {
		if entries[len(entries)-1].declaredSize == 0 {
			t.Fatalf("tar Close: %v", err)
		}
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}
	return buf.Bytes()
}
