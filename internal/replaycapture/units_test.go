// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package replaycapture

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/signing"
	auditpacket "github.com/luckyPipewrench/pipelock/sdk/audit-packet"
)

func TestAddVerdict_AllBuckets(t *testing.T) {
	t.Parallel()
	var totals auditpacket.Totals
	for _, v := range []string{
		verdictAllow, verdictBlock, verdictWarn,
		"ask", "strip", "forward", "redirect", "mystery",
	} {
		addVerdict(&totals, v)
	}
	want := auditpacket.Totals{
		Allow: 1, Block: 1, Warn: 1, Ask: 1, Strip: 1, Forward: 1, Redirect: 1, Other: 1,
	}
	if totals != want {
		t.Errorf("totals=%+v want=%+v", totals, want)
	}
}

func TestBoundedInt(t *testing.T) {
	t.Parallel()
	if got := boundedInt(7); got != 7 {
		t.Errorf("boundedInt(7)=%d", got)
	}
	if got := boundedInt(0); got != 0 {
		t.Errorf("boundedInt(0)=%d", got)
	}
}

func TestNewEngineWithKey(t *testing.T) {
	t.Parallel()
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	eng, err := NewEngineWithKey(t.TempDir(), priv)
	if err != nil {
		t.Fatalf("NewEngineWithKey: %v", err)
	}
	if eng.PublicKeyHex() == "" {
		t.Errorf("expected non-empty public key")
	}

	if _, err := NewEngineWithKey(t.TempDir(), []byte("too-short")); err == nil {
		t.Errorf("expected error for short key")
	}
}

func TestDecisiveVerdict_Fallback(t *testing.T) {
	t.Parallel()

	cs := &CapturedScenario{
		Scenario: Scenario{ExpectedVerdict: verdictBlock},
		Receipts: []receipt.Receipt{
			{ActionRecord: receipt.ActionRecord{Verdict: verdictWarn}},
		},
	}
	// No receipt matches the expected verdict, so the last receipt's verdict wins.
	if got := decisiveVerdict(cs); got != verdictWarn {
		t.Errorf("fallback verdict=%q want warn", got)
	}

	empty := &CapturedScenario{Scenario: Scenario{ExpectedVerdict: verdictBlock}}
	if got := decisiveVerdict(empty); got != "unknown" {
		t.Errorf("empty verdict=%q want unknown", got)
	}
}

func TestFindingsError(t *testing.T) {
	t.Parallel()
	if err := findingsError(nil); err != nil {
		t.Errorf("expected nil for no findings, got %v", err)
	}
	f := []Finding{{File: "packet.json", Line: 3, Rule: "private-ip", Match: "10.0.0.1"}}
	err := findingsError(f)
	if err == nil || !strings.Contains(err.Error(), "private-ip") {
		t.Errorf("expected finding in error, got %v", err)
	}
	// Finding.String formatting.
	if s := f[0].String(); !strings.Contains(s, "packet.json:3") {
		t.Errorf("Finding.String=%q", s)
	}
}

func TestAssemblePacket_Rejections(t *testing.T) {
	t.Parallel()

	if _, err := AssemblePacket(nil, t.TempDir(), fixedStamp()); err == nil {
		t.Errorf("expected error for nil captured scenario")
	}

	empty := &CapturedScenario{Scenario: Scenario{ID: "x"}}
	if _, err := AssemblePacket(empty, t.TempDir(), fixedStamp()); err == nil {
		t.Errorf("expected error for no receipts")
	}

	// A receipt that fails the allowlist must abort assembly.
	bad := &CapturedScenario{
		Scenario: Scenario{ID: "bad"},
		Receipts: []receipt.Receipt{
			{ActionRecord: receipt.ActionRecord{
				Principal: "org:acme", Actor: labActor,
				Target: "https://collector.example.com/x", Verdict: verdictBlock,
			}},
		},
	}
	if _, err := AssemblePacket(bad, t.TempDir(), fixedStamp()); err == nil {
		t.Errorf("expected allowlist gate to reject assembly")
	}
}

func TestVerifyPacketDir_Negatives(t *testing.T) {
	t.Parallel()

	eng := newTestEngine(t)
	outDir := t.TempDir()
	cs, err := eng.Capture(DefaultScenarios()[1])
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	res, err := AssemblePacket(cs, outDir, fixedStamp())
	if err != nil {
		t.Fatalf("AssemblePacket: %v", err)
	}

	// Wrong key fails.
	if err := VerifyPacketDir(res.PacketDir, strings.Repeat("00", 32)); err == nil {
		t.Errorf("expected wrong-key verification to fail")
	}

	// Missing packet.json fails.
	if err := VerifyPacketDir(t.TempDir(), eng.PublicKeyHex()); err == nil {
		t.Errorf("expected missing packet to fail")
	}

	// Corrupt packet.json fails.
	corrupt := filepath.Join(t.TempDir(), cs.Scenario.ID)
	if err := os.MkdirAll(corrupt, dirPerm); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(corrupt, artifactPacketName), []byte("{not json"), filePerm); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPacketDir(corrupt, eng.PublicKeyHex()); err == nil {
		t.Errorf("expected corrupt packet to fail")
	}
}

// TestVerifyPacketDir_DetectsTamper proves the cross-check rejects a packet
// whose summary was edited to overstate the receipt count while the signed
// evidence is unchanged — tamper-evidence, not just coverage.
func TestVerifyPacketDir_DetectsTamper(t *testing.T) {
	t.Parallel()

	eng := newTestEngine(t)
	cs, err := eng.Capture(DefaultScenarios()[1])
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	res, err := AssemblePacket(cs, t.TempDir(), fixedStamp())
	if err != nil {
		t.Fatalf("AssemblePacket: %v", err)
	}

	// Inflate the claimed receipt count and rewrite packet.json (evidence stays
	// byte-for-byte signed).
	tampered := res.Packet
	tampered.Summary.ReceiptCount = cs.ReceiptCount + 9
	data, err := marshalIndentNoEscape(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(res.PacketDir, artifactPacketName), data, filePerm); err != nil {
		t.Fatal(err)
	}

	if err := VerifyPacketDir(res.PacketDir, eng.PublicKeyHex()); err == nil {
		t.Errorf("expected tampered receipt_count to be rejected")
	}
}

func TestVerifyPacketDir_DetectsVerifierTamper(t *testing.T) {
	t.Parallel()

	eng := newTestEngine(t)
	cs, err := eng.Capture(DefaultScenarios()[1])
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}

	t.Run("final seq", func(t *testing.T) {
		t.Parallel()
		res, assembleErr := AssemblePacket(cs, t.TempDir(), fixedStamp())
		if assembleErr != nil {
			t.Fatalf("AssemblePacket: %v", assembleErr)
		}
		tampered := res.Packet
		tampered.Verifier.FinalSeq = 99
		writePacketForTest(t, res.PacketDir, tampered)
		if err := VerifyPacketDir(res.PacketDir, eng.PublicKeyHex()); err == nil {
			t.Errorf("expected tampered final_seq to be rejected")
		}
	})

	t.Run("trust verdict", func(t *testing.T) {
		t.Parallel()
		res, assembleErr := AssemblePacket(cs, t.TempDir(), fixedStamp())
		if assembleErr != nil {
			t.Fatalf("AssemblePacket: %v", assembleErr)
		}
		tampered := res.Packet
		tampered.Verifier.Verdict = auditpacket.VerdictSelfConsistentOnly
		tampered.Verifier.Trusted = false
		writePacketForTest(t, res.PacketDir, tampered)
		if err := VerifyPacketDir(res.PacketDir, eng.PublicKeyHex()); err == nil {
			t.Errorf("expected untrusted verifier verdict to be rejected")
		}
	})
}

func TestVerifyPacketBytes_BrowserBundlePath(t *testing.T) {
	t.Parallel()

	eng := newTestEngine(t)
	cs, err := eng.Capture(DefaultScenarios()[1])
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	res, err := AssemblePacket(cs, t.TempDir(), fixedStamp())
	if err != nil {
		t.Fatalf("AssemblePacket: %v", err)
	}
	packetJSON, err := os.ReadFile(filepath.Join(res.PacketDir, artifactPacketName))
	if err != nil {
		t.Fatalf("read packet.json: %v", err)
	}
	evidenceJSONL, err := os.ReadFile(filepath.Join(res.PacketDir, artifactEvidenceName))
	if err != nil {
		t.Fatalf("read evidence.jsonl: %v", err)
	}

	if err := VerifyPacketBytes(packetJSON, evidenceJSONL, eng.PublicKeyHex()); err != nil {
		t.Fatalf("VerifyPacketBytes valid bundle: %v", err)
	}
	if err := VerifyPacketBytes([]byte("{"), evidenceJSONL, eng.PublicKeyHex()); err == nil ||
		!strings.Contains(err.Error(), "parsing packet.json") {
		t.Fatalf("malformed packet error = %v", err)
	}
	if err := VerifyPacketBytes(packetJSON, evidenceJSONL, strings.Repeat("00", 32)); err == nil ||
		!strings.Contains(err.Error(), "chain verification failed") {
		t.Fatalf("wrong key error = %v", err)
	}

	tampered := *res.Packet
	tampered.Artifacts.Packet = "nested/packet.json"
	tamperedJSON, err := marshalIndentNoEscape(&tampered)
	if err != nil {
		t.Fatalf("marshal tampered packet path: %v", err)
	}
	if err := VerifyPacketBytes(tamperedJSON, evidenceJSONL, eng.PublicKeyHex()); err == nil ||
		!strings.Contains(err.Error(), "packet artifact path") {
		t.Fatalf("packet path error = %v", err)
	}

	tampered = *res.Packet
	tampered.Artifacts.Evidence = "../evidence.jsonl"
	tamperedJSON, err = marshalIndentNoEscape(&tampered)
	if err != nil {
		t.Fatalf("marshal traversal evidence path: %v", err)
	}
	if err := VerifyPacketBytes(tamperedJSON, evidenceJSONL, eng.PublicKeyHex()); err == nil ||
		!strings.Contains(err.Error(), "evidence path must stay inside the packet directory") {
		t.Fatalf("traversal evidence path error = %v", err)
	}

	tampered = *res.Packet
	tampered.Artifacts.Evidence = "other.jsonl"
	tamperedJSON, err = marshalIndentNoEscape(&tampered)
	if err != nil {
		t.Fatalf("marshal evidence path mismatch: %v", err)
	}
	if err := VerifyPacketBytes(tamperedJSON, evidenceJSONL, eng.PublicKeyHex()); err == nil ||
		!strings.Contains(err.Error(), "evidence artifact path") {
		t.Fatalf("evidence path mismatch error = %v", err)
	}
}

func TestVerifyPacketBytesRejectsOversizeBeforeParsing(t *testing.T) {
	oversize := make([]byte, recorder.MaxEvidenceReadFileBytes+1)
	if err := VerifyPacketBytes(oversize, []byte("{}"), strings.Repeat("00", 32)); err == nil || !strings.Contains(err.Error(), "packet.json exceeds") {
		t.Fatalf("oversize packet error = %v", err)
	}
	if err := VerifyPacketBytes([]byte("{}"), oversize, strings.Repeat("00", 32)); err == nil || !strings.Contains(err.Error(), "evidence.jsonl exceeds") {
		t.Fatalf("oversize evidence error = %v", err)
	}
}

func writePacketForTest(t *testing.T, packetDir string, pkt *auditpacket.Packet) {
	t.Helper()
	data, err := marshalIndentNoEscape(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packetDir, artifactPacketName), data, filePerm); err != nil {
		t.Fatal(err)
	}
}

func TestCrossCheckTotals_Mismatch(t *testing.T) {
	t.Parallel()
	summary := auditpacket.Summary{Totals: auditpacket.Totals{Allow: 5}}
	receipts := []receipt.Receipt{{ActionRecord: receipt.ActionRecord{Verdict: verdictBlock}}}
	if err := crossCheckTotals(summary, receipts); err == nil {
		t.Errorf("expected totals mismatch error")
	}
}

func TestSingleEvidenceFile_Errors(t *testing.T) {
	t.Parallel()
	// Empty dir: zero evidence files.
	if _, err := singleEvidenceFile(t.TempDir()); err == nil {
		t.Errorf("expected error for no evidence file")
	}
}

func TestLabConfig_UnknownScenario(t *testing.T) {
	t.Parallel()
	if _, err := labConfig(Scenario{ID: "does-not-exist"}); err == nil {
		t.Errorf("expected unknown scenario error")
	}
}

func TestLabConfig_FixtureTrustDoesNotAllowRawLoopback(t *testing.T) {
	t.Parallel()

	cfg, err := labConfig(DefaultScenarios()[0])
	if err != nil {
		t.Fatalf("labConfig: %v", err)
	}
	sc := scanner.New(cfg)
	defer sc.Close()

	result := sc.Scan(context.Background(), "http://127.0.0.1:1/admin")
	if result.Allowed {
		t.Fatalf("raw loopback target was allowed; fixture trust must stay hostname-scoped")
	}
}

func TestLint_DirErrors(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "nope")
	if _, err := LintArtifacts(missing, nil); err == nil {
		t.Errorf("expected LintArtifacts error for missing dir")
	}
	if _, err := LintGallery(missing, nil); err == nil {
		t.Errorf("expected LintGallery error for missing dir")
	}
	if err := LintGalleryFailClosed(missing, nil); err == nil {
		t.Errorf("expected LintGalleryFailClosed error for missing dir")
	}
}

func TestLintGalleryFailClosed_FlagsPlantedFile(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	sub := filepath.Join(root, "scenario")
	if err := os.MkdirAll(sub, dirPerm); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "packet.json"), []byte(`{"host":"10.0.0.5"}`), filePerm); err != nil {
		t.Fatal(err)
	}
	if err := LintGalleryFailClosed(root, nil); err == nil {
		t.Errorf("expected planted private IP to fail the gallery linter")
	}
}

func TestWriteManifest_Error(t *testing.T) {
	t.Parallel()
	// A path whose parent is a regular file cannot be written into.
	file := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(file, []byte("x"), filePerm); err != nil {
		t.Fatal(err)
	}
	if err := WriteManifest(file, Manifest{}); err == nil {
		t.Errorf("expected WriteManifest error when dir is a file")
	}
}

func TestValidateSafeHost(t *testing.T) {
	t.Parallel()
	if err := validateSafeHost(""); err == nil {
		t.Errorf("expected empty host error")
	}
	if err := validateSafeHost("collector.example.com"); err != nil {
		t.Errorf("expected reserved host to pass, got %v", err)
	}
	if err := validateSafeHost("api.realvendor.io"); err == nil {
		t.Errorf("expected real host to fail")
	}
}

func TestHostOf(t *testing.T) {
	t.Parallel()
	if got := hostOf("https://collector.example.com/x"); got != "collector.example.com" {
		t.Errorf("hostOf=%q", got)
	}
	if got := hostOf("://bad\x00url"); got != "" {
		t.Errorf("expected empty host for unparseable target, got %q", got)
	}
}

// TestGenerate_CaptureError covers the capture-failure propagation path: when
// the engine work dir is a regular file, per-scenario evidence dir creation
// fails and Generate aborts.
func TestGenerate_CaptureError(t *testing.T) {
	t.Parallel()
	workFile := filepath.Join(t.TempDir(), "work-as-file")
	if err := os.WriteFile(workFile, []byte("x"), filePerm); err != nil {
		t.Fatal(err)
	}
	eng, err := NewEngine(workFile)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if _, err := eng.Generate(DefaultScenarios()[:1], t.TempDir(), "v", fixedStamp()); err == nil {
		t.Errorf("expected Generate to fail when work dir is a file")
	}
}
