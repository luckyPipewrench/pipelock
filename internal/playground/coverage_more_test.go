// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package playground

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

const rootRequirement = "requires root"

type badAddr string

func (a badAddr) Network() string { return "bad" }
func (a badAddr) String() string  { return string(a) }

func TestLiveRunHelperBranches(t *testing.T) {
	t.Parallel()

	if got := portFromAddr(badAddr("not-a-host-port")); got != "0" {
		t.Fatalf("bad addr port = %q, want 0", got)
	}
	if got := portFromAddr(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}); got != "12345" {
		t.Fatalf("tcp addr port = %q, want 12345", got)
	}

	if _, err := singleLiveEvidenceFile(t.TempDir()); err == nil {
		t.Fatal("empty evidence dir must fail closed")
	}

	evidenceDir := t.TempDir()
	want := filepath.Join(evidenceDir, "evidence-proxy-test.jsonl")
	if err := os.WriteFile(want, nil, 0o600); err != nil {
		t.Fatalf("write evidence file: %v", err)
	}
	got, err := singleLiveEvidenceFile(evidenceDir)
	if err != nil {
		t.Fatalf("singleLiveEvidenceFile: %v", err)
	}
	if got != want {
		t.Fatalf("evidence file = %q, want %q", got, want)
	}

	cfg := config.Defaults()
	hash := liveRunConfigHash(cfg)
	if !strings.HasPrefix(hash, "sha256:") || len(hash) != len("sha256:")+64 {
		t.Fatalf("policy hash has wrong shape: %q", hash)
	}
}

func TestLiveRunAgentCommandBranches(t *testing.T) {
	t.Parallel()

	lr := &LiveRun{
		ctx:      t.Context(),
		agentBin: "/bin/echo",
		opts:     LiveRunOpts{},
	}
	cmd, err := lr.agentCommand([]string{"hello"})
	if err != nil {
		t.Fatalf("uncontained agentCommand: %v", err)
	}
	if cmd.Path != "/bin/echo" {
		t.Fatalf("cmd path = %q", cmd.Path)
	}
	if len(cmd.Args) != 2 || cmd.Args[1] != "hello" {
		t.Fatalf("cmd args = %v", cmd.Args)
	}

	if os.Geteuid() == 0 {
		t.Skip("non-root contained error branch requires non-root test process")
	}
	lr.opts.Contained = true
	if _, err := lr.agentCommand(nil); err == nil || !strings.Contains(err.Error(), rootRequirement) {
		t.Fatalf("contained non-root error = %v, want root requirement", err)
	}
}

func TestRunStepsReturnsNonExitExecErrors(t *testing.T) {
	t.Parallel()

	safeLn := listenLocal(t)
	defer func() { _ = safeLn.Close() }()
	collectorLn := listenLocal(t)
	defer func() { _ = collectorLn.Close() }()
	proxyLn := listenLocal(t)
	defer func() { _ = proxyLn.Close() }()

	lr := &LiveRun{
		ctx:         t.Context(),
		safeLn:      safeLn,
		collectorLn: collectorLn,
		proxyLn:     proxyLn,
		agentBin:    filepath.Join(t.TempDir(), "missing-agent"),
		opts: LiveRunOpts{
			RunNonce: "N1",
		},
	}
	err := lr.RunSteps(1)
	if err == nil || !strings.Contains(err.Error(), "step 1 exec") {
		t.Fatalf("RunSteps error = %v, want step 1 exec", err)
	}
}

func TestContainmentAvailableFalseWhenPipelockMissing(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	if ContainmentAvailable() {
		t.Fatal("empty PATH must report containment unavailable")
	}
}

func TestVerifyBodyExfilLiveDemoSemantics(t *testing.T) {
	t.Parallel()

	receipts := []receipt.Receipt{
		semanticReceipt(liveDemoAllowedVerdict, "domain_allow"),
		semanticReceipt(liveDemoExpectedVerdict, liveDemoExpectedBlockLayer),
	}
	if err := verifyBodyExfilLiveDemo(receipts, Witness{}); err != nil {
		t.Fatalf("valid body exfil semantics: %v", err)
	}

	if err := verifyBodyExfilLiveDemo(receipts, Witness{ObservedCount: 1}); err == nil ||
		!strings.Contains(err.Error(), "must not reach the collector") {
		t.Fatalf("collector-observed error = %v", err)
	}

	if err := verifyBodyExfilLiveDemo(receipts[:1], Witness{}); err == nil ||
		!strings.Contains(err.Error(), "body_dlp block receipt") {
		t.Fatalf("missing block error = %v", err)
	}

	if err := verifyBodyExfilLiveDemo(receipts[1:], Witness{}); err == nil ||
		!strings.Contains(err.Error(), "allow receipt") {
		t.Fatalf("missing allow error = %v", err)
	}
}

func TestVerifyURLExfilReplayCompatibleSemantics(t *testing.T) {
	t.Parallel()

	receipts := []receipt.Receipt{semanticReceipt(liveDemoExpectedVerdict, "core_dlp")}
	if err := verifyURLExfilReplayCompatible(receipts, Witness{}); err != nil {
		t.Fatalf("valid URL exfil semantics: %v", err)
	}

	if err := verifyURLExfilReplayCompatible(receipts, Witness{ObservedCount: 1}); err == nil ||
		!strings.Contains(err.Error(), "observed=1") {
		t.Fatalf("collector-observed error = %v", err)
	}

	if err := verifyURLExfilReplayCompatible([]receipt.Receipt{semanticReceipt(liveDemoExpectedVerdict, "body_dlp")}, Witness{}); err == nil ||
		!strings.Contains(err.Error(), "missing core_dlp block receipt") {
		t.Fatalf("missing core_dlp error = %v", err)
	}
}

func TestVerifyLiveDemoSemanticsRejectsBadPacketManifest(t *testing.T) {
	t.Parallel()

	runDir := t.TempDir()
	lm := LaunchManifest{
		ScenarioID: LiveDemoScenarioID,
		PolicyHash: "sha256:test-policy",
	}
	if err := verifyLiveDemoSemantics(runDir, lm, Witness{}); err == nil ||
		!strings.Contains(err.Error(), "cannot read packet manifest") {
		t.Fatalf("missing manifest error = %v", err)
	}

	packetDir := filepath.Join(runDir, packetSubdir)
	if err := os.MkdirAll(packetDir, 0o750); err != nil {
		t.Fatalf("mkdir packet: %v", err)
	}
	manifestPath := filepath.Join(packetDir, "manifest.json")
	if err := os.WriteFile(manifestPath, []byte("{"), 0o600); err != nil {
		t.Fatalf("write malformed manifest: %v", err)
	}
	if err := verifyLiveDemoSemantics(runDir, lm, Witness{}); err == nil ||
		!strings.Contains(err.Error(), "malformed packet manifest") {
		t.Fatalf("malformed manifest error = %v", err)
	}

	writePacketManifest(t, manifestPath, "other-scenario", lm.PolicyHash)
	if err := verifyLiveDemoSemantics(runDir, lm, Witness{}); err == nil ||
		!strings.Contains(err.Error(), "scenario_id") {
		t.Fatalf("scenario mismatch error = %v", err)
	}

	writePacketManifest(t, manifestPath, lm.ScenarioID, "sha256:other-policy")
	if err := verifyLiveDemoSemantics(runDir, lm, Witness{}); err == nil ||
		!strings.Contains(err.Error(), "policy_hash") {
		t.Fatalf("policy mismatch error = %v", err)
	}

	writePacketManifest(t, manifestPath, lm.ScenarioID, lm.PolicyHash)
	if err := verifyLiveDemoSemantics(runDir, lm, Witness{}); err == nil ||
		!strings.Contains(err.Error(), "extract packet receipts") {
		t.Fatalf("missing evidence error = %v", err)
	}
}

func TestConfigureContainedCommandNonRootPath(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("non-root error branch requires non-root test process")
	}

	cmd := exec.CommandContext(t.Context(), "/bin/true")
	err := configureContainedCommand(cmd, "")
	if err == nil || !strings.Contains(err.Error(), "requires root") {
		t.Fatalf("configureContainedCommand error = %v, want root requirement", err)
	}
}

func TestPreflightRunDirMustBeDirectory(t *testing.T) {
	t.Parallel()

	runDir := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(runDir, []byte("file"), 0o600); err != nil {
		t.Fatalf("write run dir placeholder: %v", err)
	}
	err := Preflight(DemoOpts{RunDir: runDir, RunNonce: "N1"})
	if err == nil || !strings.Contains(err.Error(), "not writable") {
		t.Fatalf("preflight error = %v, want not writable", err)
	}
}

func TestResetCallsContainmentTeardown(t *testing.T) {
	runDir := t.TempDir()
	hook := &recordingContainmentHook{}
	SetContainmentHook(hook)
	t.Cleanup(func() { SetContainmentHook(nil) })

	if err := Reset(runDir); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if hook.teardownRunDir != runDir {
		t.Fatalf("teardown runDir = %q, want %q", hook.teardownRunDir, runDir)
	}

	hook.teardownErr = fmt.Errorf("teardown failed")
	if err := Reset(runDir); err == nil || !strings.Contains(err.Error(), "containment teardown") {
		t.Fatalf("Reset teardown error = %v, want containment teardown", err)
	}
}

func TestRenderVerifySummaryFailureOutput(t *testing.T) {
	t.Parallel()

	rep := VerifyReport{
		OrchestratorKey: "abc123",
		Checks: []Check{{
			Name:   checkManifestSig,
			OK:     false,
			Reason: "bad signature",
		}},
	}
	var buf bytes.Buffer
	renderVerifySummary(&buf, rep, "/tmp/playground-run")
	out := buf.String()
	for _, want := range []string{"[FAIL] launch-manifest-signature -- bad signature", "VERIFY FAILED", "--orchestrator-key abc123"} {
		if !strings.Contains(out, want) {
			t.Fatalf("summary missing %q in:\n%s", want, out)
		}
	}
}

func TestWitnessVerificationRejectsMalformedInputs(t *testing.T) {
	t.Parallel()

	w := Witness{RunNonce: "N1"}
	w.Signature = strings.Repeat("00", 64)

	if VerifyWitness("not-hex", w) {
		t.Fatal("non-hex collector key must fail")
	}
	if VerifyWitness(strings.Repeat("00", 31), w) {
		t.Fatal("short collector key must fail")
	}
	pub, _ := genKey(t)
	w.Signature = "not-hex"
	if VerifyWitness(hexEnc(pub), w) {
		t.Fatal("non-hex witness signature must fail")
	}
}

func TestAssembleFromEvidenceRejectsMissingAndEmptyEvidence(t *testing.T) {
	t.Parallel()

	if _, err := assembleFromEvidenceCore(filepath.Join(t.TempDir(), "missing.jsonl"), "", nil, t.TempDir(), time.Now()); err == nil {
		t.Fatal("missing evidence file must fail")
	}

	evidenceFile := filepath.Join(t.TempDir(), "evidence.jsonl")
	if err := os.WriteFile(evidenceFile, nil, 0o600); err != nil {
		t.Fatalf("write empty evidence: %v", err)
	}
	if _, err := assembleFromEvidenceCore(evidenceFile, "", nil, t.TempDir(), time.Now()); err == nil {
		t.Fatal("empty evidence file must fail")
	}
}

func semanticReceipt(verdict, layer string) receipt.Receipt {
	return receipt.Receipt{
		ActionRecord: receipt.ActionRecord{
			Verdict: verdict,
			Layer:   layer,
		},
	}
}

type recordingContainmentHook struct {
	teardownRunDir string
	teardownErr    error
}

func (h *recordingContainmentHook) Setup(context.Context, DemoOpts) error { return nil }

func (h *recordingContainmentHook) Teardown(runDir string) error {
	h.teardownRunDir = runDir
	return h.teardownErr
}

func listenLocal(t *testing.T) net.Listener {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return ln
}

func writePacketManifest(t *testing.T, path, scenarioID, policyHash string) {
	t.Helper()
	data := []byte(fmt.Sprintf(`{"scenario_id":%q,"policy_hash":%q}`, scenarioID, policyHash))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write packet manifest: %v", err)
	}
}
