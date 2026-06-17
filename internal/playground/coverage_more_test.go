// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package playground

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
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

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return false }

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

func TestContainmentErrorHelpers(t *testing.T) {
	t.Parallel()

	for _, err := range []error{
		timeoutError{},
		os.ErrPermission,
		errors.New("network is unreachable"),
		errors.New("operation not permitted"),
		errors.New("administratively prohibited"),
	} {
		if !isEgressBlockError(err) {
			t.Fatalf("isEgressBlockError(%v) = false, want true", err)
		}
	}
	if isEgressBlockError(errors.New("connection refused")) {
		t.Fatal("connection refused must be reachable, not blocked")
	}
	if got := probeErrorDetail(errors.New("connection refused"), false); !strings.Contains(got, "reachable: connection refused") {
		t.Fatalf("connection refused detail = %q", got)
	}
	if got := probeErrorDetail(errors.New("network is unreachable"), true); !strings.Contains(got, "blocked:") {
		t.Fatalf("blocked detail = %q", got)
	}
	if got := probeErrorDetail(errors.New("reset by peer"), false); !strings.Contains(got, "not blocked:") {
		t.Fatalf("not-blocked detail = %q", got)
	}
}

func TestContainedAgentIdentityHelpers(t *testing.T) {
	t.Parallel()

	if got := containedAgentUserName(""); got != defaultContainedAgentUser {
		t.Fatalf("default contained agent user = %q, want %q", got, defaultContainedAgentUser)
	}
	if got := containedAgentUserName("custom-agent"); got != "custom-agent" {
		t.Fatalf("custom contained agent user = %q", got)
	}
	if got := containedAgentUID("pipelock-missing-test-user"); got != -1 {
		t.Fatalf("missing contained agent uid = %d, want -1", got)
	}
}

func TestChecksPassed(t *testing.T) {
	t.Parallel()

	rep := VerifyReport{Checks: []Check{
		{Name: checkHostContainSig, OK: true},
		{Name: checkHostContainBinding, OK: true},
		{Name: checkHostContainEnforced, OK: false},
	}}
	if !checksPassed(rep, checkHostContainSig, checkHostContainBinding) {
		t.Fatal("expected selected passing checks to pass")
	}
	if checksPassed(rep, checkHostContainSig, checkHostContainEnforced) {
		t.Fatal("failed check must make checksPassed false")
	}
	if checksPassed(rep, "missing-check") {
		t.Fatal("missing check must make checksPassed false")
	}
}

func TestRunEgressProbeRequiresRootWhenContained(t *testing.T) {
	t.Parallel()

	// Split-proof refactor removed LiveRun.agentCommand: mediated steps now exec
	// inline as the operator, and the only uid-dropped path is the egress probe.
	// The equivalent root-requirement branch lives in runEgressProbe(asAgent=true).
	if os.Geteuid() == 0 {
		t.Skip("non-root contained error branch requires non-root test process")
	}

	lr := &LiveRun{
		ctx:      t.Context(),
		agentBin: "/bin/echo",
		opts:     LiveRunOpts{},
	}
	// asAgent=true drops to the contained uid, which requires root; as a non-root
	// test process it must fail closed with the root requirement.
	if _, err := lr.runEgressProbe([]string{"127.0.0.1:1"}, true); err == nil || !strings.Contains(err.Error(), rootRequirement) {
		t.Fatalf("contained egress probe non-root error = %v, want root requirement", err)
	}
}

func TestRunEgressProbeParsesSubprocessOutput(t *testing.T) {
	t.Parallel()

	agent := buildLLMHelper(t, `package main
import "fmt"
func main() {
	fmt.Println(`+"`"+`[{"target":"127.0.0.1:1","open":false,"blocked":true,"detail":"blocked"}]`+"`"+`)
}
`)

	lr := &LiveRun{
		ctx:      t.Context(),
		agentBin: agent,
	}
	got, err := lr.runEgressProbe([]string{"127.0.0.1:1"}, false)
	if err != nil {
		t.Fatalf("runEgressProbe: %v", err)
	}
	if len(got) != 1 || got[0].Target != "127.0.0.1:1" || !got[0].Blocked || got[0].Open {
		t.Fatalf("probe results = %+v, want one blocked result", got)
	}
}

func TestRunStepsReturnsNonExitExecErrors(t *testing.T) {
	t.Parallel()

	lr := newRunStepsTestLiveRun(t, filepath.Join(t.TempDir(), "missing-agent"))
	err := lr.RunSteps(1)
	if err == nil || !strings.Contains(err.Error(), "step 1 exec") {
		t.Fatalf("RunSteps error = %v, want step 1 exec", err)
	}
}

func TestRunStepsReturnsAgentExitErrors(t *testing.T) {
	t.Parallel()

	lr := newRunStepsTestLiveRun(t, "/bin/false")
	err := lr.RunSteps(1)
	if err == nil || !strings.Contains(err.Error(), "step 1 exec") {
		t.Fatalf("RunSteps error = %v, want step 1 exec", err)
	}
}

func TestRunStepsRejectsUnsupportedSteps(t *testing.T) {
	t.Parallel()

	lr := newRunStepsTestLiveRun(t, "/bin/false")
	err := lr.RunSteps(99)
	if err == nil || !strings.Contains(err.Error(), "unsupported mediated step 99") {
		t.Fatalf("RunSteps error = %v, want unsupported mediated step", err)
	}
}

func TestBuildHostContainmentWitnessSignsProbeEvidence(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	lr := &LiveRun{
		ctx:              t.Context(),
		orchestratorPub:  pub,
		orchestratorPriv: priv,
		manifest: LaunchManifest{
			RunNonce:   "N1",
			ScenarioID: LiveDemoScenarioID,
			Contained:  true,
		},
		opts: LiveRunOpts{
			RunNonce:  "N1",
			AgentUser: "missing-test-agent-user",
		},
	}

	var controlTarget string
	lr.egressProbe = func(targets []string, asAgent bool) ([]ProbeResult, error) {
		if len(targets) == 0 {
			return nil, errors.New("missing targets")
		}
		if !asAgent {
			if len(targets) != 1 {
				return nil, fmt.Errorf("operator target count = %d", len(targets))
			}
			controlTarget = targets[0]
			return []ProbeResult{{Target: targets[0], Open: true, Blocked: false, Detail: "connected"}}, nil
		}
		if targets[0] != controlTarget {
			return nil, fmt.Errorf("agent control target = %q, want %q", targets[0], controlTarget)
		}
		results := make([]ProbeResult, 0, len(targets))
		for _, target := range targets {
			results = append(results, ProbeResult{Target: target, Open: false, Blocked: true, Detail: "blocked"})
		}
		return results, nil
	}

	w, err := lr.buildHostContainmentWitness()
	if err != nil {
		t.Fatalf("buildHostContainmentWitness: %v", err)
	}
	if !VerifyHostContainmentWitness(hex.EncodeToString(pub), w) {
		t.Fatal("host-containment witness signature must verify")
	}
	if !HostContainmentBindsRun(w, "N1", lr.manifest.Hash()) {
		t.Fatal("host-containment witness must bind run nonce and launch manifest")
	}
	if !w.Enforced() {
		t.Fatalf("host-containment witness must prove enforcement: %+v", w)
	}
	if len(w.AgentProbes) != len(DirectEgressTargets()) {
		t.Fatalf("agent probe count = %d, want %d", len(w.AgentProbes), len(DirectEgressTargets()))
	}
}

func TestBuildHostContainmentWitnessFailsClosedOnProbeError(t *testing.T) {
	t.Parallel()

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	lr := &LiveRun{
		ctx:              t.Context(),
		orchestratorPriv: priv,
		opts:             LiveRunOpts{RunNonce: "N1"},
	}
	lr.egressProbe = func(_ []string, asAgent bool) ([]ProbeResult, error) {
		if !asAgent {
			return nil, errors.New("operator probe failed")
		}
		return nil, errors.New("agent probe should not run")
	}

	_, err = lr.buildHostContainmentWitness()
	if err == nil || !strings.Contains(err.Error(), "operator control probe") {
		t.Fatalf("buildHostContainmentWitness error = %v, want operator probe failure", err)
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

func newRunStepsTestLiveRun(t *testing.T, agentBin string) *LiveRun {
	t.Helper()
	safeLn := listenLocal(t)
	t.Cleanup(func() { _ = safeLn.Close() })
	collectorLn := listenLocal(t)
	t.Cleanup(func() { _ = collectorLn.Close() })
	proxyLn := listenLocal(t)
	t.Cleanup(func() { _ = proxyLn.Close() })

	return &LiveRun{
		ctx:         t.Context(),
		safeLn:      safeLn,
		collectorLn: collectorLn,
		proxyLn:     proxyLn,
		agentBin:    agentBin,
		opts: LiveRunOpts{
			RunNonce: "N1",
		},
	}
}

func writePacketManifest(t *testing.T, path, scenarioID, policyHash string) {
	t.Helper()
	data := []byte(fmt.Sprintf(`{"scenario_id":%q,"policy_hash":%q}`, scenarioID, policyHash))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write packet manifest: %v", err)
	}
}
