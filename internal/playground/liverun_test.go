// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/playground"
	"github.com/luckyPipewrench/pipelock/internal/replaycapture"
)

// binDir holds the compiled toy-agent and web-tool binaries, built once per
// test binary invocation via TestMain.
var (
	binOnce    sync.Once
	binDir     string
	binBuildOK bool
)

// buildBinaries compiles the toy-agent and webtool into a temp dir. It is
// called at most once per test process via sync.Once.
func buildBinaries(t *testing.T) (agentBin, webtoolBin string) {
	t.Helper()
	binOnce.Do(func() {
		var err error
		binDir, err = os.MkdirTemp("", "playground-bins-*")
		if err != nil {
			return
		}

		agentOut := filepath.Join(binDir, "toyagent")
		webtoolOut := filepath.Join(binDir, "webtool")

		// Build toy agent. The -o path is a test-controlled temp dir, not
		// untrusted input.
		buildCtx := context.Background()
		agentArgs := []string{"build", "-o", agentOut, "./cmd/pipelock-playground-toyagent"}
		cmd := exec.CommandContext(buildCtx, "go", agentArgs...)
		cmd.Dir = repoRoot(t)
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Logf("build toyagent: %s\n%s", err, out)
			return
		}

		// Build web tool.
		wtArgs := []string{"build", "-o", webtoolOut, "./cmd/pipelock-playground-webtool"}
		cmd = exec.CommandContext(buildCtx, "go", wtArgs...)
		cmd.Dir = repoRoot(t)
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Logf("build webtool: %s\n%s", err, out)
			return
		}

		binBuildOK = true
	})

	if !binBuildOK {
		t.Fatal("failed to build playground binaries (see earlier log)")
	}

	return filepath.Join(binDir, "toyagent"), filepath.Join(binDir, "webtool")
}

// repoRoot returns the module root by walking up from the test file.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find go.mod")
		}
		dir = parent
	}
}

func TestLiveRun_Uncontained_ProducesVerifiableRun(t *testing.T) {
	if testing.Short() {
		t.Skip("live run test builds binaries and boots a real proxy")
	}

	agentBin, webtoolBin := buildBinaries(t)

	rc, err := playground.StartLiveRun(t.Context(), playground.LiveRunOpts{
		Contained:   false,
		ScenarioID:  playground.LiveDemoScenarioID,
		RunNonce:    "N1",
		ToyAgentBin: agentBin,
		WebToolBin:  webtoolBin,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()

	// Step 1 = allowed GET, Step 2 = blocked exfil POST.
	if err := rc.RunSteps(1, 2); err != nil {
		t.Fatal(err)
	}

	if !rc.HasReceipt("allow") || !rc.HasReceipt("block") {
		t.Fatalf("need allow+block receipts; got %v", rc.Verdicts())
	}

	runDir := t.TempDir()
	rep, err := rc.AssembleAndVerify(runDir)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("live run must verify end-to-end: %+v", rep)
	}
	if rep.ObservedCount != 0 {
		t.Fatalf("blocked exfil -> collector must observe 0, got %d", rep.ObservedCount)
	}

	assertNoLoopbackInArtifacts(t, runDir)
}

// assertNoLoopbackInArtifacts greps all JSON/JSONL files in runDir for the
// literal "127.0.0.1" to confirm no loopback IP leaks into signed artifacts.
func assertNoLoopbackInArtifacts(t *testing.T, runDir string) {
	t.Helper()

	err := filepath.Walk(runDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		switch ext {
		case ".json", ".jsonl":
			// check these files
		default:
			return nil
		}

		cleanPath := filepath.Clean(path)
		data, readErr := os.ReadFile(cleanPath)
		if readErr != nil {
			t.Errorf("cannot read %s: %v", path, readErr)
			return nil
		}

		// For JSON files, check the string content for loopback.
		// We check both the raw bytes and unmarshaled string fields.
		if strings.Contains(string(data), "127.0.0.1") {
			// Allow it in specific non-artifact fields (like proxy addr configs),
			// but NOT in packet.json, evidence.jsonl, manifest.json,
			// launch-manifest.json, or witness.json.
			baseName := filepath.Base(path)
			switch baseName {
			case "packet.json", "manifest.json", "launch-manifest.json", "witness.json", "red-witness.json":
				t.Errorf("loopback IP found in signed artifact %s", path)
			default:
				// evidence.jsonl: check each line's receipt fields
				if ext == ".jsonl" {
					checkJSONLForLoopback(t, path, data)
				}
			}
		}

		return nil
	})
	if err != nil {
		t.Fatalf("walking runDir: %v", err)
	}
}

// checkJSONLForLoopback checks evidence lines for loopback in receipt fields.
func checkJSONLForLoopback(t *testing.T, path string, data []byte) {
	t.Helper()
	for i, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		var entry map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		// Check the receipt's action_record target field specifically.
		if rcRaw, ok := entry["receipt"]; ok {
			var rc struct {
				ActionRecord struct {
					Target string `json:"target"`
				} `json:"action_record"`
			}
			if err := json.Unmarshal(rcRaw, &rc); err == nil {
				if strings.Contains(rc.ActionRecord.Target, "127.0.0.1") {
					t.Errorf("loopback IP in receipt target at %s line %d: %s",
						path, i+1, rc.ActionRecord.Target)
				}
			}
		}
	}
}

func TestAssembleFromEvidenceWithScenario_PreservesScenarioFields(t *testing.T) {
	t.Parallel()

	// Drive a real scenario through the capture engine.
	scenarios := replaycapture.DefaultScenarios()
	var exfilScenario replaycapture.Scenario
	for _, s := range scenarios {
		if s.ID == "secret-exfil-url-blocked" {
			exfilScenario = s
			break
		}
	}
	if exfilScenario.ID == "" {
		t.Fatal("scenario not found")
	}

	engine, err := replaycapture.NewEngine(t.TempDir())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	captured, err := engine.Capture(exfilScenario)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}

	// Assemble WITH the full scenario.
	outDir := t.TempDir()
	result, err := playground.AssembleFromEvidenceWithScenario(
		captured.EvidenceFile,
		engine.PublicKeyHex(),
		&exfilScenario,
		outDir,
		time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("AssembleFromEvidenceWithScenario: %v", err)
	}

	if result.PacketDir == "" {
		t.Fatal("PacketDir is empty")
	}

	// The assembled result should carry the real scenario.
	if result.Scenario.ID != exfilScenario.ID {
		t.Errorf("scenario ID = %q, want %q", result.Scenario.ID, exfilScenario.ID)
	}
	if result.Scenario.Title != exfilScenario.Title {
		t.Errorf("scenario Title = %q, want %q", result.Scenario.Title, exfilScenario.Title)
	}

	// Verify the packet is still valid.
	if err := replaycapture.VerifyPacketDir(result.PacketDir, engine.PublicKeyHex()); err != nil {
		t.Fatalf("VerifyPacketDir: %v", err)
	}
}

// TestLiveRun_ModelProvenance_EndToEnd drives a full uncontained live run with
// a configured RequestedModel and a provider-reported model attached before
// sealing, then confirms both survive on disk in the artifacts VerifyRun
// consumes: RequestedModel in the signed launch manifest, ProviderModel in
// the signed collector witness. It also covers the sanitization failure
// direction: an invalid provider-reported value must NOT fail the run.
func TestLiveRun_ModelProvenance_EndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("live run test builds binaries and boots a real proxy")
	}
	agentBin, webtoolBin := buildBinaries(t)

	cases := []struct {
		name          string
		providerModel string
		wantWitness   string
	}{
		{name: "valid provider model recorded", providerModel: "served-model-2026-09-15", wantWitness: "served-model-2026-09-15"},
		{name: "invalid provider model dropped, run still succeeds", providerModel: "bad\x00value", wantWitness: ""},
		{name: "never observed, empty", providerModel: "", wantWitness: ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			rc, err := playground.StartLiveRun(t.Context(), playground.LiveRunOpts{
				Contained:    false,
				ScenarioID:   playground.LiveDemoScenarioID,
				RunNonce:     "MODELPROV-" + tc.name,
				ToyAgentBin:  agentBin,
				WebToolBin:   webtoolBin,
				Model:        "requested-model-alias",
				ModelBaseURL: "http://model.example",
			})
			if err != nil {
				t.Fatal(err)
			}
			defer rc.Close()

			if err := rc.RunSteps(1, 2); err != nil {
				t.Fatal(err)
			}
			if tc.providerModel != "" {
				rc.SetProviderModel(tc.providerModel)
			}

			runDir := t.TempDir()
			rep, err := rc.AssembleAndVerify(runDir)
			if err != nil {
				t.Fatalf("AssembleAndVerify must not fail even on an invalid provider model: %v", err)
			}
			if !rep.OK {
				t.Fatalf("run must verify end-to-end: %+v", rep)
			}

			lmBytes, err := os.ReadFile(filepath.Clean(filepath.Join(runDir, "launch-manifest.json")))
			if err != nil {
				t.Fatal(err)
			}
			var lm map[string]any
			if err := json.Unmarshal(lmBytes, &lm); err != nil {
				t.Fatal(err)
			}
			if got, _ := lm["requested_model"].(string); got != "requested-model-alias" {
				t.Fatalf("launch-manifest.json requested_model = %q, want %q", got, "requested-model-alias")
			}

			wBytes, err := os.ReadFile(filepath.Clean(filepath.Join(runDir, "witness.json")))
			if err != nil {
				t.Fatal(err)
			}
			var w map[string]any
			if err := json.Unmarshal(wBytes, &w); err != nil {
				t.Fatal(err)
			}
			got, _ := w["provider_model"].(string)
			if got != tc.wantWitness {
				t.Fatalf("witness.json provider_model = %q, want %q", got, tc.wantWitness)
			}

			// Both new fields must be signature-covered: tampering either one
			// on disk, independently, must make VerifyRun reject the run.
			// This is the proof that requested_model/provider_model are
			// actually part of the signed bytes rather than incidental
			// fields VerifyRun happens to never check.
			orchestratorPubHex := rc.OrchestratorPubHex()

			t.Run("tampered requested_model on disk fails verification", func(t *testing.T) {
				tamperDir := t.TempDir()
				copyRunDir(t, runDir, tamperDir)
				tamperJSONField(t, filepath.Join(tamperDir, "launch-manifest.json"), "requested_model", "attacker-model")

				tamperedRep, err := playground.VerifyRun(tamperDir, orchestratorPubHex)
				if err != nil {
					t.Fatalf("VerifyRun: %v", err)
				}
				if tamperedRep.OK {
					t.Fatal("VerifyRun accepted a run with a tampered requested_model, want fail-closed rejection")
				}
			})

			t.Run("tampered provider_model on disk fails verification", func(t *testing.T) {
				tamperDir := t.TempDir()
				copyRunDir(t, runDir, tamperDir)
				tamperJSONField(t, filepath.Join(tamperDir, "witness.json"), "provider_model", "attacker-served-model")

				tamperedRep, err := playground.VerifyRun(tamperDir, orchestratorPubHex)
				if err != nil {
					t.Fatalf("VerifyRun: %v", err)
				}
				if tamperedRep.OK {
					t.Fatal("VerifyRun accepted a run with a tampered provider_model, want fail-closed rejection")
				}
			})
		})
	}
}

// copyRunDir recursively copies an AssembleAndVerify output directory (dst
// must not yet exist as a populated tree) so a tamper case can mutate one
// artifact without corrupting the shared valid-path fixture other subtests
// or later assertions in the same test still read.
func copyRunDir(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, relErr := filepath.Rel(src, path)
		if relErr != nil {
			return relErr
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o750)
		}
		data, readErr := os.ReadFile(filepath.Clean(path))
		if readErr != nil {
			return readErr
		}
		return os.WriteFile(target, data, 0o600)
	})
	if err != nil {
		t.Fatalf("copyRunDir: %v", err)
	}
}

// tamperJSONField rewrites a single top-level string field of an on-disk JSON
// artifact, the way an attacker with filesystem access to an unsealed run
// directory could, and re-writes the file. The artifact's signature is left
// untouched, so a fail-closed verifier must reject the mismatch.
func tamperJSONField(t *testing.T, path, field, newValue string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	encoded, err := json.Marshal(newValue)
	if err != nil {
		t.Fatalf("marshal replacement value: %v", err)
	}
	m[field] = encoded
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal %s: %v", path, err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestStartLiveRun_RejectsModelWithoutBaseURL reproduces the case where a
// caller sets LiveRunOpts.Model without ModelBaseURL. manifestAgentKind
// classifies such a run as AgentKindDeterministic (no model-backed subprocess
// exists), so a requested model name here could never have driven the run.
// StartLiveRun must refuse before creating any evidence, fail-closed at
// start rather than signing an unearned RequestedModel into the manifest.
func TestStartLiveRun_RejectsModelWithoutBaseURL(t *testing.T) {
	if testing.Short() {
		t.Skip("live run test builds binaries and boots a real proxy")
	}
	agentBin, webtoolBin := buildBinaries(t)

	rc, err := playground.StartLiveRun(t.Context(), playground.LiveRunOpts{
		Contained:   false,
		ScenarioID:  playground.LiveDemoScenarioID,
		RunNonce:    "REJECT-MODEL-NO-BASEURL",
		ToyAgentBin: agentBin,
		WebToolBin:  webtoolBin,
		Model:       "requested-model-alias",
		// ModelBaseURL intentionally empty.
	})
	if err == nil {
		if rc != nil {
			rc.Close()
		}
		t.Fatal("StartLiveRun succeeded with Model set and no ModelBaseURL, want a fail-closed error")
	}
	if !strings.Contains(err.Error(), "requested-model-alias") {
		t.Fatalf("error = %q, want it to name the rejected model", err.Error())
	}
}

// TestLiveRun_SetProviderModel_NoOpOnDeterministicRun starts a deterministic
// run (no ModelBaseURL: manifestAgentKind reports AgentKindDeterministic, so
// no model-backed subprocess exists to have produced a provider model value),
// then calls SetProviderModel directly, the way a caller error or a stale
// code path might. The witness must never carry a provider model for a run
// no model drove.
func TestLiveRun_SetProviderModel_NoOpOnDeterministicRun(t *testing.T) {
	if testing.Short() {
		t.Skip("live run test builds binaries and boots a real proxy")
	}
	agentBin, webtoolBin := buildBinaries(t)

	rc, err := playground.StartLiveRun(t.Context(), playground.LiveRunOpts{
		Contained:   false,
		ScenarioID:  playground.LiveDemoScenarioID,
		RunNonce:    "DETERMINISTIC-SETPROVIDERMODEL-NOOP",
		ToyAgentBin: agentBin,
		WebToolBin:  webtoolBin,
		// Model and ModelBaseURL both empty: deterministic run.
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()

	if err := rc.RunSteps(1, 2); err != nil {
		t.Fatal(err)
	}

	// A caller (or a stale/misrouted code path) reports a provider model on
	// a run that has no model-backed subprocess. It must be dropped.
	rc.SetProviderModel("should-never-be-signed")

	runDir := t.TempDir()
	rep, err := rc.AssembleAndVerify(runDir)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("deterministic run must still verify end-to-end: %+v", rep)
	}

	wBytes, err := os.ReadFile(filepath.Clean(filepath.Join(runDir, "witness.json")))
	if err != nil {
		t.Fatal(err)
	}
	var w map[string]any
	if err := json.Unmarshal(wBytes, &w); err != nil {
		t.Fatal(err)
	}
	if got, _ := w["provider_model"].(string); got != "" {
		t.Fatalf("witness.json provider_model = %q, want empty: a deterministic run must never sign a provider model", got)
	}
}
