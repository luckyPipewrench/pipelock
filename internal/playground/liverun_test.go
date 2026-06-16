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
