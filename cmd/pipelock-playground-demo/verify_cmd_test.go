// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/playground"
	"github.com/luckyPipewrench/pipelock/internal/replaycapture"
)

// cmdCanaryValue builds the canary at runtime (gosec G101).
const cmdCanaryValue = "AKIA" + "IOSFODNN7EXAMPLE"

const cmdReplayFixtureScenarioID = "secret-exfil-url-blocked"

// cmdTestRunDir builds a good run dir for command-level testing.
func cmdTestRunDir(t *testing.T) (string, string) {
	t.Helper()

	orchPub, orchPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	colPub, colPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	engineDir := t.TempDir()
	engine, err := replaycapture.NewEngine(engineDir)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	scenarios := replaycapture.DefaultScenarios()
	var exfil replaycapture.Scenario
	for _, s := range scenarios {
		if s.ID == cmdReplayFixtureScenarioID {
			exfil = s
			break
		}
	}
	if exfil.ID == "" {
		t.Fatal("scenario not found")
	}

	captured, err := engine.Capture(exfil)
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

	lm := playground.SignLaunchManifest(orchPriv, playground.LaunchManifest{
		RunNonce:        "cmd-test",
		ScenarioID:      exfil.ID,
		CanaryID:        "aws_canary",
		PipelockPubKey:  engine.PublicKeyHex(),
		CollectorPubKey: hex.EncodeToString(colPub),
		PolicyHash:      captured.PolicyHash,
		TargetHost:      "exfil.target.test",
		StartedAt:       time.Now().UTC(),
	})

	ctx := context.Background()
	rc, redWitness, err := playground.RunRedCaseCalibrationWithWitness(ctx, colPriv, "aws_canary", cmdCanaryValue)
	if err != nil {
		t.Fatalf("redcase: %v", err)
	}

	c := playground.NewCollector("aws_canary", cmdCanaryValue)
	if err := c.OpenRun("cmd-test", lm.Hash()); err != nil {
		t.Fatalf("OpenRun: %v", err)
	}
	if err := c.AttachRedCase("cmd-test", rc); err != nil {
		t.Fatalf("AttachRedCase: %v", err)
	}
	w, err := c.SealAndSign("cmd-test", colPriv, 200*time.Millisecond)
	if err != nil {
		t.Fatalf("SealAndSign: %v", err)
	}

	writeJSON(t, filepath.Join(runDir, "launch-manifest.json"), lm)
	writeJSON(t, filepath.Join(runDir, "witness.json"), w)
	writeJSON(t, filepath.Join(runDir, "red-witness.json"), redWitness)

	return runDir, hex.EncodeToString(orchPub)
}

func writeJSON(t *testing.T, path string, v interface{}) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestVerifyCmd_GoodDir_ExitZero(t *testing.T) {
	t.Parallel()
	dir, orchKey := cmdTestRunDir(t)
	cmd := newRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"verify", dir, "--orchestrator-key", orchKey})
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("expected exit 0 on good dir, got error: %v\noutput:\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), "VERIFY OK") {
		t.Fatalf("expected VERIFY OK in output, got:\n%s", buf.String())
	}
}

func TestOfflineCommandsDefaultToPublishedOrchestratorKey(t *testing.T) {
	t.Parallel()

	for name, newCmd := range map[string]func() *cobra.Command{
		"verify":   newVerifyCmd,
		"fallback": newFallbackCmd,
		"bundle":   newBundleCmd,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cmd := newCmd()
			flag := cmd.Flags().Lookup("orchestrator-key")
			if flag == nil {
				t.Fatal("missing orchestrator-key flag")
			}
			if flag.DefValue != playground.PublishedOrchestratorPubKeyHex {
				t.Fatalf("default orchestrator-key = %q, want published key", flag.DefValue)
			}
		})
	}
}

func TestResolveOrchestratorKeyPath(t *testing.T) {
	configDir := filepath.Join(t.TempDir(), "config")
	t.Setenv("XDG_CONFIG_HOME", configDir)

	explicit := filepath.Join(t.TempDir(), "custom.key")
	if got := resolveOrchestratorKeyPath(explicit, true); got != explicit {
		t.Fatalf("explicit key path = %q, want %q", got, explicit)
	}

	if got := resolveOrchestratorKeyPath("", false); got != "" {
		t.Fatalf("missing default key path = %q, want empty", got)
	}

	def := playground.DefaultOrchestratorKeyPath()
	if err := os.MkdirAll(filepath.Dir(def), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(def, []byte("present"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := resolveOrchestratorKeyPath("", false); got != def {
		t.Fatalf("default key path = %q, want %q", got, def)
	}
}

func TestKeygenOrchestratorCmd_DefaultPathForceAndRefuse(t *testing.T) {
	configDir := filepath.Join(t.TempDir(), "config")
	t.Setenv("XDG_CONFIG_HOME", configDir)
	def := playground.DefaultOrchestratorKeyPath()

	cmd := newRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"keygen-orchestrator"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("keygen default path: %v\noutput:\n%s", err, buf.String())
	}
	if _, err := playground.LoadOrchestratorSigningKey(def); err != nil {
		t.Fatalf("generated default key must load: %v", err)
	}
	if !strings.Contains(buf.String(), "public key") {
		t.Fatalf("keygen output missing public key:\n%s", buf.String())
	}

	cmd = newRootCmd()
	buf.Reset()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"keygen-orchestrator"})
	if err := cmd.Execute(); err == nil {
		t.Fatalf("keygen must refuse to overwrite without --force\noutput:\n%s", buf.String())
	}

	cmd = newRootCmd()
	buf.Reset()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"keygen-orchestrator", "--force"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("keygen --force: %v\noutput:\n%s", err, buf.String())
	}
}

func TestBundleCmd_FailsClosedOnUnverifiedRun(t *testing.T) {
	t.Parallel()

	cmd := newRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"bundle", t.TempDir()})
	if err := cmd.Execute(); err == nil {
		t.Fatalf("bundle must fail on an unverified run\noutput:\n%s", buf.String())
	}
}

func TestBundleCmd_LiveDemo_WritesFileAndStdout(t *testing.T) {
	if testing.Short() {
		t.Skip("bundle command test builds binaries and boots a real proxy")
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
		t.Fatalf("run must verify: %+v", rep.Checks)
	}

	outPath := filepath.Join(t.TempDir(), "bundle.json")
	cmd := newRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"bundle", runDir, "--orchestrator-key", rep.OrchestratorKey, "--out", outPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("bundle --out: %v\noutput:\n%s", err, buf.String())
	}
	data, err := os.ReadFile(outPath) // #nosec G304 -- test file under t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"mode": "replay"`) || !strings.Contains(string(data), rep.RunNonce) {
		t.Fatalf("bundle file missing real run data:\n%s", string(data))
	}

	cmd = newRootCmd()
	buf.Reset()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"bundle", runDir, "--orchestrator-key", rep.OrchestratorKey})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("bundle stdout: %v\noutput:\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), rep.RunNonce) {
		t.Fatalf("stdout bundle missing run nonce:\n%s", buf.String())
	}
}

func TestVerifyCmd_TamperedDir_ExitNonZero(t *testing.T) {
	t.Parallel()
	dir, orchKey := cmdTestRunDir(t)

	// Tamper the manifest signature.
	path := filepath.Clean(filepath.Join(dir, "launch-manifest.json"))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	m["run_nonce"] = json.RawMessage(`"tampered"`)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := newRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"verify", dir, "--orchestrator-key", orchKey})
	err = cmd.Execute()
	if err == nil {
		t.Fatalf("expected non-zero exit on tampered dir, got nil error\noutput:\n%s", buf.String())
	}
}
