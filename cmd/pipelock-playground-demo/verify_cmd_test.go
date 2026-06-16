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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
