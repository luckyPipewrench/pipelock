// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/luckyPipewrench/pipelock/internal/config"
	posturepkg "github.com/luckyPipewrench/pipelock/internal/posture"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestPostureEmitCmdSuccess(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey(): %v", err)
	}

	keyPath := filepath.Join(t.TempDir(), "signing.key")
	if err := signing.SavePrivateKey(priv, keyPath); err != nil {
		t.Fatalf("signing.SavePrivateKey(): %v", err)
	}

	recorderDir := filepath.Join(t.TempDir(), "recorder")
	writeCLIReceipt(t, recorderDir, priv)

	cfg := config.Defaults()
	cfg.FlightRecorder.Enabled = true
	cfg.FlightRecorder.Dir = recorderDir
	cfg.FlightRecorder.SigningKeyPath = keyPath

	cfgPath := writeCLIConfig(t, cfg)
	outDir := filepath.Join(t.TempDir(), "out")

	var stdout bytes.Buffer
	cmd := rootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"posture", "emit", "--config", cfgPath, "--output", outDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute(): %v", err)
	}

	if !strings.Contains(stdout.String(), "Wrote "+filepath.Join(outDir, posturepkg.ProofFilename)) {
		t.Fatalf("stdout = %q, want write message", stdout.String())
	}

	proofPath := filepath.Clean(filepath.Join(outDir, posturepkg.ProofFilename))
	data, err := os.ReadFile(proofPath)
	if err != nil {
		t.Fatalf("os.ReadFile(): %v", err)
	}

	var capsule posturepkg.Capsule
	if err := json.Unmarshal(data, &capsule); err != nil {
		t.Fatalf("json.Unmarshal(): %v", err)
	}

	if err := posturepkg.Verify(&capsule, pub); err != nil {
		t.Fatalf("posture.Verify(): %v", err)
	}

	if _, err := os.Stat(filepath.Join(outDir, "proof.md")); !os.IsNotExist(err) {
		t.Fatalf("proof.md should not exist, got err=%v", err)
	}
}

func TestPostureEmitCmdMissingKey(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	cfg := config.Defaults()
	cfg.FlightRecorder.Enabled = true
	cfg.FlightRecorder.Dir = filepath.Join(t.TempDir(), "recorder")

	cfgPath := writeCLIConfig(t, cfg)

	cmd := rootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"posture", "emit", "--config", cfgPath})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "flight_recorder.signing_key_path is required") {
		t.Fatalf("cmd.Execute() error = %v, want missing signing key path", err)
	}
}

func TestPostureEmitCmdBadOutputDir(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey(): %v", err)
	}

	keyPath := filepath.Join(t.TempDir(), "signing.key")
	if err := signing.SavePrivateKey(priv, keyPath); err != nil {
		t.Fatalf("signing.SavePrivateKey(): %v", err)
	}

	recorderDir := filepath.Join(t.TempDir(), "recorder")
	writeCLIReceipt(t, recorderDir, priv)

	cfg := config.Defaults()
	cfg.FlightRecorder.Enabled = true
	cfg.FlightRecorder.Dir = recorderDir
	cfg.FlightRecorder.SigningKeyPath = keyPath

	cfgPath := writeCLIConfig(t, cfg)

	badOutput := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(badOutput, []byte("x"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(): %v", err)
	}

	cmd := rootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"posture", "emit", "--config", cfgPath, "--output", badOutput})

	err = cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "create output directory") {
		t.Fatalf("cmd.Execute() error = %v, want output dir failure", err)
	}
}

func writeCLIConfig(t *testing.T, cfg *config.Config) string {
	t.Helper()

	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("yaml.Marshal(): %v", err)
	}

	path := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("os.WriteFile(): %v", err)
	}
	return path
}

func writeCLIReceipt(t *testing.T, dir string, priv ed25519.PrivateKey) {
	t.Helper()

	rec, err := recorder.New(recorder.Config{
		Enabled:         true,
		Dir:             dir,
		SignCheckpoints: true,
	}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New(): %v", err)
	}
	defer func() {
		if err := rec.Close(); err != nil {
			t.Fatalf("rec.Close(): %v", err)
		}
	}()

	emitter := receipt.NewEmitter(receipt.EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: "cfg-hash",
	})
	if emitter == nil {
		t.Fatal("receipt.NewEmitter() returned nil")
	}

	if err := emitter.Emit(receipt.EmitOpts{
		ActionID:  "cli-action",
		Verdict:   config.ActionBlock,
		Layer:     "dlp",
		Transport: "forward",
		Method:    "GET",
		Target:    "https://example.com",
		RequestID: "req-cli",
	}); err != nil {
		t.Fatalf("emitter.Emit(): %v", err)
	}
}
