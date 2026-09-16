// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/luckyPipewrench/pipelock/internal/cli/audit"
	"github.com/luckyPipewrench/pipelock/internal/cli/contain/workspacediff"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	posturepkg "github.com/luckyPipewrench/pipelock/internal/posture"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	testVerifyPolicyEnterprise = posturepkg.PolicyEnterprise
	testVerifyPolicyStrict     = posturepkg.PolicyStrict
	testVerifyPolicyNone       = posturepkg.PolicyNone
)

// testVerifyFixture creates a signed proof.json and key files for testing.
type testVerifyFixture struct {
	ProofPath     string
	PubKeyPath    string
	HexPubKeyPath string
	ConfigPath    string
	Capsule       *posturepkg.Capsule
	PublicKey     ed25519.PublicKey
	PrivateKey    ed25519.PrivateKey
}

func newTestVerifyFixture(t *testing.T, evidence posturepkg.EvidenceBundle) testVerifyFixture {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey(): %v", err)
	}

	// Write config to YAML first, then load it back. This ensures the config
	// hash is consistent between emit and verify (YAML round-trip stable).
	cfgData, err := yaml.Marshal(config.Defaults())
	if err != nil {
		t.Fatalf("yaml.Marshal(): %v", err)
	}
	configPath := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.WriteFile(configPath, cfgData, 0o600); err != nil {
		t.Fatalf("os.WriteFile(config): %v", err)
	}

	cfg, err := cliutil.LoadConfigOrDefault(configPath)
	if err != nil {
		t.Fatalf("LoadConfigOrDefault(): %v", err)
	}

	capsule, err := posturepkg.Emit(cfg, posturepkg.Options{
		SigningKey:     priv,
		EvidenceBundle: &evidence,
	})
	if err != nil {
		t.Fatalf("posture.Emit(): %v", err)
	}

	// Write proof.json.
	proofDir := filepath.Join(t.TempDir(), "proof")
	proofPath, err := posturepkg.WriteProofJSON(proofDir, capsule)
	if err != nil {
		t.Fatalf("posture.WriteProofJSON(): %v", err)
	}

	// Write versioned public key.
	pubKeyPath := filepath.Join(t.TempDir(), "pub.key")
	if err := os.WriteFile(pubKeyPath, []byte(signing.EncodePublicKey(pub)), 0o600); err != nil {
		t.Fatalf("os.WriteFile(pub.key): %v", err)
	}

	// Write hex-encoded public key.
	hexPubKeyPath := filepath.Join(t.TempDir(), "pub.hex")
	if err := os.WriteFile(hexPubKeyPath, []byte(hex.EncodeToString(pub)), 0o600); err != nil {
		t.Fatalf("os.WriteFile(pub.hex): %v", err)
	}

	return testVerifyFixture{
		ProofPath:     proofPath,
		PubKeyPath:    pubKeyPath,
		HexPubKeyPath: hexPubKeyPath,
		ConfigPath:    configPath,
		Capsule:       capsule,
		PublicKey:     pub,
		PrivateKey:    priv,
	}
}

func perfectEvidence() posturepkg.EvidenceBundle {
	recent := time.Now().Add(-1 * time.Hour)
	return posturepkg.EvidenceBundle{
		Discover: posturepkg.DiscoverEvidence{
			TotalServers:      5,
			ProtectedPipelock: 5,
		},
		VerifyInstall: posturepkg.VerifyInstallEvidence{
			FlightRecorderActive: true,
			ReceiptCount:         100,
		},
		Simulate: audit.SimulateResult{
			Total:      10,
			Passed:     10,
			Percentage: 100,
			Scenarios: []audit.ScenarioResult{
				{Category: "DLP", Detected: true},
				{Category: "Injection", Detected: true},
			},
		},
		FlightRecorder: posturepkg.FlightRecorderCounts{
			ReceiptCount:  100,
			LastReceiptAt: &recent,
		},
	}
}

func failEvidence() posturepkg.EvidenceBundle {
	return posturepkg.EvidenceBundle{
		Discover: posturepkg.DiscoverEvidence{
			TotalServers: 5,
			Unprotected:  5,
		},
		VerifyInstall: posturepkg.VerifyInstallEvidence{
			FlightRecorderActive: false,
		},
		Simulate: audit.SimulateResult{
			Total:      10,
			Passed:     0,
			Failed:     10,
			Percentage: 0,
			Scenarios: []audit.ScenarioResult{
				{Category: "DLP", Detected: false},
			},
		},
		FlightRecorder: posturepkg.FlightRecorderCounts{},
	}
}

func TestPostureVerifyPass(t *testing.T) {
	fix := newTestVerifyFixture(t, perfectEvidence())

	var stdout bytes.Buffer
	cmd := rootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"posture", "verify",
		"--proof", fix.ProofPath,
		"--key", fix.PubKeyPath,
		"--policy", testVerifyPolicyEnterprise,
		"--min-score", "85",
		"--max-age", "30d",
		"--max-receipt-age", "7d",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute(): %v", err)
	}

	output := stdout.String()
	if !strings.Contains(output, "PASS") {
		t.Errorf("output missing PASS, got: %s", output)
	}
	if !strings.Contains(output, "score 100/100") {
		t.Errorf("output missing score, got: %s", output)
	}
}

func TestPostureVerifyPassHexKey(t *testing.T) {
	fix := newTestVerifyFixture(t, perfectEvidence())

	var stdout bytes.Buffer
	cmd := rootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"posture", "verify",
		"--proof", fix.ProofPath,
		"--key", fix.HexPubKeyPath,
		"--policy", testVerifyPolicyNone,
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute(): %v", err)
	}

	if !strings.Contains(stdout.String(), "PASS") {
		t.Errorf("output missing PASS with hex key, got: %s", stdout.String())
	}
}

func TestPostureVerifyJSONOutput(t *testing.T) {
	fix := newTestVerifyFixture(t, perfectEvidence())

	var stdout bytes.Buffer
	cmd := rootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"posture", "verify",
		"--proof", fix.ProofPath,
		"--key", fix.PubKeyPath,
		"--policy", testVerifyPolicyNone,
		"--json",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute(): %v", err)
	}

	var result posturepkg.VerifyResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("json.Unmarshal(): %v (output: %s)", err, stdout.String())
	}
	if !result.Verified {
		t.Error("result.Verified = false, want true")
	}
	if !result.Passed {
		t.Error("result.Passed = false, want true")
	}
	if result.Score != 100 {
		t.Errorf("result.Score = %d, want 100", result.Score)
	}
	if result.PolicyVersion != posturepkg.PolicyVersion {
		t.Errorf("result.PolicyVersion = %q, want %q", result.PolicyVersion, posturepkg.PolicyVersion)
	}
	if result.ScoringVersion != posturepkg.ScoringVersion {
		t.Errorf("result.ScoringVersion = %q, want %q", result.ScoringVersion, posturepkg.ScoringVersion)
	}
}

func TestPostureVerifyJSONBadSignature(t *testing.T) {
	fix := newTestVerifyFixture(t, perfectEvidence())

	tamperedCapsule := *fix.Capsule
	tamperedCapsule.ConfigHash = "tampered"
	proofDir := filepath.Join(t.TempDir(), "tampered-json")
	proofPath, err := posturepkg.WriteProofJSON(proofDir, &tamperedCapsule)
	if err != nil {
		t.Fatalf("WriteProofJSON(): %v", err)
	}

	var stdout bytes.Buffer
	cmd := rootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"posture", "verify",
		"--proof", proofPath,
		"--key", fix.PubKeyPath,
		"--json",
	})

	err = cmd.Execute()
	if err == nil {
		t.Fatal("cmd.Execute() = nil, want error")
	}
	assertExitCode(t, err, exitVerifyIntegrity)

	var result posturepkg.VerifyResult
	if jsonErr := json.Unmarshal(stdout.Bytes(), &result); jsonErr != nil {
		t.Fatalf("json.Unmarshal(): %v (output: %s)", jsonErr, stdout.String())
	}
	if result.Verified {
		t.Error("result.Verified = true, want false")
	}
	if !strings.Contains(result.Error, "verification failed") {
		t.Errorf("result.Error = %q, want verification failure", result.Error)
	}
	if result.PolicyVersion != posturepkg.PolicyVersion {
		t.Errorf("result.PolicyVersion = %q, want %q", result.PolicyVersion, posturepkg.PolicyVersion)
	}
}

func TestPostureVerifyBadSignature(t *testing.T) {
	fix := newTestVerifyFixture(t, perfectEvidence())

	// Write a proof with a tampered config hash.
	tamperedCapsule := *fix.Capsule
	tamperedCapsule.ConfigHash = "tampered"
	proofDir := filepath.Join(t.TempDir(), "tampered")
	proofPath, err := posturepkg.WriteProofJSON(proofDir, &tamperedCapsule)
	if err != nil {
		t.Fatalf("WriteProofJSON(): %v", err)
	}

	cmd := rootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"posture", "verify",
		"--proof", proofPath,
		"--key", fix.PubKeyPath,
	})

	err = cmd.Execute()
	if err == nil {
		t.Fatal("cmd.Execute() = nil, want error")
	}
	assertExitCode(t, err, exitVerifyIntegrity)
}

func TestPostureVerifyRejectsTrailingPayload(t *testing.T) {
	fix := newTestVerifyFixture(t, perfectEvidence())

	data, err := os.ReadFile(fix.ProofPath)
	if err != nil {
		t.Fatalf("os.ReadFile(): %v", err)
	}
	trailingProof := filepath.Join(t.TempDir(), "proof-trailing.json")
	if err := os.WriteFile(trailingProof, append(bytes.TrimSpace(data), []byte(`{"tampered":true}`)...), 0o600); err != nil {
		t.Fatalf("os.WriteFile(): %v", err)
	}

	cmd := rootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"posture", "verify",
		"--proof", trailingProof,
		"--key", fix.PubKeyPath,
		"--policy", testVerifyPolicyNone,
		"--min-score", "0",
	})

	err = cmd.Execute()
	if err == nil {
		t.Fatal("cmd.Execute() = nil, want error for trailing payload")
	}
	assertExitCode(t, err, exitVerifyIntegrity)
}

func TestPostureVerifyExpiredCapsule(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey(): %v", err)
	}

	capsule, err := posturepkg.Emit(config.Defaults(), posturepkg.Options{
		SigningKey:     priv,
		ExpirationDays: 1,
		EvidenceBundle: &posturepkg.EvidenceBundle{},
	})
	if err != nil {
		t.Fatalf("Emit(): %v", err)
	}

	// Write the valid capsule as JSON, then patch ExpiresAt to be in the past.
	// Verify() checks expiry before signature, so the tampered time triggers
	// an integrity failure without needing a valid signature over it.
	proofDir := filepath.Join(t.TempDir(), "expired")
	expiredProof := writeExpiredProof(t, proofDir, capsule)

	pubKeyPath := writeVersionedPubKey(t, pub)

	var stdout bytes.Buffer
	cmd := rootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"posture", "verify",
		"--proof", expiredProof,
		"--key", pubKeyPath,
		"--max-age", "30d",
	})

	err = cmd.Execute()
	if err == nil {
		t.Fatal("cmd.Execute() = nil, want error for expired capsule")
	}
	assertExitCode(t, err, exitVerifyIntegrity)
}

func TestPostureVerifyLowScore(t *testing.T) {
	fix := newTestVerifyFixture(t, failEvidence())

	cmd := rootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"posture", "verify",
		"--proof", fix.ProofPath,
		"--key", fix.PubKeyPath,
		"--policy", testVerifyPolicyNone,
		"--min-score", "85",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("cmd.Execute() = nil, want error for low score")
	}
	assertExitCode(t, err, exitVerifyPolicyFail)
}

func TestPostureVerifyEnterpriseFailure(t *testing.T) {
	fix := newTestVerifyFixture(t, failEvidence())

	var stdout bytes.Buffer
	cmd := rootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"posture", "verify",
		"--proof", fix.ProofPath,
		"--key", fix.PubKeyPath,
		"--policy", testVerifyPolicyEnterprise,
		"--min-score", "0",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("cmd.Execute() = nil, want error for enterprise policy failure")
	}
	assertExitCode(t, err, exitVerifyPolicyFail)

	output := stdout.String()
	if !strings.Contains(output, "FAIL") {
		t.Errorf("output missing FAIL, got: %s", output)
	}
	if !strings.Contains(output, "unprotected_servers") {
		t.Errorf("output missing unprotected_servers failure, got: %s", output)
	}
}

func TestPostureVerifyConfigHashMismatch(t *testing.T) {
	fix := newTestVerifyFixture(t, perfectEvidence())

	// Write a different config that will produce a different hash.
	differentCfg := config.Defaults()
	differentCfg.Mode = config.ModeStrict
	cfgData, err := yaml.Marshal(differentCfg)
	if err != nil {
		t.Fatalf("yaml.Marshal(): %v", err)
	}
	differentConfigPath := filepath.Join(t.TempDir(), "different.yaml")
	if err := os.WriteFile(differentConfigPath, cfgData, 0o600); err != nil {
		t.Fatalf("os.WriteFile(): %v", err)
	}

	cmd := rootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"posture", "verify",
		"--proof", fix.ProofPath,
		"--key", fix.PubKeyPath,
		"--policy", testVerifyPolicyEnterprise,
		"--min-score", "0",
		"--config", differentConfigPath,
	})

	err = cmd.Execute()
	if err == nil {
		t.Fatal("cmd.Execute() = nil, want error for config hash mismatch")
	}
	assertExitCode(t, err, exitVerifyPolicyFail)
}

func TestPostureVerifyConfigHashMatch(t *testing.T) {
	fix := newTestVerifyFixture(t, perfectEvidence())

	var stdout bytes.Buffer
	cmd := rootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"posture", "verify",
		"--proof", fix.ProofPath,
		"--key", fix.PubKeyPath,
		"--policy", testVerifyPolicyEnterprise,
		"--config", fix.ConfigPath,
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute(): %v", err)
	}

	output := stdout.String()
	if !strings.Contains(output, "Config hash: match") {
		t.Errorf("output missing config hash match, got: %s", output)
	}
}

func TestPostureVerifyJSONPolicyFail(t *testing.T) {
	fix := newTestVerifyFixture(t, failEvidence())

	var stdout bytes.Buffer
	cmd := rootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"posture", "verify",
		"--proof", fix.ProofPath,
		"--key", fix.PubKeyPath,
		"--policy", testVerifyPolicyEnterprise,
		"--min-score", "0",
		"--json",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("cmd.Execute() = nil, want error for policy failure")
	}
	assertExitCode(t, err, exitVerifyPolicyFail)

	var result posturepkg.VerifyResult
	if jsonErr := json.Unmarshal(stdout.Bytes(), &result); jsonErr != nil {
		t.Fatalf("json.Unmarshal(): %v (output: %s)", jsonErr, stdout.String())
	}
	if result.Passed {
		t.Error("result.Passed = true, want false")
	}
}

func TestPostureVerifyMissingProofFile(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey(): %v", err)
	}
	pubKeyPath := writeVersionedPubKey(t, pub)

	cmd := rootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"posture", "verify",
		"--proof", "/nonexistent/proof.json",
		"--key", pubKeyPath,
	})

	err = cmd.Execute()
	if err == nil {
		t.Fatal("cmd.Execute() = nil, want error for missing proof")
	}
	assertExitCode(t, err, exitVerifyIntegrity)
}

func TestPostureVerifyJSONMissingProofFile(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey(): %v", err)
	}
	pubKeyPath := writeVersionedPubKey(t, pub)

	var stdout bytes.Buffer
	cmd := rootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"posture", "verify",
		"--proof", "/nonexistent/proof.json",
		"--key", pubKeyPath,
		"--json",
	})

	err = cmd.Execute()
	if err == nil {
		t.Fatal("cmd.Execute() = nil, want error for missing proof")
	}
	assertExitCode(t, err, exitVerifyIntegrity)

	var result posturepkg.VerifyResult
	if jsonErr := json.Unmarshal(stdout.Bytes(), &result); jsonErr != nil {
		t.Fatalf("json.Unmarshal(): %v (output: %s)", jsonErr, stdout.String())
	}
	if result.Verified {
		t.Error("result.Verified = true, want false")
	}
	if !strings.Contains(result.Error, "loading proof") {
		t.Errorf("result.Error = %q, want loading proof failure", result.Error)
	}
}

func TestPostureVerifyBadKeyFile(t *testing.T) {
	fix := newTestVerifyFixture(t, perfectEvidence())

	badKeyPath := filepath.Join(t.TempDir(), "bad.key")
	if err := os.WriteFile(badKeyPath, []byte("not-a-key-at-all"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(): %v", err)
	}

	cmd := rootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"posture", "verify",
		"--proof", fix.ProofPath,
		"--key", badKeyPath,
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("cmd.Execute() = nil, want error for bad key")
	}
	assertExitCode(t, err, exitVerifyIntegrity)
}

func TestPostureVerifyJSONBadKeyFile(t *testing.T) {
	fix := newTestVerifyFixture(t, perfectEvidence())

	badKeyPath := filepath.Join(t.TempDir(), "bad-json.key")
	if err := os.WriteFile(badKeyPath, []byte("not-a-key-at-all"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(): %v", err)
	}

	var stdout bytes.Buffer
	cmd := rootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"posture", "verify",
		"--proof", fix.ProofPath,
		"--key", badKeyPath,
		"--json",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("cmd.Execute() = nil, want error for bad key")
	}
	assertExitCode(t, err, exitVerifyIntegrity)

	var result posturepkg.VerifyResult
	if jsonErr := json.Unmarshal(stdout.Bytes(), &result); jsonErr != nil {
		t.Fatalf("json.Unmarshal(): %v (output: %s)", jsonErr, stdout.String())
	}
	if result.Verified {
		t.Error("result.Verified = true, want false")
	}
	if !strings.Contains(result.Error, "loading public key") {
		t.Errorf("result.Error = %q, want loading public key failure", result.Error)
	}
}

func TestPostureVerifyBadMaxAge(t *testing.T) {
	fix := newTestVerifyFixture(t, perfectEvidence())

	cmd := rootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"posture", "verify",
		"--proof", fix.ProofPath,
		"--key", fix.PubKeyPath,
		"--max-age", "bad",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("cmd.Execute() = nil, want error for bad max-age")
	}
	if !strings.Contains(err.Error(), "parsing --max-age") {
		t.Errorf("error = %v, want max-age parse error", err)
	}
}

func TestPostureVerifyBadMaxReceiptAge(t *testing.T) {
	fix := newTestVerifyFixture(t, perfectEvidence())

	cmd := rootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"posture", "verify",
		"--proof", fix.ProofPath,
		"--key", fix.PubKeyPath,
		"--max-receipt-age", "xyz",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("cmd.Execute() = nil, want error for bad max-receipt-age")
	}
	if !strings.Contains(err.Error(), "parsing --max-receipt-age") {
		t.Errorf("error = %v, want max-receipt-age parse error", err)
	}
}

func TestPostureVerifyBadMinScore(t *testing.T) {
	fix := newTestVerifyFixture(t, perfectEvidence())

	cmd := rootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"posture", "verify",
		"--proof", fix.ProofPath,
		"--key", fix.PubKeyPath,
		"--min-score", "101",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("cmd.Execute() = nil, want error for bad min-score")
	}
	if !strings.Contains(err.Error(), "--min-score must be between 0 and 100") {
		t.Errorf("error = %v, want min-score validation error", err)
	}
}

func TestPostureVerifyOldCapsule(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey(): %v", err)
	}

	capsule, err := posturepkg.Emit(config.Defaults(), posturepkg.Options{
		SigningKey:     priv,
		ExpirationDays: 90,
		EvidenceBundle: &posturepkg.EvidenceBundle{},
	})
	if err != nil {
		t.Fatalf("Emit(): %v", err)
	}

	proofDir := filepath.Join(t.TempDir(), "old")
	oldProof := writeOldProof(t, proofDir, capsule, priv)

	pubKeyPath := writeVersionedPubKey(t, pub)

	var stdout bytes.Buffer
	cmd := rootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"posture", "verify",
		"--proof", oldProof,
		"--key", pubKeyPath,
		"--max-age", "30d",
	})

	err = cmd.Execute()
	if err == nil {
		t.Fatal("cmd.Execute() = nil, want error for capsule exceeding max age")
	}
	assertExitCode(t, err, exitVerifyPolicyFail)
	if !strings.Contains(stdout.String(), "capsule_too_old") {
		t.Errorf("output missing capsule_too_old failure, got: %s", stdout.String())
	}
}

func TestPostureVerifyRequireDiscovery(t *testing.T) {
	recent := time.Now().Add(-1 * time.Hour)
	emptyDiscover := posturepkg.EvidenceBundle{
		Discover: posturepkg.DiscoverEvidence{},
		VerifyInstall: posturepkg.VerifyInstallEvidence{
			FlightRecorderActive: true,
			ReceiptCount:         10,
		},
		Simulate: audit.SimulateResult{
			Total:      1,
			Passed:     1,
			Percentage: 100,
			Scenarios: []audit.ScenarioResult{
				{Category: "DLP", Detected: true},
			},
		},
		FlightRecorder: posturepkg.FlightRecorderCounts{
			ReceiptCount:  10,
			LastReceiptAt: &recent,
		},
	}

	fix := newTestVerifyFixture(t, emptyDiscover)

	cmd := rootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"posture", "verify",
		"--proof", fix.ProofPath,
		"--key", fix.PubKeyPath,
		"--policy", testVerifyPolicyNone,
		"--min-score", "0",
		"--require-discovery",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("cmd.Execute() = nil, want error for require-discovery")
	}
	assertExitCode(t, err, exitVerifyPolicyFail)
}

func TestPostureVerifyRequireDiscoveryTreatsParseErrorsAsNoServers(t *testing.T) {
	recent := time.Now().Add(-1 * time.Hour)
	parseOnly := posturepkg.EvidenceBundle{
		Discover: posturepkg.DiscoverEvidence{
			ParseErrors: 2,
		},
		VerifyInstall: posturepkg.VerifyInstallEvidence{
			FlightRecorderActive: true,
			ReceiptCount:         10,
		},
		Simulate: audit.SimulateResult{
			Total:      1,
			Passed:     1,
			Percentage: 100,
			Scenarios: []audit.ScenarioResult{
				{Category: "DLP", Detected: true},
			},
		},
		FlightRecorder: posturepkg.FlightRecorderCounts{
			ReceiptCount:  10,
			LastReceiptAt: &recent,
		},
	}

	fix := newTestVerifyFixture(t, parseOnly)

	cmd := rootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"posture", "verify",
		"--proof", fix.ProofPath,
		"--key", fix.PubKeyPath,
		"--policy", testVerifyPolicyNone,
		"--min-score", "0",
		"--require-discovery",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("cmd.Execute() = nil, want error for parse-errors-only discovery")
	}
	assertExitCode(t, err, exitVerifyPolicyFail)
}

func TestPostureVerifyStrictTreatsParseErrorsAsNoServers(t *testing.T) {
	recent := time.Now().Add(-1 * time.Hour)
	parseOnly := posturepkg.EvidenceBundle{
		Discover: posturepkg.DiscoverEvidence{
			ParseErrors: 2,
		},
		VerifyInstall: posturepkg.VerifyInstallEvidence{
			FlightRecorderActive: true,
			ReceiptCount:         10,
		},
		Simulate: audit.SimulateResult{
			Total:      1,
			Passed:     1,
			Percentage: 100,
			Scenarios: []audit.ScenarioResult{
				{Category: "DLP", Detected: true},
			},
		},
		FlightRecorder: posturepkg.FlightRecorderCounts{
			ReceiptCount:  10,
			LastReceiptAt: &recent,
		},
	}

	fix := newTestVerifyFixture(t, parseOnly)

	var stdout bytes.Buffer
	cmd := rootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"posture", "verify",
		"--proof", fix.ProofPath,
		"--key", fix.PubKeyPath,
		"--policy", testVerifyPolicyStrict,
		"--min-score", "0",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("cmd.Execute() = nil, want error for strict parse-errors-only discovery")
	}
	assertExitCode(t, err, exitVerifyPolicyFail)

	output := stdout.String()
	if !strings.Contains(output, "FAIL: no_servers_discovered") {
		t.Fatalf("output missing no_servers_discovered failure, got: %s", output)
	}
	if !strings.Contains(output, "FAIL: discovery_parse_errors") {
		t.Fatalf("output missing discovery_parse_errors failure, got: %s", output)
	}
	if strings.Contains(output, "WARN: no_servers_discovered") {
		t.Fatalf("output should not duplicate no_servers_discovered as warning under strict, got: %s", output)
	}
}

func TestPostureVerifyStrictFailsEmptyDiscovery(t *testing.T) {
	recent := time.Now().Add(-1 * time.Hour)
	emptyDiscover := posturepkg.EvidenceBundle{
		Discover: posturepkg.DiscoverEvidence{},
		VerifyInstall: posturepkg.VerifyInstallEvidence{
			FlightRecorderActive: true,
			ReceiptCount:         10,
		},
		Simulate: audit.SimulateResult{
			Total:      1,
			Passed:     1,
			Percentage: 100,
			Scenarios: []audit.ScenarioResult{
				{Category: "DLP", Detected: true},
			},
		},
		FlightRecorder: posturepkg.FlightRecorderCounts{
			ReceiptCount:  10,
			LastReceiptAt: &recent,
		},
	}

	fix := newTestVerifyFixture(t, emptyDiscover)

	var stdout bytes.Buffer
	cmd := rootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"posture", "verify",
		"--proof", fix.ProofPath,
		"--key", fix.PubKeyPath,
		"--policy", testVerifyPolicyStrict,
		"--min-score", "0",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("cmd.Execute() = nil, want error for strict empty discovery")
	}
	assertExitCode(t, err, exitVerifyPolicyFail)

	output := stdout.String()
	if !strings.Contains(output, "FAIL: no_servers_discovered") {
		t.Fatalf("output missing no_servers_discovered failure, got: %s", output)
	}
	if strings.Contains(output, "WARN: no_servers_discovered") {
		t.Fatalf("output should not duplicate no_servers_discovered as warning under strict, got: %s", output)
	}
}

func TestPostureVerifyPolicyTypo(t *testing.T) {
	fix := newTestVerifyFixture(t, perfectEvidence())

	cmd := rootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"posture", "verify",
		"--proof", fix.ProofPath,
		"--key", fix.PubKeyPath,
		"--policy", "bad-policy",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("cmd.Execute() = nil, want error for invalid policy")
	}
	assertExitCode(t, err, exitVerifyPolicyFail)
}

func TestPostureVerifyMaxAgeDisabledLabel(t *testing.T) {
	fix := newTestVerifyFixture(t, perfectEvidence())

	var stdout bytes.Buffer
	cmd := rootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"posture", "verify",
		"--proof", fix.ProofPath,
		"--key", fix.PubKeyPath,
		"--max-age", "0d",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute(): %v", err)
	}
	if !strings.Contains(stdout.String(), "max: disabled") {
		t.Errorf("output missing disabled max-age label, got: %s", stdout.String())
	}
}

func TestPostureVerifyOversizeProofFile(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey(): %v", err)
	}
	pubKeyPath := writeVersionedPubKey(t, pub)

	proofPath := filepath.Join(t.TempDir(), "proof.json")
	data := bytes.Repeat([]byte("a"), maxProofJSONBytes+1)
	if err := os.WriteFile(proofPath, data, 0o600); err != nil {
		t.Fatalf("os.WriteFile(): %v", err)
	}

	cmd := rootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"posture", "verify",
		"--proof", proofPath,
		"--key", pubKeyPath,
	})

	err = cmd.Execute()
	if err == nil {
		t.Fatal("cmd.Execute() = nil, want error for oversize proof")
	}
	assertExitCode(t, err, exitVerifyIntegrity)
}

func TestParseDays(t *testing.T) {
	tests := []struct {
		input   string
		want    int
		wantErr bool
	}{
		{input: "30d", want: 30},
		{input: "7d", want: 7},
		{input: "0d", want: 0},
		{input: "365d", want: 365},
		{input: "bad", wantErr: true},
		{input: "30", wantErr: true},
		{input: "-1d", wantErr: true},
		{input: "abcd", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseDays(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseDays(%q) = %d, want error", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Errorf("parseDays(%q) error = %v", tt.input, err)
				return
			}
			if got != tt.want {
				t.Errorf("parseDays(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestLoadPublicKeyVersionedFormat(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey(): %v", err)
	}

	path := writeVersionedPubKey(t, pub)
	loaded, err := loadPublicKey(path)
	if err != nil {
		t.Fatalf("loadPublicKey(): %v", err)
	}
	if !pub.Equal(loaded) {
		t.Error("loaded key does not match original")
	}
}

func TestLoadPublicKeyHexFormat(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey(): %v", err)
	}

	path := filepath.Join(t.TempDir(), "pub.hex")
	if err := os.WriteFile(path, []byte(hex.EncodeToString(pub)), 0o600); err != nil {
		t.Fatalf("os.WriteFile(): %v", err)
	}

	loaded, err := loadPublicKey(path)
	if err != nil {
		t.Fatalf("loadPublicKey(): %v", err)
	}
	if !pub.Equal(loaded) {
		t.Error("loaded key does not match original")
	}
}

func TestLoadPublicKeyRawHexArgument(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey(): %v", err)
	}

	loaded, err := loadPublicKey(hex.EncodeToString(pub))
	if err != nil {
		t.Fatalf("loadPublicKey(): %v", err)
	}
	if !pub.Equal(loaded) {
		t.Error("loaded key does not match original")
	}
}

func TestLoadPublicKeyBadFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.key")
	if err := os.WriteFile(path, []byte("not-a-key"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(): %v", err)
	}

	_, err := loadPublicKey(path)
	if err == nil {
		t.Fatal("loadPublicKey() = nil, want error")
	}
}

func TestLoadPublicKeyMissingFile(t *testing.T) {
	_, err := loadPublicKey(filepath.Join(t.TempDir(), "missing.key"))
	if err == nil {
		t.Fatal("loadPublicKey() = nil, want error for missing file")
	}
}

func TestLoadPublicKeyWrongHexLength(t *testing.T) {
	path := filepath.Join(t.TempDir(), "short.hex")
	if err := os.WriteFile(path, []byte("deadbeef"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(): %v", err)
	}

	_, err := loadPublicKey(path)
	if err == nil {
		t.Fatal("loadPublicKey() = nil, want error for wrong length")
	}
	if !strings.Contains(err.Error(), "invalid public key length") {
		t.Errorf("error = %v, want length error", err)
	}
}

// --- helpers ---

func writeVersionedPubKey(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pub.key")
	if err := os.WriteFile(path, []byte(signing.EncodePublicKey(pub)), 0o600); err != nil {
		t.Fatalf("os.WriteFile(): %v", err)
	}
	return path
}

// writeExpiredProof writes a proof.json with ExpiresAt set to the past.
func writeExpiredProof(t *testing.T, dir string, capsule *posturepkg.Capsule) string {
	t.Helper()

	// Marshal, patch expires_at, write.
	data, err := json.Marshal(capsule)
	if err != nil {
		t.Fatalf("json.Marshal(): %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal(): %v", err)
	}

	expired := time.Now().Add(-1 * time.Hour)
	expiredJSON, err := json.Marshal(expired)
	if err != nil {
		t.Fatalf("json.Marshal(expired): %v", err)
	}
	raw["expires_at"] = expiredJSON

	patched, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("json.Marshal(patched): %v", err)
	}

	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("os.MkdirAll(): %v", err)
	}
	path := filepath.Join(dir, posturepkg.ProofFilename)
	if err := os.WriteFile(path, patched, 0o600); err != nil {
		t.Fatalf("os.WriteFile(): %v", err)
	}
	return path
}

// writeOldProof writes a proof.json with GeneratedAt set to 35 days ago and a
// valid signature so the CLI can classify it as a freshness policy failure.
func writeOldProof(t *testing.T, dir string, capsule *posturepkg.Capsule, priv ed25519.PrivateKey) string {
	t.Helper()

	oldCapsule := *capsule
	oldCapsule.GeneratedAt = time.Now().Add(-35 * 24 * time.Hour)
	oldCapsule.ExpiresAt = time.Now().Add(55 * 24 * time.Hour)
	oldCapsule.Signature = resignCapsuleCLI(t, &oldCapsule, priv)

	patched, err := json.Marshal(&oldCapsule)
	if err != nil {
		t.Fatalf("json.Marshal(oldCapsule): %v", err)
	}

	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("os.MkdirAll(): %v", err)
	}
	path := filepath.Join(dir, posturepkg.ProofFilename)
	if err := os.WriteFile(path, patched, 0o600); err != nil {
		t.Fatalf("os.WriteFile(): %v", err)
	}
	return path
}

func resignCapsuleCLI(t *testing.T, capsule *posturepkg.Capsule, priv ed25519.PrivateKey) string {
	t.Helper()

	payload, err := signableCapsuleJSON(t, capsule)
	if err != nil {
		t.Fatalf("signableCapsuleJSON(): %v", err)
	}
	return hex.EncodeToString(ed25519.Sign(priv, payload))
}

func signableCapsuleJSON(t *testing.T, capsule *posturepkg.Capsule) ([]byte, error) {
	t.Helper()

	type signableCapsule struct {
		SchemaVersion string                    `json:"schema_version"`
		GeneratedAt   time.Time                 `json:"generated_at"`
		ExpiresAt     time.Time                 `json:"expires_at"`
		ToolVersion   string                    `json:"tool_version"`
		ConfigHash    string                    `json:"config_hash"`
		Evidence      posturepkg.EvidenceBundle `json:"evidence"`
	}

	raw, err := json.Marshal(signableCapsule{
		SchemaVersion: capsule.SchemaVersion,
		GeneratedAt:   capsule.GeneratedAt,
		ExpiresAt:     capsule.ExpiresAt,
		ToolVersion:   capsule.ToolVersion,
		ConfigHash:    capsule.ConfigHash,
		Evidence:      capsule.Evidence,
	})
	if err != nil {
		return nil, err
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	var parsed any
	if err := dec.Decode(&parsed); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := appendCanonicalJSON(&buf, parsed); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func appendCanonicalJSON(buf *bytes.Buffer, v any) error {
	switch value := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if value {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		data, err := json.Marshal(value)
		if err != nil {
			return err
		}
		buf.Write(data)
	case json.Number:
		buf.WriteString(value.String())
	case float64:
		data, err := json.Marshal(value)
		if err != nil {
			return err
		}
		buf.Write(data)
	case []any:
		buf.WriteByte('[')
		for i, item := range value {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := appendCanonicalJSON(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		buf.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			keyJSON, err := json.Marshal(key)
			if err != nil {
				return err
			}
			buf.Write(keyJSON)
			buf.WriteByte(':')
			if err := appendCanonicalJSON(buf, value[key]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		data, err := json.Marshal(value)
		if err != nil {
			return err
		}
		buf.Write(data)
	}
	return nil
}

// twoCapsulesSameKey emits two DISTINCT, independently-valid posture capsules
// signed by the SAME key, so a mismatched-pairing test isolates the capsule
// DIGEST check from signer-key mismatch (a different bug this test must not
// accidentally exercise instead).
func twoCapsulesSameKey(t *testing.T, evidence posturepkg.EvidenceBundle) (capsuleAPath, capsuleBPath, pubKeyPath string, priv ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	cfgData, err := yaml.Marshal(config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.WriteFile(configPath, cfgData, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := cliutil.LoadConfigOrDefault(configPath)
	if err != nil {
		t.Fatal(err)
	}
	capsuleA, err := posturepkg.Emit(cfg, posturepkg.Options{SigningKey: priv, EvidenceBundle: &evidence})
	if err != nil {
		t.Fatal(err)
	}
	// A tiny expiration-window difference guarantees distinct capsule bytes
	// (hence a distinct hash) even if GeneratedAt granularity collides.
	capsuleB, err := posturepkg.Emit(cfg, posturepkg.Options{SigningKey: priv, EvidenceBundle: &evidence, ExpirationDays: posturepkg.DefaultExpirationDays + 1})
	if err != nil {
		t.Fatal(err)
	}
	pathA, err := posturepkg.WriteProofJSON(filepath.Join(t.TempDir(), "a"), capsuleA)
	if err != nil {
		t.Fatal(err)
	}
	pathB, err := posturepkg.WriteProofJSON(filepath.Join(t.TempDir(), "b"), capsuleB)
	if err != nil {
		t.Fatal(err)
	}
	if pathA == pathB {
		t.Fatalf("test setup bug: same path for both capsules")
	}
	hashA, err := workspacediff.HashFileSHA256(pathA)
	if err != nil {
		t.Fatal(err)
	}
	hashB, err := workspacediff.HashFileSHA256(pathB)
	if err != nil {
		t.Fatal(err)
	}
	if hashA == hashB {
		t.Fatalf("test setup bug: both capsules hashed identically")
	}
	pubKeyPath = filepath.Join(t.TempDir(), "pub.key")
	if err := os.WriteFile(pubKeyPath, []byte(signing.EncodePublicKey(pub)), 0o600); err != nil {
		t.Fatal(err)
	}
	return pathA, pathB, pubKeyPath, priv
}

// TestPostureVerify_WorkspaceStatement_MismatchedCapsuleRejected is H1's CLI
// surface proof: a workspace change statement genuinely signed and bound to
// ONE capsule, verified against a DIFFERENT capsule (SAME signer key, so this
// isolates the digest-binding check from an unrelated signer-key mismatch)
// via the same shipped `posture verify` command, must be rejected. Before
// this flag existed, no shipped command checked the pairing at all.
func TestPostureVerify_WorkspaceStatement_MismatchedCapsuleRejected(t *testing.T) {
	capsuleAPath, capsuleBPath, pubKeyPath, priv := twoCapsulesSameKey(t, perfectEvidence())

	capsuleAHash, err := workspacediff.HashFileSHA256(capsuleAPath)
	if err != nil {
		t.Fatalf("hash capsule A: %v", err)
	}
	signed, err := workspacediff.Sign([]workspacediff.Statement{{Root: "/granted"}}, capsuleAHash, priv)
	if err != nil {
		t.Fatalf("sign statement for capsule A: %v", err)
	}
	stmtPath := filepath.Join(t.TempDir(), "workspace-change-statement.json")
	data, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stmtPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	cmd := rootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{
		"posture", "verify",
		"--proof", capsuleBPath, // WRONG capsule for this statement, same signer key.
		"--key", pubKeyPath,
		"--policy", testVerifyPolicyNone,
		"--workspace-statement", stmtPath,
	})
	err = cmd.Execute()
	if err == nil {
		t.Fatalf("expected posture verify to reject a statement bound to a different capsule")
	}
	assertExitCode(t, err, exitVerifyIntegrity)
}

func TestPostureVerify_WorkspaceStatement_JSONBindingFailureReportsUnbound(t *testing.T) {
	capsuleAPath, capsuleBPath, pubKeyPath, priv := twoCapsulesSameKey(t, perfectEvidence())

	capsuleAHash, err := workspacediff.HashFileSHA256(capsuleAPath)
	if err != nil {
		t.Fatalf("hash capsule A: %v", err)
	}
	signed, err := workspacediff.Sign([]workspacediff.Statement{{Root: "/granted"}}, capsuleAHash, priv)
	if err != nil {
		t.Fatalf("sign statement for capsule A: %v", err)
	}
	stmtPath := filepath.Join(t.TempDir(), "workspace-change-statement.json")
	data, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stmtPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	cmd := rootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"posture", "verify",
		"--proof", capsuleBPath,
		"--key", pubKeyPath,
		"--policy", testVerifyPolicyNone,
		"--workspace-statement", stmtPath,
		"--json",
	})
	err = cmd.Execute()
	if err == nil {
		t.Fatal("expected posture verify to reject a statement bound to a different capsule")
	}
	assertExitCode(t, err, exitVerifyIntegrity)

	var out struct {
		WorkspaceStatement *struct {
			Bound  bool   `json:"bound"`
			Reason string `json:"reason"`
		} `json:"workspace_statement"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\noutput:\n%s", err, stdout.String())
	}
	if out.WorkspaceStatement == nil || out.WorkspaceStatement.Bound {
		t.Fatalf("workspace_statement = %+v, want bound=false", out.WorkspaceStatement)
	}
	if out.WorkspaceStatement.Reason == "" {
		t.Fatalf("workspace_statement.reason missing from output:\n%s", stdout.String())
	}
}

// TestPostureVerify_WorkspaceStatement_MatchedPairPasses is the positive
// control for the same surface: the SAME capsule the statement is bound to.
// TestPostureVerify_WorkspaceStatement_JSONModeStaysValidJSON is M7: before
// the fix, "  Workspace change statement: signature valid..." was printed
// as a bare prose line even under --json, corrupting stdout so it no longer
// parses as one JSON document. The binding outcome must live INSIDE the
// JSON result instead.
func TestPostureVerify_WorkspaceStatement_JSONModeStaysValidJSON(t *testing.T) {
	fix := newTestVerifyFixture(t, perfectEvidence())

	capsuleHash, err := workspacediff.HashFileSHA256(fix.ProofPath)
	if err != nil {
		t.Fatalf("hash capsule: %v", err)
	}
	signed, err := workspacediff.Sign([]workspacediff.Statement{{Root: "/granted"}}, capsuleHash, fix.PrivateKey)
	if err != nil {
		t.Fatalf("sign statement: %v", err)
	}
	stmtPath := filepath.Join(t.TempDir(), "workspace-change-statement.json")
	data, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stmtPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	cmd := rootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"posture", "verify",
		"--proof", fix.ProofPath,
		"--key", fix.PubKeyPath,
		"--policy", testVerifyPolicyNone,
		"--workspace-statement", stmtPath,
		"--json",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute(): %v", err)
	}

	// The whole of stdout must parse as ONE JSON document: any stray prose
	// line (before or after) breaks this.
	var out struct {
		Verified           bool `json:"verified"`
		Passed             bool `json:"passed"`
		WorkspaceStatement *struct {
			Bound bool `json:"bound"`
		} `json:"workspace_statement"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\noutput:\n%s", err, stdout.String())
	}
	if !out.Verified || !out.Passed {
		t.Fatalf("expected a passing verified result, got %+v", out)
	}
	if out.WorkspaceStatement == nil || !out.WorkspaceStatement.Bound {
		t.Fatalf("expected workspace_statement.bound=true in the JSON result, got %+v", out.WorkspaceStatement)
	}
}

func TestPostureVerify_WorkspaceStatement_MatchedPairPasses(t *testing.T) {
	fix := newTestVerifyFixture(t, perfectEvidence())

	capsuleHash, err := workspacediff.HashFileSHA256(fix.ProofPath)
	if err != nil {
		t.Fatalf("hash capsule: %v", err)
	}
	signed, err := workspacediff.Sign([]workspacediff.Statement{{Root: "/granted"}}, capsuleHash, fix.PrivateKey)
	if err != nil {
		t.Fatalf("sign statement: %v", err)
	}
	stmtPath := filepath.Join(t.TempDir(), "workspace-change-statement.json")
	data, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stmtPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	cmd := rootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"posture", "verify",
		"--proof", fix.ProofPath,
		"--key", fix.PubKeyPath,
		"--policy", testVerifyPolicyNone,
		"--workspace-statement", stmtPath,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute(): %v", err)
	}
	if !strings.Contains(stdout.String(), "Workspace change statement: signature valid and bound to this capsule") {
		t.Fatalf("expected the binding confirmation line, got:\n%s", stdout.String())
	}
}

func TestPostureVerify_WorkspaceStatementCompleteness(t *testing.T) {
	tests := []struct {
		name                 string
		statement            func(*testing.T) workspacediff.Statement
		wantPassed           bool
		wantBoundaryCheck    workspacediff.BoundaryCheck
		wantIncompleteReason string
	}{
		{
			name:              "complete statement passes",
			statement:         completeWorkspaceStatement,
			wantPassed:        true,
			wantBoundaryCheck: workspacediff.BoundaryCheckMountID,
		},
		{
			name:                 "device-only statement fails as partial evidence",
			statement:            deviceOnlyWorkspaceStatement,
			wantPassed:           false,
			wantBoundaryCheck:    workspacediff.BoundaryCheckDeviceOnly,
			wantIncompleteReason: "mount boundary check unavailable",
		},
		{
			name:                 "budget-exhausted statement fails as partial evidence",
			statement:            budgetExhaustedWorkspaceStatement,
			wantPassed:           false,
			wantBoundaryCheck:    workspacediff.BoundaryCheckMountID,
			wantIncompleteReason: "snapshot budget exceeded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fix := newTestVerifyFixture(t, perfectEvidence())
			stmtPath := writeWorkspaceStatementForVerify(t, fix, tt.statement(t))

			var jsonOutput bytes.Buffer
			jsonCmd := rootCmd()
			jsonCmd.SetOut(&jsonOutput)
			jsonCmd.SetErr(&bytes.Buffer{})
			jsonCmd.SetArgs([]string{
				"posture", "verify",
				"--proof", fix.ProofPath,
				"--key", fix.PubKeyPath,
				"--policy", testVerifyPolicyNone,
				"--workspace-statement", stmtPath,
				"--json",
			})
			err := jsonCmd.Execute()
			if tt.wantPassed {
				if err != nil {
					t.Fatalf("JSON verification: %v", err)
				}
			} else {
				if err == nil {
					t.Fatal("expected incomplete workspace statement to fail verification")
				}
				assertExitCode(t, err, exitVerifyPolicyFail)
			}

			var out struct {
				Verified           bool   `json:"verified"`
				Passed             bool   `json:"passed"`
				Error              string `json:"error"`
				WorkspaceStatement struct {
					Bound            bool   `json:"bound"`
					Complete         *bool  `json:"complete"`
					BoundaryCheck    string `json:"boundary_check"`
					IncompleteReason string `json:"incomplete_reason"`
				} `json:"workspace_statement"`
			}
			if err := json.Unmarshal(jsonOutput.Bytes(), &out); err != nil {
				t.Fatalf("stdout is not valid JSON: %v\noutput:\n%s", err, jsonOutput.String())
			}
			if out.Passed != tt.wantPassed {
				t.Errorf("passed = %v, want %v\noutput:\n%s", out.Passed, tt.wantPassed, jsonOutput.String())
			}
			if !out.Verified {
				t.Errorf("verified = false, want true\noutput:\n%s", jsonOutput.String())
			}
			if !out.WorkspaceStatement.Bound {
				t.Fatalf("workspace_statement.bound = false, want true\noutput:\n%s", jsonOutput.String())
			}
			if out.WorkspaceStatement.Complete == nil || *out.WorkspaceStatement.Complete != tt.wantPassed {
				t.Errorf("workspace_statement.complete = %v, want %v", out.WorkspaceStatement.Complete, tt.wantPassed)
			}
			if out.WorkspaceStatement.BoundaryCheck != string(tt.wantBoundaryCheck) {
				t.Errorf("workspace_statement.boundary_check = %q, want %q", out.WorkspaceStatement.BoundaryCheck, tt.wantBoundaryCheck)
			}
			if !strings.Contains(out.WorkspaceStatement.IncompleteReason, tt.wantIncompleteReason) {
				t.Errorf("workspace_statement.incomplete_reason = %q, want it to contain %q", out.WorkspaceStatement.IncompleteReason, tt.wantIncompleteReason)
			}
			if !tt.wantPassed && !strings.Contains(out.Error, "incomplete") {
				t.Errorf("error = %q, want it to name incomplete evidence", out.Error)
			}

			var textOutput bytes.Buffer
			textCmd := rootCmd()
			textCmd.SetOut(&textOutput)
			textCmd.SetErr(&bytes.Buffer{})
			textCmd.SetArgs([]string{
				"posture", "verify",
				"--proof", fix.ProofPath,
				"--key", fix.PubKeyPath,
				"--policy", testVerifyPolicyNone,
				"--workspace-statement", stmtPath,
			})
			err = textCmd.Execute()
			if tt.wantPassed {
				if err != nil {
					t.Fatalf("text verification: %v", err)
				}
			} else {
				assertExitCode(t, err, exitVerifyPolicyFail)
			}
			if !strings.Contains(textOutput.String(), "boundary check: "+string(tt.wantBoundaryCheck)) {
				t.Errorf("text output does not name boundary check %q:\n%s", tt.wantBoundaryCheck, textOutput.String())
			}
			if !strings.Contains(textOutput.String(), tt.wantIncompleteReason) {
				t.Errorf("text output does not name incomplete reason %q:\n%s", tt.wantIncompleteReason, textOutput.String())
			}
		})
	}
}

func completeWorkspaceStatement(t *testing.T) workspacediff.Statement {
	t.Helper()
	statement, err := workspacediff.Diff(
		workspacediff.Manifest{Root: "/granted", CapBytes: 1, Entries: map[string]workspacediff.Entry{}, BoundaryCheck: workspacediff.BoundaryCheckMountID},
		workspacediff.Manifest{Root: "/granted", CapBytes: 1, Entries: map[string]workspacediff.Entry{}, BoundaryCheck: workspacediff.BoundaryCheckMountID},
		time.Now(),
	)
	if err != nil {
		t.Fatalf("produce complete workspace statement: %v", err)
	}
	return statement
}

func deviceOnlyWorkspaceStatement(t *testing.T) workspacediff.Statement {
	t.Helper()
	statement, err := workspacediff.Diff(
		workspacediff.Manifest{Root: "/granted", CapBytes: 1, Entries: map[string]workspacediff.Entry{}, BoundaryCheck: workspacediff.BoundaryCheckDeviceOnly},
		workspacediff.Manifest{Root: "/granted", CapBytes: 1, Entries: map[string]workspacediff.Entry{}, BoundaryCheck: workspacediff.BoundaryCheckMountID},
		time.Now(),
	)
	if err != nil {
		t.Fatalf("produce device-only workspace statement: %v", err)
	}
	return statement
}

func budgetExhaustedWorkspaceStatement(t *testing.T) workspacediff.Statement {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "entry"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write workspace entry: %v", err)
	}
	before, err := workspacediff.Snapshot(root, 1024, workspacediff.Budget{MaxEntries: 1})
	if err != nil {
		t.Fatalf("snapshot before: %v", err)
	}
	after, err := workspacediff.Snapshot(root, 1024, workspacediff.Budget{MaxEntries: 1})
	if err != nil {
		t.Fatalf("snapshot after: %v", err)
	}
	statement, err := workspacediff.Diff(before, after, time.Now())
	if err != nil {
		t.Fatalf("produce budget-exhausted workspace statement: %v", err)
	}
	if !statement.Incomplete {
		t.Fatalf("test setup: expected budget-exhausted statement to be incomplete, got %+v", statement)
	}
	return statement
}

func writeWorkspaceStatementForVerify(t *testing.T, fix testVerifyFixture, statement workspacediff.Statement) string {
	t.Helper()
	capsuleHash, err := workspacediff.HashFileSHA256(fix.ProofPath)
	if err != nil {
		t.Fatalf("hash capsule: %v", err)
	}
	signed, err := workspacediff.Sign([]workspacediff.Statement{statement}, capsuleHash, fix.PrivateKey)
	if err != nil {
		t.Fatalf("sign workspace statement: %v", err)
	}
	path, err := workspacediff.WriteJSON(t.TempDir(), signed)
	if err != nil {
		t.Fatalf("write workspace statement: %v", err)
	}
	return path
}

// TestPostureVerify_WorkspaceStatement_TamperedCapsuleRejected proves the
// binding check hashes the ACTUAL capsule FILE bytes, not just the parsed
// struct: after the statement is bound and signed, the capsule file on disk
// is overwritten (e.g. corrupted, replaced) and verification must fail even
// though the statement's own signature is untouched.
func TestPostureVerify_WorkspaceStatement_TamperedCapsuleRejected(t *testing.T) {
	fix := newTestVerifyFixture(t, perfectEvidence())

	capsuleHash, err := workspacediff.HashFileSHA256(fix.ProofPath)
	if err != nil {
		t.Fatalf("hash capsule: %v", err)
	}
	signed, err := workspacediff.Sign([]workspacediff.Statement{{Root: "/granted"}}, capsuleHash, fix.PrivateKey)
	if err != nil {
		t.Fatalf("sign statement: %v", err)
	}
	stmtPath := filepath.Join(t.TempDir(), "workspace-change-statement.json")
	data, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stmtPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	// Tamper with the capsule file's bytes after binding: append trailing
	// whitespace so the digest changes while the JSON still parses fine
	// (proving the check compares BYTES, not just "does it still parse the
	// same struct").
	original, err := os.ReadFile(filepath.Clean(fix.ProofPath))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fix.ProofPath, append(original, '\n', ' '), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"posture", "verify",
		"--proof", fix.ProofPath,
		"--key", fix.PubKeyPath,
		"--policy", testVerifyPolicyNone,
		"--workspace-statement", stmtPath,
	})
	if err := cmd.Execute(); err == nil {
		t.Fatalf("expected rejection of a tampered capsule file")
	}
}

func assertExitCode(t *testing.T, err error, wantCode int) {
	t.Helper()
	gotCode := cliutil.ExitCodeOf(err)
	if gotCode != wantCode {
		t.Errorf("exit code = %d, want %d (error: %v)", gotCode, wantCode, err)
	}

	// Also verify it's an ExitError.
	var ee *cliutil.ExitError
	if !errors.As(err, &ee) {
		t.Errorf("error is not *cliutil.ExitError: %T", err)
	}
}
