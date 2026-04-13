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

func TestPostureVerifyRequireDiscoveryIgnoresParseErrors(t *testing.T) {
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
