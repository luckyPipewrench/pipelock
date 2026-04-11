// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package posture

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cli/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestCapsuleMarshalJSONDeterministic(t *testing.T) {
	t.Parallel()

	expectedCapsule := Capsule{
		SchemaVersion: "1",
		GeneratedAt:   time.Date(2026, time.April, 11, 17, 45, 0, 0, time.UTC),
		ExpiresAt:     time.Date(2026, time.May, 11, 17, 45, 0, 0, time.UTC),
		ToolVersion:   "0.1.0-dev",
		ConfigHash:    "abc123",
		Evidence:      testEvidenceBundle(),
		Signature:     "deadbeef",
		SignerKeyID:   "feedface",
	}

	expectedJSON, err := json.Marshal(expectedCapsule)
	if err != nil {
		t.Fatalf("json.Marshal(expectedCapsule): %v", err)
	}

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "top-level fields shuffled",
			input: `{"tool_version":"0.1.0-dev","signature":"deadbeef","schema_version":"1","generated_at":"2026-04-11T17:45:00Z","evidence":{"verify_install":{"proxying":true,"receipt_count":2,"flight_recorder_active":true},"discover":{"unknown":0,"total_servers":2,"protected_other":0,"parse_errors":0,"high_risk":0,"protected_pipelock":1,"total_clients":1,"unprotected":1},"simulate":{"total":2,"passed":2,"failed":0,"known_limitations":0,"percentage":100,"grade":"A","mode":"balanced","scenarios":[{"name":"scenario-a","category":"DLP Exfiltration","detected":true},{"name":"scenario-b","category":"Prompt Injection","detected":true,"detail":"matched"}]},"flight_recorder":{"scanner_verdict":{"zeta":{"warn":1,"allow":0,"block":0},"alpha":{"block":2,"allow":1,"warn":0}},"receipt_count":2,"last_receipt_at":"2026-04-11T17:40:00Z"}},"expires_at":"2026-05-11T17:45:00Z","signer_key_id":"feedface","config_hash":"abc123"}`,
		},
		{
			name:  "nested map fields shuffled",
			input: `{"schema_version":"1","generated_at":"2026-04-11T17:45:00Z","expires_at":"2026-05-11T17:45:00Z","tool_version":"0.1.0-dev","config_hash":"abc123","evidence":{"discover":{"total_clients":1,"total_servers":2,"protected_pipelock":1,"protected_other":0,"unprotected":1,"unknown":0,"high_risk":0,"parse_errors":0},"verify_install":{"receipt_count":2,"flight_recorder_active":true,"proxying":true},"simulate":{"passed":2,"total":2,"failed":0,"known_limitations":0,"percentage":100,"grade":"A","mode":"balanced","scenarios":[{"category":"DLP Exfiltration","name":"scenario-a","detected":true},{"detail":"matched","detected":true,"category":"Prompt Injection","name":"scenario-b"}]},"flight_recorder":{"last_receipt_at":"2026-04-11T17:40:00Z","receipt_count":2,"scanner_verdict":{"alpha":{"warn":0,"block":2,"allow":1},"zeta":{"allow":0,"warn":1,"block":0}}}},"signature":"deadbeef","signer_key_id":"feedface"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var capsule Capsule
			if err := json.Unmarshal([]byte(tt.input), &capsule); err != nil {
				t.Fatalf("json.Unmarshal(): %v", err)
			}

			got, err := json.Marshal(capsule)
			if err != nil {
				t.Fatalf("json.Marshal(): %v", err)
			}

			if string(got) != string(expectedJSON) {
				t.Fatalf("canonical JSON mismatch:\n got: %s\nwant: %s", got, expectedJSON)
			}
		})
	}
}

func TestEmitAndVerifyRoundTrip(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey(): %v", err)
	}

	cfg := config.Defaults()
	capsule, err := Emit(cfg, Options{
		SigningKey:     priv,
		EvidenceBundle: bundlePtr(testEvidenceBundle()),
	})
	if err != nil {
		t.Fatalf("Emit(): %v", err)
	}

	if err := Verify(capsule, pub); err != nil {
		t.Fatalf("Verify(): %v", err)
	}

	data, err := json.Marshal(capsule)
	if err != nil {
		t.Fatalf("json.Marshal(): %v", err)
	}

	var decoded Capsule
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(): %v", err)
	}

	if err := Verify(&decoded, pub); err != nil {
		t.Fatalf("Verify(decoded): %v", err)
	}
}

func TestVerifyExpiration(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey(): %v", err)
	}

	base, err := Emit(config.Defaults(), Options{
		SigningKey:     priv,
		EvidenceBundle: bundlePtr(testEvidenceBundle()),
	})
	if err != nil {
		t.Fatalf("Emit(): %v", err)
	}

	tests := []struct {
		name    string
		mutate  func(*Capsule)
		wantErr string
	}{
		{
			name: "fresh",
			mutate: func(c *Capsule) {
				c.ExpiresAt = time.Now().UTC().Add(2 * time.Hour)
			},
		},
		{
			name: "near expiration",
			mutate: func(c *Capsule) {
				c.ExpiresAt = time.Now().UTC().Add(1 * time.Second)
			},
		},
		{
			name: "expired",
			mutate: func(c *Capsule) {
				c.ExpiresAt = time.Now().UTC().Add(-1 * time.Second)
			},
			wantErr: "expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			capsule := *base
			tt.mutate(&capsule)
			capsule.Signature = resignCapsule(t, &capsule, priv)

			err := Verify(&capsule, pub)
			if tt.wantErr == "" && err != nil {
				t.Fatalf("Verify(): %v", err)
			}
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Verify() error = %v, want substring %q", err, tt.wantErr)
				}
			}
		})
	}
}

func TestVerifyRejectsSchemaVersionMismatch(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey(): %v", err)
	}

	capsule, err := Emit(config.Defaults(), Options{
		SigningKey:     priv,
		EvidenceBundle: bundlePtr(testEvidenceBundle()),
	})
	if err != nil {
		t.Fatalf("Emit(): %v", err)
	}

	capsule.SchemaVersion = "2"
	capsule.Signature = resignCapsule(t, capsule, priv)

	err = Verify(capsule, pub)
	if err == nil || !strings.Contains(err.Error(), "unsupported schema_version") {
		t.Fatalf("Verify() error = %v, want schema version rejection", err)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey(): %v", err)
	}

	capsule, err := Emit(config.Defaults(), Options{
		SigningKey:     priv,
		EvidenceBundle: bundlePtr(testEvidenceBundle()),
	})
	if err != nil {
		t.Fatalf("Emit(): %v", err)
	}

	capsule.ConfigHash = "tampered"
	err = Verify(capsule, pub)
	if err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("Verify() error = %v, want signature failure", err)
	}
}

func TestEmitDefaultsExpirationDays(t *testing.T) {
	t.Parallel()

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey(): %v", err)
	}

	capsule, err := Emit(config.Defaults(), Options{
		SigningKey:     priv,
		EvidenceBundle: bundlePtr(testEvidenceBundle()),
	})
	if err != nil {
		t.Fatalf("Emit(): %v", err)
	}

	want := capsule.GeneratedAt.AddDate(0, 0, DefaultExpirationDays)
	if !capsule.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt = %s, want %s", capsule.ExpiresAt, want)
	}
}

func TestEmitCollectsEvidenceAndWritesProof(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey(): %v", err)
	}

	recorderDir := filepath.Join(t.TempDir(), "recorder")
	createTestReceipt(t, recorderDir, priv)

	cfg := config.Defaults()
	cfg.FlightRecorder.Enabled = true
	cfg.FlightRecorder.Dir = recorderDir

	capsule, err := Emit(cfg, Options{SigningKey: priv})
	if err != nil {
		t.Fatalf("Emit(): %v", err)
	}

	if capsule.Evidence.VerifyInstall.ReceiptCount != 1 {
		t.Fatalf("VerifyInstall.ReceiptCount = %d, want 1", capsule.Evidence.VerifyInstall.ReceiptCount)
	}
	if !capsule.Evidence.VerifyInstall.Proxying {
		t.Fatal("VerifyInstall.Proxying = false, want true")
	}
	if capsule.Evidence.FlightRecorder.ReceiptCount != 1 {
		t.Fatalf("FlightRecorder.ReceiptCount = %d, want 1", capsule.Evidence.FlightRecorder.ReceiptCount)
	}
	if capsule.Evidence.FlightRecorder.LastReceiptAt == nil {
		t.Fatal("FlightRecorder.LastReceiptAt = nil, want timestamp")
	}
	if got := capsule.Evidence.FlightRecorder.ScannerVerdict["dlp"].Block; got != 1 {
		t.Fatalf("ScannerVerdict[dlp].Block = %d, want 1", got)
	}
	if capsule.Evidence.Discover.TotalClients != 0 {
		t.Fatalf("Discover.TotalClients = %d, want 0", capsule.Evidence.Discover.TotalClients)
	}
	if capsule.Evidence.Simulate.Total == 0 {
		t.Fatal("Simulate.Total = 0, want non-zero scenarios")
	}
	if err := Verify(capsule, pub); err != nil {
		t.Fatalf("Verify(): %v", err)
	}

	outDir := filepath.Join(t.TempDir(), "posture")
	path, err := WriteProofJSON(outDir, capsule)
	if err != nil {
		t.Fatalf("WriteProofJSON(): %v", err)
	}
	if path != filepath.Join(outDir, ProofFilename) {
		t.Fatalf("WriteProofJSON path = %s, want %s", path, filepath.Join(outDir, ProofFilename))
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("os.ReadFile(): %v", err)
	}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		t.Fatalf("proof.json should end with newline, got %q", data)
	}
}

func TestEmitLoadsSigningKeyFromConfigPath(t *testing.T) {
	t.Parallel()

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey(): %v", err)
	}

	keyPath := filepath.Join(t.TempDir(), "signing.key")
	if err := signing.SavePrivateKey(priv, keyPath); err != nil {
		t.Fatalf("signing.SavePrivateKey(): %v", err)
	}

	cfg := config.Defaults()
	cfg.FlightRecorder.SigningKeyPath = keyPath

	capsule, err := Emit(cfg, Options{EvidenceBundle: bundlePtr(testEvidenceBundle())})
	if err != nil {
		t.Fatalf("Emit(): %v", err)
	}
	if capsule.SignerKeyID == "" {
		t.Fatal("SignerKeyID = empty, want populated")
	}
}

func TestEmitMissingSigningKeyPath(t *testing.T) {
	t.Parallel()

	_, err := Emit(config.Defaults(), Options{EvidenceBundle: bundlePtr(testEvidenceBundle())})
	if err == nil || !strings.Contains(err.Error(), "flight_recorder.signing_key_path is required") {
		t.Fatalf("Emit() error = %v, want missing signing key path", err)
	}
}

func TestEmitReturnsEvidenceCollectionError(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey(): %v", err)
	}

	badPath := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(badPath, []byte("x"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(): %v", err)
	}

	cfg := config.Defaults()
	cfg.FlightRecorder.Dir = badPath

	_, err = Emit(cfg, Options{SigningKey: priv})
	if err == nil || !strings.Contains(err.Error(), "read flight recorder dir") {
		t.Fatalf("Emit() error = %v, want flight recorder collection failure", err)
	}
}

func TestEmitNilConfig(t *testing.T) {
	t.Parallel()

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey(): %v", err)
	}

	_, err = Emit(nil, Options{SigningKey: priv, EvidenceBundle: bundlePtr(testEvidenceBundle())})
	if err == nil || !strings.Contains(err.Error(), "config is required") {
		t.Fatalf("Emit() error = %v, want nil config rejection", err)
	}
}

func TestResolveSigningKeyLoadFailure(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.FlightRecorder.SigningKeyPath = filepath.Join(t.TempDir(), "missing.key")

	_, err := resolveSigningKey(cfg, nil)
	if err == nil || !strings.Contains(err.Error(), "load signing key") {
		t.Fatalf("resolveSigningKey() error = %v, want load failure", err)
	}
}

func TestVerifyValidationFailures(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey(): %v", err)
	}

	base, err := Emit(config.Defaults(), Options{
		SigningKey:     priv,
		EvidenceBundle: bundlePtr(testEvidenceBundle()),
	})
	if err != nil {
		t.Fatalf("Emit(): %v", err)
	}

	tests := []struct {
		name    string
		capsule *Capsule
		key     ed25519.PublicKey
		wantErr string
	}{
		{
			name:    "nil capsule",
			capsule: nil,
			key:     pub,
			wantErr: "capsule is required",
		},
		{
			name: "invalid key length",
			capsule: func() *Capsule {
				c := *base
				return &c
			}(),
			key:     ed25519.PublicKey([]byte("short")),
			wantErr: "invalid trusted key length",
		},
		{
			name: "missing signature",
			capsule: func() *Capsule {
				c := *base
				c.Signature = ""
				return &c
			}(),
			key:     pub,
			wantErr: "capsule signature is required",
		},
		{
			name: "signer mismatch",
			capsule: func() *Capsule {
				c := *base
				c.SignerKeyID = "other"
				return &c
			}(),
			key:     pub,
			wantErr: "does not match trusted key",
		},
		{
			name: "invalid signature hex",
			capsule: func() *Capsule {
				c := *base
				c.Signature = "not-hex"
				return &c
			}(),
			key:     pub,
			wantErr: "decode signature",
		},
		{
			name: "invalid signature length",
			capsule: func() *Capsule {
				c := *base
				c.Signature = "deadbeef"
				return &c
			}(),
			key:     pub,
			wantErr: "invalid signature length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Verify(tt.capsule, tt.key)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Verify() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestWriteProofJSONValidationFailures(t *testing.T) {
	t.Parallel()

	_, err := WriteProofJSON(t.TempDir(), nil)
	if err == nil || !strings.Contains(err.Error(), "capsule is required") {
		t.Fatalf("WriteProofJSON(nil) error = %v, want nil capsule rejection", err)
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey(): %v", err)
	}

	capsule, err := Emit(config.Defaults(), Options{
		SigningKey:     priv,
		EvidenceBundle: bundlePtr(testEvidenceBundle()),
	})
	if err != nil {
		t.Fatalf("Emit(): %v", err)
	}
	if err := Verify(capsule, pub); err != nil {
		t.Fatalf("Verify(): %v", err)
	}

	badOutput := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(badOutput, []byte("x"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(): %v", err)
	}

	_, err = WriteProofJSON(badOutput, capsule)
	if err == nil || !strings.Contains(err.Error(), "create output directory") {
		t.Fatalf("WriteProofJSON() error = %v, want output dir failure", err)
	}

	writeFailDir := filepath.Join(t.TempDir(), "write-fail")
	if err := os.Mkdir(writeFailDir, 0o750); err != nil {
		t.Fatalf("os.Mkdir(): %v", err)
	}
	if err := os.Mkdir(filepath.Join(writeFailDir, ProofFilename), 0o750); err != nil {
		t.Fatalf("os.Mkdir(proof dir): %v", err)
	}

	_, err = WriteProofJSON(writeFailDir, capsule)
	if err == nil || !strings.Contains(err.Error(), "write proof.json") {
		t.Fatalf("WriteProofJSON() error = %v, want write failure", err)
	}
}

func TestUnmarshalJSONError(t *testing.T) {
	t.Parallel()

	var capsule Capsule
	if err := json.Unmarshal([]byte(`{"schema_version":`), &capsule); err == nil {
		t.Fatal("json.Unmarshal() error = nil, want invalid JSON error")
	}
}

func TestCollectEvidenceWithoutRecorder(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	evidence, err := collectEvidence(config.Defaults())
	if err != nil {
		t.Fatalf("collectEvidence(): %v", err)
	}

	if evidence.VerifyInstall.FlightRecorderActive {
		t.Fatal("VerifyInstall.FlightRecorderActive = true, want false")
	}
	if evidence.VerifyInstall.Proxying {
		t.Fatal("VerifyInstall.Proxying = true, want false")
	}
	if evidence.FlightRecorder.ReceiptCount != 0 {
		t.Fatalf("FlightRecorder.ReceiptCount = %d, want 0", evidence.FlightRecorder.ReceiptCount)
	}
}

func TestCollectFlightRecorderEvidence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		setup   func(t *testing.T) *config.Config
		wantErr string
	}{
		{
			name: "empty dir",
			setup: func(t *testing.T) *config.Config {
				cfg := config.Defaults()
				cfg.FlightRecorder.Dir = ""
				return cfg
			},
		},
		{
			name: "missing dir",
			setup: func(t *testing.T) *config.Config {
				cfg := config.Defaults()
				cfg.FlightRecorder.Dir = filepath.Join(t.TempDir(), "missing")
				return cfg
			},
		},
		{
			name: "malformed receipt detail",
			setup: func(t *testing.T) *config.Config {
				dir := t.TempDir()
				entry := recorder.Entry{
					Version:   recorder.EntryVersion,
					Sequence:  0,
					Timestamp: time.Now().UTC(),
					SessionID: "proxy",
					Type:      "action_receipt",
					Transport: "forward",
					Summary:   "bad",
					Detail:    "not-a-receipt",
					PrevHash:  recorder.GenesisHash,
					Hash:      "placeholder",
				}
				entry.Hash = recorder.ComputeHash(entry)

				data, err := json.Marshal(entry)
				if err != nil {
					t.Fatalf("json.Marshal(entry): %v", err)
				}
				path := filepath.Join(dir, "evidence-proxy-0.jsonl")
				if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
					t.Fatalf("os.WriteFile(): %v", err)
				}

				cfg := config.Defaults()
				cfg.FlightRecorder.Dir = dir
				return cfg
			},
			wantErr: "decode receipt detail",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.setup(t)
			got, err := collectFlightRecorderEvidence(cfg)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("collectFlightRecorderEvidence() error = %v", err)
				}
				if got.ReceiptCount != 0 {
					t.Fatalf("ReceiptCount = %d, want 0", got.ReceiptCount)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("collectFlightRecorderEvidence() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestCanonicalHelpers(t *testing.T) {
	t.Parallel()

	t.Run("canonical JSON sorts keys", func(t *testing.T) {
		got, err := canonicalJSON(map[string]any{
			"b": true,
			"a": json.Number("2"),
			"c": []any{"x", float64(1)},
		})
		if err != nil {
			t.Fatalf("canonicalJSON(): %v", err)
		}
		want := `{"a":2,"b":true,"c":["x",1]}`
		if string(got) != want {
			t.Fatalf("canonicalJSON() = %s, want %s", got, want)
		}
	})

	t.Run("appendCanonical handles direct types", func(t *testing.T) {
		cases := []struct {
			name  string
			value any
			want  string
		}{
			{name: "nil", value: nil, want: "null"},
			{name: "bool true", value: true, want: "true"},
			{name: "bool false", value: false, want: "false"},
			{name: "string", value: "hello", want: `"hello"`},
			{name: "json number", value: json.Number("3"), want: "3"},
			{name: "float64", value: float64(1.5), want: "1.5"},
			{name: "slice", value: []any{"a", json.Number("4")}, want: `["a",4]`},
			{name: "map", value: map[string]any{"b": 2, "a": 1}, want: `{"a":1,"b":2}`},
			{name: "default", value: 7, want: "7"},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				var buf bytes.Buffer
				if err := appendCanonical(&buf, tc.value); err != nil {
					t.Fatalf("appendCanonical(): %v", err)
				}
				if buf.String() != tc.want {
					t.Fatalf("appendCanonical() = %s, want %s", buf.String(), tc.want)
				}
			})
		}
	})

	t.Run("canonical JSON propagates marshal errors", func(t *testing.T) {
		_, err := canonicalJSON(failingJSONMarshaler{})
		if err == nil || !strings.Contains(err.Error(), "boom") {
			t.Fatalf("canonicalJSON() error = %v, want marshal error", err)
		}
	})

	t.Run("canonical JSON rejects invalid JSON from marshaler", func(t *testing.T) {
		_, err := canonicalJSON(invalidJSONMarshaler{})
		if err == nil {
			t.Fatal("canonicalJSON() error = nil, want decoder failure")
		}
	})
}

func TestHashConfigDeterministic(t *testing.T) {
	t.Parallel()

	cfgA := config.Defaults()
	cfgB := config.Defaults()

	hashA, err := hashConfig(cfgA)
	if err != nil {
		t.Fatalf("hashConfig(cfgA): %v", err)
	}
	hashB, err := hashConfig(cfgB)
	if err != nil {
		t.Fatalf("hashConfig(cfgB): %v", err)
	}

	if hashA != hashB {
		t.Fatalf("hashConfig mismatch: %s != %s", hashA, hashB)
	}
}

func testEvidenceBundle() EvidenceBundle {
	lastReceipt := time.Date(2026, time.April, 11, 17, 40, 0, 0, time.UTC)

	return EvidenceBundle{
		Discover: DiscoverEvidence{
			TotalClients:      1,
			TotalServers:      2,
			ProtectedPipelock: 1,
			ProtectedOther:    0,
			Unprotected:       1,
			Unknown:           0,
			HighRisk:          0,
			ParseErrors:       0,
		},
		VerifyInstall: VerifyInstallEvidence{
			FlightRecorderActive: true,
			ReceiptCount:         2,
			Proxying:             true,
		},
		Simulate: audit.SimulateResult{
			Total:       2,
			Passed:      2,
			Failed:      0,
			KnownLimits: 0,
			Percentage:  100,
			Grade:       "A",
			Mode:        config.ModeBalanced,
			Scenarios: []audit.ScenarioResult{
				{Name: "scenario-a", Category: "DLP Exfiltration", Detected: true},
				{Name: "scenario-b", Category: "Prompt Injection", Detected: true, Detail: "matched"},
			},
		},
		FlightRecorder: FlightRecorderCounts{
			ReceiptCount:  2,
			LastReceiptAt: &lastReceipt,
			ScannerVerdict: map[string]VerdictCount{
				"zeta":  {Warn: 1},
				"alpha": {Allow: 1, Block: 2},
			},
		},
	}
}

func bundlePtr(bundle EvidenceBundle) *EvidenceBundle {
	return &bundle
}

func resignCapsule(t *testing.T, capsule *Capsule, priv ed25519.PrivateKey) string {
	t.Helper()

	payload, err := capsule.signableJSON()
	if err != nil {
		t.Fatalf("signableJSON(): %v", err)
	}
	return hexEncode(ed25519.Sign(priv, payload))
}

func createTestReceipt(t *testing.T, dir string, priv ed25519.PrivateKey) {
	t.Helper()

	rec, err := recorder.New(recorder.Config{
		Enabled:         true,
		Dir:             dir,
		SignCheckpoints: true,
	}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New(): %v", err)
	}
	t.Cleanup(func() {
		if err := rec.Close(); err != nil {
			t.Fatalf("rec.Close(): %v", err)
		}
	})

	emitter := receipt.NewEmitter(receipt.EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: "cfg-hash",
	})
	if emitter == nil {
		t.Fatal("receipt.NewEmitter() returned nil")
	}

	if err := emitter.Emit(receipt.EmitOpts{
		ActionID:  "action-1",
		Verdict:   config.ActionBlock,
		Layer:     "dlp",
		Transport: "forward",
		Method:    "GET",
		Target:    "https://example.com",
		RequestID: "req-1",
	}); err != nil {
		t.Fatalf("emitter.Emit(): %v", err)
	}

	if err := rec.Close(); err != nil {
		t.Fatalf("rec.Close(): %v", err)
	}
}

func hexEncode(b []byte) string {
	return hex.EncodeToString(b)
}

type failingJSONMarshaler struct{}

func (failingJSONMarshaler) MarshalJSON() ([]byte, error) {
	return nil, fmt.Errorf("boom")
}

type invalidJSONMarshaler struct{}

func (invalidJSONMarshaler) MarshalJSON() ([]byte, error) {
	return []byte("{"), nil
}
