// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package posture

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cli/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	testPolicyEnterprise = PolicyEnterprise
	testPolicyStrict     = PolicyStrict
	testPolicyNone       = PolicyNone
)

func TestComputeScore(t *testing.T) {
	recentReceipt := time.Now().Add(-1 * time.Hour)
	staleReceipt := time.Now().Add(-10 * 24 * time.Hour)

	tests := []struct {
		name         string
		evidence     EvidenceBundle
		maxAgeDays   int
		wantScore    int
		wantTransp   int
		wantRecorder int
		wantSim      int
		wantClean    int
	}{
		{
			name: "perfect score",
			evidence: EvidenceBundle{
				Discover: DiscoverEvidence{
					TotalServers:      5,
					ProtectedPipelock: 5,
				},
				VerifyInstall: VerifyInstallEvidence{
					FlightRecorderActive: true,
					ReceiptCount:         100,
				},
				Simulate: audit.SimulateResult{Percentage: 100},
				FlightRecorder: FlightRecorderCounts{
					ReceiptCount:  100,
					LastReceiptAt: &recentReceipt,
				},
			},
			maxAgeDays:   MaxReceiptAgeDays,
			wantScore:    100,
			wantTransp:   100,
			wantRecorder: 100,
			wantSim:      100,
			wantClean:    100,
		},
		{
			name: "zero score all bad",
			evidence: EvidenceBundle{
				Discover: DiscoverEvidence{
					TotalServers: 5,
					Unprotected:  5,
				},
				VerifyInstall: VerifyInstallEvidence{
					FlightRecorderActive: false,
				},
				Simulate:       audit.SimulateResult{Percentage: 0},
				FlightRecorder: FlightRecorderCounts{},
			},
			maxAgeDays:   MaxReceiptAgeDays,
			wantScore:    0,
			wantTransp:   0,
			wantRecorder: 0,
			wantSim:      0,
			wantClean:    0,
		},
		{
			name: "partial transport coverage",
			evidence: EvidenceBundle{
				Discover: DiscoverEvidence{
					TotalServers:      10,
					ProtectedPipelock: 3,
					ProtectedOther:    3,
					Unprotected:       4,
				},
				VerifyInstall: VerifyInstallEvidence{
					FlightRecorderActive: true,
					ReceiptCount:         50,
				},
				Simulate: audit.SimulateResult{Percentage: 96},
				FlightRecorder: FlightRecorderCounts{
					ReceiptCount:  50,
					LastReceiptAt: &recentReceipt,
				},
			},
			maxAgeDays:   MaxReceiptAgeDays,
			wantScore:    63,
			wantTransp:   60,
			wantRecorder: 100,
			wantSim:      96,
			wantClean:    0,
		},
		{
			name: "stale receipts reduce recorder to 50",
			evidence: EvidenceBundle{
				Discover: DiscoverEvidence{
					TotalServers:      5,
					ProtectedPipelock: 5,
				},
				VerifyInstall: VerifyInstallEvidence{
					FlightRecorderActive: true,
					ReceiptCount:         100,
				},
				Simulate: audit.SimulateResult{Percentage: 100},
				FlightRecorder: FlightRecorderCounts{
					ReceiptCount:  100,
					LastReceiptAt: &staleReceipt,
				},
			},
			maxAgeDays:   MaxReceiptAgeDays,
			wantScore:    92,
			wantTransp:   100,
			wantRecorder: 50,
			wantSim:      100,
			wantClean:    100,
		},
		{
			name: "no servers discovered vacuous truth",
			evidence: EvidenceBundle{
				Discover: DiscoverEvidence{},
				VerifyInstall: VerifyInstallEvidence{
					FlightRecorderActive: true,
					ReceiptCount:         10,
				},
				Simulate: audit.SimulateResult{Percentage: 100},
				FlightRecorder: FlightRecorderCounts{
					ReceiptCount:  10,
					LastReceiptAt: &recentReceipt,
				},
			},
			maxAgeDays:   MaxReceiptAgeDays,
			wantScore:    100,
			wantTransp:   100,
			wantRecorder: 100,
			wantSim:      100,
			wantClean:    100,
		},
		{
			name: "only parse errors no servers",
			evidence: EvidenceBundle{
				Discover: DiscoverEvidence{
					ParseErrors: 3,
				},
				VerifyInstall: VerifyInstallEvidence{
					FlightRecorderActive: true,
					ReceiptCount:         10,
				},
				Simulate: audit.SimulateResult{Percentage: 100},
				FlightRecorder: FlightRecorderCounts{
					ReceiptCount:  10,
					LastReceiptAt: &recentReceipt,
				},
			},
			maxAgeDays:   MaxReceiptAgeDays,
			wantScore:    62,
			wantTransp:   0,
			wantRecorder: 100,
			wantSim:      100,
			wantClean:    50,
		},
		{
			name: "unknown servers reduce cleanliness to 50",
			evidence: EvidenceBundle{
				Discover: DiscoverEvidence{
					TotalServers:      3,
					ProtectedPipelock: 3,
					Unknown:           1,
				},
				VerifyInstall: VerifyInstallEvidence{
					FlightRecorderActive: true,
					ReceiptCount:         10,
				},
				Simulate: audit.SimulateResult{Percentage: 100},
				FlightRecorder: FlightRecorderCounts{
					ReceiptCount:  10,
					LastReceiptAt: &recentReceipt,
				},
			},
			maxAgeDays:   MaxReceiptAgeDays,
			wantScore:    87,
			wantTransp:   100,
			wantRecorder: 100,
			wantSim:      100,
			wantClean:    50,
		},
		{
			name: "recorder active but zero receipts",
			evidence: EvidenceBundle{
				Discover: DiscoverEvidence{
					TotalServers:      2,
					ProtectedPipelock: 2,
				},
				VerifyInstall: VerifyInstallEvidence{
					FlightRecorderActive: true,
					ReceiptCount:         0,
				},
				Simulate:       audit.SimulateResult{Percentage: 80},
				FlightRecorder: FlightRecorderCounts{},
			},
			maxAgeDays:   MaxReceiptAgeDays,
			wantScore:    78,
			wantTransp:   100,
			wantRecorder: 0,
			wantSim:      80,
			wantClean:    100,
		},
		{
			name: "max receipt age zero skips staleness check",
			evidence: EvidenceBundle{
				Discover: DiscoverEvidence{
					TotalServers:      2,
					ProtectedPipelock: 2,
				},
				VerifyInstall: VerifyInstallEvidence{
					FlightRecorderActive: true,
					ReceiptCount:         10,
				},
				Simulate: audit.SimulateResult{Percentage: 100},
				FlightRecorder: FlightRecorderCounts{
					ReceiptCount:  10,
					LastReceiptAt: &staleReceipt,
				},
			},
			maxAgeDays:   0,
			wantScore:    100,
			wantTransp:   100,
			wantRecorder: 100,
			wantSim:      100,
			wantClean:    100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, factors := ComputeScore(tt.evidence, tt.maxAgeDays)
			if score != tt.wantScore {
				t.Errorf("score = %d, want %d", score, tt.wantScore)
			}
			if factors.TransportRatio.RawPercent != tt.wantTransp {
				t.Errorf("transport raw = %d, want %d", factors.TransportRatio.RawPercent, tt.wantTransp)
			}
			if factors.RecorderHealth.RawPercent != tt.wantRecorder {
				t.Errorf("recorder raw = %d, want %d", factors.RecorderHealth.RawPercent, tt.wantRecorder)
			}
			if factors.SimulatePassRate.RawPercent != tt.wantSim {
				t.Errorf("simulate raw = %d, want %d", factors.SimulatePassRate.RawPercent, tt.wantSim)
			}
			if factors.DiscoveryCleanliness.RawPercent != tt.wantClean {
				t.Errorf("cleanliness raw = %d, want %d", factors.DiscoveryCleanliness.RawPercent, tt.wantClean)
			}
		})
	}
}

func TestEvaluatePolicy(t *testing.T) {
	recentReceipt := time.Now().Add(-1 * time.Hour)
	staleReceipt := time.Now().Add(-10 * 24 * time.Hour)

	tests := []struct {
		name         string
		policy       string
		evidence     EvidenceBundle
		opts         VerifyOpts
		wantFailures []string // rule names
		wantWarnings []string
	}{
		{
			name:   "none policy skips all checks",
			policy: testPolicyNone,
			evidence: EvidenceBundle{
				Discover: DiscoverEvidence{Unprotected: 5},
			},
			opts: VerifyOpts{MaxReceiptAge: MaxReceiptAgeDays},
		},
		{
			name:   "enterprise clean pass",
			policy: testPolicyEnterprise,
			evidence: EvidenceBundle{
				Discover: DiscoverEvidence{
					TotalServers:      3,
					ProtectedPipelock: 3,
				},
				VerifyInstall: VerifyInstallEvidence{
					FlightRecorderActive: true,
					ReceiptCount:         10,
				},
				Simulate: audit.SimulateResult{
					Scenarios: []audit.ScenarioResult{
						{Category: "DLP", Detected: true},
						{Category: "Injection", Detected: true},
					},
				},
				FlightRecorder: FlightRecorderCounts{
					ReceiptCount:  10,
					LastReceiptAt: &recentReceipt,
				},
			},
			opts: VerifyOpts{MaxReceiptAge: MaxReceiptAgeDays},
		},
		{
			name:   "enterprise unprotected servers",
			policy: testPolicyEnterprise,
			evidence: EvidenceBundle{
				Discover: DiscoverEvidence{
					TotalServers:      5,
					ProtectedPipelock: 3,
					Unprotected:       2,
				},
				VerifyInstall: VerifyInstallEvidence{
					FlightRecorderActive: true,
					ReceiptCount:         10,
				},
				Simulate: audit.SimulateResult{
					Scenarios: []audit.ScenarioResult{
						{Category: "DLP", Detected: true},
					},
				},
				FlightRecorder: FlightRecorderCounts{
					ReceiptCount:  10,
					LastReceiptAt: &recentReceipt,
				},
			},
			opts:         VerifyOpts{MaxReceiptAge: MaxReceiptAgeDays},
			wantFailures: []string{ruleUnprotectedServers},
		},
		{
			name:   "enterprise zero detection category",
			policy: testPolicyEnterprise,
			evidence: EvidenceBundle{
				Discover: DiscoverEvidence{
					TotalServers:      3,
					ProtectedPipelock: 3,
				},
				VerifyInstall: VerifyInstallEvidence{
					FlightRecorderActive: true,
					ReceiptCount:         10,
				},
				Simulate: audit.SimulateResult{
					Scenarios: []audit.ScenarioResult{
						{Category: "DLP", Detected: true},
						{Category: "SSRF", Detected: false},
						{Category: "SSRF", Detected: false},
					},
				},
				FlightRecorder: FlightRecorderCounts{
					ReceiptCount:  10,
					LastReceiptAt: &recentReceipt,
				},
			},
			opts:         VerifyOpts{MaxReceiptAge: MaxReceiptAgeDays},
			wantFailures: []string{ruleZeroDetection},
		},
		{
			name:   "limitation scenarios excluded from zero detection",
			policy: testPolicyEnterprise,
			evidence: EvidenceBundle{
				Discover: DiscoverEvidence{
					TotalServers:      3,
					ProtectedPipelock: 3,
				},
				VerifyInstall: VerifyInstallEvidence{
					FlightRecorderActive: true,
					ReceiptCount:         10,
				},
				Simulate: audit.SimulateResult{
					Scenarios: []audit.ScenarioResult{
						{Category: "DLP", Detected: true},
						{Category: "SSRF", Detected: false, Limitation: true},
					},
				},
				FlightRecorder: FlightRecorderCounts{
					ReceiptCount:  10,
					LastReceiptAt: &recentReceipt,
				},
			},
			opts: VerifyOpts{MaxReceiptAge: MaxReceiptAgeDays},
		},
		{
			name:   "enterprise recorder inactive",
			policy: testPolicyEnterprise,
			evidence: EvidenceBundle{
				Discover: DiscoverEvidence{
					TotalServers:      3,
					ProtectedPipelock: 3,
				},
				VerifyInstall: VerifyInstallEvidence{
					FlightRecorderActive: false,
					ReceiptCount:         0,
				},
				Simulate: audit.SimulateResult{
					Scenarios: []audit.ScenarioResult{
						{Category: "DLP", Detected: true},
					},
				},
				FlightRecorder: FlightRecorderCounts{},
			},
			opts:         VerifyOpts{MaxReceiptAge: MaxReceiptAgeDays},
			wantFailures: []string{ruleRecorderInactive, ruleNoReceipts},
		},
		{
			name:   "enterprise stale receipts",
			policy: testPolicyEnterprise,
			evidence: EvidenceBundle{
				Discover: DiscoverEvidence{
					TotalServers:      3,
					ProtectedPipelock: 3,
				},
				VerifyInstall: VerifyInstallEvidence{
					FlightRecorderActive: true,
					ReceiptCount:         10,
				},
				Simulate: audit.SimulateResult{
					Scenarios: []audit.ScenarioResult{
						{Category: "DLP", Detected: true},
					},
				},
				FlightRecorder: FlightRecorderCounts{
					ReceiptCount:  10,
					LastReceiptAt: &staleReceipt,
				},
			},
			opts:         VerifyOpts{MaxReceiptAge: MaxReceiptAgeDays},
			wantFailures: []string{ruleStaleReceipts},
		},
		{
			name:   "strict adds unknown servers",
			policy: testPolicyStrict,
			evidence: EvidenceBundle{
				Discover: DiscoverEvidence{
					TotalServers:      3,
					ProtectedPipelock: 3,
					Unknown:           1,
				},
				VerifyInstall: VerifyInstallEvidence{
					FlightRecorderActive: true,
					ReceiptCount:         10,
				},
				Simulate: audit.SimulateResult{
					Scenarios: []audit.ScenarioResult{
						{Category: "DLP", Detected: true},
					},
				},
				FlightRecorder: FlightRecorderCounts{
					ReceiptCount:  10,
					LastReceiptAt: &recentReceipt,
				},
			},
			opts:         VerifyOpts{MaxReceiptAge: MaxReceiptAgeDays},
			wantFailures: []string{ruleUnknownServers},
		},
		{
			name:   "strict adds parse errors",
			policy: testPolicyStrict,
			evidence: EvidenceBundle{
				Discover: DiscoverEvidence{
					TotalServers:      3,
					ProtectedPipelock: 3,
					ParseErrors:       2,
				},
				VerifyInstall: VerifyInstallEvidence{
					FlightRecorderActive: true,
					ReceiptCount:         10,
				},
				Simulate: audit.SimulateResult{
					Scenarios: []audit.ScenarioResult{
						{Category: "DLP", Detected: true},
					},
				},
				FlightRecorder: FlightRecorderCounts{
					ReceiptCount:  10,
					LastReceiptAt: &recentReceipt,
				},
			},
			opts:         VerifyOpts{MaxReceiptAge: MaxReceiptAgeDays},
			wantFailures: []string{ruleDiscoveryParseError},
		},
		{
			name:   "no servers warning",
			policy: testPolicyEnterprise,
			evidence: EvidenceBundle{
				Discover: DiscoverEvidence{},
				VerifyInstall: VerifyInstallEvidence{
					FlightRecorderActive: true,
					ReceiptCount:         10,
				},
				Simulate: audit.SimulateResult{
					Scenarios: []audit.ScenarioResult{
						{Category: "DLP", Detected: true},
					},
				},
				FlightRecorder: FlightRecorderCounts{
					ReceiptCount:  10,
					LastReceiptAt: &recentReceipt,
				},
			},
			opts:         VerifyOpts{MaxReceiptAge: MaxReceiptAgeDays},
			wantWarnings: []string{warnNoServersDiscovered},
		},
		{
			name:   "stale receipt check skipped when max age is 0",
			policy: testPolicyEnterprise,
			evidence: EvidenceBundle{
				Discover: DiscoverEvidence{
					TotalServers:      3,
					ProtectedPipelock: 3,
				},
				VerifyInstall: VerifyInstallEvidence{
					FlightRecorderActive: true,
					ReceiptCount:         10,
				},
				Simulate: audit.SimulateResult{
					Scenarios: []audit.ScenarioResult{
						{Category: "DLP", Detected: true},
					},
				},
				FlightRecorder: FlightRecorderCounts{
					ReceiptCount:  10,
					LastReceiptAt: &staleReceipt,
				},
			},
			opts: VerifyOpts{MaxReceiptAge: 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			failures, warnings := EvaluatePolicy(tt.policy, tt.evidence, tt.opts)

			gotRules := make(map[string]bool)
			for _, f := range failures {
				gotRules[f.Rule] = true
			}
			for _, wantRule := range tt.wantFailures {
				if !gotRules[wantRule] {
					t.Errorf("missing expected failure rule %q, got %v", wantRule, failures)
				}
			}
			if len(failures) != len(tt.wantFailures) {
				t.Errorf("failure count = %d, want %d; got %v", len(failures), len(tt.wantFailures), failures)
			}

			gotWarns := make(map[string]bool)
			for _, w := range warnings {
				gotWarns[w] = true
			}
			for _, wantWarn := range tt.wantWarnings {
				if !gotWarns[wantWarn] {
					t.Errorf("missing expected warning %q, got %v", wantWarn, warnings)
				}
			}
			if len(warnings) != len(tt.wantWarnings) {
				t.Errorf("warning count = %d, want %d; got %v", len(warnings), len(tt.wantWarnings), warnings)
			}
		})
	}
}

func TestVerifyCapsule(t *testing.T) {
	recentReceipt := time.Now().Add(-1 * time.Hour)

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey(): %v", err)
	}

	perfectEvidence := EvidenceBundle{
		Discover: DiscoverEvidence{
			TotalServers:      5,
			ProtectedPipelock: 5,
		},
		VerifyInstall: VerifyInstallEvidence{
			FlightRecorderActive: true,
			ReceiptCount:         100,
		},
		Simulate: audit.SimulateResult{
			Percentage: 100,
			Scenarios: []audit.ScenarioResult{
				{Category: "DLP", Detected: true},
				{Category: "Injection", Detected: true},
			},
		},
		FlightRecorder: FlightRecorderCounts{
			ReceiptCount:  100,
			LastReceiptAt: &recentReceipt,
		},
	}

	badEvidence := EvidenceBundle{
		Discover: DiscoverEvidence{
			TotalServers: 5,
			Unprotected:  5,
		},
		VerifyInstall: VerifyInstallEvidence{
			FlightRecorderActive: false,
		},
		Simulate: audit.SimulateResult{
			Percentage: 0,
			Scenarios: []audit.ScenarioResult{
				{Category: "DLP", Detected: false},
			},
		},
		FlightRecorder: FlightRecorderCounts{},
	}

	emitCapsule := func(t *testing.T, evidence EvidenceBundle) *Capsule {
		t.Helper()
		capsule, err := Emit(config.Defaults(), Options{
			SigningKey:     priv,
			EvidenceBundle: bundlePtr(evidence),
		})
		if err != nil {
			t.Fatalf("Emit(): %v", err)
		}
		return capsule
	}

	t.Run("pass with perfect score", func(t *testing.T) {
		capsule := emitCapsule(t, perfectEvidence)
		result, err := VerifyCapsule(capsule, pub, VerifyOpts{
			Policy:        testPolicyEnterprise,
			MinScore:      85,
			MaxReceiptAge: MaxReceiptAgeDays,
		})
		if err != nil {
			t.Fatalf("VerifyCapsule(): %v", err)
		}
		if !result.Verified {
			t.Error("Verified = false, want true")
		}
		if !result.Passed {
			t.Error("Passed = false, want true")
		}
		if result.Score != 100 {
			t.Errorf("Score = %d, want 100", result.Score)
		}
	})

	t.Run("fail due to low score", func(t *testing.T) {
		capsule := emitCapsule(t, badEvidence)
		result, err := VerifyCapsule(capsule, pub, VerifyOpts{
			Policy:        testPolicyNone,
			MinScore:      85,
			MaxReceiptAge: MaxReceiptAgeDays,
		})
		if err != nil {
			t.Fatalf("VerifyCapsule(): %v", err)
		}
		if result.Passed {
			t.Error("Passed = true, want false (low score)")
		}
	})

	t.Run("fail due to hard failures", func(t *testing.T) {
		capsule := emitCapsule(t, badEvidence)
		result, err := VerifyCapsule(capsule, pub, VerifyOpts{
			Policy:        testPolicyEnterprise,
			MinScore:      0,
			MaxReceiptAge: MaxReceiptAgeDays,
		})
		if err != nil {
			t.Fatalf("VerifyCapsule(): %v", err)
		}
		if result.Passed {
			t.Error("Passed = true, want false (hard failures)")
		}
		if len(result.HardFailures) == 0 {
			t.Error("HardFailures = empty, want at least one")
		}
	})

	t.Run("signature failure returns error", func(t *testing.T) {
		capsule := emitCapsule(t, perfectEvidence)
		capsule.ConfigHash = "tampered"
		_, err := VerifyCapsule(capsule, pub, VerifyOpts{
			Policy:   testPolicyEnterprise,
			MinScore: 85,
		})
		if err == nil {
			t.Fatal("VerifyCapsule() error = nil, want signature failure")
		}
	})

	t.Run("config hash match", func(t *testing.T) {
		capsule := emitCapsule(t, perfectEvidence)
		result, err := VerifyCapsule(capsule, pub, VerifyOpts{
			Policy:        testPolicyEnterprise,
			MinScore:      85,
			ConfigHash:    capsule.ConfigHash,
			MaxReceiptAge: MaxReceiptAgeDays,
		})
		if err != nil {
			t.Fatalf("VerifyCapsule(): %v", err)
		}
		if result.ConfigHashMatch == nil {
			t.Fatal("ConfigHashMatch = nil, want non-nil")
		}
		if !*result.ConfigHashMatch {
			t.Error("ConfigHashMatch = false, want true")
		}
		if result.Passed != true {
			t.Error("Passed = false, want true")
		}
	})

	t.Run("config hash mismatch adds hard failure", func(t *testing.T) {
		capsule := emitCapsule(t, perfectEvidence)
		result, err := VerifyCapsule(capsule, pub, VerifyOpts{
			Policy:        testPolicyEnterprise,
			MinScore:      0,
			ConfigHash:    "wrong-hash",
			MaxReceiptAge: MaxReceiptAgeDays,
		})
		if err != nil {
			t.Fatalf("VerifyCapsule(): %v", err)
		}
		if result.ConfigHashMatch == nil || *result.ConfigHashMatch {
			t.Error("ConfigHashMatch should be false")
		}
		found := false
		for _, f := range result.HardFailures {
			if f.Rule == ruleConfigHashMismatch {
				found = true
			}
		}
		if !found {
			t.Errorf("missing %s hard failure, got %v", ruleConfigHashMismatch, result.HardFailures)
		}
	})

	t.Run("require discovery fails when no servers", func(t *testing.T) {
		emptyDiscovery := EvidenceBundle{
			Discover: DiscoverEvidence{},
			VerifyInstall: VerifyInstallEvidence{
				FlightRecorderActive: true,
				ReceiptCount:         10,
			},
			Simulate: audit.SimulateResult{
				Percentage: 100,
				Scenarios: []audit.ScenarioResult{
					{Category: "DLP", Detected: true},
				},
			},
			FlightRecorder: FlightRecorderCounts{
				ReceiptCount:  10,
				LastReceiptAt: &recentReceipt,
			},
		}
		capsule := emitCapsule(t, emptyDiscovery)
		result, err := VerifyCapsule(capsule, pub, VerifyOpts{
			Policy:           testPolicyEnterprise,
			MinScore:         0,
			MaxReceiptAge:    MaxReceiptAgeDays,
			RequireDiscovery: true,
		})
		if err != nil {
			t.Fatalf("VerifyCapsule(): %v", err)
		}
		if result.Passed {
			t.Error("Passed = true, want false (require-discovery)")
		}
	})

	t.Run("default max receipt age applied", func(t *testing.T) {
		capsule := emitCapsule(t, perfectEvidence)
		result, err := VerifyCapsule(capsule, pub, VerifyOpts{
			Policy:   testPolicyEnterprise,
			MinScore: 0,
		})
		if err != nil {
			t.Fatalf("VerifyCapsule(): %v", err)
		}
		// With recent receipt and default age, should pass.
		if !result.Verified {
			t.Error("Verified = false, want true")
		}
	})

	t.Run("scoring and policy version populated", func(t *testing.T) {
		capsule := emitCapsule(t, perfectEvidence)
		result, err := VerifyCapsule(capsule, pub, VerifyOpts{
			Policy:        testPolicyNone,
			MaxReceiptAge: MaxReceiptAgeDays,
		})
		if err != nil {
			t.Fatalf("VerifyCapsule(): %v", err)
		}
		if result.ScoringVersion != ScoringVersion {
			t.Errorf("ScoringVersion = %q, want %q", result.ScoringVersion, ScoringVersion)
		}
		if result.PolicyVersion != SchemaVersion {
			t.Errorf("PolicyVersion = %q, want %q", result.PolicyVersion, SchemaVersion)
		}
	})
}

func TestHasZeroDetectionCategory(t *testing.T) {
	tests := []struct {
		name      string
		scenarios []audit.ScenarioResult
		want      bool
	}{
		{
			name:      "empty scenarios",
			scenarios: nil,
			want:      false,
		},
		{
			name: "all detected",
			scenarios: []audit.ScenarioResult{
				{Category: "DLP", Detected: true},
				{Category: "DLP", Detected: true},
				{Category: "SSRF", Detected: true},
			},
			want: false,
		},
		{
			name: "one category all undetected",
			scenarios: []audit.ScenarioResult{
				{Category: "DLP", Detected: true},
				{Category: "SSRF", Detected: false},
				{Category: "SSRF", Detected: false},
			},
			want: true,
		},
		{
			name: "partial detection in category ok",
			scenarios: []audit.ScenarioResult{
				{Category: "DLP", Detected: true},
				{Category: "SSRF", Detected: true},
				{Category: "SSRF", Detected: false},
			},
			want: false,
		},
		{
			name: "limitation exclusion",
			scenarios: []audit.ScenarioResult{
				{Category: "DLP", Detected: true},
				{Category: "SSRF", Detected: false, Limitation: true},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasZeroDetectionCategory(tt.scenarios)
			if got != tt.want {
				t.Errorf("hasZeroDetectionCategory() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFactorDetail(t *testing.T) {
	d := factor(60, 25)
	if d.RawPercent != 60 {
		t.Errorf("RawPercent = %d, want 60", d.RawPercent)
	}
	if d.Weight != 25 {
		t.Errorf("Weight = %d, want 25", d.Weight)
	}
	if d.Weighted != 15 {
		t.Errorf("Weighted = %d, want 15 (60*25/100)", d.Weighted)
	}
}
