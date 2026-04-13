// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package posture

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cli/audit"
)

// Policy levels for verification gates.
const (
	PolicyNone       = "none"       // score only, no hard gates
	PolicyEnterprise = "enterprise" // standard hard gates
	PolicyStrict     = "strict"     // enterprise + unknown/parse_error gates
)

// ScoreWeights are the factor weights (must sum to 100).
const (
	WeightTransportRatio       = 25
	WeightRecorderHealth       = 15
	WeightSimulatePassRate     = 35
	WeightDiscoveryCleanliness = 25
)

// ScoringVersion tracks the score model for reproducibility.
const ScoringVersion = "1"

// MaxReceiptAgeDays is the default max age for the most recent receipt.
const MaxReceiptAgeDays = 7

// Hard failure rule names.
const (
	ruleUnprotectedServers  = "unprotected_servers"
	ruleZeroDetection       = "zero_detection_category"
	ruleRecorderInactive    = "recorder_inactive"
	ruleNoReceipts          = "no_receipts"
	ruleStaleReceipts       = "stale_receipts"
	ruleCapsuleTooOld       = "capsule_too_old"
	ruleConfigHashMismatch  = "config_hash_mismatch"
	ruleUnknownServers      = "unknown_servers"
	ruleDiscoveryParseError = "discovery_parse_errors"
)

// Warning message for no discovered servers.
const warnNoServersDiscovered = "no_servers_discovered"

// VerifyResult is the full verification outcome.
type VerifyResult struct {
	Verified        bool          `json:"verified"`
	Passed          bool          `json:"passed"`
	Score           int           `json:"score"`
	FactorScores    FactorScores  `json:"factor_scores"`
	HardFailures    []HardFailure `json:"hard_failures,omitempty"`
	Warnings        []string      `json:"warnings,omitempty"`
	Policy          string        `json:"policy"`
	PolicyVersion   string        `json:"policy_version"`
	ScoringVersion  string        `json:"scoring_version"`
	GeneratedAt     time.Time     `json:"generated_at"`
	ExpiresAt       time.Time     `json:"expires_at"`
	LastReceiptAt   *time.Time    `json:"last_receipt_at,omitempty"`
	ConfigHashMatch *bool         `json:"config_hash_match,omitempty"`
}

// FactorScores contains the breakdown of each scoring factor.
type FactorScores struct {
	TransportRatio       FactorDetail `json:"transport_ratio"`
	RecorderHealth       FactorDetail `json:"recorder_health"`
	SimulatePassRate     FactorDetail `json:"simulate_pass_rate"`
	DiscoveryCleanliness FactorDetail `json:"discovery_cleanliness"`
}

// FactorDetail is a single scoring factor with raw and weighted values.
type FactorDetail struct {
	RawPercent int `json:"raw_percent"` // 0-100
	Weight     int `json:"weight"`
	Weighted   int `json:"weighted"` // raw_percent * weight / 100
}

// HardFailure is a policy gate failure.
type HardFailure struct {
	Rule   string `json:"rule"`
	Detail string `json:"detail"`
}

// VerifyOpts configures posture verification.
type VerifyOpts struct {
	Policy           string // "none", "enterprise", "strict"
	MinScore         int
	MaxAgeDays       int
	MaxReceiptAge    int    // days; 0 = skip
	ConfigHash       string // from local config; empty = skip
	RequireDiscovery bool
}

// ComputeScore calculates the posture score from an evidence bundle.
func ComputeScore(evidence EvidenceBundle, maxReceiptAgeDays int) (int, FactorScores) {
	transportPct := computeTransportPct(evidence.Discover)
	recorderPct := computeRecorderPct(evidence.VerifyInstall, evidence.FlightRecorder, maxReceiptAgeDays)
	simulatePct := evidence.Simulate.Percentage
	cleanlinessPct := computeCleanlinessPct(evidence.Discover)

	transport := factor(transportPct, WeightTransportRatio)
	recorder := factor(recorderPct, WeightRecorderHealth)
	simulate := factor(simulatePct, WeightSimulatePassRate)
	cleanliness := factor(cleanlinessPct, WeightDiscoveryCleanliness)

	score := (transport.Weighted + recorder.Weighted + simulate.Weighted + cleanliness.Weighted)

	factors := FactorScores{
		TransportRatio:       transport,
		RecorderHealth:       recorder,
		SimulatePassRate:     simulate,
		DiscoveryCleanliness: cleanliness,
	}

	return score, factors
}

// EvaluatePolicy checks the evidence bundle against the given policy.
// Returns hard failures and warnings.
func EvaluatePolicy(policy string, evidence EvidenceBundle, opts VerifyOpts) ([]HardFailure, []string) {
	var failures []HardFailure
	var warnings []string

	switch policy {
	case PolicyNone:
		return failures, warnings
	case PolicyEnterprise, PolicyStrict:
		// valid, continue
	default:
		failures = append(failures, HardFailure{
			Rule:   "invalid_policy",
			Detail: fmt.Sprintf("unknown policy %q; must be none, enterprise, or strict", policy),
		})
		return failures, warnings
	}

	// Warning: no servers discovered (vacuous truth, not a failure).
	totalScannable := evidence.Discover.TotalServers + evidence.Discover.ParseErrors
	if totalScannable == 0 && evidence.Discover.ParseErrors == 0 {
		warnings = append(warnings, warnNoServersDiscovered)
	}

	// Enterprise gates.
	if evidence.Discover.Unprotected > 0 {
		failures = append(failures, HardFailure{
			Rule:   ruleUnprotectedServers,
			Detail: fmt.Sprintf("%d unprotected MCP servers", evidence.Discover.Unprotected),
		})
	}

	if hasZeroDetectionCategory(evidence.Simulate.Scenarios) {
		failures = append(failures, HardFailure{
			Rule:   ruleZeroDetection,
			Detail: "at least one category has 0% detection rate",
		})
	}

	if !evidence.VerifyInstall.FlightRecorderActive {
		failures = append(failures, HardFailure{
			Rule:   ruleRecorderInactive,
			Detail: "flight recorder is not active",
		})
	}

	if evidence.VerifyInstall.ReceiptCount == 0 {
		failures = append(failures, HardFailure{
			Rule:   ruleNoReceipts,
			Detail: "no action receipts recorded",
		})
	}

	maxAge := opts.MaxReceiptAge
	if maxAge > 0 && evidence.FlightRecorder.LastReceiptAt != nil {
		elapsed := time.Since(*evidence.FlightRecorder.LastReceiptAt)
		if elapsed > maxAgeDuration(maxAge) {
			failures = append(failures, HardFailure{
				Rule:   ruleStaleReceipts,
				Detail: fmt.Sprintf("last receipt %s ago (max: %dd)", formatElapsedDays(elapsed), maxAge),
			})
		}
	}

	// Strict gates (superset of enterprise).
	if policy == PolicyStrict {
		if evidence.Discover.Unknown > 0 {
			failures = append(failures, HardFailure{
				Rule:   ruleUnknownServers,
				Detail: fmt.Sprintf("%d unknown MCP servers", evidence.Discover.Unknown),
			})
		}

		if evidence.Discover.ParseErrors > 0 {
			failures = append(failures, HardFailure{
				Rule:   ruleDiscoveryParseError,
				Detail: fmt.Sprintf("%d discovery parse errors", evidence.Discover.ParseErrors),
			})
		}
	}

	return failures, warnings
}

// VerifyCapsule performs full verification: signature, score, and policy gates.
func VerifyCapsule(capsule *Capsule, trustedKey ed25519.PublicKey, opts VerifyOpts) (*VerifyResult, error) {
	if err := Verify(capsule, trustedKey); err != nil {
		return nil, err
	}

	result := &VerifyResult{
		Verified:       true,
		Policy:         opts.Policy,
		PolicyVersion:  SchemaVersion,
		ScoringVersion: ScoringVersion,
		GeneratedAt:    capsule.GeneratedAt,
		ExpiresAt:      capsule.ExpiresAt,
		LastReceiptAt:  capsule.Evidence.FlightRecorder.LastReceiptAt,
	}

	// Config hash comparison.
	if opts.ConfigHash != "" {
		match := opts.ConfigHash == capsule.ConfigHash
		result.ConfigHashMatch = &match
	}

	// MaxReceiptAge=0 means skip stale-receipt scoring. The CLI sets the
	// default (7d); callers that want no staleness check pass 0 explicitly.
	score, factors := ComputeScore(capsule.Evidence, opts.MaxReceiptAge)
	result.Score = score
	result.FactorScores = factors

	failures, warnings := EvaluatePolicy(opts.Policy, capsule.Evidence, opts)
	result.HardFailures = failures
	result.Warnings = warnings

	if opts.MaxAgeDays > 0 {
		elapsed := time.Since(capsule.GeneratedAt)
		if elapsed > maxAgeDuration(opts.MaxAgeDays) {
			result.HardFailures = append(result.HardFailures, HardFailure{
				Rule:   ruleCapsuleTooOld,
				Detail: fmt.Sprintf("capsule age %s exceeds max %dd", formatElapsedDays(elapsed), opts.MaxAgeDays),
			})
		}
	}

	// Config hash mismatch as a hard failure.
	if result.ConfigHashMatch != nil && !*result.ConfigHashMatch {
		result.HardFailures = append(result.HardFailures, HardFailure{
			Rule:   ruleConfigHashMismatch,
			Detail: "local config hash does not match capsule",
		})
	}

	// Require discovery gate.
	if opts.RequireDiscovery {
		if capsule.Evidence.Discover.TotalServers == 0 {
			result.HardFailures = append(result.HardFailures, HardFailure{
				Rule:   "no_servers_discovered",
				Detail: "0 servers discovered (--require-discovery)",
			})
		}
	}

	// Determine pass/fail.
	result.Passed = len(result.HardFailures) == 0 && result.Score >= opts.MinScore

	return result, nil
}

func computeTransportPct(d DiscoverEvidence) int {
	totalScannable := d.TotalServers + d.ParseErrors
	if totalScannable == 0 {
		// Vacuous truth: no servers to protect = 100%.
		return 100
	}
	if d.TotalServers == 0 && d.ParseErrors > 0 {
		// Parse errors only, no successfully-parsed servers to assess.
		return 0
	}

	protectedAny := d.ProtectedPipelock + d.ProtectedOther
	return (100 * protectedAny) / totalScannable
}

func computeRecorderPct(vi VerifyInstallEvidence, fr FlightRecorderCounts, maxAgeDays int) int {
	if !vi.FlightRecorderActive {
		return 0
	}
	if vi.ReceiptCount == 0 {
		return 0
	}
	if maxAgeDays > 0 && fr.LastReceiptAt != nil {
		if time.Since(*fr.LastReceiptAt) > maxAgeDuration(maxAgeDays) {
			// Active but stale.
			return 50
		}
	}
	return 100
}

func computeCleanlinessPct(d DiscoverEvidence) int {
	if d.Unprotected > 0 {
		return 0
	}
	if d.Unknown > 0 || d.ParseErrors > 0 {
		return 50
	}
	return 100
}

func factor(rawPct, weight int) FactorDetail {
	return FactorDetail{
		RawPercent: rawPct,
		Weight:     weight,
		Weighted:   (rawPct * weight) / 100,
	}
}

func maxAgeDuration(days int) time.Duration {
	return time.Duration(days) * 24 * time.Hour
}

func formatElapsedDays(elapsed time.Duration) string {
	if elapsed <= 0 {
		return "0d"
	}
	days := int((elapsed + (24 * time.Hour) - time.Nanosecond) / (24 * time.Hour))
	return fmt.Sprintf("%dd", days)
}

// hasZeroDetectionCategory checks if any scenario category has total>0
// but detected==0, excluding limitation scenarios.
func hasZeroDetectionCategory(scenarios []audit.ScenarioResult) bool {
	type categoryStats struct {
		total    int
		detected int
	}
	cats := make(map[string]*categoryStats)

	for _, s := range scenarios {
		if s.Limitation {
			continue
		}
		stats, ok := cats[s.Category]
		if !ok {
			stats = &categoryStats{}
			cats[s.Category] = stats
		}
		stats.total++
		if s.Detected {
			stats.detected++
		}
	}

	for _, stats := range cats {
		if stats.total > 0 && stats.detected == 0 {
			return true
		}
	}
	return false
}
