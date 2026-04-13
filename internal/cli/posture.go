// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	posturepkg "github.com/luckyPipewrench/pipelock/internal/posture"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// Exit codes for posture verify. Exit 0 = passed, 1 = integrity failure
// (bad signature, expired, bad schema), 2 = verified but policy failed.
const (
	exitVerifyIntegrity  = 1
	exitVerifyPolicyFail = 2
	verifyDefaultMaxAge  = "30d"
	verifyDefaultReceipt = "7d"
	maxProofJSONBytes    = 8 << 20

	// errPolicyFailed is the sentinel message for policy-fail exit code.
	errPolicyFailed = "posture verification failed: policy gates or minimum score not met"
)

func postureCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "posture",
		Short: "Generate and verify signed posture evidence",
	}

	cmd.AddCommand(postureEmitCmd())
	cmd.AddCommand(postureVerifyCmd())
	return cmd
}

func postureVerifyCmd() *cobra.Command {
	var (
		proofFile        string
		keyFile          string
		policy           string
		minScore         int
		maxAgeStr        string
		maxReceiptAgeStr string
		configFile       string
		jsonOutput       bool
		requireDiscovery bool
	)

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a signed posture capsule against policy gates",
		Long: `Verify the signature, score, and policy compliance of a posture
proof.json capsule.

Exit codes:
  0  Verified and passed all policy gates
  1  Integrity/authenticity failure (bad signature, expired, bad schema)
  2  Verified but policy failed (hard gate violation or score below minimum)`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			maxAgeDays, err := parseDays(maxAgeStr)
			if err != nil {
				return fmt.Errorf("parsing --max-age: %w", err)
			}

			maxReceiptAgeDays, err := parseDays(maxReceiptAgeStr)
			if err != nil {
				return fmt.Errorf("parsing --max-receipt-age: %w", err)
			}
			if minScore < 0 || minScore > 100 {
				return fmt.Errorf("--min-score must be between 0 and 100, got %d", minScore)
			}

			opts := posturepkg.VerifyOpts{
				Policy:               policy,
				MinScore:             minScore,
				SkipMinScoreGate:     minScore == 0,
				MaxAgeDays:           maxAgeDays,
				MaxReceiptAge:        maxReceiptAgeDays,
				SkipReceiptFreshness: maxReceiptAgeDays == 0,
				RequireDiscovery:     requireDiscovery,
			}

			// Compute local config hash for comparison if --config is set.
			if configFile != "" {
				cfg, cfgErr := cliutil.LoadConfigOrDefault(configFile)
				if cfgErr != nil {
					return fmt.Errorf("loading config for hash comparison: %w", cfgErr)
				}
				hash, hashErr := posturepkg.HashConfig(cfg)
				if hashErr != nil {
					return fmt.Errorf("hashing local config: %w", hashErr)
				}
				opts.ConfigHash = hash
			}

			capsule, err := loadProofFile(proofFile)
			if err != nil {
				return exitVerifyIntegrityError(cmd, jsonOutput, policy, nil, fmt.Errorf("loading proof: %w", err))
			}

			pubKey, err := loadPublicKey(keyFile)
			if err != nil {
				return exitVerifyIntegrityError(cmd, jsonOutput, policy, capsule, fmt.Errorf("loading public key: %w", err))
			}

			result, err := posturepkg.VerifyCapsule(capsule, pubKey, opts)
			if err != nil {
				return exitVerifyIntegrityError(cmd, jsonOutput, policy, capsule, fmt.Errorf("verification failed: %w", err))
			}

			if jsonOutput {
				if encErr := writeVerifyJSON(cmd, result); encErr != nil {
					return fmt.Errorf("encoding JSON output: %w", encErr)
				}
				if !result.Passed {
					return cliutil.ExitCodeError(exitVerifyPolicyFail, fmt.Errorf("%s", errPolicyFailed))
				}
				return nil
			}

			printVerifyResult(cmd, result, capsule, maxAgeDays)

			if !result.Passed {
				return cliutil.ExitCodeError(exitVerifyPolicyFail, fmt.Errorf("%s", errPolicyFailed))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&proofFile, "proof", "", "path to proof.json (required)")
	cmd.Flags().StringVar(&keyFile, "key", "", "path to Ed25519 public key file (required)")
	cmd.Flags().StringVar(&policy, "policy", posturepkg.PolicyEnterprise, "policy level: none, enterprise, strict")
	cmd.Flags().IntVar(&minScore, "min-score", posturepkg.DefaultMinScore, "minimum passing score (0-100)")
	cmd.Flags().StringVar(&maxAgeStr, "max-age", verifyDefaultMaxAge, "maximum capsule age (e.g. 30d)")
	cmd.Flags().StringVar(&maxReceiptAgeStr, "max-receipt-age", verifyDefaultReceipt, "maximum receipt staleness (e.g. 7d)")
	cmd.Flags().StringVarP(&configFile, "config", "c", "", "local config for hash comparison")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output as JSON")
	cmd.Flags().BoolVar(&requireDiscovery, "require-discovery", false, "fail if 0 servers discovered")

	_ = cmd.MarkFlagRequired("proof")
	_ = cmd.MarkFlagRequired("key")

	return cmd
}

// printVerifyResult formats the human-readable verify output.
func printVerifyResult(cmd *cobra.Command, result *posturepkg.VerifyResult, capsule *posturepkg.Capsule, maxAgeDays int) {
	w := cmd.OutOrStdout()
	verdict := "PASS"
	if !result.Passed {
		verdict = "FAIL"
	}

	_, _ = fmt.Fprintf(w, "Posture Verification: %s (score %d/100)\n\n", verdict, result.Score)

	// Transport coverage detail.
	disc := capsule.Evidence.Discover
	protectedAny := disc.ProtectedPipelock + disc.ProtectedOther
	totalScannable := disc.TotalServers + disc.ParseErrors
	transportDesc := "no servers"
	if totalScannable > 0 {
		transportDesc = fmt.Sprintf("%d/%d protected", protectedAny, totalScannable)
	}
	_, _ = fmt.Fprintf(w, "  Transport coverage:    %d%% (%s)%s\n",
		result.FactorScores.TransportRatio.RawPercent, transportDesc,
		weightedSuffix(result.FactorScores.TransportRatio))

	// Recorder health detail.
	recDesc := "inactive"
	if capsule.Evidence.VerifyInstall.FlightRecorderActive {
		recDesc = fmt.Sprintf("active, %d receipts", capsule.Evidence.VerifyInstall.ReceiptCount)
		if result.FactorScores.RecorderHealth.RawPercent == 50 {
			recDesc += ", stale"
		}
	}
	_, _ = fmt.Fprintf(w, "  Flight recorder:       %d%% (%s)%s\n",
		result.FactorScores.RecorderHealth.RawPercent, recDesc,
		weightedSuffix(result.FactorScores.RecorderHealth))

	// Simulate detail.
	sim := capsule.Evidence.Simulate
	simDesc := fmt.Sprintf("%d/%d scenarios", sim.Passed, sim.Total)
	_, _ = fmt.Fprintf(w, "  Simulate pass rate:    %d%% (%s)%s\n",
		result.FactorScores.SimulatePassRate.RawPercent, simDesc,
		weightedSuffix(result.FactorScores.SimulatePassRate))

	// Cleanliness detail.
	cleanDesc := fmt.Sprintf("%d unprotected", disc.Unprotected)
	_, _ = fmt.Fprintf(w, "  Discovery cleanliness: %d%% (%s)%s\n",
		result.FactorScores.DiscoveryCleanliness.RawPercent, cleanDesc,
		weightedSuffix(result.FactorScores.DiscoveryCleanliness))

	_, _ = fmt.Fprintf(w, "\n")

	// Policy summary.
	_, _ = fmt.Fprintf(w, "  Policy: %s (%d hard failures)\n",
		result.Policy, len(result.HardFailures))

	for _, f := range result.HardFailures {
		_, _ = fmt.Fprintf(w, "    FAIL: %s -- %s\n", f.Rule, f.Detail)
	}

	for _, warn := range result.Warnings {
		_, _ = fmt.Fprintf(w, "    WARN: %s\n", warn)
	}

	// Generated line.
	maxAgeLabel := "disabled"
	if maxAgeDays > 0 {
		maxAgeLabel = fmt.Sprintf("%dd", maxAgeDays)
	}
	_, _ = fmt.Fprintf(w, "\n  Generated: %s (age: %s, max: %s)\n",
		capsule.GeneratedAt.Format(time.RFC3339), formatVerifyAge(capsule.GeneratedAt), maxAgeLabel)

	// Config hash.
	if result.ConfigHashMatch != nil {
		hashStatus := "match"
		if !*result.ConfigHashMatch {
			hashStatus = "mismatch"
		}
		_, _ = fmt.Fprintf(w, "  Config hash: %s\n", hashStatus)
	}
}

func weightedSuffix(d posturepkg.FactorDetail) string {
	return fmt.Sprintf(" [%d/%d]", d.Weighted, d.Weight)
}

func writeVerifyJSON(cmd *cobra.Command, result *posturepkg.VerifyResult) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func exitVerifyIntegrityError(
	cmd *cobra.Command,
	jsonOutput bool,
	policy string,
	capsule *posturepkg.Capsule,
	err error,
) error {
	if jsonOutput {
		result := &posturepkg.VerifyResult{
			Verified:       false,
			Passed:         false,
			Error:          err.Error(),
			Policy:         policy,
			PolicyVersion:  posturepkg.SchemaVersion,
			ScoringVersion: posturepkg.ScoringVersion,
		}
		if capsule != nil {
			result.GeneratedAt = capsule.GeneratedAt
			result.ExpiresAt = capsule.ExpiresAt
			result.LastReceiptAt = capsule.Evidence.FlightRecorder.LastReceiptAt
		}
		if jsonErr := writeVerifyJSON(cmd, result); jsonErr != nil {
			return fmt.Errorf("encoding JSON output: %w", jsonErr)
		}
	}
	return cliutil.ExitCodeError(exitVerifyIntegrity, err)
}

func formatVerifyAge(ts time.Time) string {
	elapsed := time.Since(ts)
	if elapsed <= 0 {
		return "0d"
	}
	days := int((elapsed + (24 * time.Hour) - time.Nanosecond) / (24 * time.Hour))
	return fmt.Sprintf("%dd", days)
}

func loadProofFile(path string) (*posturepkg.Capsule, error) {
	cleanPath := filepath.Clean(path)
	f, err := os.Open(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", cleanPath, err)
	}
	defer func() {
		_ = f.Close()
	}()

	data, err := io.ReadAll(io.LimitReader(f, maxProofJSONBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", cleanPath, err)
	}
	if len(data) > maxProofJSONBytes {
		return nil, fmt.Errorf("proof JSON exceeds %d bytes", maxProofJSONBytes)
	}

	var capsule posturepkg.Capsule
	if err := json.Unmarshal(data, &capsule); err != nil {
		return nil, fmt.Errorf("parsing proof JSON: %w", err)
	}
	return &capsule, nil
}

// loadPublicKey reads a public key file, trying the pipelock versioned format
// first, then falling back to raw hex encoding.
func loadPublicKey(path string) (ed25519.PublicKey, error) {
	// Try pipelock versioned format first.
	key, err := signing.LoadPublicKeyFile(path)
	if err == nil {
		return key, nil
	}

	// Fall back to raw hex encoding.
	cleanPath := filepath.Clean(path)
	data, readErr := os.ReadFile(cleanPath)
	if readErr != nil {
		return nil, fmt.Errorf("reading key file: %w", readErr)
	}

	raw, hexErr := hex.DecodeString(strings.TrimSpace(string(data)))
	if hexErr != nil {
		// Return the original versioned-format error since it's more informative.
		return nil, fmt.Errorf("loading public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length: got %d, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// parseDays parses a duration string like "30d" into days.
func parseDays(s string) (int, error) {
	s = strings.TrimSpace(s)
	if !strings.HasSuffix(s, "d") {
		return 0, fmt.Errorf("expected format Nd (e.g. 30d), got %q", s)
	}
	numStr := strings.TrimSuffix(s, "d")
	n, err := strconv.Atoi(numStr)
	if err != nil {
		return 0, fmt.Errorf("invalid day count %q: %w", numStr, err)
	}
	if n < 0 {
		return 0, fmt.Errorf("day count must be non-negative, got %d", n)
	}
	return n, nil
}

func postureEmitCmd() *cobra.Command {
	var (
		configFile     string
		outputDir      string
		expirationDays int
	)

	cmd := &cobra.Command{
		Use:   "emit",
		Short: "Emit a signed posture capsule",
		Long: `Generate a signed posture capsule from the current config, discovery
state, simulated scanner coverage, and flight recorder receipts.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := cliutil.LoadConfigOrDefault(configFile)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			capsule, err := posturepkg.Emit(cfg, posturepkg.Options{
				ExpirationDays: expirationDays,
			})
			if err != nil {
				return fmt.Errorf("emit posture capsule: %w", err)
			}

			path, err := posturepkg.WriteProofJSON(outputDir, capsule)
			if err != nil {
				return fmt.Errorf("write posture capsule: %w", err)
			}

			// TODO: write proof.md once the human-readable posture summary lands.
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Wrote %s\n", path)
			return nil
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "config file (default: built-in defaults)")
	cmd.Flags().StringVarP(&outputDir, "output", "o", posturepkg.DefaultOutputDir, "output directory for posture artifacts")
	cmd.Flags().IntVar(&expirationDays, "expiration-days", 0, "days until the capsule expires (default 30)")
	return cmd
}
