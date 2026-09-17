// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cli/contain/workspacediff"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/contract"
	posturepkg "github.com/luckyPipewrench/pipelock/internal/posture"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// Exit codes for posture verify. These are part of the CLI's stable contract.
// CI pipelines should key on these values:
//
//	0 = Verification passed: signature valid, score meets minimum, all policy gates passed.
//	1 = Verification could not complete: flag parse error, bad proof file, bad key,
//	    bad signature, expired capsule, or schema mismatch.
//	2 = Verified but failed: signature is valid, but policy gates or minimum score not met.
//	    This means the capsule is authentic but the environment doesn't meet the policy.
const (
	exitVerifyIntegrity  = 1
	exitVerifyPolicyFail = 2
	verifyDefaultMaxAge  = "30d"
	verifyDefaultReceipt = "7d"
	maxProofJSONBytes    = 8 << 20
	// maxWorkspaceStatementBytes bounds untrusted CI input before JSON parsing.
	maxWorkspaceStatementBytes = 8 << 20

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
		workspaceStmt    string
	)

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a signed posture capsule against policy gates",
		Long: `Verify the signature, score, and policy compliance of a posture
proof.json capsule.

Exit codes:
  0  Verification passed: signature valid, score meets minimum, all policy gates passed
  1  Verification could not complete: flag parse error, bad proof file, bad key,
     bad signature, expired capsule, or schema mismatch
  2  Verified but failed: signature is valid, but policy gates or minimum score not met`,
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

			capsule, capsuleBytes, err := loadProofFile(proofFile)
			if err != nil {
				return exitVerifyIntegrityError(cmd, jsonOutput, policy, nil, workspaceStmt != "", fmt.Errorf("loading proof: %w", err))
			}

			pubKey, err := loadPublicKey(keyFile)
			if err != nil {
				return exitVerifyIntegrityError(cmd, jsonOutput, policy, capsule, workspaceStmt != "", fmt.Errorf("loading public key: %w", err))
			}

			result, err := posturepkg.VerifyCapsule(capsule, pubKey, opts)
			if err != nil {
				return exitVerifyIntegrityError(cmd, jsonOutput, policy, capsule, workspaceStmt != "", fmt.Errorf("verification failed: %w", err))
			}

			// A valid posture capsule and a valid workspace change statement
			// are each individually authentic on their own signature, but
			// that does NOT prove they came from the same session: a
			// statement from an unrelated run verifies against the same key
			// just as well. --workspace-statement additionally hashes the
			// EXACT capsule bytes at --proof and requires that digest to
			// match the statement's declared binding, so a mismatched pair
			// is rejected here rather than accepted as if it were coherent.
			workspaceStmtBound := false
			var workspaceStmtSummary *workspaceStatementSummary
			if workspaceStmt != "" {
				signedStmt, bindErr := verifyWorkspaceStatementBinding(workspaceStmt, capsuleBytes, pubKey)
				if bindErr != nil {
					return exitVerifyIntegrityError(cmd, jsonOutput, policy, capsule, true,
						fmt.Errorf("workspace change statement verification failed: %w", bindErr))
				}
				workspaceStmtBound = true
				summary := summarizeWorkspaceStatement(signedStmt)
				workspaceStmtSummary = &summary
				if !jsonOutput {
					_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Workspace change statement: signature valid and bound to this capsule (boundary check: %s)\n", summary.BoundaryCheck)
					if !summary.Complete {
						_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Workspace change statement: incomplete: %s\n", summary.IncompleteReason)
					}
				}
				if !summary.Complete {
					result.Passed = false
					result.Error = fmt.Sprintf("workspace change statement is incomplete: %s", summary.IncompleteReason)
				}
			}

			if jsonOutput {
				if encErr := writeVerifyJSON(cmd, result, workspaceStmt != "", workspaceStmtBound, "", workspaceStmtSummary); encErr != nil {
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
	cmd.Flags().StringVar(&keyFile, "key", "", "path to Ed25519 public key file or raw hex public key (required)")
	cmd.Flags().StringVar(&policy, "policy", posturepkg.PolicyEnterprise, "policy level: none, enterprise, strict")
	cmd.Flags().IntVar(&minScore, "min-score", posturepkg.DefaultMinScore, "minimum passing score (0-100)")
	cmd.Flags().StringVar(&maxAgeStr, "max-age", verifyDefaultMaxAge, "maximum capsule age (e.g. 30d)")
	cmd.Flags().StringVar(&maxReceiptAgeStr, "max-receipt-age", verifyDefaultReceipt, "maximum receipt staleness (e.g. 7d)")
	cmd.Flags().StringVarP(&configFile, "config", "c", "", "local config for hash comparison")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output as JSON")
	cmd.Flags().BoolVar(&requireDiscovery, "require-discovery", false, "fail if 0 servers discovered")
	cmd.Flags().StringVar(&workspaceStmt, "workspace-statement", "", "path to a signed workspace-change-statement.json to verify against --proof (checks its signature AND that it is bound to this exact capsule's bytes)")

	_ = cmd.MarkFlagRequired("proof")
	_ = cmd.MarkFlagRequired("key")

	return cmd
}

// verifyWorkspaceStatementBinding reads the signed workspace change statement
// at stmtPath and verifies both its own signature and that it is bound to
// capsuleBytes -- the EXACT bytes this command already authenticated via
// loadProofFile, never bytes re-read from the capsule's path (H1: a re-read
// here would authenticate one set of bytes and bind against a possibly
// different set read moments later).
func verifyWorkspaceStatementBinding(stmtPath string, capsuleBytes []byte, pubKey ed25519.PublicKey) (workspacediff.SignedStatement, error) {
	cleanPath := filepath.Clean(stmtPath)
	f, err := os.Open(cleanPath)
	if err != nil {
		return workspacediff.SignedStatement{}, fmt.Errorf("reading %s: %w", cleanPath, err)
	}
	defer func() {
		_ = f.Close()
	}()
	data, err := io.ReadAll(io.LimitReader(f, maxWorkspaceStatementBytes+1))
	if err != nil {
		return workspacediff.SignedStatement{}, fmt.Errorf("reading %s: %w", cleanPath, err)
	}
	if len(data) > maxWorkspaceStatementBytes {
		return workspacediff.SignedStatement{}, fmt.Errorf("workspace change statement exceeds %d bytes", maxWorkspaceStatementBytes)
	}
	// A signed artifact is decoded strictly: an unknown field is dropped by a
	// permissive parse, so a statement carrying one verifies here and means
	// something else to a consumer that does read it. DecodeStrictJSON is the
	// shared signed-artifact transport decoder and also rejects duplicate keys
	// and trailing tokens.
	var signed workspacediff.SignedStatement
	if err := contract.DecodeStrictJSON(data, &signed); err != nil {
		return workspacediff.SignedStatement{}, fmt.Errorf("parsing %s: %w", cleanPath, err)
	}
	if err := workspacediff.VerifyBindingBytes(signed, capsuleBytes, pubKey); err != nil {
		return workspacediff.SignedStatement{}, err
	}
	return signed, nil
}

type workspaceStatementSummary struct {
	Complete         bool
	BoundaryCheck    string
	IncompleteReason string
}

func summarizeWorkspaceStatement(signed workspacediff.SignedStatement) workspaceStatementSummary {
	summary := workspaceStatementSummary{Complete: true}
	boundaryChecks := make(map[string]struct{}, len(signed.Statements))
	incompleteReasons := make([]string, 0, len(signed.Statements))
	for _, statement := range signed.Statements {
		boundaryChecks[string(statement.BoundaryCheck)] = struct{}{}
		if statement.Incomplete {
			summary.Complete = false
			if statement.IncompleteReason != "" {
				incompleteReasons = append(incompleteReasons, statement.IncompleteReason)
			}
		}
	}
	summary.BoundaryCheck = joinWorkspaceStatementFields(boundaryChecks)
	summary.IncompleteReason = strings.Join(incompleteReasons, "; ")
	if !summary.Complete && summary.IncompleteReason == "" {
		summary.IncompleteReason = "signed workspace observation is incomplete"
	}
	return summary
}

func joinWorkspaceStatementFields(fields map[string]struct{}) string {
	values := make([]string, 0, len(fields))
	for field := range fields {
		values = append(values, field)
	}
	sort.Strings(values)
	return strings.Join(values, "; ")
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

// verifyJSONOutput is the --json result shape for `pipelock posture verify`.
// It embeds posturepkg.VerifyResult unmodified and adds the
// workspace-statement binding outcome only when --workspace-statement was
// requested, so a bound-statement check never has to fall back to a stray
// prose line that would corrupt --json output (M7).
type verifyJSONOutput struct {
	*posturepkg.VerifyResult
	WorkspaceStatement *workspaceStatementJSONResult `json:"workspace_statement,omitempty"`
}

type workspaceStatementJSONResult struct {
	Bound            bool   `json:"bound"`
	Complete         *bool  `json:"complete,omitempty"`
	BoundaryCheck    string `json:"boundary_check,omitempty"`
	IncompleteReason string `json:"incomplete_reason,omitempty"`
	Reason           string `json:"reason,omitempty"`
}

func writeVerifyJSON(cmd *cobra.Command, result *posturepkg.VerifyResult, workspaceStmtRequested, workspaceStmtBound bool, workspaceStmtReason string, summary *workspaceStatementSummary) error {
	out := verifyJSONOutput{VerifyResult: result}
	if workspaceStmtRequested {
		out.WorkspaceStatement = &workspaceStatementJSONResult{Bound: workspaceStmtBound, Reason: workspaceStmtReason}
		if summary != nil {
			out.WorkspaceStatement.Complete = &summary.Complete
			out.WorkspaceStatement.BoundaryCheck = summary.BoundaryCheck
			out.WorkspaceStatement.IncompleteReason = summary.IncompleteReason
		}
	}
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func exitVerifyIntegrityError(
	cmd *cobra.Command,
	jsonOutput bool,
	policy string,
	capsule *posturepkg.Capsule,
	workspaceStmtRequested bool,
	err error,
) error {
	if jsonOutput {
		result := &posturepkg.VerifyResult{
			Verified:       false,
			Passed:         false,
			Error:          err.Error(),
			Policy:         policy,
			PolicyVersion:  posturepkg.PolicyVersion,
			ScoringVersion: posturepkg.ScoringVersion,
		}
		if capsule != nil {
			result.GeneratedAt = capsule.GeneratedAt
			result.ExpiresAt = capsule.ExpiresAt
			result.LastReceiptAt = capsule.Evidence.FlightRecorder.LastReceiptAt
		}
		if jsonErr := writeVerifyJSON(cmd, result, workspaceStmtRequested, false, err.Error(), nil); jsonErr != nil {
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

// loadProofFile reads and parses the proof file at path, returning both the
// parsed capsule AND the exact raw bytes it was parsed from. Callers that
// need to bind or hash the capsule (see VerifyBindingBytes) MUST use these
// same bytes rather than re-opening path: re-reading the path separately
// would authenticate one set of bytes and bind against a possibly different
// set read moments later (H1 TOCTOU).
func loadProofFile(path string) (*posturepkg.Capsule, []byte, error) {
	cleanPath := filepath.Clean(path)
	f, err := os.Open(cleanPath)
	if err != nil {
		return nil, nil, fmt.Errorf("reading %s: %w", cleanPath, err)
	}
	defer func() {
		_ = f.Close()
	}()

	data, err := io.ReadAll(io.LimitReader(f, maxProofJSONBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("reading %s: %w", cleanPath, err)
	}
	if len(data) > maxProofJSONBytes {
		return nil, nil, fmt.Errorf("proof JSON exceeds %d bytes", maxProofJSONBytes)
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var capsule posturepkg.Capsule
	if err := dec.Decode(&capsule); err != nil {
		return nil, nil, fmt.Errorf("parsing proof JSON: %w", err)
	}
	if err := rejectTrailingJSON(dec); err != nil {
		return nil, nil, fmt.Errorf("parsing proof JSON: %w", err)
	}
	return &capsule, data, nil
}

// loadPublicKey resolves either a public key path or a raw hex argument.
func loadPublicKey(pathOrValue string) (ed25519.PublicKey, error) {
	return signing.LoadPublicKey(pathOrValue)
}

func rejectTrailingJSON(dec *json.Decoder) error {
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("unexpected trailing JSON payload")
		}
		return err
	}
	return nil
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

			mdPath, err := posturepkg.WriteProofMarkdown(outputDir, capsule)
			if err != nil {
				return fmt.Errorf("write posture markdown: %w", err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Wrote %s\nWrote %s\n", path, mdPath)
			return nil
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "config file (default: built-in defaults)")
	cmd.Flags().StringVarP(&outputDir, "output", "o", posturepkg.DefaultOutputDir, "output directory for posture artifacts")
	cmd.Flags().IntVar(&expirationDays, "expiration-days", 0, "days until the capsule expires (default 30)")
	return cmd
}
