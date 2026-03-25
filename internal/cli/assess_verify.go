// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// Exit code constants for assess verify.
const (
	verifyExitTamperedArtifact = 1
	verifyExitBadSignature     = 2
	verifyExitUnsigned         = 3
)

// assessVerifyCmd creates the cobra command for "assess verify".
func assessVerifyCmd() *cobra.Command {
	var (
		agent       string
		keystoreDir string
		jsonOutput  bool
	)

	cmd := &cobra.Command{
		Use:   "verify <run-dir>",
		Short: "Verify artifact integrity and optional signature of an assessment",
		Long: `Check artifact hashes (integrity) and optionally verify the manifest
signature (authenticity) for a finalized assessment.

Exit codes:
  0 = integrity + authenticity verified (signed)
  1 = integrity check failed (tampered artifact)
  2 = signature verification failed (bad signature)
  3 = integrity verified, no signature present (unsigned)

Examples:
  pipelock assess verify assessment-a1b2c3d4/
  pipelock assess verify assessment-a1b2c3d4/ --agent claude-code`,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()

			exitCode, err := runAssessVerify(args[0], agent, keystoreDir)
			if err != nil {
				return ExitCodeError(exitCode, err)
			}

			if jsonOutput {
				result := map[string]interface{}{
					"exit_code": exitCode,
					"signed":    exitCode == 0,
					"integrity": exitCode != verifyExitTamperedArtifact,
				}
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				if encErr := enc.Encode(result); encErr != nil {
					return encErr
				}
				if exitCode == verifyExitUnsigned {
					return ExitCodeError(verifyExitUnsigned, fmt.Errorf("integrity verified, no signature"))
				}
				return nil
			}

			switch exitCode {
			case 0:
				_, _ = fmt.Fprintln(out, "Integrity + authenticity: verified")
			case verifyExitUnsigned:
				_, _ = fmt.Fprintln(out, "Integrity: verified (unsigned)")
				return ExitCodeError(verifyExitUnsigned, fmt.Errorf("integrity verified, no signature"))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&agent, "agent", "", "agent name for signature verification (or set PIPELOCK_AGENT)")
	cmd.Flags().StringVar(&keystoreDir, "keystore", "", "keystore directory (default ~/.pipelock)")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "machine-readable output")

	return cmd
}

// runAssessVerify is the testable core of assess verify.
// Returns (0, nil) for integrity+authenticity OK,
// (1, err) for tampered artifact,
// (2, err) for bad signature,
// (3, nil) for integrity OK but unsigned.
func runAssessVerify(runDir, agent, keystoreDir string) (int, error) {
	cleanDir := filepath.Clean(runDir)
	manifestPath := filepath.Join(cleanDir, "manifest.json")

	// Step 1: read manifest.
	manifestBytes, err := os.ReadFile(filepath.Clean(manifestPath))
	if err != nil {
		return 1, fmt.Errorf("reading manifest: %w", err)
	}

	var manifest AssessManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return 1, fmt.Errorf("parsing manifest: %w", err)
	}

	// Step 2: verify status is finalized.
	if manifest.Status != assessStatusFinalized {
		return 1, fmt.Errorf("assessment status is %q, expected %q", manifest.Status, assessStatusFinalized)
	}

	// Step 3: verify artifact hashes.
	for name, expectedHash := range manifest.Artifacts {
		artifactPath := filepath.Join(cleanDir, name)
		actualHash, err := hashFile(artifactPath)
		if err != nil {
			return verifyExitTamperedArtifact, fmt.Errorf("integrity check failed: %s: %w", name, err)
		}
		if actualHash != expectedHash {
			return verifyExitTamperedArtifact, fmt.Errorf("integrity check failed: %s", name)
		}
	}

	// Step 4: check for signature file.
	sigPath := manifestPath + signing.SigExtension
	if _, err := os.Stat(sigPath); os.IsNotExist(err) {
		// No signature — integrity only.
		return verifyExitUnsigned, nil
	}

	// Step 5: load public key and verify signature.
	agentName, err := resolveAgentName(agent)
	if err != nil {
		return verifyExitBadSignature, fmt.Errorf("resolving agent: %w", err)
	}

	dir, err := resolveKeystoreDir(keystoreDir)
	if err != nil {
		return verifyExitBadSignature, fmt.Errorf("resolving keystore: %w", err)
	}
	ks := signing.NewKeystore(dir)

	pubKey, err := ks.ResolvePublicKey(agentName)
	if err != nil {
		return verifyExitBadSignature, fmt.Errorf("loading public key for agent %q: %w", agentName, err)
	}

	sig, err := signing.LoadSignature(sigPath)
	if err != nil {
		return verifyExitBadSignature, fmt.Errorf("loading signature: %w", err)
	}

	if !ed25519.Verify(pubKey, manifestBytes, sig) {
		return verifyExitBadSignature, fmt.Errorf("signature verification failed")
	}

	return 0, nil
}

// assessStatusCmd creates the cobra command for "assess status".
func assessStatusCmd() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "status <run-dir>",
		Short: "Show status and metadata for an assessment run",
		Long: `Display the run ID, status, config, timestamps, artifact count,
and signing state of an assessment run directory.

Examples:
  pipelock assess status assessment-a1b2c3d4/
  pipelock assess status assessment-a1b2c3d4/ --json`,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if jsonOutput {
				return runAssessStatusJSON(cmd, args[0])
			}
			return runAssessStatus(cmd, args[0])
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "machine-readable output")

	return cmd
}

// runAssessStatus prints human-readable status for a run directory.
func runAssessStatus(cmd *cobra.Command, runDir string) error {
	manifest, signed, err := loadAssessStatusManifest(runDir)
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(out, "Run ID:     %s\n", manifest.RunID)
	_, _ = fmt.Fprintf(out, "Status:     %s\n", manifest.Status)
	_, _ = fmt.Fprintf(out, "Config:     %s\n", manifest.ConfigFile)
	_, _ = fmt.Fprintf(out, "Started:    %s\n", manifest.StartedAt.Format("2006-01-02T15:04:05Z"))

	if manifest.CompletedAt != nil {
		_, _ = fmt.Fprintf(out, "Completed:  %s\n", manifest.CompletedAt.Format("2006-01-02T15:04:05Z"))
	}
	if manifest.FinalizedAt != nil {
		_, _ = fmt.Fprintf(out, "Finalized:  %s\n", manifest.FinalizedAt.Format("2006-01-02T15:04:05Z"))
	}

	_, _ = fmt.Fprintf(out, "Artifacts:  %d\n", len(manifest.Artifacts))
	_, _ = fmt.Fprintf(out, "Signed:     %v\n", signed)

	return nil
}

// runAssessStatusJSON prints JSON status for a run directory.
func runAssessStatusJSON(cmd *cobra.Command, runDir string) error {
	manifest, signed, err := loadAssessStatusManifest(runDir)
	if err != nil {
		return err
	}

	result := map[string]interface{}{
		"run_id":         manifest.RunID,
		"status":         manifest.Status,
		"config_file":    manifest.ConfigFile,
		"started_at":     manifest.StartedAt,
		"completed_at":   manifest.CompletedAt,
		"finalized_at":   manifest.FinalizedAt,
		"artifact_count": len(manifest.Artifacts),
		"signed":         signed,
	}

	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

// loadAssessStatusManifest reads the manifest from runDir and checks for a sig file.
func loadAssessStatusManifest(runDir string) (manifest AssessManifest, signed bool, err error) {
	cleanDir := filepath.Clean(runDir)
	manifestPath := filepath.Join(cleanDir, "manifest.json")

	data, err := os.ReadFile(filepath.Clean(manifestPath))
	if err != nil {
		return manifest, false, fmt.Errorf("reading manifest: %w", err)
	}

	if err := json.Unmarshal(data, &manifest); err != nil {
		return manifest, false, fmt.Errorf("parsing manifest: %w", err)
	}

	sigPath := manifestPath + signing.SigExtension
	_, statErr := os.Stat(sigPath)
	signed = statErr == nil

	return manifest, signed, nil
}
