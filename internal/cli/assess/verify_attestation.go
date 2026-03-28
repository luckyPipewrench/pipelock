// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package assess

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/report/attestation"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// assessVerifyAttestationCmd creates the cobra command for "assess verify-attestation".
func assessVerifyAttestationCmd() *cobra.Command {
	var (
		agent       string
		keystoreDir string
		jsonOutput  bool
	)

	cmd := &cobra.Command{
		Use:   "verify-attestation <run-dir>",
		Short: "Verify the signed attestation and badge artifacts for an assessment",
		Long: `Check the attestation payload, its detached signature, and the
primary artifact hash for a finalized assessment.

Exit codes:
  0 = attestation verified
  1 = attestation integrity failed
  2 = signature verification failed
  3 = no attestation present

Examples:
  pipelock assess verify-attestation assessment-a1b2c3d4/
  pipelock assess verify-attestation assessment-a1b2c3d4/ --agent claude-code`,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()

			exitCode, err := runAssessVerifyAttestation(args[0], agent, keystoreDir)
			if err != nil {
				return cliutil.ExitCodeError(exitCode, err)
			}

			if jsonOutput {
				result := map[string]interface{}{
					"exit_code": exitCode,
					"verified":  exitCode == 0,
				}
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				if encErr := enc.Encode(result); encErr != nil {
					return encErr
				}
				if exitCode == verifyExitUnsigned {
					return cliutil.ExitCodeError(verifyExitUnsigned, fmt.Errorf("attestation not present"))
				}
				return nil
			}

			switch exitCode {
			case 0:
				_, _ = fmt.Fprintln(out, "Attestation: verified")
			case verifyExitUnsigned:
				_, _ = fmt.Fprintln(out, "Attestation: not present")
				return cliutil.ExitCodeError(verifyExitUnsigned, fmt.Errorf("attestation not present"))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&agent, "agent", "", "agent name for signature verification (or set PIPELOCK_AGENT)")
	cmd.Flags().StringVar(&keystoreDir, "keystore", "", "keystore directory (default ~/.pipelock)")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "machine-readable output")

	return cmd
}

// runAssessVerifyAttestation verifies the attestation payload and signature.
func runAssessVerifyAttestation(runDir, agent, keystoreDir string) (int, error) {
	// Reuse the existing bundle integrity check first.
	// Both error AND non-zero exit code must abort — verifyExitUnsigned
	// (no manifest.json.sig) means a forged manifest could hide tampered artifacts.
	if exitCode, err := runAssessVerify(runDir, agent, keystoreDir); exitCode != 0 || err != nil {
		if err == nil {
			err = fmt.Errorf("bundle verification failed (exit %d)", exitCode)
		}
		return exitCode, err
	}

	cleanDir := filepath.Clean(runDir)
	attPath := filepath.Join(cleanDir, "attestation.json")
	data, err := os.ReadFile(filepath.Clean(attPath))
	if err != nil {
		if os.IsNotExist(err) {
			return verifyExitUnsigned, fmt.Errorf("attestation not present")
		}
		return verifyExitTamperedArtifact, fmt.Errorf("reading attestation: %w", err)
	}

	var att attestation.Attestation
	if err := json.Unmarshal(data, &att); err != nil {
		return verifyExitTamperedArtifact, fmt.Errorf("parsing attestation: %w", err)
	}

	if att.SchemaVersion != attestation.SchemaVersion {
		return verifyExitTamperedArtifact, fmt.Errorf("attestation schema version is %q, expected %q", att.SchemaVersion, attestation.SchemaVersion)
	}

	manifest, _, err := loadAssessStatusManifest(runDir)
	if err != nil {
		return verifyExitTamperedArtifact, err
	}
	if att.RunID != manifest.RunID {
		return verifyExitTamperedArtifact, fmt.Errorf("attestation run ID %q does not match manifest %q", att.RunID, manifest.RunID)
	}
	if att.LicenseTier != assessTierAssess {
		return verifyExitTamperedArtifact, fmt.Errorf("attestation license tier %q is not %q", att.LicenseTier, assessTierAssess)
	}
	// Containment: primary artifact must be a bare filename within the run dir.
	// Prevents path traversal via crafted attestation (e.g., "../../etc/passwd").
	if att.PrimaryArtifact != "assessment.json" || att.PrimaryArtifactSHA256 == "" {
		return verifyExitTamperedArtifact, fmt.Errorf("attestation missing or invalid primary artifact")
	}
	if att.Expired() {
		return verifyExitTamperedArtifact, fmt.Errorf("attestation expired at %s", att.ExpiresAt.Format("2006-01-02"))
	}

	// Safe: att.PrimaryArtifact is validated as "assessment.json" above,
	// so this Join cannot escape cleanDir.
	artifactPath := filepath.Join(cleanDir, att.PrimaryArtifact)
	actualHash, err := hashFile(artifactPath)
	if err != nil {
		return verifyExitTamperedArtifact, fmt.Errorf("hashing primary artifact: %w", err)
	}
	if actualHash != att.PrimaryArtifactSHA256 {
		return verifyExitTamperedArtifact, fmt.Errorf("primary artifact hash mismatch")
	}

	// Verify attestation signature exists — distinguish stripped sig (tampered)
	// from absent attestation (verifyExitUnsigned already returned above).
	sigPath := attPath + signing.SigExtension
	if _, err := os.Stat(sigPath); err != nil {
		if os.IsNotExist(err) {
			return verifyExitBadSignature, fmt.Errorf("attestation signature file missing (possible tampering)")
		}
		return verifyExitTamperedArtifact, fmt.Errorf("stat attestation signature: %w", err)
	}

	agentName, err := cliutil.ResolveAgentName(agent)
	if err != nil {
		return verifyExitBadSignature, fmt.Errorf("resolving agent: %w", err)
	}

	dir, err := cliutil.ResolveKeystoreDir(keystoreDir)
	if err != nil {
		return verifyExitBadSignature, fmt.Errorf("resolving keystore: %w", err)
	}
	ks := signing.NewKeystore(dir)

	pubKey, err := ks.ResolvePublicKey(agentName)
	if err != nil {
		return verifyExitBadSignature, fmt.Errorf("loading public key for agent %q: %w", agentName, err)
	}

	// Verify signer identity matches attestation payload (non-repudiation).
	if att.SignerKeyFingerprint != "" {
		resolvedFP := attestation.KeyFingerprint(pubKey)
		if att.SignerKeyFingerprint != resolvedFP {
			return verifyExitBadSignature, fmt.Errorf("key fingerprint mismatch: attestation says %s, resolved key is %s",
				att.SignerKeyFingerprint, resolvedFP)
		}
	}

	sig, err := signing.LoadSignature(sigPath)
	if err != nil {
		return verifyExitBadSignature, fmt.Errorf("loading attestation signature: %w", err)
	}

	if !ed25519.Verify(pubKey, data, sig) {
		return verifyExitBadSignature, fmt.Errorf("attestation signature verification failed")
	}

	// Verify badge integrity if attestation claims one.
	if att.BadgeSHA256 != "" {
		badgePath := filepath.Join(cleanDir, "badge.svg")
		badgeHash, err := hashFile(badgePath)
		if err != nil {
			return verifyExitTamperedArtifact, fmt.Errorf("badge.svg referenced in attestation but: %w", err)
		}
		if badgeHash != att.BadgeSHA256 {
			return verifyExitTamperedArtifact, fmt.Errorf("badge.svg hash mismatch (possible tampering)")
		}
	}

	return 0, nil
}
