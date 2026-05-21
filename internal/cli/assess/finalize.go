// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package assess

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cli/audit"
	"github.com/luckyPipewrench/pipelock/internal/cli/diag"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/report/attestation"
	"github.com/luckyPipewrench/pipelock/internal/report/compliance"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// checkAssessLicense reads the manifest to find the config, loads it,
// resolves the license public key, verifies the token, and returns true
// if the license includes the "assess" feature. Returns false silently
// on any failure — the free path is the safe default.
func checkAssessLicense(runDir string) bool {
	manifestPath := filepath.Join(runDir, "manifest.json")
	data, err := os.ReadFile(filepath.Clean(manifestPath))
	if err != nil {
		return false
	}
	var manifest AssessManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return false
	}

	// Load the config to get the license key.
	cfg, err := loadConfigForAssess(manifest.ConfigFile)
	if err != nil {
		return false
	}

	if cfg.LicenseKey == "" {
		return false
	}

	// Resolve public key: embedded (official builds) > config field.
	pubKey := license.EmbeddedPublicKey()
	if pubKey == nil && cfg.LicensePublicKey != "" {
		keyBytes, hexErr := hex.DecodeString(cfg.LicensePublicKey)
		if hexErr == nil && len(keyBytes) == ed25519.PublicKeySize {
			pubKey = keyBytes
		}
	}
	if pubKey == nil {
		return false
	}

	lic, err := license.Verify(cfg.LicenseKey, pubKey)
	if err != nil {
		return false
	}

	return lic.HasFeature(license.FeatureAssess)
}

// assessFinalizeCmd creates the cobra command for "assess finalize".
func assessFinalizeCmd() *cobra.Command {
	var (
		unsigned        bool
		allowPartial    bool
		archive         bool
		badge           bool
		attestationFlag bool
		agent           string
		keystoreDir     string
		jsonOutput      bool
	)

	cmd := &cobra.Command{
		Use:   "finalize <run-dir>",
		Short: "Synthesize assessment, produce report, and optionally sign",
		Long: `Read completed evidence from the run directory, synthesize a scored
assessment, produce JSON and HTML output, and optionally sign the manifest.

Licensed users (assess feature) get the full assessment with signature.
Unlicensed users get a summary projection without signature.

Examples:
  pipelock assess finalize assessment-a1b2c3d4/
  pipelock assess finalize assessment-a1b2c3d4/ --unsigned
  pipelock assess finalize assessment-a1b2c3d4/ --allow-partial
  pipelock assess finalize assessment-a1b2c3d4/ --archive
  pipelock assess finalize assessment-a1b2c3d4/ --attestation --badge`,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if badge && !attestationFlag {
				return fmt.Errorf("--badge requires --attestation (badge is derived from the signed attestation)")
			}

			opts := assessFinalizeOpts{
				Unsigned:     unsigned,
				AllowPartial: allowPartial,
				Archive:      archive,
				Badge:        badge,
				Attestation:  attestationFlag,
				Agent:        agent,
				KeystoreDir:  keystoreDir,
				HasAssess:    checkAssessLicense(args[0]),
			}

			if err := runAssessFinalize(args[0], opts); err != nil {
				return err
			}

			if jsonOutput {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]string{"status": assessStatusFinalized})
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), assessStatusFinalized)
			return nil
		},
	}

	cmd.Flags().BoolVar(&unsigned, "unsigned", false, "skip signing even with license")
	cmd.Flags().BoolVar(&allowPartial, "allow-partial", false, "allow finalization with skipped primitives")
	cmd.Flags().BoolVar(&archive, "archive", false, "produce .tar.gz bundle")
	cmd.Flags().BoolVar(&attestationFlag, "attestation", false, "write attestation.json and detached signature")
	cmd.Flags().BoolVar(&badge, "badge", false, "write SVG badge derived from the attestation")
	cmd.Flags().StringVar(&agent, "agent", "", "agent name for signing (or set PIPELOCK_AGENT)")
	cmd.Flags().StringVar(&keystoreDir, "keystore", "", "keystore directory (default ~/.pipelock)")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "machine-readable output")

	return cmd
}

// assessFinalizeOpts controls the finalize phase behavior.
type assessFinalizeOpts struct {
	Unsigned     bool
	AllowPartial bool
	Archive      bool
	Badge        bool
	Attestation  bool
	Agent        string
	KeystoreDir  string
	HasAssess    bool // true if license has "assess" feature
}

// runAssessFinalize is the testable core of assess finalize.
func runAssessFinalize(runDir string, opts assessFinalizeOpts) error {
	cleanDir := filepath.Clean(runDir)

	// Step 1: read manifest and validate.
	manifestPath := filepath.Join(cleanDir, "manifest.json")
	manifestData, err := os.ReadFile(filepath.Clean(manifestPath))
	if err != nil {
		return cliutil.ExitCodeError(2, fmt.Errorf("reading manifest: %w", err))
	}

	var manifest AssessManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return cliutil.ExitCodeError(2, fmt.Errorf("parsing manifest: %w", err))
	}

	if manifest.Status == assessStatusFinalized {
		return cliutil.ExitCodeError(2, fmt.Errorf("already finalized"))
	}
	if manifest.Status != assessStatusCompleted {
		return cliutil.ExitCodeError(2, fmt.Errorf("status is %q, expected %q", manifest.Status, assessStatusCompleted))
	}
	if len(manifest.SkippedPrimitives) > 0 && !opts.AllowPartial {
		return cliutil.ExitCodeError(2, fmt.Errorf("assessment has skipped primitives %v; use --allow-partial to finalize", manifest.SkippedPrimitives))
	}
	if opts.AllowPartial {
		manifest.AllowPartial = true
	}

	// Only the current manifest schema can be finalized. v1 manifests
	// predate the evidence-hash integrity field; future schemas may add
	// primitives or semantics this binary cannot safely interpret.
	switch manifest.SchemaVersion {
	case assessSchemaVersion:
		// current schema
	case assessSchemaVersionV1:
		return cliutil.ExitCodeError(2, fmt.Errorf("manifest schema_version is %q; this binary requires schema %q (re-run `pipelock assess init`)", manifest.SchemaVersion, assessSchemaVersion))
	default:
		return cliutil.ExitCodeError(2, fmt.Errorf("unsupported manifest schema_version %q; this binary finalizes schema %q only", manifest.SchemaVersion, assessSchemaVersion))
	}

	// Step 2a: verify every non-skipped primitive's evidence file exists,
	// is non-empty, and matches the hash recorded by `assess run`. This
	// closes the window where evidence is mutated, replaced, or deleted
	// between `run` and `finalize` — a signed bundle must reflect what
	// the primitives actually produced, not what was on disk at finalize.
	if err := verifyEvidenceIntegrity(cleanDir, &manifest); err != nil {
		return cliutil.ExitCodeError(2, fmt.Errorf("evidence integrity: %w", err))
	}

	// Step 2b: read evidence.
	sources, err := readEvidenceSources(cleanDir)
	if err != nil {
		return cliutil.ExitCodeError(2, fmt.Errorf("reading evidence: %w", err))
	}

	// Pre-set finalized state on manifest so the embedded copy in
	// assessment/summary JSON reflects the final status.
	now := time.Now().UTC()
	manifest.FinalizedAt = &now
	manifest.Status = assessStatusFinalized
	if opts.HasAssess {
		manifest.LicenseTier = assessTierAssess
	} else {
		manifest.LicenseTier = assessTierFree
	}

	// Step 3: synthesize. synthesizeAssessment may set
	// ComplianceOmittedReason on its embedded manifest copy when partial
	// evidence prevents an honest framework-coverage claim — propagate
	// that back to the manifest written to disk.
	assessment := synthesizeAssessment(manifest, sources)
	manifest.ComplianceOmittedReason = assessment.Manifest.ComplianceOmittedReason

	// Step 4: determine tier and produce output.
	artifacts := make(map[string]string)
	shouldEmitAttestation := opts.HasAssess && !opts.Unsigned && (opts.Attestation || opts.Badge)

	// Set signed flag before rendering so the template can display the correct badge.
	// This reflects intent (will sign), not state (has been signed) — signing happens after render.
	assessment.Signed = opts.HasAssess && !opts.Unsigned

	// Load signing identity once when ANY downstream step needs it.
	// Without this, an attestation+manifest-signed run would load the
	// private key off disk twice with two distinct error sites for the
	// same underlying failure. nil when no signing happens.
	var signID *signingIdentity
	if opts.HasAssess && !opts.Unsigned {
		var err error
		signID, err = loadSigningIdentity(opts)
		if err != nil {
			return cliutil.ExitCodeError(1, err)
		}
	}

	if opts.HasAssess {
		// Paid path: full assessment.
		if err := writeAssessmentJSON(filepath.Join(cleanDir, "assessment.json"), &assessment); err != nil {
			return cliutil.ExitCodeError(2, err)
		}
		if err := writeAssessmentHTML(filepath.Join(cleanDir, "assessment.html"), &assessment); err != nil {
			return cliutil.ExitCodeError(2, err)
		}
		if h, err := hashFile(filepath.Join(cleanDir, "assessment.json")); err == nil {
			artifacts["assessment.json"] = h
		}
		if h, err := hashFile(filepath.Join(cleanDir, "assessment.html")); err == nil {
			artifacts["assessment.html"] = h
		}

		if shouldEmitAttestation {
			primaryHash, ok := artifacts["assessment.json"]
			if !ok {
				return cliutil.ExitCodeError(2, fmt.Errorf("missing assessment hash for attestation"))
			}

			// Generate badge BEFORE attestation so its hash is included
			// in the signed payload. Badge alone cannot be trusted without
			// verifying the attestation that binds it.
			var badgeSHA string
			if opts.Badge {
				attPreview := attestation.New(attestation.Input{
					GeneratedAt:  now,
					OverallGrade: assessment.OverallGrade,
					OverallScore: assessment.OverallScore,
				})
				badgePath := filepath.Join(cleanDir, "badge.svg")
				if err := os.WriteFile(badgePath, []byte(attestation.SVG(attPreview)), 0o600); err != nil {
					return cliutil.ExitCodeError(2, fmt.Errorf("writing badge.svg: %w", err))
				}
				h, err := hashFile(badgePath)
				if err != nil {
					return cliutil.ExitCodeError(2, fmt.Errorf("hashing badge.svg: %w", err))
				}
				badgeSHA = h
				artifacts["badge.svg"] = h
			}

			// Build attestation with signer identity and badge hash.
			att := attestation.New(attestation.Input{
				Tool:                  "pipelock assess",
				Version:               manifest.Version,
				BuildSHA:              manifest.BuildSHA,
				RunID:                 manifest.RunID,
				GeneratedAt:           now,
				LicenseTier:           manifest.LicenseTier,
				OverallGrade:          assessment.OverallGrade,
				OverallScore:          assessment.OverallScore,
				PrimaryArtifact:       "assessment.json",
				PrimaryArtifactSHA256: primaryHash,
				Compliance:            compliance.CoverageSummaries(assessment.Compliance),
				SignerAgent:           signID.AgentName,
				SignerKeyFingerprint:  attestation.KeyFingerprint(signID.PubKey),
				BadgeSHA256:           badgeSHA,
			})

			if err := writeAttestationJSON(filepath.Join(cleanDir, "attestation.json"), &att); err != nil {
				return cliutil.ExitCodeError(2, err)
			}
			if h, err := hashFile(filepath.Join(cleanDir, "attestation.json")); err == nil {
				artifacts["attestation.json"] = h
			}

			// Sign AFTER attestation includes all metadata (signer, badge hash).
			sig, err := signing.SignFile(filepath.Join(cleanDir, "attestation.json"), signID.PrivKey)
			if err != nil {
				return cliutil.ExitCodeError(1, fmt.Errorf("signing attestation: %w", err))
			}
			sigPath := filepath.Join(cleanDir, "attestation.json"+signing.SigExtension)
			if err := signing.SaveSignature(sig, sigPath); err != nil {
				return cliutil.ExitCodeError(1, fmt.Errorf("saving attestation signature: %w", err))
			}
			if h, err := hashFile(sigPath); err == nil {
				artifacts["attestation.json"+signing.SigExtension] = h
			}
		}
	} else {
		// Free path: summary projection.
		summary := projectToSummary(assessment)
		if err := writeSummaryJSON(filepath.Join(cleanDir, "summary.json"), &summary); err != nil {
			return cliutil.ExitCodeError(2, err)
		}
		if err := writeSummaryHTML(filepath.Join(cleanDir, "summary.html"), &summary); err != nil {
			return cliutil.ExitCodeError(2, err)
		}
		if h, err := hashFile(filepath.Join(cleanDir, "summary.json")); err == nil {
			artifacts["summary.json"] = h
		}
		if h, err := hashFile(filepath.Join(cleanDir, "summary.html")); err == nil {
			artifacts["summary.html"] = h
		}
	}

	// Copy already-verified evidence hashes into the artifact map.
	// These were validated up front by verifyEvidenceIntegrity, so the
	// recorded values are authoritative.
	for name, h := range manifest.EvidenceHashes {
		artifacts[filepath.Join("evidence", name)] = h
	}

	// Step 6: update manifest with artifact hashes.
	manifest.Artifacts = artifacts

	// Step 7: sign (if licensed and not --unsigned). signID was loaded
	// once near the top of the function and reused here — both this
	// and the attestation path share the same key material.
	if signID != nil {
		// Write manifest first so we can sign it.
		if err := writeManifest(manifestPath, &manifest); err != nil {
			return err
		}

		sig, err := signing.SignFile(manifestPath, signID.PrivKey)
		if err != nil {
			assessment.Signed = false
			rewriteAssessmentArtifacts(cleanDir, &assessment, artifacts)
			_ = writeManifest(manifestPath, &manifest) // update hashes after rewrite
			return cliutil.ExitCodeError(1, fmt.Errorf("signing manifest: %w", err))
		}
		sigPath := manifestPath + signing.SigExtension
		if err := signing.SaveSignature(sig, sigPath); err != nil {
			assessment.Signed = false
			rewriteAssessmentArtifacts(cleanDir, &assessment, artifacts)
			_ = writeManifest(manifestPath, &manifest) // update hashes after rewrite
			return cliutil.ExitCodeError(1, fmt.Errorf("saving signature: %w", err))
		}
	} else {
		// Unsigned or free: just write manifest.
		if err := writeManifest(manifestPath, &manifest); err != nil {
			return err
		}
	}

	// Step 8: write verify.txt.
	agentHint := opts.Agent
	if agentHint == "" {
		agentHint = "<agent-name>"
	}
	htmlFilename := "summary.html"
	if opts.HasAssess {
		htmlFilename = "assessment.html"
	}
	attestationText := ""
	if shouldEmitAttestation {
		attestationText = fmt.Sprintf(`
To verify attestation:
  pipelock assess verify-attestation %s --agent %s
`, runDir, agentHint)
	}
	verifyText := fmt.Sprintf(`Pipelock Assessment Verification
================================
Run ID: %s
Generated: %s

To verify this assessment:
  pipelock assess verify %s --agent %s

Manual verification:
  1. Check artifact hashes match manifest.json
  2. Verify manifest signature: pipelock verify manifest.json --agent %s
%s
To export as PDF:
  Open %s in a browser and print to PDF (Ctrl+P / Cmd+P).
`, manifest.RunID, now.Format(time.RFC3339), runDir, agentHint, agentHint, attestationText, htmlFilename)

	if err := os.WriteFile(filepath.Join(cleanDir, "verify.txt"), []byte(verifyText), 0o600); err != nil {
		return cliutil.ExitCodeError(2, fmt.Errorf("writing verify.txt: %w", err))
	}

	// Step 9: archive.
	if opts.Archive {
		archivePrefix := "summary"
		if opts.HasAssess {
			archivePrefix = "assessment"
		}
		// Use first 8 chars of run ID (strip hyphens) for brevity.
		idShort := strings.ReplaceAll(manifest.RunID, "-", "")
		if len(idShort) > 8 {
			idShort = idShort[:8]
		}
		archiveName := fmt.Sprintf("%s-%s.tar.gz", archivePrefix, idShort)
		archivePath := filepath.Join(filepath.Dir(cleanDir), archiveName)
		if err := createTarGz(archivePath, cleanDir); err != nil {
			return cliutil.ExitCodeError(2, fmt.Errorf("creating archive: %w", err))
		}
	}

	return nil
}

// rewriteAssessmentArtifacts re-renders assessment JSON and HTML after a
// signing failure so the on-disk artifacts do not claim to be signed.
// If re-render fails, the stale artifacts AND their hashes in the
// artifacts map are dropped — leaving a hash that points at a file
// that no longer exists (or worse, at a file claiming Signed=true)
// would let verify-attestation succeed against a torn bundle.
func rewriteAssessmentArtifacts(cleanDir string, a *Assessment, artifacts map[string]string) {
	jsonPath := filepath.Join(cleanDir, "assessment.json")
	htmlPath := filepath.Join(cleanDir, "assessment.html")

	purge := func() {
		_ = os.Remove(filepath.Clean(jsonPath))
		_ = os.Remove(filepath.Clean(htmlPath))
		delete(artifacts, "assessment.json")
		delete(artifacts, "assessment.html")
	}

	if err := writeAssessmentJSON(jsonPath, a); err != nil {
		purge()
		return
	}
	if err := writeAssessmentHTML(htmlPath, a); err != nil {
		purge()
		return
	}
	if h, err := hashFile(jsonPath); err == nil {
		artifacts["assessment.json"] = h
	} else {
		// Re-render succeeded but hash failed (disk swapped out under us
		// or perms changed). Drop the entry so the manifest is honest
		// about what it can prove.
		delete(artifacts, "assessment.json")
	}
	if h, err := hashFile(htmlPath); err == nil {
		artifacts["assessment.html"] = h
	} else {
		delete(artifacts, "assessment.html")
	}
}

// readEvidenceSources reads JSONL evidence files from the run directory
// and reconstructs AssessSources. Missing files (from skipped primitives)
// produce nil source entries.
func readEvidenceSources(runDir string) (AssessSources, error) {
	evidenceDir := filepath.Join(filepath.Clean(runDir), "evidence")
	var sources AssessSources

	// Simulate: each line is a ScenarioResult.
	simPath := filepath.Join(evidenceDir, "simulate.jsonl")
	if data, err := os.ReadFile(filepath.Clean(simPath)); err == nil {
		lines := splitJSONLines(data)
		var scenarios []audit.ScenarioResult
		for _, line := range lines {
			var sr audit.ScenarioResult
			if err := json.Unmarshal(line, &sr); err != nil {
				return sources, fmt.Errorf("parsing simulate evidence: %w", err)
			}
			scenarios = append(scenarios, sr)
		}
		sources.Simulate = reconstructSimulateResult(scenarios)
	}

	// Audit score: first line is ScoreResult, remaining are ScoreFinding.
	auditPath := filepath.Join(evidenceDir, "audit-score.jsonl")
	if data, err := os.ReadFile(filepath.Clean(auditPath)); err == nil {
		lines := splitJSONLines(data)
		if len(lines) > 0 {
			var score audit.ScoreResult
			if err := json.Unmarshal(lines[0], &score); err != nil {
				return sources, fmt.Errorf("parsing audit-score evidence: %w", err)
			}
			sources.AuditScore = &score
		}
	}

	// Verify install: single JSONL line containing the full VerifyReport.
	verifyPath := filepath.Join(evidenceDir, "verify-install.jsonl")
	if data, err := os.ReadFile(filepath.Clean(verifyPath)); err == nil {
		lines := splitJSONLines(data)
		if len(lines) > 0 {
			var report diag.VerifyReport
			if err := json.Unmarshal(lines[0], &report); err != nil {
				return sources, fmt.Errorf("parsing verify-install evidence: %w", err)
			}
			sources.VerifyInstall = &report
		}
	}

	// Discover: single JSONL line containing the full AssessDiscoverReport.
	discoverPath := filepath.Join(evidenceDir, "discover.jsonl")
	if data, err := os.ReadFile(filepath.Clean(discoverPath)); err == nil {
		lines := splitJSONLines(data)
		if len(lines) > 0 {
			var report AssessDiscoverReport
			if err := json.Unmarshal(lines[0], &report); err != nil {
				return sources, fmt.Errorf("parsing discover evidence: %w", err)
			}
			sources.Discover = &report
		}
	}

	return sources, nil
}

// reconstructSimulateResult rebuilds a SimulateResult from individual ScenarioResult entries.
func reconstructSimulateResult(scenarios []audit.ScenarioResult) *audit.SimulateResult {
	if len(scenarios) == 0 {
		return nil
	}

	total := len(scenarios)
	var passed, failed, knownLimits int
	for _, s := range scenarios {
		switch {
		case s.Limitation:
			knownLimits++
		case s.Detected:
			passed++
		default:
			failed++
		}
	}

	applicable := total - knownLimits
	pct := 0
	if applicable > 0 {
		pct = (passed * 100) / applicable
	}

	return &audit.SimulateResult{
		Total:       total,
		Passed:      passed,
		Failed:      failed,
		KnownLimits: knownLimits,
		Percentage:  pct,
		Grade:       gradeFromPercentage(pct),
		Scenarios:   scenarios,
	}
}

// splitJSONLines splits raw bytes into non-empty lines suitable for JSON parsing.
func splitJSONLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			line := data[start:i]
			if len(line) > 0 {
				lines = append(lines, line)
			}
			start = i + 1
		}
	}
	if start < len(data) {
		remaining := data[start:]
		if len(remaining) > 0 {
			lines = append(lines, remaining)
		}
	}
	return lines
}

// projectToSummary creates a Summary from a full Assessment, stripping
// detail fields and limiting findings.
func projectToSummary(a Assessment) Summary {
	// Copy sections but strip Detail.
	sections := make([]AssessmentSection, len(a.Sections))
	for i, s := range a.Sections {
		sections[i] = s
		sections[i].Detail = ""
	}

	// Top 3 findings by severity (already sorted).
	topCount := 3
	if len(a.Findings) < topCount {
		topCount = len(a.Findings)
	}
	topFindings := make([]SummaryFinding, topCount)
	for i := 0; i < topCount; i++ {
		f := a.Findings[i]
		title := f.Title
		id := f.ID
		// Redact server names from discover findings in free tier.
		// The free summary should show "you have unprotected servers"
		// without naming them — names are actionable detail for paid tier.
		if f.Source == sourceDiscover {
			title = redactDiscoverTitle(f.Severity)
			id = fmt.Sprintf("find-discover-redacted-%d", i)
		}
		topFindings[i] = SummaryFinding{
			SchemaVersion: f.SchemaVersion,
			ID:            id,
			Severity:      f.Severity,
			Category:      f.Category,
			Source:        f.Source,
			Title:         title,
		}
	}

	// ServerCounts from discover source.
	var serverCounts AssessDiscoverSummary
	if a.Sources.Discover != nil {
		serverCounts = a.Sources.Discover.Summary
	}

	// DetectionPct from simulate.
	detectionPct := 0
	if a.Sources.Simulate != nil {
		detectionPct = a.Sources.Simulate.Percentage
	}

	// CapReason from the effective cap reason (for the summary topline).
	var capReason string
	if a.GradeCap != "" && len(a.CapReasons) > 0 {
		capReason = effectiveCapReason(a.GradeCap, a.CapReasons)
	}

	return Summary{
		SchemaVersion: a.SchemaVersion,
		Manifest:      a.Manifest,
		OverallGrade:  a.OverallGrade,
		OverallScore:  a.OverallScore,
		GradeCap:      a.GradeCap,
		CapReason:     capReason,
		Sections:      sections,
		TopFindings:   topFindings,
		ServerCounts:  serverCounts,
		DetectionPct:  detectionPct,
		Signed:        false,
		Compliance:    compliance.CoverageSummaries(a.Compliance),
	}
}

// redactDiscoverTitle produces a generic finding title for the free tier,
// hiding server names that would let someone fix the issue without paying.
func redactDiscoverTitle(severity string) string {
	if severity == assessSevHigh {
		return "A high-risk MCP server is unprotected"
	}
	return "An MCP server is unprotected"
}

// writeAssessmentJSON writes the full assessment to a JSON file.
func writeAssessmentJSON(path string, a *Assessment) error {
	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling assessment: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(filepath.Clean(path), data, 0o600); err != nil {
		return fmt.Errorf("writing assessment.json: %w", err)
	}
	return nil
}

// writeAssessmentHTML writes the assessment as an HTML file.
func writeAssessmentHTML(path string, a *Assessment) error {
	f, err := os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("creating assessment.html: %w", err)
	}
	defer func() { _ = f.Close() }()

	if err := renderAssessmentHTML(f, a); err != nil {
		return fmt.Errorf("rendering assessment.html: %w", err)
	}
	return nil
}

// writeSummaryJSON writes the summary projection to a JSON file.
func writeSummaryJSON(path string, s *Summary) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling summary: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(filepath.Clean(path), data, 0o600); err != nil {
		return fmt.Errorf("writing summary.json: %w", err)
	}
	return nil
}

// writeSummaryHTML writes the summary projection as an HTML file.
func writeSummaryHTML(path string, s *Summary) error {
	f, err := os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("creating summary.html: %w", err)
	}
	defer func() { _ = f.Close() }()

	if err := renderSummaryHTML(f, s); err != nil {
		return fmt.Errorf("rendering summary.html: %w", err)
	}
	return nil
}

// writeAttestationJSON writes the attestation payload to a JSON file.
func writeAttestationJSON(path string, a *attestation.Attestation) error {
	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling attestation: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(filepath.Clean(path), data, 0o600); err != nil {
		return fmt.Errorf("writing attestation.json: %w", err)
	}
	return nil
}

// hashFile computes the SHA-256 hex digest of a file.
func hashFile(path string) (string, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// signingIdentity bundles the resolved agent + keystore + key material
// needed by every downstream signing call in finalize. Loading it once
// avoids reading the same private key off disk twice when both an
// attestation and a signed manifest are being produced.
type signingIdentity struct {
	AgentName string
	PrivKey   ed25519.PrivateKey
	PubKey    ed25519.PublicKey
}

// loadSigningIdentity resolves the operator-selected agent name and
// keystore directory, then loads the corresponding ed25519 key pair.
// Returns a wrapped error explaining which step failed.
func loadSigningIdentity(opts assessFinalizeOpts) (*signingIdentity, error) {
	agentName, err := cliutil.ResolveAgentName(opts.Agent)
	if err != nil {
		return nil, fmt.Errorf("resolving agent for signing: %w", err)
	}
	dir, err := cliutil.ResolveKeystoreDir(opts.KeystoreDir)
	if err != nil {
		return nil, fmt.Errorf("resolving keystore for signing: %w", err)
	}
	ks := signing.NewKeystore(dir)
	privKey, err := ks.LoadPrivateKey(agentName)
	if err != nil {
		return nil, fmt.Errorf("loading key for agent %q: %w", agentName, err)
	}
	pubKey, err := ks.LoadPublicKey(agentName)
	if err != nil {
		return nil, fmt.Errorf("loading public key for agent %q: %w", agentName, err)
	}
	return &signingIdentity{AgentName: agentName, PrivKey: privKey, PubKey: pubKey}, nil
}

// verifyEvidenceIntegrity enforces that the evidence directory contains
// exactly the files `assess run` claimed it produced, byte-for-byte. It
// runs after manifest validation and before synthesis; any anomaly returns
// an error and finalize refuses to produce a report.
//
// Rules, in order:
//   - manifest.EvidenceHashes must be non-empty (v2 invariant — v1 manifests
//     are rejected upstream by SchemaVersion check).
//   - Every primitive not in SkippedPrimitives must have an entry.
//   - Every entry's file must exist, be non-empty, and hash to the recorded value.
//   - No extra EvidenceHashes entries are tolerated — keeps finalize from
//     silently trusting a future or injected primitive that this binary
//     cannot interpret.
//
// Threat model: the integrity contract assumes the same principal runs
// both `assess run` and `assess finalize`. The manifest itself is written
// unsigned at run time, so an actor with write access to the run
// directory can update manifest.EvidenceHashes in lockstep with a
// swapped evidence file and bypass this check. Closing that gap requires
// signing the manifest at run time with a separate trust anchor (out of
// scope for v2 — tracked for the next schema bump). Until then,
// operators running `run` and `finalize` on different machines or under
// different principals should sign the entire run directory out of
// band (tar + ed25519) between the two steps.
func verifyEvidenceIntegrity(runDir string, manifest *AssessManifest) error {
	skipSet := make(map[string]bool, len(manifest.SkippedPrimitives))
	for _, p := range manifest.SkippedPrimitives {
		skipSet[p] = true
	}

	if len(manifest.EvidenceHashes) == 0 {
		return fmt.Errorf("manifest is missing evidence_hashes — manifest was not produced by `assess run` or has been truncated")
	}

	allPrimitives := []string{primitiveSimulate, primitiveAuditScore, primitiveVerifyInstall, primitiveDiscover}
	evidenceDir := filepath.Join(filepath.Clean(runDir), "evidence")

	for _, p := range allPrimitives {
		name := evidenceFilename(p)
		recorded, claimed := manifest.EvidenceHashes[name]

		if skipSet[p] {
			if claimed {
				return fmt.Errorf("primitive %q is listed as skipped but evidence_hashes has an entry for %s", p, name)
			}
			continue
		}

		if !claimed {
			return fmt.Errorf("primitive %q not in skipped list but evidence_hashes lacks %s", p, name)
		}

		path := filepath.Join(evidenceDir, name)
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("evidence file %s for primitive %q: %w", name, p, err)
		}
		if info.Size() == 0 {
			return fmt.Errorf("evidence file %s for primitive %q is empty", name, p)
		}

		actual, err := hashFile(path)
		if err != nil {
			return fmt.Errorf("hashing evidence %s: %w", name, err)
		}
		if actual != recorded {
			return fmt.Errorf("evidence file %s for primitive %q has been modified since run (manifest hash %s, on-disk %s)", name, p, shortHash(recorded), shortHash(actual))
		}
	}

	// Reject extra entries the binary doesn't know about. A future schema
	// addition would bump assessSchemaVersion; today's binary should not
	// trust evidence it can't name.
	known := map[string]bool{}
	for _, p := range allPrimitives {
		known[evidenceFilename(p)] = true
	}
	for name := range manifest.EvidenceHashes {
		if !known[name] {
			return fmt.Errorf("manifest references unknown evidence file %q — schema version mismatch?", name)
		}
	}

	return nil
}

// shortHash returns the first 12 hex chars of a SHA-256 digest, enough
// for an operator to grep but short enough to fit in an error message.
func shortHash(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}

// createTarGz creates a gzipped tar archive of the given directory.
func createTarGz(archivePath, sourceDir string) error {
	f, err := os.OpenFile(filepath.Clean(archivePath), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("creating archive file: %w", err)
	}
	defer func() { _ = f.Close() }()

	gw := gzip.NewWriter(f)
	defer func() { _ = gw.Close() }()

	tw := tar.NewWriter(gw)
	defer func() { _ = tw.Close() }()

	baseDir := filepath.Base(sourceDir)
	cleanSource := filepath.Clean(sourceDir)

	// Open the source dir as a root so per-file opens inside the walk reject
	// symlinks that escape (G122 symlink TOCTOU).
	root, err := os.OpenRoot(cleanSource)
	if err != nil {
		return fmt.Errorf("opening source root: %w", err)
	}
	defer func() { _ = root.Close() }()

	return filepath.Walk(cleanSource, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		// Compute relative path within the archive.
		rel, err := filepath.Rel(cleanSource, path)
		if err != nil {
			return fmt.Errorf("computing relative path: %w", err)
		}

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return fmt.Errorf("creating tar header: %w", err)
		}
		header.Name = filepath.Join(baseDir, rel)

		if err := tw.WriteHeader(header); err != nil {
			return fmt.Errorf("writing tar header: %w", err)
		}

		if info.IsDir() {
			return nil
		}

		file, err := root.Open(rel)
		if err != nil {
			return fmt.Errorf("opening file for archive: %w", err)
		}
		defer func() { _ = file.Close() }()

		if _, err := io.Copy(tw, file); err != nil {
			return fmt.Errorf("writing file to archive: %w", err)
		}

		return nil
	})
}
