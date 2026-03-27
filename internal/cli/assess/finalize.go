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
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cli/audit"
	"github.com/luckyPipewrench/pipelock/internal/cli/diag"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/license"
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
		unsigned     bool
		allowPartial bool
		archive      bool
		agent        string
		keystoreDir  string
		jsonOutput   bool
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
  pipelock assess finalize assessment-a1b2c3d4/ --archive`,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := assessFinalizeOpts{
				Unsigned:     unsigned,
				AllowPartial: allowPartial,
				Archive:      archive,
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

	// Step 2: read evidence.
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

	// Step 3: synthesize.
	assessment := synthesizeAssessment(manifest, sources)

	// Step 4: determine tier and produce output.
	artifacts := make(map[string]string)

	// Set signed flag before rendering so the template can display the correct badge.
	// This reflects intent (will sign), not state (has been signed) — signing happens after render.
	assessment.Signed = opts.HasAssess && !opts.Unsigned

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

	// Hash evidence files.
	evidenceDir := filepath.Join(cleanDir, "evidence")
	evidenceFiles := []string{"simulate.jsonl", "audit-score.jsonl", "verify-install.jsonl", "discover.jsonl"}
	for _, name := range evidenceFiles {
		path := filepath.Join(evidenceDir, name)
		if h, err := hashFile(path); err == nil {
			artifacts[filepath.Join("evidence", name)] = h
		}
	}

	// Step 6: update manifest with artifact hashes.
	manifest.Artifacts = artifacts

	// Step 7: sign (if licensed and not --unsigned).
	if opts.HasAssess && !opts.Unsigned {
		agentName, err := cliutil.ResolveAgentName(opts.Agent)
		if err != nil {
			return cliutil.ExitCodeError(1, fmt.Errorf("resolving agent for signing: %w", err))
		}

		dir, err := cliutil.ResolveKeystoreDir(opts.KeystoreDir)
		if err != nil {
			return cliutil.ExitCodeError(1, fmt.Errorf("resolving keystore: %w", err))
		}
		ks := signing.NewKeystore(dir)

		privKey, err := ks.LoadPrivateKey(agentName)
		if err != nil {
			// Signing failed: re-render artifacts with Signed=false so they
			// don't claim to be signed when no signature file exists.
			assessment.Signed = false
			rewriteAssessmentArtifacts(cleanDir, &assessment, artifacts)
			return cliutil.ExitCodeError(1, fmt.Errorf("loading key for agent %q: %w", agentName, err))
		}

		// Write manifest first so we can sign it.
		if err := writeManifest(manifestPath, &manifest); err != nil {
			return err
		}

		sig, err := signing.SignFile(manifestPath, privKey)
		if err != nil {
			assessment.Signed = false
			rewriteAssessmentArtifacts(cleanDir, &assessment, artifacts)
			return cliutil.ExitCodeError(1, fmt.Errorf("signing manifest: %w", err))
		}
		sigPath := manifestPath + signing.SigExtension
		if err := signing.SaveSignature(sig, sigPath); err != nil {
			assessment.Signed = false
			rewriteAssessmentArtifacts(cleanDir, &assessment, artifacts)
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
	verifyText := fmt.Sprintf(`Pipelock Assessment Verification
================================
Run ID: %s
Generated: %s

To verify this assessment:
  pipelock assess verify %s --agent %s

Manual verification:
  1. Check artifact hashes match manifest.json
  2. Verify manifest signature: pipelock verify manifest.json --agent %s

To export as PDF:
  Open %s in a browser and print to PDF (Ctrl+P / Cmd+P).
`, manifest.RunID, now.Format(time.RFC3339), runDir, agentHint, agentHint, htmlFilename)

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

// rewriteAssessmentArtifacts re-renders assessment JSON and HTML after a signing
// failure so that on-disk artifacts don't claim to be signed. If re-render fails,
// the stale artifacts are deleted to prevent Signed=true from persisting on disk
// when no signature file exists (fail-closed).
func rewriteAssessmentArtifacts(cleanDir string, a *Assessment, artifacts map[string]string) {
	jsonPath := filepath.Join(cleanDir, "assessment.json")
	htmlPath := filepath.Join(cleanDir, "assessment.html")

	if err := writeAssessmentJSON(jsonPath, a); err != nil {
		// Rewrite failed — delete stale artifact that claims Signed=true.
		_ = os.Remove(filepath.Clean(jsonPath))
		_ = os.Remove(filepath.Clean(htmlPath))
		return
	}
	if err := writeAssessmentHTML(htmlPath, a); err != nil {
		_ = os.Remove(filepath.Clean(jsonPath))
		_ = os.Remove(filepath.Clean(htmlPath))
		return
	}
	if h, err := hashFile(jsonPath); err == nil {
		artifacts["assessment.json"] = h
	}
	if h, err := hashFile(htmlPath); err == nil {
		artifacts["assessment.html"] = h
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

// hashFile computes the SHA-256 hex digest of a file.
func hashFile(path string) (string, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
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

		file, err := os.Open(filepath.Clean(path))
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

// sortedArtifactKeys returns artifact map keys in sorted order for deterministic output.
func sortedArtifactKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
