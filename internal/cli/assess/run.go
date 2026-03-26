// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package assess

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	domaudit "github.com/luckyPipewrench/pipelock/internal/audit"
	cliaudit "github.com/luckyPipewrench/pipelock/internal/cli/audit"
	"github.com/luckyPipewrench/pipelock/internal/cli/diag"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/discover"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
	"github.com/luckyPipewrench/pipelock/internal/rules"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// Primitive name constants used for evidence file naming and skip flags.
const (
	primitiveSimulate      = "simulate"
	primitiveAuditScore    = "audit-score"
	primitiveVerifyInstall = "verify-install"
	primitiveDiscover      = "discover"
)

// assessRunCmd creates the cobra command for "assess run".
func assessRunCmd() *cobra.Command {
	var (
		jsonOutput bool
		skip       []string
		force      bool
	)

	cmd := &cobra.Command{
		Use:   "run <run-dir>",
		Short: "Execute assessment primitives and write evidence",
		Long: `Run all assessment primitives (simulate, audit-score, verify-install,
discover) against the initialized run directory, writing JSONL evidence
files to the evidence/ subdirectory.

Verifies config integrity via SHA-256 hash before running. Use --force
to override config drift detection. Use --skip to exclude primitives.

Examples:
  pipelock assess run assessment-a1b2c3d4/
  pipelock assess run assessment-a1b2c3d4/ --skip verify-install
  pipelock assess run assessment-a1b2c3d4/ --force
  pipelock assess run assessment-a1b2c3d4/ --json`,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := runAssessRun(args[0], force, skip)
			if err != nil {
				return err
			}
			if jsonOutput {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]string{"status": assessStatusCompleted})
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), assessStatusCompleted)
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "machine-readable output")
	cmd.Flags().StringSliceVar(&skip, "skip", nil, "primitives to skip (simulate,audit-score,verify-install,discover)")
	cmd.Flags().BoolVar(&force, "force", false, "override config drift check")

	return cmd
}

// runAssessRun is the testable core of assess run.
func runAssessRun(runDir string, force bool, skip []string) error {
	// Step 1: read manifest.
	manifestPath := filepath.Join(filepath.Clean(runDir), "manifest.json")
	manifestData, err := os.ReadFile(filepath.Clean(manifestPath))
	if err != nil {
		return cliutil.ExitCodeError(2, fmt.Errorf("reading manifest: %w", err))
	}

	var manifest AssessManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return cliutil.ExitCodeError(2, fmt.Errorf("parsing manifest: %w", err))
	}

	// Step 2: verify status.
	if manifest.Status != assessStatusInitialized {
		return cliutil.ExitCodeError(2, fmt.Errorf("run directory status is %q, expected %q", manifest.Status, assessStatusInitialized))
	}

	// Step 3: config integrity check. Fail closed: missing hash on a non-default
	// config is treated as a tampered manifest, not a skip condition.
	if manifest.ConfigFile != configLabelDefaults {
		if manifest.ConfigHash == "" {
			return cliutil.ExitCodeError(2, fmt.Errorf("manifest has no config_hash for %q; cannot verify integrity", manifest.ConfigFile))
		}
		data, err := os.ReadFile(filepath.Clean(manifest.ConfigFile))
		if err != nil {
			return failManifest(manifestPath, &manifest, fmt.Errorf("reading config for integrity check: %w", err))
		}
		sum := sha256.Sum256(data)
		currentHash := hex.EncodeToString(sum[:])
		if currentHash != manifest.ConfigHash {
			if !force {
				// Config drift gets exit code 2, distinct from primitive failure (exit 1).
				now := time.Now().UTC()
				manifest.Status = assessStatusFailed
				manifest.FailedAt = &now
				manifest.FailureReason = "config drift detected"
				_ = writeManifest(manifestPath, &manifest)
				return cliutil.ExitCodeError(2, fmt.Errorf("config file has changed since init (expected hash %s, got %s); use --force to override", manifest.ConfigHash[:12], currentHash[:12]))
			}
			manifest.ConfigDrifted = true
		}
	}

	// Step 4: transition to running.
	manifest.Status = assessStatusRunning
	if err := writeManifest(manifestPath, &manifest); err != nil {
		return err
	}

	// Step 5: load config.
	cfg, err := loadConfigForAssess(manifest.ConfigFile)
	if err != nil {
		return failManifest(manifestPath, &manifest, fmt.Errorf("loading config: %w", err))
	}

	// Build skip set for O(1) lookup. Validate values upfront.
	validPrimitives := map[string]bool{
		"simulate": true, "audit-score": true,
		"verify-install": true, "discover": true,
	}
	skipSet := make(map[string]bool, len(skip))
	for _, s := range skip {
		if !validPrimitives[s] {
			return failManifest(manifestPath, &manifest,
				fmt.Errorf("unknown --skip value %q (valid: simulate, audit-score, verify-install, discover)", s))
		}
		skipSet[s] = true
	}

	evidenceDir := filepath.Join(filepath.Clean(runDir), "evidence")
	var failureErr error

	// Step 6: run primitives in order.

	// --- Simulate ---
	if !skipSet[primitiveSimulate] {
		if err := runPrimitiveSimulate(cfg, evidenceDir, manifest.ConfigFile); err != nil {
			failureErr = err
		}
	}

	// --- Audit Score ---
	if failureErr == nil && !skipSet[primitiveAuditScore] {
		if err := runPrimitiveAuditScore(cfg, evidenceDir, manifest.ConfigFile); err != nil {
			failureErr = err
		}
	}

	// --- Verify Install ---
	if failureErr == nil && !skipSet[primitiveVerifyInstall] {
		if err := runPrimitiveVerifyInstall(cfg, evidenceDir, manifest.ConfigFile); err != nil {
			failureErr = err
		}
	}

	// --- Discover ---
	if failureErr == nil && !skipSet[primitiveDiscover] {
		if err := runPrimitiveDiscover(evidenceDir); err != nil {
			failureErr = err
		}
	}

	// Step 9: record skipped primitives.
	var skipped []string
	allPrimitives := []string{primitiveSimulate, primitiveAuditScore, primitiveVerifyInstall, primitiveDiscover}
	for _, p := range allPrimitives {
		if skipSet[p] {
			skipped = append(skipped, p)
		}
	}
	sort.Strings(skipped)
	manifest.SkippedPrimitives = skipped

	// Step 8: set final status.
	if failureErr != nil {
		return failManifest(manifestPath, &manifest, failureErr)
	}

	now := time.Now().UTC()
	manifest.Status = assessStatusCompleted
	manifest.CompletedAt = &now
	if err := writeManifest(manifestPath, &manifest); err != nil {
		return err
	}

	return nil
}

// loadConfigForAssess loads the config file or returns defaults.
func loadConfigForAssess(configFile string) (*config.Config, error) {
	if configFile == configLabelDefaults {
		return config.Defaults(), nil
	}
	return config.Load(configFile)
}

// runPrimitiveSimulate executes the simulate primitive and writes evidence.
func runPrimitiveSimulate(cfg *config.Config, evidenceDir, configFile string) error {
	// Disable SSRF for simulation (no DNS in assessment context).
	simCfg := *cfg
	simCfg.Internal = nil

	sc := scanner.New(&simCfg)
	defer sc.Close()

	scenarios := cliaudit.BuildSimScenarios(&simCfg, sc)
	cfgLabel := configFile
	if configFile == configLabelDefaults {
		cfgLabel = ""
	}
	simResult := cliaudit.RunSimulation(scenarios, cfgLabel, simCfg.Mode)

	// Write evidence: one line per ScenarioResult.
	var lines []any
	for _, sr := range simResult.Scenarios {
		lines = append(lines, sr)
	}

	return writeEvidenceJSONL(filepath.Join(evidenceDir, "simulate.jsonl"), lines)
}

// runPrimitiveAuditScore executes the audit-score primitive and writes evidence.
func runPrimitiveAuditScore(cfg *config.Config, evidenceDir, configFile string) error {
	cfgLabel := configFile
	if configFile == configLabelDefaults {
		cfgLabel = ""
	}
	scoreResult := cliaudit.ScoreConfig(cfg, cfgLabel)

	// Write evidence: ScoreResult as first line, then each ScoreFinding.
	var lines []any
	lines = append(lines, scoreResult)
	for _, f := range scoreResult.Findings {
		lines = append(lines, f)
	}

	return writeEvidenceJSONL(filepath.Join(evidenceDir, "audit-score.jsonl"), lines)
}

// runPrimitiveVerifyInstall executes the verify-install primitive and writes evidence.
func runPrimitiveVerifyInstall(cfg *config.Config, evidenceDir, configFile string) error {
	// Clone config to avoid mutating the caller's copy.
	verifyCfg := *cfg
	verifyCfg.Internal = nil
	verifyCfg.DLP.ScanEnv = false

	// When no config was provided (defaults), enable full protection.
	if configFile == configLabelDefaults {
		verifyCfg.ForwardProxy.Enabled = true
		verifyCfg.MCPToolPolicy = config.MCPToolPolicy{
			Enabled: true,
			Action:  config.ActionBlock,
			Rules:   policy.DefaultToolPolicyRules(),
		}
		verifyCfg.ResponseScanning.Enabled = true
		verifyCfg.ResponseScanning.Action = config.ActionBlock
		verifyCfg.MCPInputScanning.Enabled = true
		verifyCfg.MCPInputScanning.Action = config.ActionBlock
	}

	// Start mock upstream server.
	var lc net.ListenConfig
	mockLn, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("verify-install mock listener: %w", err)
	}
	mock := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("mock upstream OK"))
	}))
	mock.Listener = mockLn
	mock.Start()
	defer mock.Close()

	// Add mock host to allowlist.
	mockHostPort := strings.TrimPrefix(mock.URL, "http://")
	mockHost, _, _ := net.SplitHostPort(mockHostPort)
	verifyCfg.APIAllowlist = append(verifyCfg.APIAllowlist, mockHost)
	verifyCfg.FetchProxy.Monitoring.Blocklist = append(verifyCfg.FetchProxy.Monitoring.Blocklist, "malware.example.com")

	// Merge community rule bundles.
	bundleResult := rules.MergeIntoConfig(&verifyCfg, cliutil.Version)
	if len(bundleResult.Errors) > 0 {
		first := bundleResult.Errors[0]
		return fmt.Errorf("verify-install merging rules: bundle %s: %s", first.Name, first.Reason)
	}

	// Build scanner and temporary proxy.
	sc := scanner.New(&verifyCfg)
	defer sc.Close()

	logger := domaudit.NewNop()
	defer logger.Close()

	m := metrics.New()
	p, pErr := proxy.New(&verifyCfg, logger, sc, m)
	if pErr != nil {
		return fmt.Errorf("verify-install creating proxy: %w", pErr)
	}

	proxyLn, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("verify-install proxy listener: %w", err)
	}
	ts := httptest.NewUnstartedServer(p.Handler())
	ts.Listener = proxyLn
	ts.Start()
	defer ts.Close()

	pc := policy.New(verifyCfg.MCPToolPolicy)
	runCtx := cliutil.DetectRunContext()

	cfgLabel := configFile
	if configFile == configLabelDefaults {
		cfgLabel = configLabelDefaults
	}

	env := &diag.VerifyEnv{
		ProxyURL:  ts.URL,
		MockURL:   mock.URL,
		Cfg:       &verifyCfg,
		Sc:        sc,
		PolicyCfg: pc,
		RunCtx:    runCtx,
		DialTCP:   diag.DirectTCPConnect,
		DialUDP:   diag.DirectUDPConnect,
	}

	checks := diag.BuildVerifyChecks()
	report := diag.BuildVerifyReport(env, checks, cfgLabel)

	// Write evidence: report as single JSON line.
	return writeEvidenceJSONL(filepath.Join(evidenceDir, "verify-install.jsonl"), []any{report})
}

// runPrimitiveDiscover executes the discover primitive and writes evidence.
func runPrimitiveDiscover(evidenceDir string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("discover home dir: %w", err)
	}

	report, err := discover.Discover(home)
	if err != nil {
		return fmt.Errorf("discover: %w", err)
	}

	wrapped := wrapDiscoverReport(report, home)

	return writeEvidenceJSONL(filepath.Join(evidenceDir, "discover.jsonl"), []any{wrapped})
}

// wrapDiscoverReport converts a discover.Report into the versioned assess wrapper.
func wrapDiscoverReport(r *discover.Report, home string) AssessDiscoverReport {
	result := AssessDiscoverReport{
		SchemaVersion: assessSchemaVersion,
		ScannedRoot:   home,
	}
	for _, c := range r.Clients {
		result.Clients = append(result.Clients, AssessDiscoverClient{
			ClientConfig:  c,
			SchemaVersion: assessSchemaVersion,
		})
	}
	for _, s := range r.Servers {
		// Redact fields that may contain secrets (env vars, connection strings
		// in args, config paths that reveal infrastructure). The assessment
		// only needs protection status, risk, and server identity.
		redacted := s
		redacted.Env = nil
		redacted.Args = nil
		redacted.URL = ""
		redacted.ConfigPath = ""
		redacted.ProjectPath = ""
		result.Servers = append(result.Servers, AssessDiscoverServer{
			MCPServer:     redacted,
			SchemaVersion: assessSchemaVersion,
		})
	}
	result.Summary = AssessDiscoverSummary{
		Summary:       r.Summary,
		SchemaVersion: assessSchemaVersion,
	}
	return result
}

// writeEvidenceJSONL writes one JSON object per line to the given path.
// Each line is marshaled independently. File permissions are 0o600.
func writeEvidenceJSONL(path string, lines []any) error {
	f, err := os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("creating evidence file %s: %w", filepath.Base(path), err)
	}
	defer func() { _ = f.Close() }()

	enc := json.NewEncoder(f)
	for _, line := range lines {
		if err := enc.Encode(line); err != nil {
			return fmt.Errorf("writing evidence line to %s: %w", filepath.Base(path), err)
		}
	}

	return nil
}

// writeManifest marshals the manifest and writes it atomically via temp+rename.
// This prevents a crash during write from corrupting manifest.json.
func writeManifest(path string, manifest *AssessManifest) error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return cliutil.ExitCodeError(2, fmt.Errorf("marshaling manifest: %w", err))
	}
	data = append(data, '\n')

	cleanPath := filepath.Clean(path)
	tmpPath := cleanPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return cliutil.ExitCodeError(2, fmt.Errorf("writing manifest temp: %w", err))
	}
	if err := os.Rename(tmpPath, cleanPath); err != nil {
		_ = os.Remove(tmpPath)
		return cliutil.ExitCodeError(2, fmt.Errorf("renaming manifest: %w", err))
	}
	return nil
}

// failManifest records a failure in the manifest and writes it.
func failManifest(manifestPath string, manifest *AssessManifest, reason error) error {
	now := time.Now().UTC()
	manifest.Status = assessStatusFailed
	manifest.FailedAt = &now
	manifest.FailureReason = reason.Error()
	// Best-effort write -- the original error is more important.
	_ = writeManifest(manifestPath, manifest)
	return cliutil.ExitCodeError(1, reason)
}
